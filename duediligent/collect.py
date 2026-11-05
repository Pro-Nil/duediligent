"""Gather evidence: Crustdata records, web search, vendor pages and passive checks."""
from __future__ import annotations

import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse

import dns.resolver
import httpx
from bs4 import BeautifulSoup

from .crust import Crust, CrustError
from .evidence import EvidenceStore, Finding, dig, normalize

BREACH_WORDS = re.compile(r"breach|hack|compromis|ransomware|leak|exposed|stolen|cyberattack|cyber attack|incident|intrusion|unauthori[sz]ed", re.I)
CERT_WORDS = re.compile(r"soc\s*2|iso\s*27001|trust|security|compliance|certif", re.I)
CLOSURE_WORDS = re.compile(r"shut(s|ting)? down|shutdown|ceas(e|ed|es|ing) operations|out of business|bankrupt|insolven|liquidat|wind(ing|s)? down|closed its doors", re.I)
SECURITY_TITLE = re.compile(r"\bciso\b|chief (information )?security|head of (information |cyber)?security|vp,? (of )?(information )?security", re.I)
BLOCK_PAGE = re.compile(r"attention required|just a moment|access denied|verify you are human|are you a robot|enable javascript and cookies", re.I)
TRUST_PATHS = ["/security", "/trust", "/compliance", "/legal/security"]
TRUST_HOSTS = ["trust", "security"]
UA = {"User-Agent": "duediligent-vendor-review/0.1"}
MAX_TEXT = 60000


def html_to_text(html: str) -> str:
    soup = BeautifulSoup(html or "", "html.parser")
    for tag in soup(["script", "style", "noscript", "svg", "template"]):
        tag.decompose()
    return re.sub(r"\s+", " ", soup.get_text(" ")).strip()[:MAX_TEXT]


def registered(url: str) -> str:
    return re.sub(r"^www\.", "", urlparse(url).netloc.lower())


def canonical_domain(domain: str) -> str:
    """Where the vendor's own website lands. Falls back to the given domain."""
    try:
        with httpx.Client(timeout=12, follow_redirects=True, headers=UA) as client:
            with client.stream("GET", f"https://{domain}/") as resp:
                host = registered(str(resp.url))
                # A marketing subdomain still belongs to the same registered name.
                return host if host else domain
    except (httpx.HTTPError, httpx.InvalidURL, ValueError):
        return domain


def resolve_links(rows: list[dict]) -> None:
    """Search results can hold redirect links. A citation must name the real page."""
    def one(row: dict) -> None:
        url = row.get("url") or ""
        if "google.com/goto" not in url:
            return
        try:
            with httpx.Client(timeout=12, follow_redirects=True, headers=UA) as client:
                with client.stream("GET", url) as resp:
                    final = str(resp.url)
            row["url"] = None if "google.com" in registered(final) else final
        except httpx.HTTPError:
            row["url"] = None

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(one, rows))


def fetch_pages(crust: Crust, store: EvidenceStore, urls: list[str], log) -> tuple[list[str], list[str]]:
    """Fetch through Crustdata, in chunks of ten. Returns (evidence ids, failed urls)."""
    ev_ids, failed = [], []
    urls = list(dict.fromkeys(urls))
    for i in range(0, len(urls), 10):
        chunk = urls[i:i + 10]
        try:
            rows = crust.fetch(chunk)
        except CrustError as exc:
            log("warn", f"Page fetch failed: {exc}")
            if exc.terminal:
                raise
            failed.extend(chunk)
            continue
        seen = set()
        for row in rows:
            url = row.get("url")
            if not row.get("success") or not row.get("content"):
                continue
            seen.add(url)
            text = html_to_text(row["content"])
            # Empty shells and bot-check screens hold no facts. We report them, not bypass them.
            if len(text) < 200 or BLOCK_PAGE.search(str(row.get("title") or "")):
                failed.append(url)
                continue
            ev_ids.append(store.add("web_page", row.get("title") or url, url, text=text).id)
        failed.extend(u for u in chunk if u not in seen)
    return ev_ids, failed


def stability_facts(store: EvidenceStore, company: dict, ev_id: str) -> tuple[dict, list[Finding]]:
    """Company facts from the Crustdata record, each tied to a data path."""
    facts: list[Finding] = []

    def fact(path: str, label: str, kind: str = "stability") -> object:
        value = dig(company, path)
        if value not in (None, "", [], {}):
            f = Finding(kind=kind, claim=f"{label}: {value}", evidence_id=ev_id, path=path, value=value)
            if store.verify(f):
                facts.append(f)
        return value

    fact("basic_info.name", "Legal or trading name", "identity")
    fact("basic_info.primary_domain", "Primary domain", "identity")
    fact("basic_info.year_founded", "Founded")
    fact("basic_info.company_type", "Company type")
    status = fact("basic_info.status", "Record status")
    headcount = fact("headcount.total", "Headcount")
    yoy = fact("headcount.growth_percent.yoy", "Headcount change, year on year (%)")
    fact("funding.total_investment_usd", "Total funding (USD)")
    fact("funding.last_round_type", "Last round")
    fact("funding.last_fundraise_date", "Last fundraise date")
    fact("hiring.openings_count", "Open roles")
    acquisition = fact("revenue.acquisition_status", "Acquisition status")
    if isinstance(acquisition, dict):
        acquisition = acquisition.get("status") or acquisition.get("acquired_by") or None
    if isinstance(acquisition, str) and acquisition.lower() in ("none", "operating", "independent", "not acquired", "n/a"):
        acquisition = None

    leaders = leader_candidates(company)

    closed = isinstance(status, str) and bool(re.search(r"closed|defunct|inactive|out of business|dissolved", status, re.I))
    flags = []
    founded = dig(company, "basic_info.year_founded")
    if isinstance(founded, str) and founded[:4].isdigit():
        founded = int(founded[:4])
    if isinstance(founded, int) and datetime.now(timezone.utc).year - founded <= 2:
        flags.append({"text": f"The company is young (founded {founded}). Confirm it can meet its support and continuity commitments.", "evidence": [ev_id]})
    if isinstance(headcount, (int, float)) and headcount < 5:
        flags.append({"text": f"Only {int(headcount)} staff on record. Confirm this is a trading business with real operations.", "evidence": [ev_id]})
    if not leaders:
        flags.append({"text": "The company record names no founder or executive. Ask who runs the business.", "evidence": [ev_id]})
    notes = []
    size_band = re.findall(r"\d[\d,]*", str(dig(company, "basic_info.employee_count_range") or ""))
    if isinstance(headcount, (int, float)) and len(size_band) == 2:
        low, high = (int(n.replace(",", "")) for n in size_band)
        if headcount > high * 2 or headcount < low / 2:
            notes.append({"text": f"The record disagrees with itself: {int(headcount):,} staff, but a size band of {low:,} to {high:,}. Treat its headcount as unreliable.", "evidence": [ev_id]})
    return {
        "flags": flags,
        "notes": notes,
        "founded": founded,
        "status": status,
        "openings": dig(company, "hiring.openings_count"),
        "closed": closed,
        "closed_detail": f"The company record shows status \"{status}\"." if closed else None,
        "acquired": acquisition or None,
        "headcount": headcount,
        "headcount_yoy": yoy,
        "evidence": [ev_id],
        "leader_candidates": leaders,
    }, facts


LEADER_TITLE = re.compile(r"\bceo\b|chief executive|founder|\bciso\b|chief (information )?security|\bcto\b|chief technology", re.I)


def leader_candidates(company: dict) -> list[dict]:
    """People the record lists in senior roles. Profiles are self-reported, so these are
    only candidates until another source names them."""
    rows, seen = [], set()
    for group in ("cxos", "founders", "decision_makers"):
        people = dig(company, f"people.{group}") or []
        if not isinstance(people, list):
            continue
        for i, person in enumerate(people[:300]):
            name = dig(person, "basic_profile.name")
            title = str(dig(person, "basic_profile.current_title") or ("Founder" if group == "founders" else ""))
            if not name or name in seen or not LEADER_TITLE.search(title):
                continue
            seen.add(name)
            rows.append({"name": name, "title": title[:90], "path": f"people.{group}.{i}.basic_profile.name"})
    return rows[:25]


def confirm_leaders(crust: Crust, store: EvidenceStore, vendor: str, record_ev: str, candidates: list[dict], log) -> tuple[list[Finding], int]:
    """Keep a listed leader only when an independent web search names them too."""
    if not candidates:
        return [], 0
    rows, search_ev = _safe_search(crust, store, log, f'"{vendor}" CEO founder CISO leadership team', ["web", "news"])
    text = normalize(" ".join(f"{r.get('title')} {r.get('snippet')}" for r in rows))
    found: list[Finding] = []
    for cand in candidates:
        if len(found) >= 4:
            break
        name = normalize(cand["name"])
        if search_ev and len(name.split()) >= 2 and name in text:
            f = Finding(kind="leader", claim=cand["title"], evidence_id=record_ev, path=cand["path"], value=cand["name"],
                        attrs={"confirmed_by": search_ev})
            if store.verify(f):
                found.append(f)
    return found, len(candidates) - len(found)


def passive_checks(store: EvidenceStore, domain: str) -> tuple[bool, list[Finding], str]:
    """Only what any browser or mail server sees. No probing or scanning."""
    lines: list[str] = []
    obs: dict = {"domain": domain}
    reachable = False

    try:
        with httpx.Client(timeout=15, follow_redirects=True, headers=UA) as client:
            resp = client.get(f"https://{domain}/")
            reachable = resp.status_code < 500
            obs["https_status"] = resp.status_code
            obs["final_url"] = str(resp.url)
            obs["hsts"] = bool(resp.headers.get("strict-transport-security"))
            lines.append(f"GET https://{domain}/ returned {resp.status_code}; HSTS header present: {obs['hsts']}")
    except httpx.HTTPError as exc:
        obs["https_error"] = type(exc).__name__
        lines.append(f"GET https://{domain}/ failed: {type(exc).__name__}")

    host = urlparse(obs.get("final_url") or f"https://{domain}").netloc or domain
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                obs["tls_version"] = tls.version()
                expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                obs["tls_days_left"] = (expiry - datetime.now(timezone.utc)).days
                lines.append(f"TLS {obs['tls_version']} on {host}; certificate valid for {obs['tls_days_left']} more days")
    except (OSError, ssl.SSLError, ValueError, KeyError) as exc:
        obs["tls_error"] = type(exc).__name__
        lines.append(f"TLS check on {host} failed: {type(exc).__name__}")

    def txt(name: str) -> list[str]:
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 6
            return [r.to_text().strip('"') for r in resolver.resolve(name, "TXT")]
        except Exception:  # noqa: BLE001 - any DNS failure means the record was not seen
            return []

    obs["spf"] = any(t.lower().startswith("v=spf1") for t in txt(domain))
    dmarc = [t for t in txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    obs["dmarc"] = bool(dmarc)
    obs["dmarc_policy"] = (re.search(r"p=(\w+)", dmarc[0]) or [None, None])[1] if dmarc else None
    lines.append(f"DNS: SPF present {obs['spf']}; DMARC present {obs['dmarc']}; policy {obs['dmarc_policy']}")

    try:
        with httpx.Client(timeout=10, follow_redirects=True, headers=UA) as client:
            r = client.get(f"https://{domain}/.well-known/security.txt")
            obs["security_txt"] = r.status_code == 200 and "contact:" in r.text.lower()
    except httpx.HTTPError:
        obs["security_txt"] = False
    lines.append(f"security.txt published: {obs['security_txt']}")

    ev = store.add("passive", f"Passive checks for {domain}", f"passive://{domain}", text="\n".join(lines), data=obs)
    findings = []
    labels = {"hsts": "HSTS header sent", "spf": "SPF record published", "dmarc": "DMARC record published",
              "dmarc_policy": "DMARC policy", "security_txt": "security.txt published", "tls_version": "TLS version"}
    for key, label in labels.items():
        if key in obs and obs[key] is not None:
            f = Finding(kind="posture", claim=f"{label}: {obs[key]}", evidence_id=ev.id, path=key, value=obs[key])
            store.verify(f)
            findings.append(f)
    return reachable, findings, ev.id


def breach_db(store: EvidenceStore, domain: str, log) -> tuple[list[dict], str | None]:
    """Have I Been Pwned's public breach catalogue, as a source independent of search."""
    url = f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}"
    try:
        with httpx.Client(timeout=15, headers=UA) as client:
            resp = client.get(url)
        rows = resp.json() if resp.status_code == 200 else []
    except (httpx.HTTPError, ValueError) as exc:
        log("warn", f"Breach catalogue unavailable: {type(exc).__name__}")
        return [], None
    if not isinstance(rows, list):
        return [], None
    incidents = []
    ev = store.add("breach_db", f"Have I Been Pwned entries for {domain}", url, data=rows,
                   text="; ".join(f"{r.get('Name')} {r.get('BreachDate')}" for r in rows))
    for i, row in enumerate(rows):
        incidents.append({
            "summary": f"Have I Been Pwned lists the {row.get('Title')} breach, affecting {row.get('PwnCount'):,} accounts",
            "date": (row.get("BreachDate") or "")[:7] or None,
            "role": "breached_vendor", "remediated": False,
            "evidence": [ev.id], "quotes": [{"evidence": ev.id, "path": f"{i}.BreachDate"}],
        })
    return incidents, ev.id


def _safe_search(crust: Crust, store: EvidenceStore, log, query: str, sources: list[str], site: str | None = None) -> tuple[list[dict], str | None]:
    try:
        rows = crust.search(query, sources, site=site)
    except CrustError as exc:
        if exc.terminal:
            raise
        log("warn", f"Search failed for \"{query}\": {exc}")
        return [], None
    text = "\n".join(f"{r.get('title')} | {r.get('url')} | {r.get('snippet')}" for r in rows)
    label = f"Web search: {query}" + (f" (site:{site})" if site else "")
    ev = store.add("search", label, f"crustdata:/web/search/live?q={query}&sources={','.join(sources)}", text=text or "(no results)")
    return rows, ev.id


def gather_web(crust: Crust, store: EvidenceStore, name: str, domain: str, news: list | None, log) -> dict:
    """Run the searches, choose pages to read, and fetch them."""
    with ThreadPoolExecutor(max_workers=4) as pool:
        jobs = {
            "news": pool.submit(_safe_search, crust, store, log, f'"{name}" data breach security incident', ["news"]),
            "web": pool.submit(_safe_search, crust, store, log, f'"{name}" breach disclosure security incident', ["web"]),
            "cert": pool.submit(_safe_search, crust, store, log, f'"{name}" SOC 2 ISO 27001 trust center', ["web"]),
            "site": pool.submit(_safe_search, crust, store, log, "security compliance SOC 2 ISO 27001", ["web"], domain),
            "closure": pool.submit(_safe_search, crust, store, log, f'"{name}" shut down ceased operations bankruptcy', ["news"]),
        }
        out = {k: j.result() for k, j in jobs.items()}
    resolve_links([r for rows, _ in out.values() for r in rows])

    search_ev = [e for _, e in out.values() if e]
    needle = normalize(name)

    breach_urls: list[str] = []
    for key in ("news", "web"):
        for r in out[key][0]:
            blob = f"{r.get('title')} {r.get('snippet')}"
            if r.get("url") and needle in normalize(blob) and BREACH_WORDS.search(blob):
                breach_urls.append(r["url"])
    for item in news or []:
        if isinstance(item, dict):
            title = str(item.get("article_title") or "")
            if item.get("article_url") and needle in normalize(title) and BREACH_WORDS.search(title):
                breach_urls.append(item["article_url"])

    closure_urls = [r["url"] for r in out["closure"][0]
                    if r.get("url") and needle in normalize(f"{r.get('title')} {r.get('snippet')}") and CLOSURE_WORDS.search(f"{r.get('title')} {r.get('snippet')}")][:3]
    breach_urls = closure_urls + breach_urls

    trust_urls = [f"https://{domain}{p}" for p in TRUST_PATHS] + [f"https://{h}.{domain}/" for h in TRUST_HOSTS]
    for r in out["site"][0]:
        if r.get("url"):
            trust_urls.append(r["url"])
    for r in out["cert"][0]:
        url = r.get("url") or ""
        blob = f"{r.get('title')} {r.get('snippet')} {url}"
        # Third-party pages cannot speak for a vendor's certification status, so stay on its own hosts.
        if url and registered(url).endswith(domain) and CERT_WORDS.search(blob):
            trust_urls.append(url)
    trust_urls = list(dict.fromkeys(trust_urls))[:10]
    breach_urls = list(dict.fromkeys(breach_urls))[:10]

    log("step", f"Reading {len(trust_urls)} vendor pages and {len(breach_urls)} incident reports")
    trust_ev, trust_failed = fetch_pages(crust, store, trust_urls, log)
    breach_ev, breach_failed = fetch_pages(crust, store, breach_urls, log)
    return {
        "searches_ok": len(search_ev) >= 2,
        "search_evidence": search_ev,
        "trust_pages": trust_ev,
        "breach_pages": breach_ev,
        "failed_urls": trust_failed + breach_failed,
    }
