"""The end-to-end vendor review: request in, finished assessment out."""
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict
from datetime import date
from difflib import SequenceMatcher
from pathlib import Path
from typing import Callable

from . import collect, extract, policy, report
from .crust import Crust, CrustError
from .evidence import EvidenceStore, Finding, dig, normalize, now_iso
from .llm import LLM, LLMError

Emit = Callable[[str, str], None]
RUNS = Path(__file__).resolve().parent.parent / "runs"


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, normalize(a), normalize(b)).ratio()


def _slim(match: dict) -> dict:
    info = dig(match, "company_data.basic_info") or {}
    return {
        "confidence": match.get("confidence_score"),
        "id": dig(match, "company_data.crustdata_company_id"),
        "name": info.get("name"),
        "domain": info.get("primary_domain"),
        "all_domains": info.get("all_domains") or [],
        "type": info.get("company_type"),
        "employees": info.get("employee_count_range"),
    }


def _same_company(a: str, b: str) -> bool:
    x, y = normalize(a), normalize(b)
    return bool(x and y) and (x in y or y in x or _similarity(x, y) >= 0.75)


def _compact(text: str) -> str:
    return normalize(text).replace(" ", "")


def _names_match(query: str, cand: dict) -> int:
    """1: same name. 2: website is the name. 3: name starts with it. 0: no match."""
    q, name = normalize(query), normalize(cand.get("name") or "")
    stem = _compact((cand.get("domain") or "").split(".")[0])
    if not q:
        return 0
    if name == q:
        return 1
    if stem == _compact(query):
        return 2
    return 3 if name.startswith(q + " ") else 0


def _discover_domain(crust: Crust, store: EvidenceStore, query: str, emit: Emit) -> str | None:
    """When no record carries the name, look for the official site whose domain is the name."""
    try:
        rows = crust.search(f'"{query}" official website', ["web"])
    except CrustError as exc:
        if exc.terminal:
            raise
        return None
    store.add("search", f"Web search: {query} official website", f"crustdata:/web/search/live?q={query} official website",
              text="\n".join(f"{r.get('title')} | {r.get('url')}" for r in rows) or "(no results)")
    want = _compact(query)
    for r in rows:
        host = collect.registered(r.get("url") or "")
        if host and "google." not in host and _compact(host.split(".")[0]) == want:
            emit("info", f"Found the official site {host} by web search")
            return host
    return None


def _size_rank(employees: str | None) -> int:
    nums = re.findall(r"\d[\d,]*", str(employees or ""))
    return int(nums[0].replace(",", "")) if nums else 0


def resolve_identity(crust: Crust, store: EvidenceStore, intake: dict, emit: Emit, _discovered: bool = False) -> dict:
    """Pin the request to one company, or say exactly why that is not possible."""
    typed = intake.get("vendor_name")
    corrected = intake.get("corrected_name")
    domain = intake.get("domain")
    if not typed and not domain:
        return {"status": "unresolved", "detail": "The request does not name a vendor to review.", "evidence": []}

    query = corrected or typed
    stated_domain = domain
    if domain:
        # Follow the customer's link first: an alias such as notion.so can hold another company's record.
        domain = collect.canonical_domain(domain)
        if domain != stated_domain:
            emit("info", f"{stated_domain} redirects to {domain}")
    try:
        matches = crust.identify(domain=domain) if domain else crust.identify(name=query)
    except CrustError as exc:
        if exc.terminal:
            raise
        return {"status": "unresolved", "detail": f"Company lookup failed: {exc}", "evidence": []}

    label = domain or query
    ev = store.add("crustdata", f"Company lookup for {label}", f"crustdata:/company/identify?q={label}",
                   text=json.dumps([_slim(m) for m in matches])[:4000], data=[_slim(m) for m in matches])
    candidates = [c for c in (_slim(m) for m in matches) if c["name"] and c["domain"]]
    if not candidates:
        return {"status": "unresolved", "input": label, "evidence": [ev.id],
                "detail": f"No company record matches \"{label}\". Please supply the vendor's website."}

    if domain:
        owners = [c for c in candidates if c["domain"] == domain or domain in (c.get("all_domains") or [])]
        best = next((c for c in owners if typed and _same_company(query, c["name"])), owners[0] if owners else None)
        if best is None:
            names = ", ".join(f"{c['name']} ({c['domain']})" for c in candidates[:3])
            return {"status": "unresolved", "input": domain, "evidence": [ev.id],
                    "detail": f"No company record clearly owns {domain}. Nearest records: {names}. Please confirm the vendor's legal name."}
        # The name and website came from the customer, so they must describe one company.
        if typed and not _same_company(query, best["name"]):
            return {"status": "unresolved", "input": f"{typed} / {domain}", "evidence": [ev.id],
                    "detail": f"The request names \"{typed}\", but {domain} belongs to {best['name']}. Please confirm which company you mean."}
        return {"status": "resolved", "input": domain, "name": best["name"], "domain": best["domain"],
                "id": best["id"], "assumed": False, "evidence": [ev.id]}

    # No spelling guesses: a near-miss name is a different company (C3iHub is not Cxihub).
    # A record matches when its name is the query, starts with it ("C3iHub, IIT Kanpur"),
    # or its website is the query ("c3ihub.org"). The model may correct an obvious typo first.
    # Strongest evidence first, so "Okta Partners" never competes with an exact "Okta".
    pool = []
    for tier in (1, 2, 3):
        pool = [c for c in candidates if _names_match(query, c) == tier]
        if pool:
            break
    if not pool:
        # "GitLab SaaS" names a product of GitLab: accept a record that is the request's first word.
        words = normalize(query).split()
        pool = [c for c in candidates if len(words) > 1 and normalize(c["name"]) == words[0]]
    if not pool and not _discovered:
        found = _discover_domain(crust, store, query, emit)
        if found:
            return resolve_identity(crust, store, {**intake, "domain": found}, emit, _discovered=True)
    if not pool:
        names = ", ".join(f"{c['name']} ({c['domain']})" for c in candidates[:4])
        return {"status": "unresolved", "input": query, "evidence": [ev.id],
                "detail": f"No confident match for \"{query}\". Nearest records: {names}. Please supply the vendor's website."}

    # A record whose website has nothing to do with the name is noise when others match it.
    stem = normalize(query).replace(" ", "")
    on_domain = [c for c in pool if stem and stem in normalize(c["domain"]).replace(" ", "")]
    pool = on_domain or pool

    # Same-named companies: only proceed if one clearly dominates by size.
    domains = {c["domain"] for c in pool}
    if len(domains) > 1:
        ranked = sorted(pool, key=lambda c: _size_rank(c["employees"]), reverse=True)
        if _size_rank(ranked[0]["employees"]) < 5 * max(_size_rank(ranked[1]["employees"]), 1):
            names = ", ".join(f"{c['name']} ({c['domain']}, {c['employees'] or 'size unknown'})" for c in ranked[:4])
            return {"status": "unresolved", "input": query, "evidence": [ev.id], "candidates": ranked[:4],
                    "detail": f"\"{query}\" could mean several companies: {names}. Please say which one."}
        pool = ranked[:1]

    best = pool[0]
    typo = bool(typed and corrected and normalize(typed) != normalize(corrected))
    if typo:
        emit("warn", f"Read \"{typed}\" as {best['name']} ({best['domain']}). The report will ask you to confirm.")
    return {"status": "resolved", "input": typed, "name": best["name"], "domain": best["domain"],
            "id": best["id"], "assumed": typo, "evidence": [ev.id]}


def review(request: str, emit: Emit | None = None, crust: Crust | None = None, llm: LLM | None = None, save: bool = True) -> dict:
    emit = emit or (lambda level, msg: None)
    started = time.time()
    store = EvidenceStore()
    crust = crust or Crust()
    llm = llm or LLM()
    crust.notify = lambda message: emit("warn", message)

    emit("step", "Reading the request")
    intake = extract.parse_request(llm, request)
    sensitivity = intake["data_sensitivity"]
    emit("info", f"Vendor: {intake.get('vendor_name') or intake.get('domain') or 'not stated'}. Data sensitivity: {sensitivity}.")

    ctx: dict = {"sensitivity": sensitivity, "identity": {}, "incidents": [], "certifications": [], "stability": {}, "coverage": {}}
    all_findings: list[Finding] = []
    rejected = 0
    company: dict | None = None
    errors: list[str] = []

    try:
        emit("step", "Identifying the company")
        identity = resolve_identity(crust, store, intake, emit)
        ctx["identity"] = identity
        if identity["status"] == "resolved":
            name, domain = identity["name"], identity["domain"]
            emit("info", f"Matched {name} ({domain})")

            emit("step", "Pulling the company record from Crustdata")
            try:
                company = crust.enrich(company_id=identity.get("id"), domain=domain)
            except CrustError as exc:
                if exc.terminal and exc.status in (401, 402):
                    raise
                errors.append(f"Company record unavailable: {exc}")
                emit("warn", errors[-1])
            if company:
                ev = store.add("crustdata", f"Crustdata company record: {name}", f"crustdata:/company/enrich?id={identity.get('id')}", data=company)
                ctx["stability"], facts = collect.stability_facts(store, company, ev.id)
                all_findings += facts
            else:
                ctx["stability"] = {"flags": [{"text": "Identified by name or domain, but no detailed company record is available, so size, age and leadership are unverified.", "evidence": identity.get("evidence") or []}]}

            emit("step", "Checking the public security posture")
            reachable, posture, passive_id = collect.passive_checks(store, domain)
            all_findings += posture

            emit("step", "Searching for breaches and certifications")
            hibp, _ = collect.breach_db(store, domain, emit)
            web = collect.gather_web(crust, store, name, domain, dig(company or {}, "news"), emit)

            if company:
                leaders, unconfirmed = collect.confirm_leaders(crust, store, name, ctx["stability"]["evidence"][0],
                                                               ctx["stability"].get("leader_candidates") or [], emit)
                all_findings += leaders
                emit("info", f"Confirmed {len(leaders)} leaders against a web search; left out {unconfirmed} unconfirmed self-reported profiles.")
                if ctx["stability"].get("leader_candidates") and not leaders:
                    ctx["stability"].setdefault("notes", []).append({
                        "text": "The record lists senior people, but no independent source confirmed any of them, so this report names no one.",
                        "evidence": ctx["stability"]["evidence"]})

            pages = web["trust_pages"] + web["breach_pages"]
            emit("step", f"Analysing {len(pages)} pages and checking every quote")
            aliases = [domain.split(".")[0]]
            found = extract.extract_all(llm, store, name, pages, aliases)
            all_findings += found["findings"]
            rejected = found["rejected"]
            emit("info", f"Kept {len(found['findings'])} findings; discarded {rejected} that failed the quote check.")

            ctx["incidents"] = _combine_incidents(extract.merge_incidents(found["findings"]), hibp)
            ctx["certifications"] = extract.merge_certs(found["findings"])
            ctx["closures"] = [{"summary": f.claim, "date": f.attrs.get("date"), "evidence": [f.evidence_id]}
                               for f in found["findings"] if f.kind == "closure"]
            ctx["coverage"] = {
                "site_reachable": reachable or bool(web["trust_pages"]),
                "site_evidence": [passive_id],
                "searches_ok": web["searches_ok"],
                "search_evidence": web["search_evidence"],
                "extraction_failed": bool(pages) and found["pages_ok"] == 0,
                "failed_urls": web["failed_urls"],
            }
    except CrustError as exc:
        errors.append(str(exc))
        emit("warn", f"Data provider error: {exc}")
        ctx["coverage"] = {"searches_ok": False, "search_evidence": []}
        if not ctx["identity"]:
            ctx["identity"] = {"status": "unresolved", "detail": f"Data provider error: {exc}", "evidence": []}
    except LLMError as exc:
        errors.append(str(exc))
        emit("warn", f"Model error: {exc}")
        ctx["coverage"] = {"searches_ok": False, "search_evidence": []}
    except Exception as exc:  # noqa: BLE001 - nonsense from a tool must end in a referral, not a crash
        errors.append(f"{type(exc).__name__}: {exc}")
        emit("warn", f"A tool returned something unusable: {type(exc).__name__}")
        ctx["coverage"] = {"searches_ok": False, "search_evidence": []}
        if not ctx["identity"]:
            ctx["identity"] = {"status": "unresolved", "detail": "A tool returned unusable data while identifying the company.", "evidence": []}

    emit("step", "Applying the rulebook")
    decision = policy.evaluate(ctx, date.today())
    emit("info", f"Decision: {decision.outcome}")

    audit = _audit(store, all_findings, ctx, decision)
    emit("step", f"Citation audit: {audit['verified']} of {audit['total']} claims verified against snapshots")

    result = {
        "request": request,
        "reviewed_at": now_iso(),
        "elapsed_seconds": round(time.time() - started, 1),
        "intake": intake,
        "identity": ctx["identity"],
        "sensitivity": sensitivity,
        "decision": decision.to_dict(),
        "incidents": ctx["incidents"],
        "certifications": ctx["certifications"],
        "stability": ctx["stability"],
        "closures": ctx.get("closures") or [],
        "coverage": {k: v for k, v in ctx["coverage"].items()},
        "findings": [asdict(f) for f in all_findings],
        "rejected_findings": rejected,
        "audit": audit,
        "errors": errors,
        "evidence": store.to_list(),
        "api_calls": len(crust.calls),
    }
    result["vendor_email"] = report.vendor_email(result)
    if save:
        result["paths"] = _save(result, store)
    emit("done", decision.outcome)
    return result


def _combine_incidents(web: list[dict], hibp: list[dict]) -> list[dict]:
    """Attach catalogue entries to the matching web report, otherwise list them on their own."""
    out = list(web)
    for entry in hibp:
        same = next((w for w in out if w.get("date") and entry.get("date") and w["date"][:4] == entry["date"][:4]), None)
        if same:
            same["evidence"] = same["evidence"] + [e for e in entry["evidence"] if e not in same["evidence"]]
            same["quotes"] = same.get("quotes", []) + entry["quotes"]
        else:
            out.append(entry)
    return sorted(out, key=lambda i: i.get("date") or "", reverse=True)


def _audit(store: EvidenceStore, findings: list[Finding], ctx: dict, decision: policy.Decision) -> dict:
    """Re-check every finding, and confirm every reason points at evidence that exists."""
    total = verified = 0
    problems: list[str] = []
    for f in findings:
        total += 1
        if store.verify(f):
            verified += 1
        else:
            problems.append(f"{f.evidence_id}: {f.claim[:80]}")
    for group in (decision.reasons, decision.conditions, decision.referrals, decision.notes):
        for reason in group:
            total += 1
            if all(e in store.items for e in reason.evidence) and (reason.evidence or reason.rule.startswith(("R7", "R1", "R3"))):
                verified += 1
            else:
                problems.append(f"{reason.rule}: {reason.text[:80]}")
    return {"total": total, "verified": verified, "problems": problems}


def _save(result: dict, store: EvidenceStore) -> dict:
    name = result["identity"].get("name") or result["intake"].get("vendor_name") or "unknown"
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40] or "unknown"
    folder = RUNS / f"{slug}-{int(time.time())}"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "report.json").write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    (folder / "report.md").write_text(report.to_markdown(result), encoding="utf-8")
    (folder / "report.html").write_text(report.to_html(result), encoding="utf-8")
    (folder / "evidence.json").write_text(json.dumps(store.to_list(include_body=True), indent=1, default=str), encoding="utf-8")
    return {"folder": str(folder), "markdown": str(folder / "report.md"), "html": str(folder / "report.html")}
