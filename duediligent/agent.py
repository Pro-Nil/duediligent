"""The end-to-end vendor review: request in, finished assessment out."""
from __future__ import annotations

import json
import re
import secrets
import threading
import time
from dataclasses import asdict
from datetime import date
from difflib import SequenceMatcher
from pathlib import Path
from typing import Callable

from . import collect, documents, extract, policy, report
from . import watch as watch_mod
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


def _options(cands: list[dict]) -> list[dict]:
    """The companies a person can pick from when the agent will not choose."""
    seen, out = set(), []
    for c in cands:
        if c and c.get("domain") and c["domain"] not in seen:
            seen.add(c["domain"])
            out.append({"name": c.get("name"), "domain": c["domain"], "employees": c.get("employees")})
    return out


def _size_rank(employees: str | None) -> int:
    nums = re.findall(r"\d[\d,]*", str(employees or ""))
    return int(nums[0].replace(",", "")) if nums else 0


def resolve_identity(crust: Crust, store: EvidenceStore, intake: dict, emit: Emit, _discovered: bool = False) -> dict:
    """Pin the request to one company, or say exactly why that is not possible."""
    typed = intake.get("vendor_name")
    corrected = intake.get("corrected_name")
    domain = intake.get("domain")
    if not typed and not domain:
        why = "The model that reads requests is unavailable, so the vendor could not be identified." if intake.get("model_failed") else "The request does not name a vendor to review."
        return {"status": "unresolved", "detail": why, "evidence": []}

    if intake.get("request_type") == "other" or intake.get("other_companies"):
        others = ", ".join(intake.get("other_companies") or [])
        return {"status": "unresolved", "evidence": [],
                "detail": "This request is not a review of one vendor" + (f" (it also names {others})" if others else "")
                          + ". duediligent reviews one supplier at a time, for example: \"Can we use Acme for our payroll data?\""}

    confirmed = bool(intake.get("confirmed"))
    if typed and domain and re.fullmatch(r"[\w.-]+\.[a-z]{2,}", typed.strip().lower()):
        if _compact(typed.split(".")[0]) == _compact(domain.split(".")[0]) or typed.strip().lower().removeprefix("www.") == domain:
            typed = None
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
    if not candidates and confirmed and domain:
        # A person vouched for this website, so review it from web evidence even without a company record.
        emit("warn", f"No company record for {domain}. Reviewing from web evidence only, and the report will say so.")
        return {"status": "resolved", "input": domain, "name": intake.get("vendor_name") if intake.get("vendor_name") != domain else domain,
                "domain": domain, "id": None, "assumed": False, "confirmed_by_user": True, "evidence": [ev.id]}
    if not candidates:
        return {"status": "unresolved", "input": label, "evidence": [ev.id], "options": [],
                "detail": f"No company record matches \"{label}\". Please supply the vendor's website."}

    if domain:
        owners = [c for c in candidates if c["domain"] == domain or domain in (c.get("all_domains") or [])]
        best = next((c for c in owners if typed and _same_company(query, c["name"])), owners[0] if owners else None)
        if best is None:
            names = ", ".join(f"{c['name']} ({c['domain']})" for c in candidates[:3])
            return {"status": "unresolved", "input": domain, "evidence": [ev.id], "options": _options(candidates[:3]),
                    "detail": f"No company record clearly owns {domain}. Nearest records: {names}. Please confirm the vendor's legal name."}
        # The name and website came from the customer, so they must describe one company.
        if typed and not confirmed and not _same_company(query, best["name"]):
            return {"status": "unresolved", "input": f"{typed} / {domain}", "evidence": [ev.id], "options": _options([best]),
                    "detail": f"The request names \"{typed}\", but {domain} belongs to {best['name']}. Please confirm which company you mean."}
        return {"status": "resolved", "input": domain, "name": best["name"], "domain": best["domain"],
                "id": best["id"], "assumed": False, "confirmed_by_user": confirmed, "evidence": [ev.id]}

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
        # The same holds for "c3ihub security": the first word alone can name the record.
        words = normalize(query).split()
        if len(words) > 1:
            for tier in (1, 2, 3):
                pool = [c for c in candidates if _names_match(words[0], c) == tier]
                if pool:
                    break
    if not pool and not _discovered:
        found = _discover_domain(crust, store, query, emit)
        if found:
            return resolve_identity(crust, store, {**intake, "domain": found}, emit, _discovered=True)
    if not pool:
        # Offer only plausible companies: ones sharing the request's first word, if any do.
        first = _compact(query.split()[0]) if query.split() else ""
        likely = [c for c in candidates if first and (first in _compact(c["name"]) or first in _compact(c["domain"]))]
        shown = likely or candidates
        names = ", ".join(f"{c['name']} ({c['domain']})" for c in shown[:4])
        return {"status": "unresolved", "input": query, "evidence": [ev.id], "options": _options(shown[:4]),
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
            return {"status": "unresolved", "input": query, "evidence": [ev.id], "candidates": ranked[:4], "options": _options(ranked[:4]),
                    "detail": f"\"{query}\" could mean several companies: {names}. Please say which one."}
        pool = ranked[:1]

    best = pool[0]
    # An acronym can name a different, better-known body. If its full name has its own record
    # on another website, the request is ambiguous, so ask instead of picking one.
    for full in (intake.get("full_names") or [])[:2]:
        try:
            others = [c for c in (_slim(m) for m in crust.identify(name=full)) if c["name"] and c["domain"]]
        except CrustError:
            continue
        rival = next((c for c in others if normalize(c["name"]) == normalize(full) and c["domain"] != best["domain"]), None)
        if rival:
            return {"status": "unresolved", "input": query, "evidence": [ev.id], "options": _options([best, rival]),
                    "detail": f"\"{query}\" could mean {best['name']} ({best['domain']}) or {rival['name']} ({rival['domain']}). Please say which one, ideally with its website."}
    typo = bool(typed and corrected and normalize(typed) != normalize(corrected))
    if typo:
        emit("warn", f"Read \"{typed}\" as {best['name']} ({best['domain']}). The report will ask you to confirm.")
    return {"status": "resolved", "input": typed, "name": best["name"], "domain": best["domain"],
            "id": best["id"], "assumed": typo, "evidence": [ev.id]}


def review(request: str, emit: Emit | None = None, crust: Crust | None = None, llm: LLM | None = None, save: bool = True,
           watch: bool = False, pinned: dict | None = None) -> dict:
    emit = emit or (lambda level, msg: None)
    started = time.time()
    store = EvidenceStore()
    crust = crust or Crust()
    llm = llm or LLM()
    crust.notify = lambda message: emit("warn", message)
    if getattr(llm, "backend", None) == "cli":
        llm.on_wait = lambda seconds: emit("wait", f"Still waiting for the model: {seconds}s so far. Calls through the claude CLI are sometimes slow; an Anthropic API key in .env makes reviews faster.")

    emit("step", "Reading the request")
    intake = extract.parse_request(llm, request)
    if pinned:
        # A person answered the agent's question, so use exactly the company they chose.
        intake.update({"vendor_name": pinned.get("name") or pinned.get("domain"), "domain": pinned.get("domain"),
                       "corrected_name": None, "request_type": "vendor_review", "other_companies": [], "full_names": [],
                       "confirmed": True})
        emit("info", f"Using the company you confirmed: {pinned.get('name') or ''} {pinned.get('domain') or ''}".strip())
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
        "created_at": now_iso(),
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
        "ctx": ctx,
    }
    result["history"] = [{"at": result["created_at"], "kind": "review", "by": "agent", "outcome": decision.outcome,
                          "event": "Review completed after your answer" if pinned else "Review completed"}]
    if pinned:
        result["parent"] = pinned.get("parent")
    result["vendor_email"] = report.vendor_email(result)
    if watch and decision.outcome == policy.APPROVE and ctx["identity"].get("domain"):
        result["watch"] = watch_mod.ensure_watch(crust, ctx["identity"]["domain"])
        emit("info", _watch_message(result["watch"]))
    if save:
        result["paths"] = _save(result, store)
        result["case_id"] = Path(result["paths"]["folder"]).name
    emit("done", decision.outcome)
    return result


def _history(result: dict) -> list[dict]:
    """The case's timeline. Older cases have no first entry, so rebuild it."""
    hist = list(result.get("history") or [])
    if not hist or hist[0].get("kind") != "review":
        first_outcome = hist[0]["from"] if hist and hist[0].get("from") else result["decision"]["outcome"]
        hist.insert(0, {"at": result.get("created_at") or result.get("reviewed_at"), "kind": "review", "by": "agent",
                        "outcome": first_outcome, "event": "Review completed"})
    return hist


def _watch_message(w: dict) -> str:
    if w["status"] in ("created", "existing"):
        return f"Crustdata watch #{w['watch_id']} {'created' if w['status'] == 'created' else 'already active'}: alerts go to {w['email']} on news or headcount changes."
    return f"Monitoring not set up: {w.get('reason')}"


def case_dir(case_id: str) -> Path:
    if not re.fullmatch(r"[a-z0-9-]+", case_id or ""):
        raise ValueError("bad case id")
    folder = RUNS / case_id
    if not (folder / "report.json").exists():
        raise FileNotFoundError(case_id)
    return folder


_case_locks: dict[str, threading.Lock] = {}
_case_locks_guard = threading.Lock()


def case_lock(case_id: str) -> threading.Lock:
    """One lock per case, so two writers never read the same version and both save it."""
    with _case_locks_guard:
        return _case_locks.setdefault(case_id, threading.Lock())


def apply_document(case_id: str, data: bytes, filename: str, emit: Emit | None = None,
                   llm: LLM | None = None, crust: Crust | None = None) -> dict:
    """The vendor sent a document: check it, decide again, and save the case's new version.
    Uploads to one case run one at a time, so a second upload builds on the first."""
    with case_lock(case_id):
        return _apply_document(case_id, data, filename, emit, llm, crust)


def _apply_document(case_id: str, data: bytes, filename: str, emit: Emit | None = None,
                    llm: LLM | None = None, crust: Crust | None = None) -> dict:
    emit = emit or (lambda level, msg: None)
    folder = case_dir(case_id)
    result = json.loads((folder / "report.json").read_text(encoding="utf-8"))
    store = EvidenceStore.load(json.loads((folder / "evidence.json").read_text(encoding="utf-8")))
    ctx = result["ctx"]
    ident = ctx["identity"]
    emit("step", f"Reading {filename}")
    llm = llm or LLM()
    if getattr(llm, "backend", None) == "cli":
        llm.on_wait = lambda seconds: emit("wait", f"Still waiting for the model: {seconds}s so far. Calls through the claude CLI are sometimes slow.")
    doc = documents.check_document(llm, store, data, filename, ident.get("name") or "", ident.get("domain") or "")
    if doc.get("readable"):
        emit("info", f"{doc['report_type']} for {doc['organisation']}, period ending {doc.get('period_end') or doc.get('valid_until') or 'unconfirmed'}, opinion {doc['opinion']}")
    else:
        emit("warn", doc.get("problem") or "Unreadable document")
    ctx.setdefault("documents", []).append(doc)
    emit("step", "Applying the rulebook again")
    decision = policy.evaluate(ctx, date.today())
    findings = [Finding(**f) for f in result["findings"]]
    audit = _audit(store, findings, ctx, decision)
    emit("info", f"Decision: {decision.outcome}")
    result.update({"decision": decision.to_dict(), "audit": audit, "ctx": ctx, "documents": ctx["documents"],
                   "evidence": store.to_list(), "reviewed_at": now_iso(),
                   "history": _history(result) + [{
                       "at": now_iso(), "kind": "vendor_upload", "by": "vendor", "file": filename,
                       "report_type": doc.get("report_type"), "accepted": doc.get("readable", False) and not any(
                           c.rule.startswith("R5") for c in decision.conditions + decision.referrals),
                       "from": result["decision"]["outcome"], "outcome": decision.outcome,
                       "event": f"Vendor uploaded {filename}"}]})
    result["vendor_email"] = report.vendor_email(result)
    if decision.outcome == policy.APPROVE and ident.get("domain"):
        result["watch"] = watch_mod.ensure_watch(crust or Crust(), ident["domain"])
        emit("info", _watch_message(result["watch"]))
    _write(folder, result, store)
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
    # A random suffix keeps two reviews saved in the same second from sharing a folder,
    # and exist_ok=False makes any collision fail loudly instead of overwriting.
    while True:
        folder = RUNS / f"{slug}-{int(time.time())}-{secrets.token_hex(3)}"
        try:
            folder.mkdir(parents=True, exist_ok=False)
            break
        except FileExistsError:
            continue
    _write(folder, result, store)
    return {"folder": str(folder), "markdown": str(folder / "report.md"), "html": str(folder / "report.html")}


def _write(folder: Path, result: dict, store: EvidenceStore) -> None:
    (folder / "report.json").write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    (folder / "report.md").write_text(report.to_markdown(result), encoding="utf-8")
    (folder / "report.html").write_text(report.to_html(result), encoding="utf-8")
    (folder / "evidence.json").write_text(json.dumps(store.to_list(include_body=True), indent=1, default=str), encoding="utf-8")
