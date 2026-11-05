"""Local web UI: python -m duediligent.server, then open http://localhost:8765"""
from __future__ import annotations

import csv
import io
import json
import os
import queue
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .agent import RUNS, apply_document, case_dir, review
from .agent import _history as agent_history
from .config import load_env
from .crust import Crust
from .watch import ensure_watch
from .llm import LLM
from .report import markdown_body, to_html, to_markdown

load_env()
app = FastAPI(title="duediligent")
WEB = Path(__file__).resolve().parent.parent / "web"
app.mount("/web", StaticFiles(directory=WEB), name="web")


@app.middleware("http")
async def always_fresh(request, call_next):
    """Pages and scripts change often, so browsers must check for a newer copy every time."""
    response = await call_next(request)
    if not request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-cache"
    return response
SEVERITY = {"REJECT": 0, "REFER TO HUMAN": 1, "APPROVE WITH CONDITIONS": 2, "APPROVE": 3}
MAX_UPLOAD = 15 * 1024 * 1024


def _summary(result: dict) -> dict:
    d = result["decision"]
    top = (d["reasons"] + d["referrals"] + d["conditions"])
    return {
        "case_id": result.get("case_id") or Path(result.get("paths", {}).get("folder", "")).name,
        "vendor": result["identity"].get("name") or result["intake"].get("vendor_name") or "Unidentified",
        "domain": result["identity"].get("domain"),
        "outcome": d["outcome"],
        "conditions": [c["text"] for c in d["conditions"]],
        "top_reason": next((r["text"] for r in d["referrals"] + d["conditions"] + d["reasons"] if not r["rule"].startswith("R7")), top[0]["text"] if top else ""),
        "audit": result["audit"],
        "html": markdown_body(to_markdown(result)),
        "watch": result.get("watch"),
        "report": _structured(result),
    }


def _structured(r: dict) -> dict:
    """Everything the page needs to draw the report itself, without internal working state."""
    stab = r.get("stability") or {}
    cov = r.get("coverage") or {}
    keep = ("founded", "status", "headcount", "headcount_yoy", "openings", "acquired", "evidence")
    return {
        "request": r.get("request"),
        "reviewed_at": r.get("reviewed_at"),
        "elapsed": r.get("elapsed_seconds"),
        "sensitivity": r.get("sensitivity"),
        "intake": {k: (r.get("intake") or {}).get(k) for k in ("vendor_name", "purpose", "domain")},
        "identity": r.get("identity"),
        "decision": r.get("decision"),
        "stability": {k: stab.get(k) for k in keep},
        "closures": r.get("closures") or [],
        "coverage": {k: cov.get(k) for k in ("site_reachable", "site_evidence", "searches_ok", "search_evidence", "failed_urls")},
        "incidents": r.get("incidents") or [],
        "certifications": [c for c in r.get("certifications") or [] if c.get("framework") != "OTHER"],
        "documents": [{k: v for k, v in doc.items() if k != "pages"} for doc in r.get("documents") or []],
        "findings": [{k: f.get(k) for k in ("kind", "claim", "evidence_id", "quote", "value", "attrs", "verified")}
                     for f in r.get("findings") or [] if f.get("verified")],
        "evidence": r.get("evidence") or [],
        "audit": r.get("audit"),
        "vendor_email": r.get("vendor_email"),
        "watch": r.get("watch"),
        "history": r.get("history") or [],
        "parent": r.get("parent"),
    }


def _sse(item) -> str:
    return f"data: {json.dumps(item)}\n\n"


@app.get("/")
def overview_page() -> FileResponse:
    return FileResponse(WEB / "overview.html")


@app.get("/vendor/{case_id}")
def vendor_page(case_id: str) -> FileResponse:
    _case(case_id)
    return FileResponse(WEB / "vendor.html")


@app.get("/batch")
def batch_page() -> FileResponse:
    return FileResponse(WEB / "batch.html")


@app.get("/report/{case_id}")
def report_page(case_id: str) -> FileResponse:
    _case(case_id)
    return FileResponse(WEB / "report.html")


@app.get("/report/{case_id}/print")
def report_print(case_id: str) -> HTMLResponse:
    # Built fresh from the saved review, so older reviews get the current layout and print button.
    result = json.loads((_case(case_id) / "report.json").read_text(encoding="utf-8"))
    return HTMLResponse(to_html(result, back=f"/report/{case_id}"))


def _case(case_id: str) -> Path:
    try:
        return case_dir(case_id)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, "No such case")


def _status(result: dict) -> str:
    """Where the case stands, in the words a reviewer would use."""
    outcome = result["decision"]["outcome"]
    if any(h.get("kind") == "clarified" for h in result.get("history") or []):
        return "Done"
    uploads = [h for h in result.get("history") or [] if h.get("kind") == "vendor_upload"]
    if outcome == "REFER TO HUMAN":
        return "Needs a person"
    if outcome == "APPROVE WITH CONDITIONS":
        return "Vendor responded" if uploads else "Waiting on vendor"
    return "Done"


def _seen(folder: Path) -> int:
    try:
        return int(json.loads((folder / "seen.json").read_text(encoding="utf-8")).get("version", 0))
    except (OSError, ValueError):
        return 0


def _case_row(folder: Path) -> dict | None:
    try:
        result = json.loads((folder / "report.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    history = agent_history(result)
    uploads = [h for h in history if h.get("kind") == "vendor_upload"]
    version = len(uploads)
    return {
        "case_id": folder.name,
        "vendor": result["identity"].get("name") or result["intake"].get("vendor_name") or "Unidentified",
        "domain": result["identity"].get("domain"),
        "request": result.get("request"),
        "outcome": result["decision"]["outcome"],
        "status": _status(result),
        "conditions": len(result["decision"]["conditions"]),
        "created_at": history[0].get("at") if history else result.get("reviewed_at"),
        "updated_at": history[-1].get("at") if history else result.get("reviewed_at"),
        "last_event": history[-1] if history else None,
        "version": version,
        "unread": version > _seen(folder),
    }


@app.get("/api/cases")
def list_cases(limit: int = 200) -> dict:
    rows = [r for r in (_case_row(f) for f in RUNS.iterdir() if f.is_dir()) if r] if RUNS.exists() else []
    rows.sort(key=lambda r: r["updated_at"] or "", reverse=True)
    return {"cases": rows[:limit], "unread": sum(r["unread"] for r in rows)}


@app.get("/api/case/{case_id}/version")
def case_version(case_id: str) -> dict:
    row = _case_row(_case(case_id))
    return {k: row[k] for k in ("version", "outcome", "status", "last_event", "unread", "updated_at")}


@app.post("/api/case/{case_id}/seen")
def mark_seen(case_id: str) -> dict:
    folder = _case(case_id)
    row = _case_row(folder)
    (folder / "seen.json").write_text(json.dumps({"version": row["version"]}), encoding="utf-8")
    return {"ok": True, "version": row["version"]}


@app.get("/reviews")
def reviews_page() -> FileResponse:
    return FileResponse(WEB / "reviews.html")


@app.get("/new")
def new_review_page() -> FileResponse:
    return FileResponse(WEB / "index.html")


@app.get("/monitoring")
def monitoring_page() -> FileResponse:
    return FileResponse(WEB / "monitoring.html")


RULE_NAMES = {"R1": "Identity unclear", "R2": "Company viability", "R3": "Missing evidence", "R4": "Security incident",
              "R5": "Certification", "R6": "Company stability", "R8": "Business red flag"}


@app.get("/api/stats")
def stats() -> dict:
    """Totals across every saved review, for the overview page."""
    results = []
    if RUNS.exists():
        for folder in RUNS.iterdir():
            if not folder.is_dir():
                continue
            try:
                r = json.loads((folder / "report.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            r["case_id"] = folder.name
            r["history"] = agent_history(r)
            results.append(r)
    outcomes = {k: 0 for k in SEVERITY}
    statuses = {"Vendor responded": 0, "Waiting on vendor": 0, "Needs a person": 0, "Done": 0}
    issues: dict[str, int] = {}
    cited = total_claims = sources = elapsed_n = 0
    elapsed = 0.0
    uploads = accepted = 0
    latest_by_vendor: dict[str, dict] = {}
    events = []
    for r in results:
        d = r["decision"]
        outcomes[d["outcome"]] = outcomes.get(d["outcome"], 0) + 1
        statuses[_status(r)] = statuses.get(_status(r), 0) + 1
        for item in d["referrals"] + d["conditions"] + [x for x in d["reasons"] if not x["rule"].startswith("R7")]:
            code = item["rule"].split(" ")[0]
            issues[code] = issues.get(code, 0) + 1
        cited += r["audit"]["verified"]
        total_claims += r["audit"]["total"]
        sources += len(r.get("evidence") or [])
        if r.get("elapsed_seconds"):
            elapsed += r["elapsed_seconds"]
            elapsed_n += 1
        name = r["identity"].get("name") or r["intake"].get("vendor_name") or "Unidentified"
        when = r["history"][-1].get("at") or r.get("reviewed_at") or ""
        if r["identity"].get("status") == "resolved" and (name not in latest_by_vendor or when > latest_by_vendor[name]["when"]):
            latest_by_vendor[name] = {"when": when, "r": r}
        for h in r["history"]:
            if h.get("kind") == "vendor_upload":
                uploads += 1
                accepted += bool(h.get("accepted"))
            events.append({"at": h.get("at"), "kind": h.get("kind"), "vendor": name, "case_id": r["case_id"],
                           "outcome": h.get("outcome"), "file": h.get("file"), "from": h.get("from")})
    vendors = [v["r"] for v in latest_by_vendor.values()]
    incident_rank = sorted(
        ({"vendor": v["identity"]["name"], "domain": v["identity"].get("domain"), "case_id": v["case_id"],
          "incidents": len(v.get("incidents") or []), "outcome": v["decision"]["outcome"]} for v in vendors),
        key=lambda x: -x["incidents"])
    certified = sum(1 for v in vendors if any(c.get("status") == "current_claim" and c.get("framework") != "OTHER" for c in v.get("certifications") or []))
    with_incidents = sum(1 for v in vendors if v.get("incidents"))
    attention = [_case_row(RUNS / r["case_id"]) for r in results if _status(r) in ("Vendor responded", "Needs a person")]
    attention = sorted([a for a in attention if a], key=lambda a: (not a["unread"], a["status"] != "Vendor responded", a["updated_at"] or ""), reverse=False)
    events.sort(key=lambda e: e["at"] or "", reverse=True)
    try:
        watched = len(json.loads((RUNS / "watches.json").read_text(encoding="utf-8")))
    except (OSError, ValueError):
        watched = 0
    return {
        "reviews": len(results),
        "vendors": len(vendors),
        "outcomes": outcomes,
        "statuses": statuses,
        "issues": sorted(({"code": k, "label": RULE_NAMES.get(k, k), "count": v} for k, v in issues.items()), key=lambda x: -x["count"]),
        "citations": {"verified": cited, "total": total_claims},
        "sources": sources,
        "avg_seconds": round(elapsed / elapsed_n) if elapsed_n else None,
        "uploads": uploads,
        "uploads_accepted": accepted,
        "vendors_with_incidents": with_incidents,
        "incidents_total": sum(x["incidents"] for x in incident_rank),
        "vendors_certified": certified,
        "top_incidents": [x for x in incident_rank if x["incidents"]][:6],
        "attention": attention[:6],
        "recent": events[:10],
        "watched": watched,
        "first_review": min((r.get("created_at") or r.get("reviewed_at") or "" for r in results), default=None),
    }


@app.get("/api/watches")
def watches() -> dict:
    """Every vendor under watch, with Crustdata's live status for each."""
    try:
        registry = json.loads((RUNS / "watches.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        registry = {}
    names = {}
    if RUNS.exists():
        for folder in RUNS.iterdir():
            try:
                r = json.loads((folder / "report.json").read_text(encoding="utf-8")) if folder.is_dir() else None
            except (OSError, ValueError):
                continue
            if r and r["identity"].get("domain") in registry:
                names[r["identity"]["domain"]] = (r["identity"].get("name"), folder.name, r.get("request"))
    crust = Crust()
    out = []
    for domain, w in registry.items():
        row = {"domain": domain, **w, "vendor": names.get(domain, (domain,))[0], "case_id": (names.get(domain) or (None, None))[1],
               "request": (names.get(domain) or (None, None, None))[2]}
        try:
            live = crust.client.get(f"/watch/company/{w['watch_id']}").json()
            runs = crust.client.get(f"/watch/company/{w['watch_id']}/runs").json()
            row.update({
                "status": live.get("status"), "created_at": live.get("created_at"), "last_run_at": live.get("last_run_at"),
                "every_hours": ((live.get("config") or {}).get("trigger") or {}).get("every_hours"),
                "notifications_count": live.get("notifications_count"), "credits_consumed": live.get("credits_consumed"),
                "track": live.get("track"),
                "runs": [{k: x.get(k) for k in ("started_at", "status", "new_records_count", "credits_deducted", "failure_reason")}
                         for x in (runs.get("runs") or [])[:5]],
                "runs_total": runs.get("total_count"),
            })
        except Exception as exc:  # noqa: BLE001 - one unreachable watch must not hide the others
            row.update({"status": "unknown", "error": f"Could not reach Crustdata: {type(exc).__name__}"})
        out.append(row)
    return {"watches": out, "email": os.environ.get("WATCH_EMAIL", "")}


@app.post("/api/watch")
def watch_add(body: dict) -> dict:
    """Watch a vendor by website, without a review. One watch per domain."""
    import re as _re
    domain = str(body.get("domain") or "").strip().lower()
    if not _re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", domain):
        raise HTTPException(400, "Enter a website such as vendor.com")
    result = ensure_watch(Crust(), domain)
    if result["status"] in ("failed", "skipped"):
        raise HTTPException(502, result.get("reason") or "Could not create the watch")
    return result


@app.post("/api/watch/{domain}/test")
def watch_test(domain: str) -> dict:
    """Ask Crustdata to send one sample alert, so the reviewer sees what an alert looks like."""
    registry = json.loads((RUNS / "watches.json").read_text(encoding="utf-8"))
    if domain not in registry:
        raise HTTPException(404, "Not watched")
    resp = Crust().client.post(f"/watch/company/{registry[domain]['watch_id']}/test", json={})
    if resp.status_code >= 400:
        raise HTTPException(502, f"Crustdata said: {resp.text[:200]}")
    return {"ok": True, "sent_to": registry[domain].get("email")}


@app.delete("/api/watch/{domain}")
def watch_cancel(domain: str) -> dict:
    """Stop watching a vendor. Crustdata cancels the watch; it cannot be resumed."""
    path = RUNS / "watches.json"
    registry = json.loads(path.read_text(encoding="utf-8"))
    if domain not in registry:
        raise HTTPException(404, "Not watched")
    resp = Crust().client.delete(f"/watch/company/{registry[domain]['watch_id']}")
    if resp.status_code not in (200, 204):
        raise HTTPException(502, f"Crustdata said: {resp.text[:200]}")
    registry.pop(domain)
    path.write_text(json.dumps(registry, indent=1), encoding="utf-8")
    return {"ok": True}


@app.get("/api/case/{case_id}")
def case_info(case_id: str) -> dict:
    result = json.loads((_case(case_id) / "report.json").read_text(encoding="utf-8"))
    result["case_id"] = case_id
    result["history"] = agent_history(result)
    out = _summary(result)
    out["version"] = len([h for h in result["history"] if h.get("kind") == "vendor_upload"])
    out["vendor_email"] = result.get("vendor_email")
    out["case_url"] = f"/vendor/{case_id}"
    out["documents"] = [{k: doc.get(k) for k in ("filename", "report_type", "period_end", "opinion")} for doc in result.get("documents") or []]
    return out


@app.get("/api/review")
def run_review(request: str) -> StreamingResponse:
    events: queue.Queue = queue.Queue()

    def emit(level: str, msg: str) -> None:
        events.put({"type": "log", "level": level, "message": msg})

    def worker() -> None:
        try:
            result = review(request, emit, watch=True)
            events.put({"type": "result", **_summary(result), "elapsed": result["elapsed_seconds"]})
        except Exception as exc:  # noqa: BLE001 - the browser must always hear how a run ended
            events.put({"type": "error", "message": f"{type(exc).__name__}: {exc}"})
        events.put(None)

    threading.Thread(target=worker, daemon=True).start()
    return _stream(events)


@app.get("/api/case/{case_id}/clarify")
def clarify(case_id: str, name: str = "", domain: str = "") -> StreamingResponse:
    """The person answered the agent's question. Re-run the review on exactly that company."""
    folder = _case(case_id)
    parent = json.loads((folder / "report.json").read_text(encoding="utf-8"))
    domain = domain.strip().lower().removeprefix("https://").removeprefix("http://").removeprefix("www.").split("/")[0]
    if not domain and not name.strip():
        raise HTTPException(400, "Choose a company or enter its website")
    events: queue.Queue = queue.Queue()

    def emit(level: str, msg: str) -> None:
        events.put({"type": "log", "level": level, "message": msg})

    def worker() -> None:
        try:
            result = review(parent["request"], emit, watch=True,
                            pinned={"name": name.strip() or None, "domain": domain or None, "parent": case_id})
            # Link both ways, so each case shows where the other is.
            parent.setdefault("history", agent_history(parent))
            parent["history"] = agent_history(parent) + [{
                "at": result["created_at"], "kind": "clarified", "by": "you", "outcome": result["decision"]["outcome"],
                "choice": f"{name.strip()} {domain}".strip(), "child": result.get("case_id"),
                "event": f"You confirmed {name.strip() or domain}"}]
            (folder / "report.json").write_text(json.dumps(parent, indent=2, default=str), encoding="utf-8")
            events.put({"type": "result", **_summary(result), "elapsed": result["elapsed_seconds"]})
        except Exception as exc:  # noqa: BLE001
            events.put({"type": "error", "message": f"{type(exc).__name__}: {exc}"})
        events.put(None)

    threading.Thread(target=worker, daemon=True).start()
    return _stream(events)


@app.post("/api/case/{case_id}/document")
async def upload_document(case_id: str, file: UploadFile = File(...)) -> StreamingResponse:
    _case(case_id)
    data = await file.read()
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, "File is larger than 15 MB")
    if not data.startswith(b"%PDF"):
        raise HTTPException(415, "Please upload a PDF")
    name = Path(file.filename or "document.pdf").name[:120]
    events: queue.Queue = queue.Queue()

    def emit(level: str, msg: str) -> None:
        events.put({"type": "log", "level": level, "message": msg})

    def worker() -> None:
        try:
            result = apply_document(case_id, data, name, emit)
            result["case_id"] = case_id
            events.put({"type": "result", **_summary(result)})
        except Exception as exc:  # noqa: BLE001
            events.put({"type": "error", "message": f"{type(exc).__name__}: {exc}"})
        events.put(None)

    threading.Thread(target=worker, daemon=True).start()
    return _stream(events)


def _rows_from_csv(text: str) -> list[dict]:
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return []
    header = [h.strip().lower() for h in next(csv.reader([lines[0]]))]
    has_header = any(h in ("vendor", "name", "company", "domain", "website") for h in header)
    reader = csv.reader(lines[1:] if has_header else lines)
    rows = []
    for cells in reader:
        cells = [c.strip() for c in cells]
        if not any(cells):
            continue
        row = dict(zip(header, cells)) if has_header else {"vendor": cells[0], "domain": cells[1] if len(cells) > 1 else ""}
        name = row.get("vendor") or row.get("name") or row.get("company") or ""
        domain = row.get("domain") or row.get("website") or ""
        purpose = row.get("purpose") or row.get("use") or ""
        if name or domain:
            rows.append({"vendor": name, "domain": domain, "purpose": purpose})
    return rows[:50]


@app.post("/api/batch")
async def run_batch(file: UploadFile = File(...)) -> StreamingResponse:
    text = (await file.read()).decode("utf-8", "replace")
    rows = _rows_from_csv(text)
    if not rows:
        raise HTTPException(400, "No vendors found. Use a CSV with a vendor column, and optional domain and purpose columns.")
    events: queue.Queue = queue.Queue()
    events.put({"type": "start", "total": len(rows)})
    crust, llm = Crust(), LLM()

    def one(i: int, row: dict) -> None:
        request = f"Vendor review: {row['vendor'] or row['domain']}" + (f", {row['domain']}" if row["domain"] and row["vendor"] else "")
        request += f". Use: {row['purpose']}." if row["purpose"] else "."
        try:
            result = review(request, crust=crust, llm=llm)
            s = _summary(result)
            s.pop("html")
            events.put({"type": "row", "index": i, "input": row, **s, "severity": SEVERITY.get(s["outcome"], 9)})
        except Exception as exc:  # noqa: BLE001 - one bad row must not stop the register
            events.put({"type": "row", "index": i, "input": row, "vendor": row["vendor"], "outcome": "ERROR",
                        "top_reason": f"{type(exc).__name__}: {exc}", "severity": -1})

    def worker() -> None:
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(lambda pair: one(*pair), enumerate(rows)))
        events.put({"type": "done"})
        events.put(None)

    threading.Thread(target=worker, daemon=True).start()
    return _stream(events)


def _stream(events: queue.Queue) -> StreamingResponse:
    def gen():
        while True:
            try:
                item = events.get(timeout=15)
            except queue.Empty:
                yield ": keep-alive\n\n"
                continue
            if item is None:
                return
            yield _sse(item)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="warning")
