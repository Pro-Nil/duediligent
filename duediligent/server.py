"""Local web UI: python -m duediligent.server, then open http://localhost:8765"""
from __future__ import annotations

import csv
import io
import json
import queue
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .agent import apply_document, case_dir, review
from .config import load_env
from .crust import Crust
from .llm import LLM
from .report import markdown_body, to_markdown

load_env()
app = FastAPI(title="duediligent")
WEB = Path(__file__).resolve().parent.parent / "web"
app.mount("/web", StaticFiles(directory=WEB), name="web")
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
    }


def _sse(item) -> str:
    return f"data: {json.dumps(item)}\n\n"


@app.get("/")
def index() -> FileResponse:
    return FileResponse(WEB / "index.html")


@app.get("/vendor/{case_id}")
def vendor_page(case_id: str) -> FileResponse:
    _case(case_id)
    return FileResponse(WEB / "vendor.html")


@app.get("/batch")
def batch_page() -> FileResponse:
    return FileResponse(WEB / "batch.html")


@app.get("/report/{case_id}")
def report_page(case_id: str) -> HTMLResponse:
    return HTMLResponse((_case(case_id) / "report.html").read_text(encoding="utf-8"))


def _case(case_id: str) -> Path:
    try:
        return case_dir(case_id)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, "No such case")


@app.get("/api/case/{case_id}")
def case_info(case_id: str) -> dict:
    result = json.loads((_case(case_id) / "report.json").read_text(encoding="utf-8"))
    out = _summary(result)
    out["vendor_email"] = result.get("vendor_email")
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
