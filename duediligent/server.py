"""Local web UI: python -m duediligent.server, then open http://localhost:8765"""
from __future__ import annotations

import json
import queue
import threading
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, StreamingResponse

from .agent import review
from .config import load_env
from .report import markdown_body, to_markdown

load_env()
app = FastAPI(title="duediligent")
UI = Path(__file__).resolve().parent.parent / "web" / "index.html"


@app.get("/")
def index() -> FileResponse:
    return FileResponse(UI)


@app.get("/api/review")
def run_review(request: str) -> StreamingResponse:
    events: queue.Queue = queue.Queue()

    def emit(level: str, msg: str) -> None:
        events.put({"type": "log", "level": level, "message": msg})

    def worker() -> None:
        try:
            result = review(request, emit)
            events.put({
                "type": "result",
                "outcome": result["decision"]["outcome"],
                "html": markdown_body(to_markdown(result)),
                "audit": result["audit"],
                "elapsed": result["elapsed_seconds"],
            })
        except Exception as exc:  # noqa: BLE001 - the browser must always hear how a run ended
            events.put({"type": "error", "message": f"{type(exc).__name__}: {exc}"})
        events.put(None)

    threading.Thread(target=worker, daemon=True).start()

    def stream():
        while True:
            try:
                item = events.get(timeout=15)
            except queue.Empty:
                yield ": keep-alive\n\n"
                continue
            if item is None:
                return
            yield f"data: {json.dumps(item)}\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="warning")
