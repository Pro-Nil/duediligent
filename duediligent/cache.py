"""A small disk cache. A crashed review resumes without paying twice, and a reworded
request reads the same evidence, so it reaches the same decision."""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent / ".cache"
TTL_SECONDS = 24 * 3600
_MISS = object()
MISS = _MISS


def _path(namespace: str, key: Any) -> Path:
    digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode()).hexdigest()
    return ROOT / namespace / f"{digest}.json"


def get(namespace: str, key: Any) -> Any:
    if os.environ.get("DUEDILIGENT_NO_CACHE"):
        return _MISS
    path = _path(namespace, key)
    try:
        row = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _MISS
    if time.time() - row.get("at", 0) > TTL_SECONDS:
        return _MISS
    return row["value"]


def put(namespace: str, key: Any, value: Any) -> None:
    if os.environ.get("DUEDILIGENT_NO_CACHE"):
        return
    path = _path(namespace, key)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.stem}.{os.getpid()}.{time.monotonic_ns()}.tmp")
    tmp.write_text(json.dumps({"at": time.time(), "value": value}, default=str), encoding="utf-8")
    os.replace(tmp, path)
