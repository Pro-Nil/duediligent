"""After approval, ask Crustdata to watch the vendor, so a change triggers a fresh review."""
from __future__ import annotations

import json
import os
from pathlib import Path

from .crust import Crust, CrustError

REGISTRY = Path(__file__).resolve().parent.parent / "runs" / "watches.json"
TRACK = {"op": "or", "conditions": [
    {"field": "news", "type": "added"},
    {"field": "headcount.total", "type": "changed"},
]}


def _load() -> dict:
    try:
        return json.loads(REGISTRY.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def ensure_watch(crust: Crust, domain: str) -> dict:
    """One watch per vendor domain. Re-running never creates a second one."""
    registry = _load()
    if domain in registry:
        return {"status": "existing", **registry[domain]}
    email = os.environ.get("WATCH_EMAIL", "").strip()
    if not email:
        return {"status": "skipped", "reason": "Set WATCH_EMAIL in .env to receive change alerts."}
    body = {
        "entities": {"domains": [domain]},
        "track": TRACK,
        "config": {"trigger": {"type": "interval", "every_hours": 168}, "max_results_per_run": 10},
        "notifications": [{"type": "email", "to": [email]}],
    }
    try:
        resp = crust._post("/watch/company", body, retries=1)  # never cached: this must really happen
    except CrustError as exc:
        return {"status": "failed", "reason": str(exc)[:200]}
    watch_id = (resp or {}).get("id") if isinstance(resp, dict) else None
    if not watch_id:
        return {"status": "failed", "reason": "Crustdata did not return a watch id."}
    registry[domain] = {"watch_id": watch_id, "email": email, "tracks": "news added, headcount changed, weekly"}
    REGISTRY.parent.mkdir(parents=True, exist_ok=True)
    REGISTRY.write_text(json.dumps(registry, indent=1), encoding="utf-8")
    return {"status": "created", **registry[domain]}
