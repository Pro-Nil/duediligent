"""Crustdata REST client with pacing, retries and terminal-error handling."""
from __future__ import annotations

import os
import random
import threading
import time
from typing import Any

import httpx

from . import cache

BASE_URL = "https://api.crustdata.com"
API_VERSION = "2025-11-01"
# Documented default limits, in requests per minute.
RATE_LIMITS = {
    "/web/search/live": 10,
    "/web/enrich/live": 10,
    "/company/identify": 30,
    "/company/enrich": 15,
}
CALL_NAMES = {
    "/web/search/live": "A Crustdata web search",
    "/web/enrich/live": "A Crustdata page fetch",
    "/company/identify": "The Crustdata company lookup",
    "/company/enrich": "The Crustdata company record",
}
ENRICH_FIELDS = [
    "basic_info", "headcount", "funding", "revenue", "hiring",
    "people", "news", "locations", "software_reviews", "social_profiles",
]


class CrustError(Exception):
    def __init__(self, message: str, status: int | None = None, terminal: bool = False):
        super().__init__(message)
        self.status = status
        self.terminal = terminal


class Crust:
    def __init__(self, api_key: str | None = None, timeout: float = 60.0):
        self.api_key = api_key or os.environ.get("CRUSTDATA_API_KEY", "")
        if not self.api_key:
            raise CrustError("CRUSTDATA_API_KEY is not set", terminal=True)
        self.client = httpx.Client(
            base_url=BASE_URL,
            timeout=timeout,
            headers={
                "authorization": f"Bearer {self.api_key}",
                "x-api-version": API_VERSION,
                "content-type": "application/json",
            },
        )
        self._lock = threading.Lock()
        self._sent: dict[str, list[float]] = {}
        self.calls: list[dict] = []
        self.notify = lambda message: None
        # Demo switch: the first call to each endpoint times out, to show the retry working.
        self._fail_once = os.environ.get("DUEDILIGENT_FAULT") == "timeout_once"
        self._failed: set[str] = set()

    def _pace(self, path: str) -> None:
        """Sliding window: a burst is fine until the per-minute limit, then it waits."""
        rpm = RATE_LIMITS.get(path)
        if not rpm:
            return
        while True:
            with self._lock:
                now = time.monotonic()
                recent = [t for t in self._sent.get(path, []) if now - t < 61]
                if len(recent) < rpm:
                    recent.append(now)
                    self._sent[path] = recent
                    return
                wait = 61 - (now - recent[0])
            time.sleep(max(wait, 0.1))

    def post(self, path: str, body: dict, retries: int = 3) -> Any:
        cached = cache.get("crust", [path, body])
        if cached is not cache.MISS:
            self.calls.append({"path": path, "status": "cache", "credits": "0"})
            return cached
        result = self._post(path, body, retries)
        cache.put("crust", [path, body], result)
        return result

    def _post(self, path: str, body: dict, retries: int) -> Any:
        last = "no response"
        for attempt in range(retries + 1):
            self._pace(path)
            try:
                if self._fail_once and path not in self._failed:
                    self._failed.add(path)
                    raise httpx.ReadTimeout("injected timeout")
                resp = self.client.post(path, json=body)
            except httpx.HTTPError as exc:
                last = f"{type(exc).__name__}: {exc}"
                self.notify(f"{CALL_NAMES.get(path, path)} timed out ({type(exc).__name__}). Trying again.")
                time.sleep(1.5 * (attempt + 1))
                continue
            self.calls.append({
                "path": path,
                "status": resp.status_code,
                "credits": resp.headers.get("x-credits-used"),
            })
            if resp.status_code == 429:
                wait = float(resp.headers.get("x-ratelimit-reset") or 5)
                self.notify(f"{CALL_NAMES.get(path, path)} is busy. Waiting {wait:.0f}s, then trying again.")
                time.sleep(min(wait, 60) + random.random())
                last = "rate limited"
                continue
            if resp.status_code >= 500:
                last = f"HTTP {resp.status_code}"
                self.notify(f"{CALL_NAMES.get(path, path)} had a server error ({resp.status_code}). Trying again.")
                time.sleep(1.5 * (attempt + 1))
                continue
            if resp.status_code in (401, 402, 403):
                raise CrustError(f"HTTP {resp.status_code}: {resp.text[:300]}", resp.status_code, terminal=True)
            if resp.status_code >= 400:
                raise CrustError(f"HTTP {resp.status_code}: {resp.text[:300]}", resp.status_code)
            try:
                return resp.json()
            except ValueError:
                last = "response was not JSON"
        raise CrustError(f"{path} failed: {last}")

    def identify(self, name: str | None = None, domain: str | None = None) -> list[dict]:
        body = {"domains": [domain]} if domain else {"names": [name]}
        rows = self.post("/company/identify", body)
        if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
            raise CrustError("/company/identify returned an unexpected response")
        matches = rows[0].get("matches") or []
        return [m for m in matches if isinstance(m, dict)]

    def enrich(self, company_id: int | None = None, domain: str | None = None, fields: list[str] | None = None) -> dict | None:
        body: dict[str, Any] = {"fields": fields or ENRICH_FIELDS}
        if company_id is not None:
            body["crustdata_company_ids"] = [company_id]
        else:
            body["domains"] = [domain]
        try:
            rows = self.post("/company/enrich", body)
        except CrustError as exc:
            # A key may be denied specific field groups, so retry with the core set.
            if exc.status == 403 and fields is None:
                return self.enrich(company_id, domain, ["basic_info", "headcount", "funding", "revenue"])
            raise
        if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict) or not rows[0].get("matches"):
            return None
        data = rows[0]["matches"][0].get("company_data") if isinstance(rows[0]["matches"][0], dict) else None
        return data if isinstance(data, dict) else None

    def search(self, query: str, sources: list[str], site: str | None = None, start_date: int | None = None) -> list[dict]:
        body: dict[str, Any] = {"query": query, "sources": sources}
        if site:
            body["site"] = site
        if start_date:
            body["start_date"] = start_date
        data = self.post("/web/search/live", body)
        rows = data.get("results") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            raise CrustError("/web/search/live returned an unexpected response")
        return [r for r in rows if isinstance(r, dict)]

    def fetch(self, urls: list[str]) -> list[dict]:
        if not urls:
            return []
        rows = self.post("/web/enrich/live", {"urls": urls[:10]})
        return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []
