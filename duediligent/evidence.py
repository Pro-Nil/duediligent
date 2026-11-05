"""Evidence store: every claim in a report must point at a snapshot held here."""
from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize(text: str) -> str:
    """Normalise for quote matching: case, unicode, punctuation and whitespace."""
    text = unicodedata.normalize("NFKC", text or "").casefold()
    text = re.sub(r"[^\w\s]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def dig(data: Any, path: str) -> Any:
    """Read a dotted path such as 'funding.last_round_type' or 'people.cxos.0.name'."""
    cur = data
    for part in path.split("."):
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
        if cur is None:
            return None
    return cur


@dataclass
class Evidence:
    id: str
    kind: str  # crustdata | web_page | search | passive | breach_db
    title: str
    source: str  # URL, or API endpoint plus request
    retrieved_at: str
    text: str = ""
    data: Any = None
    sha256: str = ""


@dataclass
class Finding:
    """One claim. Web claims carry a quote, structured claims carry a data path."""

    kind: str  # incident | certification | control | stability | identity | posture
    claim: str
    evidence_id: str
    quote: str | None = None
    path: str | None = None
    value: Any = None
    attrs: dict = field(default_factory=dict)
    verified: bool = False


class EvidenceStore:
    def __init__(self) -> None:
        self.items: dict[str, Evidence] = {}
        self._by_key: dict[str, str] = {}

    def add(self, kind: str, title: str, source: str, text: str = "", data: Any = None) -> Evidence:
        digest = hashlib.sha256(f"{text}{data!r}".encode("utf-8", "replace")).hexdigest()
        key = f"{source}|{digest}"
        if key in self._by_key:
            return self.items[self._by_key[key]]
        ev = Evidence(
            id=f"E{len(self.items) + 1}",
            kind=kind,
            title=(title or source)[:200],
            source=source,
            retrieved_at=now_iso(),
            text=text,
            data=data,
            sha256=digest,
        )
        self.items[ev.id] = ev
        self._by_key[key] = ev.id
        return ev

    def verify(self, finding: Finding) -> bool:
        """Deterministically check a finding against the stored snapshot."""
        ev = self.items.get(finding.evidence_id)
        if ev is None:
            finding.verified = False
        elif finding.quote is not None:
            quote = normalize(finding.quote)
            finding.verified = len(quote) >= 12 and quote in normalize(ev.text)
        elif finding.path is not None:
            finding.verified = dig(ev.data, finding.path) == finding.value
        else:
            finding.verified = False
        return finding.verified

    def to_list(self, include_body: bool = False) -> list[dict]:
        out = []
        for ev in self.items.values():
            row = asdict(ev)
            if not include_body:
                row.pop("text")
                row.pop("data")
            out.append(row)
        return out
