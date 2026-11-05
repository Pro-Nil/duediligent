"""CLI: python -m duediligent "Review Notion for our customer support data" """
from __future__ import annotations

import sys

from .agent import review
from .config import load_env
from .report import to_markdown


def main() -> int:
    load_env()
    request = " ".join(sys.argv[1:]).strip()
    if not request:
        print('Usage: python -m duediligent "<vendor review request>"')
        return 2
    sys.stdout.reconfigure(encoding="utf-8")

    def emit(level: str, msg: str) -> None:
        print(f"[{level}] {msg}", file=sys.stderr, flush=True)

    result = review(request, emit)
    print(to_markdown(result))
    if result.get("paths"):
        print(f"\nSaved to {result['paths']['folder']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
