"""Model access: the Anthropic API when a key is set, otherwise the local `claude` CLI."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

from . import cache

DEFAULT_MODEL = "claude-sonnet-5-5"


class LLMError(Exception):
    pass


def parse_json(text: str) -> dict:
    """Pull the first JSON object out of a model reply."""
    text = (text or "").strip()
    fenced = re.search(r"```(?:json)?\s*(.+?)```", text, re.S)
    if fenced:
        text = fenced.group(1).strip()
    start = text.find("{")
    if start < 0:
        raise LLMError("no JSON object in model reply")
    try:
        obj, _ = json.JSONDecoder().raw_decode(text[start:])
    except ValueError as exc:
        raise LLMError(f"invalid JSON in model reply: {exc}") from exc
    return obj


class LLM:
    def __init__(self, model: str | None = None):
        self.model = model or os.environ.get("DUEDILIGENT_MODEL", DEFAULT_MODEL)
        self.api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        self.cli = shutil.which("claude")
        if self.api_key:
            import anthropic

            self.client = anthropic.Anthropic(
                api_key=self.api_key, base_url="https://api.anthropic.com", max_retries=3
            )
            self.backend = "api"
        elif self.cli:
            self.client = None
            self.backend = "cli"
        else:
            raise LLMError("Set ANTHROPIC_API_KEY or install the claude CLI")

    def complete(self, system: str, user: str, max_tokens: int = 2000) -> str:
        if self.backend == "api":
            try:
                msg = self.client.messages.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    system=system,
                    messages=[{"role": "user", "content": user}],
                )
            except Exception as exc:  # noqa: BLE001 - every SDK failure is handled the same way
                raise LLMError(f"model call failed: {exc}") from exc
            return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
        try:
            proc = subprocess.run(
                [self.cli, "-p", "--model", "sonnet", "--tools", "", "--system-prompt", system],
                input=user, capture_output=True, text=True, encoding="utf-8", timeout=240,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise LLMError(f"claude CLI failed: {exc}") from exc
        if proc.returncode != 0:
            raise LLMError(f"claude CLI exited {proc.returncode}: {proc.stderr[:300]}")
        return proc.stdout

    def json(self, system: str, user: str, max_tokens: int = 2000, retries: int = 1) -> dict:
        cached = cache.get("llm", [system, user])
        if cached is not cache.MISS:
            return cached
        last: Exception | None = None
        prompt = user
        for _ in range(retries + 1):
            try:
                result = parse_json(self.complete(system, prompt, max_tokens))
                cache.put("llm", [system, user], result)
                return result
            except LLMError as exc:
                last = exc
                prompt = user + "\n\nReply with one valid JSON object and nothing else."
        raise LLMError(str(last))
