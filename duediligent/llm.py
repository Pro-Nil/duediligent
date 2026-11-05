"""Model access: the Anthropic API when a key is set, otherwise the local `claude` CLI."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import time
import tempfile
from pathlib import Path

from . import cache

DEFAULT_MODEL = "claude-sonnet-5-5"
CLI_TIMEOUT = 150  # seconds before one CLI call is abandoned and retried
WAIT_STEP = 15  # seconds between "still waiting" notices


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
        self.on_wait = None  # called with the seconds waited when a model call is slow
        self._lock = threading.Lock()
        self._last_wait = 0.0
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
        # A prompt file keeps line breaks intact on Windows. The neutral working folder and
        # empty setting sources stop personal memory and project files reaching the model.
        with tempfile.TemporaryDirectory(prefix="duediligent-") as tmp:
            prompt_file = Path(tmp) / "system.txt"
            prompt_file.write_text(system, encoding="utf-8")
            try:
                proc = subprocess.Popen(
                    [self.cli, "-p", "--model", "sonnet", "--tools", "", "--system-prompt-file", str(prompt_file),
                     "--setting-sources", "", "--strict-mcp-config", "--no-session-persistence", "--disable-slash-commands"],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, encoding="utf-8", cwd=tmp,
                )
            except OSError as exc:
                raise LLMError(f"claude CLI failed to start: {exc}") from exc
            # Wait in short steps, so the person watching hears that the call is slow, not stuck.
            started, pending_input = time.monotonic(), user
            while True:
                try:
                    out, err = proc.communicate(input=pending_input, timeout=WAIT_STEP)
                    break
                except subprocess.TimeoutExpired:
                    pending_input = None
                    waited = int(time.monotonic() - started)
                    if waited >= CLI_TIMEOUT:
                        proc.kill()
                        proc.communicate()
                        raise LLMError(f"the claude CLI did not answer within {CLI_TIMEOUT} seconds")
                    self._waiting(waited)
        if proc.returncode != 0:
            raise LLMError(f"claude CLI exited {proc.returncode}: {err[:300]}")
        return out

    def _waiting(self, seconds: int) -> None:
        """Report a slow call at most once per step, however many calls run at once."""
        with self._lock:
            now = time.monotonic()
            if now - self._last_wait < WAIT_STEP - 1:
                return
            self._last_wait = now
        if self.on_wait:
            self.on_wait(seconds)

    def json(self, system: str, user: str, max_tokens: int = 2000, retries: int = 1, required: tuple[str, ...] = ()) -> dict:
        cached = cache.get("llm", [system, user])
        if cached is not cache.MISS:
            return cached
        last: Exception | None = None
        prompt = user
        for _ in range(retries + 1):
            try:
                result = parse_json(self.complete(system, prompt, max_tokens))
                missing = [k for k in required if k not in result]
                if missing:
                    raise LLMError(f"model reply is missing {missing}")
                cache.put("llm", [system, user], result)
                return result
            except LLMError as exc:
                last = exc
                prompt = user + "\n\nReply with one valid JSON object and nothing else."
        raise LLMError(str(last))
