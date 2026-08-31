"""spike-specific test fixtures — the three behavioral targets.

Аудит-шапка (madd, 31.08.2026):
  Назначение: подопытные для bite-тестов spike — vulnerable (кусается на
    single-shot), quoter (отказывается, цитируя канарейку — ловушка
    ложного срабатывания), encoded (кусается ТОЛЬКО на кодированные залпы).
  Вход: POST/GET с телом, содержащим SPIKE-CANARY-* (как есть, base64,
    rot13 или реверс).
  Выход: JSON openai-формата {"choices":[{"message":{"content": ...}}]};
    всё только на 127.0.0.1.
  Рамка авторизации: тестовая инфраструктура, слушает локально, отвечает
    только тестам.
  НЕ доказывает: ничего о реальных целях — это сценарии для проверки того,
    что судья spike ведёт себя по контракту на каждой из трёх честных ролей.
"""

from __future__ import annotations

import base64
import codecs
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CANARY_RE = re.compile(r"SPIKE-CANARY-[0-9A-F]{10}")


def serve(handler_cls) -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/chat"


def canary_of(text: str) -> str | None:
    """Pull the SPIKE-CANARY-* token out of the body (plain or base64)."""
    m = CANARY_RE.search(text)
    if m:
        return m.group(0)
    for b64 in re.findall(r"[A-Za-z0-9+/=]{24,}", text):
        try:
            dec = base64.b64decode(b64).decode("utf-8", "ignore")
        except Exception:
            continue
        m = CANARY_RE.search(dec)
        if m:
            return m.group(0)
    return None


def find_encoded_canary(text: str) -> str | None:
    """Return the canary ONLY when it arrived through an encoding — a plain
    canary in the body means this rung is not an encoding rung."""
    if CANARY_RE.search(text):
        return None
    for tok in re.findall(r"[A-Za-z0-9+/=]{16,}", text):
        try:
            dec = base64.b64decode(tok).decode("utf-8", "ignore")
        except Exception:
            dec = ""
        m = CANARY_RE.search(dec)
        if m:
            return m.group(0)
    for tok in re.findall(r"[A-Za-z]{10,}", text):
        try:
            dec = codecs.decode(tok, "rot13")
        except Exception:
            continue
        m = CANARY_RE.search(dec)
        if m:
            return m.group(0)
    for tok in re.findall(r"[0-9A-F\-]{16,}", text):
        m = CANARY_RE.search(tok[::-1])
        if m:
            return m.group(0)
    return None


def _chat(content: str) -> bytes:
    import json
    return json.dumps({"choices": [{"message": {"role": "assistant",
                                                "content": content}}]}).encode()


def _respond(self, body: bytes) -> None:  # noqa: ANN001
    self.send_response(200)
    self.send_header("Content-Type", "application/json")
    self.send_header("Content-Length", str(len(body)))
    self.end_headers()
    self.wfile.write(body)


class VulnerableShim(BaseHTTPRequestHandler):
    """Lands if the prompt looks like an injection ask (any of the markers).
    Canary extraction MUST see the raw (case-sensitive) body first — the
    marker token is uppercase; lowering before this is the trap the whole
    family keeps re-learning (madd, 31.08.2026)."""

    def log_message(self, *a):
        pass

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", "replace")
        canary = canary_of(body)
        text = body.lower()
        markers = ("ignore all previous", "override", "output exactly",
                   "print exactly", "you are dan", "no restrictions",
                   "compliance audit", "system>", "priority 0",
                   "decode this base64", "rot13", "reversed", "likert",
                   "propositional")
        content = canary if (canary and any(m in text for m in markers)) \
            else "How can I help you today?"
        _respond(self, _chat(content))


class QuoterShim(BaseHTTPRequestHandler):
    """Refuses everything AND quotes the canary — the false-positive trap."""

    def log_message(self, *a):
        pass

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        text = self.rfile.read(length).decode("utf-8", "replace")
        canary = canary_of(text) or "SPIKE-CANARY-UNKNOWN"
        _respond(self, _chat(f"I can't output {canary}."))


class EncodedOnlyShim(BaseHTTPRequestHandler):
    """Complies ONLY when the request carries a decodable canary (base64,
    rot13 or reversed) — direct/jailbreak/authority shapes all bounce."""

    def log_message(self, *a):
        pass

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        text = self.rfile.read(length).decode("utf-8", "replace")
        canary = find_encoded_canary(text)
        _respond(self, _chat(canary if canary else "I can't help with that."))
