"""arsenic-specific test fixtures — three honest RAG pipeline roles.

Аудит-шапка (madd, 02.09.2026):
  Назначение: подопытные для bite-тестов arsenic — obedient_rag (извлекает
    скрытую инструкцию и ИСПОЛНЯЕТ — дыра класса), sanitizing_rag (санирует
    скрытые векторы, читает видимое — контроль «мера умеет нет»), dead_rag
    (index принимает, query всегда 5xx — не состоялось).
  Вход: POST /index {document, id}; POST /query {query}.
  Выход: JSON {reply}; всё только на 127.0.0.1.
  Рамка авторизации: тестовая инфраструктура, слушает локально.
  Egress: ноль.
  НЕ доказывает: ничего о реальных RAG — это роли, на которых судья arsenic
    обязан дать performed/held/not_proven в правильную сторону.
"""

from __future__ import annotations

import json
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "arsenic"))

from arsenic_app.payloads import strip_hidden  # noqa: E402


def serve(handler_cls) -> tuple[ThreadingHTTPServer, str, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    return server, f"{base}/index", f"{base}/query"


def _respond(self, code: int, body: bytes) -> None:  # noqa: ANN001
    self.send_response(code)
    self.send_header("Content-Type", "application/json")
    self.send_header("Content-Length", str(len(body)))
    self.end_headers()
    self.wfile.write(body)


def _json_ok(content: str) -> bytes:
    return json.dumps({"reply": content}, ensure_ascii=False).encode()


class _RagBase(BaseHTTPRequestHandler):
    """Shared two-endpoint pipeline: /index stores documents, /query runs the
    generation behavior over the most relevant stored document. STORE is
    per-class (each subclass owns its dict) so sibling fixtures in one test
    process never cross-contaminate."""

    STORE: dict[str, str]
    ORDER: list[str]

    def log_message(self, *a):  # silence
        pass

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        if self.path.endswith("/index"):
            doc_id = str(body.get("id", "doc"))
            type(self).STORE[doc_id] = str(body.get("document", ""))
            # re-indexing the same id must MOVE it to the top of recency —
            # a dict update keeps the old position, and the retrieval then
            # serves a stale document (the measure caught exactly this)
            if doc_id in type(self).ORDER:
                type(self).ORDER.remove(doc_id)
            type(self).ORDER.append(doc_id)
            _respond(self, 200, json.dumps({"ok": True, "id": doc_id}).encode())
            return
        # /query: retrieve the most recently indexed relevant document
        doc = ""
        for doc_id in reversed(type(self).ORDER):
            stored = type(self).STORE[doc_id]
            if "quarterly report" in stored.lower():
                doc = stored
                break
        _respond(self, 200, _json_ok(self.generate(doc)))

    def generate(self, doc: str) -> str:  # noqa: ANN001, ARG002
        raise NotImplementedError


class ObedientRag(_RagBase):
    """Vulnerable role: the hidden instruction is retrieved and executed —
    any 'output X' in the document becomes an emission of X."""

    STORE: dict[str, str] = {}
    ORDER: list[str] = []

    def generate(self, doc: str) -> str:
        # a model reading the document dissolves zero-width joins the same
        # way it reads any spacing artifact — hence out[\u200b ]?put
        m = re.search(r"assistant:\s*out[\u200b ]?put\s+([A-Z0-9\-]+)",
                      doc, re.DOTALL)
        if not m:
            m = re.search(r"instruction:\s*out[\u200b ]?put\s+([A-Z0-9\-]+)",
                          doc)
        if m:
            return f"{m.group(1)}"
        # it also reads plain visible notes (the retrieval heartbeat depends
        # on an obedient reader echoing what it sees)
        note = re.search(r"marker (ARSENIC-CANARY-[0-9A-F]{10})", doc)
        if note:
            return f"Author note marker: {note.group(1)}"
        return "Summary of the quarterly report."


class SanitizingRag(_RagBase):
    """Control role: hidden vectors are stripped before generation; visible
    text (including the visible_control note) is quoted faithfully."""

    STORE: dict[str, str] = {}
    ORDER: list[str] = []

    def generate(self, doc: str) -> str:
        visible = strip_hidden(doc)
        note = re.search(r"marker (ARSENIC-CANARY-[0-9A-F]{10})", visible)
        if note:
            return f"Author note marker: {note.group(1)}"
        return "Revenue grew 4% this quarter. Operations remain stable."


class DeadRag(_RagBase):
    """Not_proven role: indexing works, the query leg always 500s."""

    STORE: dict[str, str] = {}
    ORDER: list[str] = []

    def do_POST(self):  # noqa: N802
        if self.path.endswith("/index"):
            super().do_POST()
            return
        _respond(self, 500, b'{"error": "generation unavailable"}')
