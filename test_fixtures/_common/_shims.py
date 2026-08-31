"""Programmable local shims — scripted HTTP targets for the battery's tests.

BehaviorShim: serve scripted responses in order (or repeat the last one),
count requests, optionally delay each response (the latency probe as
behavior). Everything binds 127.0.0.1 and shuts down cleanly.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class BehaviorShim:
    """Scripted target: replies.pop(0) per request, last reply repeats.

    Replies are plain strings (rendered as {"reply": ...}) or dicts
    (rendered verbatim) or ints (raw HTTP status, empty body).
    """

    def __init__(self, replies: list, *, delay_s: float = 0.0):
        self._replies = list(replies)
        self._lock = threading.Lock()
        self.requests: list[dict] = []
        self.delay_s = delay_s
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}/"

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def hit_count(self) -> int:
        return len(self.requests)

    def _handler(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _answer(self, reply):
                if outer.delay_s:
                    time.sleep(outer.delay_s)
                if isinstance(reply, int):          # raw status
                    self.send_response(reply)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = (json.dumps(reply, ensure_ascii=False).encode()
                        if isinstance(reply, dict) else
                        json.dumps({"reply": reply}, ensure_ascii=False).encode())
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):  # noqa: N802
                self.do_POST()

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length) if length else b""
                with outer._lock:
                    outer.requests.append({"path": self.path,
                                           "body": raw.decode("utf-8", "replace")})
                    reply = (outer._replies.pop(0) if len(outer._replies) > 1
                             else (outer._replies[0] if outer._replies else "ok"))
                self._answer(reply)

        return Handler

    def shutdown(self) -> None:
        self._server.shutdown()
        self._server.server_close()


class LatencyShim(BehaviorShim):
    """The latency probe as a target: answers correctly, slowly."""

    def __init__(self, delay_s: float, replies: list | None = None):
        super().__init__(replies or ["all good here"], delay_s=delay_s)
