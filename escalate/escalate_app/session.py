"""Target transport with session history.

The prober is multi-turn: every call sends the FULL conversation so far.
Formats:
  openai — POST {url} with {"messages": [...]} (chat-completions shape);
  custom — POST {url} with raw text body (single string, history flattened).
No third endpoints, no retries against non-targets. All calls go to the
operator-supplied URL only.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import requests


class TransportError(RuntimeError):
    """Target unreachable / bad transport — run should end rc=2."""


@dataclass
class Turn:
    role: str
    content: str


@dataclass
class Session:
    url: str
    target_format: str = "openai"  # openai | custom
    timeout: float = 30.0
    history: list[Turn] = field(default_factory=list)

    def ask(self, content: str) -> str:
        """Append a user turn, send full history, append and return the reply."""
        self.history.append(Turn("user", content))
        reply = self._send()
        self.history.append(Turn("assistant", reply))
        return reply

    def turns(self) -> int:
        """Number of user turns sent so far (multi-turn depth)."""
        return sum(1 for t in self.history if t.role == "user")

    def _send(self) -> str:
        try:
            if self.target_format == "openai":
                body = {"messages": [{"role": t.role, "content": t.content} for t in self.history]}
                r = requests.post(self.url, json=body, timeout=self.timeout)
            elif self.target_format == "custom":
                flat = "\n".join(f"{t.role}: {t.content}" for t in self.history)
                r = requests.post(self.url, data=flat.encode("utf-8"), timeout=self.timeout)
            else:
                raise TransportError(f"unknown target format: {self.target_format}")
        except requests.RequestException as exc:
            raise TransportError(f"target unreachable: {exc}") from exc
        if r.status_code != 200:
            raise TransportError(f"target HTTP {r.status_code}")
        if self.target_format == "openai":
            try:
                return r.json()["choices"][0]["message"]["content"]
            except (ValueError, KeyError, IndexError) as exc:
                raise TransportError(f"target answer not parseable: {exc}") from exc
        return r.text
