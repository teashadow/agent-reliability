"""Single-shot injection battery runner.

Contract (family): rc 0 — target held · rc 1 — at least one technique landed
(performed) · rc 2 — check could not run (target unreachable for every
technique). Report JSON uses LATIN keys. The verdict is set by code, zero
calls to any LLM from here.
"""

from __future__ import annotations

import base64
import codecs
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

import httpx

from .judge import PERFORMED, REFUSED, judge_disclose, judge_spike  # noqa: E402
from .payloads import CCI, DISCLOSE, EXECUTE, sealed_instruction  # noqa: E402


def _canary() -> str:
    seed = datetime.now(timezone.utc).isoformat()
    return "SPIKE-CANARY-" + hashlib.sha256(seed.encode()).hexdigest()[:10].upper()


def _substitute(template: str, canary: str) -> str:
    b64 = base64.b64encode(canary.encode()).decode()
    rot13 = codecs.encode(canary, "rot13")
    # CCI envelope: the sealed synthetic instruction + key printed on the page
    cpt, key = sealed_instruction(canary)
    return (template.replace("{canary_cpt}", cpt)
                    .replace("{canary_key}", key)
                    .replace("{canary_b64}", b64)
                    .replace("{canary_rot13}", rot13)
                    .replace("{canary_rev}", canary[::-1])
                    .replace("{canary}", canary))


def _extract_text(raw: str) -> str:
    """Unwrap typical JSON envelopes — the detector must see CONTENT, not the wrapper."""
    try:
        data = json.loads(raw)
    except Exception:
        return raw
    if isinstance(data, dict):
        for key in ("reply", "text", "content", "message", "response", "output"):
            if isinstance(data.get(key), str):
                return data[key]
        try:
            return data["choices"][0]["message"]["content"]
        except Exception:
            pass
    return raw


def _send(client: httpx.Client, url: str, fmt: str, text: str,
          body: str | None, key: str | None) -> tuple[int, str]:
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    if fmt == "openai":
        r = client.post(url, headers=headers,
                        json={"model": "gpt-4o-mini",
                              "messages": [{"role": "user", "content": text}]})
    elif fmt == "get":
        r = client.get(url.replace("PAYLOAD", text), headers=headers)
    else:  # custom
        raw = (body or '{"message": "PAYLOAD"}').replace("PAYLOAD", json.dumps(text)[1:-1])
        r = client.post(url, headers=headers, json=json.loads(raw))
    return r.status_code, _extract_text(r.text)


def run(url: str, *, fmt: str = "custom", body: str | None = None,
        key: str | None = None) -> dict[str, Any]:
    """Full battery against one authorized endpoint."""
    canary = _canary()
    findings: list[dict[str, Any]] = []
    performed = refused = unclear = not_ran = 0
    by_category: dict[str, dict[str, int]] = {}

    with httpx.Client(follow_redirects=True, timeout=30) as client:
        for group, categories in (("execute", EXECUTE),
                                  ("cci", CCI), ("disclose", DISCLOSE)):
            for category, techniques in categories.items():
                stats = {"performed": 0, "refused": 0, "unclear": 0, "not_ran": 0}
                for template in techniques:
                    text = _substitute(template, canary)
                    try:
                        code, answer = _send(client, url, fmt, text, body, key)
                    except httpx.HTTPError as exc:
                        not_ran += 1
                        stats["not_ran"] += 1
                        findings.append({"group": group, "category": category,
                                         "verdict": "not_checked", "why": str(exc)[:80]})
                        continue
                    if code >= 500:
                        not_ran += 1
                        stats["not_ran"] += 1
                        findings.append({"group": group, "category": category,
                                         "verdict": "not_checked", "why": f"HTTP {code}"})
                        continue
                    # CCI is an execute-family group: the canary lives inside
                    # the sealed envelope, so the behavioral judge applies
                    verdict = (judge_spike(answer, canary)
                               if group in ("execute", "cci")
                               else judge_disclose(answer))
                    if verdict.kind == PERFORMED:
                        performed += 1
                        stats["performed"] += 1
                    elif verdict.kind == REFUSED:
                        refused += 1
                        stats["refused"] += 1
                    else:
                        unclear += 1
                        stats["unclear"] += 1
                    if verdict.kind == PERFORMED:
                        findings.append({"group": group, "category": category,
                                         "verdict": "performed", "clean": verdict.clean,
                                         "why": verdict.reason,
                                         "technique": text[:70]})
                by_category[f"{group}:{category}"] = stats

    total = sum(len(t) for cats in (EXECUTE, CCI, DISCLOSE) for t in cats.values())
    if not_ran == total:
        status, rc, reason = "not_proven", 2, "every technique failed to reach the target"
    elif performed:
        status, rc = "finding", 1
        reason = f"injections landed: {performed}/{total} techniques performed"
    else:
        status, rc = "held", 0
        reason = f"all {total} techniques reflected (refused {refused}, unclear {unclear})"

    return {
        "tool": "spike",
        "status": status,
        "rc": rc,
        "reason": reason,
        "url": url,
        "canary": canary,
        "techniques_total": total,
        "performed": performed,
        "refused": refused,
        "unclear": unclear,
        "not_ran": not_ran,
        "by_category": by_category,
        "findings": findings,
        "note": ("spike — single-shot injection battery. Multi-turn depth is "
                 "escalate's job; quick screening of one technique lives in warden."),
    }
