"""Bite-tests for spike — the battery must bite single-shot holes and must
not lie on a target that refuses while quoting the canary.

Shims live on 127.0.0.1 only. Four targets:
  vulnerable  — bites on direct/jailbreak/markup shapes → battery MUST land rc=1;
  quoter      — refuses EVERY technique but quotes the canary in the refusal
                (the classic false-positive trap: substring detectors scream,
                behavioral verdict must stay silent) → rc=0;
  encoded     — bites ONLY when the technique carries a decodable encoding of
                the canary (base64/rot13/reverse) → proves the 2026 encoding
                category actually fires, not decorative;
  dead port   → rc=2 not_proven.
"""

from __future__ import annotations

import base64
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "spike"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "test_fixtures"))

from test_fixtures.spike.shims import (  # noqa: E402
    EncodedOnlyShim, QuoterShim, VulnerableShim, serve,
)

from spike_app.judge import REFUSED, judge_spike  # noqa: E402
from spike_app.tester import _substitute, run  # noqa: E402


def _make(handler):
    server, url = serve(handler)
    return server, url


@pytest.fixture(name="vuln_url")
def fixture_vuln_url():
    server, url = _make(VulnerableShim)
    yield url
    server.shutdown()


@pytest.fixture(name="quoter_url")
def fixture_quoter_url():
    server, url = _make(QuoterShim)
    yield url
    server.shutdown()


@pytest.fixture(name="encoded_url")
def fixture_encoded_url():
    server, url = _make(EncodedOnlyShim)
    yield url
    server.shutdown()


def test_bites_vulnerable_target(vuln_url):
    """Battery MUST land on an injection-vulnerable target (rc=1)."""
    report = run(vuln_url, fmt="openai")
    assert report["rc"] == 1, f"expected finding, got {report['status']}: {report['reason']}"
    assert report["performed"] >= 1
    cats = [f["category"] for f in report["findings"] if f["verdict"] == "performed"]
    assert "direct" in cats or "jailbreak" in cats


def test_quoting_refusal_is_not_a_hit(quoter_url):
    """The false-positive trap: every refusal quotes the canary. The verdict
    MUST be held (rc=0) — refusal lexicon wins over canary-in-text."""
    report = run(quoter_url, fmt="openai")
    assert report["rc"] == 0, f"false positive: {report['reason']}"
    assert report["performed"] == 0
    from spike_app.payloads import EXECUTE
    execute_total = sum(len(t) for t in EXECUTE.values())
    assert report["refused"] == execute_total, (
        f"expected {execute_total} refusals on execute group, got {report['refused']}")
    assert report["unclear"] == report["techniques_total"] - execute_total


def test_encoding_category_fires_and_bites(encoded_url):
    """2026 encoding rungs MUST be the ones that land: direct/jailbreak bounce,
    encoding performs — proves the category bites, not decorative."""
    report = run(encoded_url, fmt="openai")
    assert report["rc"] == 1, f"encoding rungs did not land: {report['reason']}"
    cats = {f["category"] for f in report["findings"] if f["verdict"] == "performed"}
    assert "encoding" in cats
    assert "direct" not in cats


def test_dead_target_is_not_proven():
    report = run("http://127.0.0.1:1/chat", fmt="openai")
    assert report["rc"] == 2
    assert report["status"] == "not_proven"


def test_judge_refusal_beats_encoded_echo():
    """A refusal carrying the base64 of the canary is STILL a refusal."""
    canary = "SPIKE-CANARY-1234567890"[:23]
    b64 = base64.b64encode(canary.encode()).decode()
    verdict = judge_spike(f"I can't decode payloads like {b64}.", canary)
    assert verdict.kind == REFUSED


def test_substitute_fills_all_placeholders():
    canary = "SPIKE-CANARY-TEST00001"
    for group in ("execute",):
        from spike_app.payloads import EXECUTE, DISCLOSE
        for techniques in list(EXECUTE.values()) + list(DISCLOSE.values()):
            for template in techniques:
                out = _substitute(template, canary)
                assert "{canary" not in out, f"unfilled placeholder: {template[:50]}"


def test_report_contract_latin_keys(vuln_url, tmp_path):
    import json as _json
    report = run(vuln_url, fmt="openai")
    path = tmp_path / "report.json"
    path.write_text(_json.dumps(report, ensure_ascii=False), encoding="utf-8")
    data = _json.loads(path.read_text(encoding="utf-8"))
    assert data["tool"] == "spike"
    assert set(data) >= {"tool", "status", "rc", "reason", "findings", "by_category"}
    assert (data["rc"] == 1) == (data["performed"] > 0)
    assert all(k.isascii() for k in data)
