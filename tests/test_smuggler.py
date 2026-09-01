"""Bite-tests for smuggler — the obfuscation panel must actually measure.

The несущая bite: on a naive keyword filter (blocks plaintext 'output'),
the CONTROL rung is refused and the obfuscated rungs LAND — that contrast is
the whole class in one measurement. The clean agent must stay rc=0 (the
measure can say 'no'), the normalizing executor is baseline-vulnerable
(11/11 — obeys even the control).
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "smuggler"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "test_fixtures"))

from smuggler_app import judge as smg_judge  # noqa: E402
from smuggler_app.payloads import (COMPOSITIONS, CONTROL_PLAIN,  # noqa: E402
                                   TECHNIQUES, build_payload, catalog)
from smuggler_app.tester import fresh_canary, run  # noqa: E402
from test_fixtures.smuggler.shims import (CleanAgentShim,  # noqa: E402
                                          NaiveKeywordFilterShim,
                                          NormalizingExecutorShim, serve)


@pytest.fixture(name="shim")
def fixture_shim():
    servers = []
    def _make(cls):
        srv, url = serve(cls)
        servers.append(srv)
        return url
    yield _make
    for s in servers:
        s.shutdown()


def test_the_class_bite_naive_filter_blocked_control_obfuscation_landed(shim):
    """THE bite: keyword filter blocks the plain control but every obfuscated
    rung lands. If obfuscation does NOT bypass this filter, the panel lies."""
    url = shim(NaiveKeywordFilterShim)
    rep = run(url, fmt="custom")
    assert rep["rc"] == 1, f"expected finding, got {rep['status']}: {rep['reason']}"
    assert "plain_control" not in rep["bypassed_by"], "control must be blocked"
    assert rep["landed"] == rep["rungs_total"] - 1
    assert {t for t in TECHNIQUES} | set(COMPOSITIONS) <= set(rep["bypassed_by"])


def test_clean_agent_is_held_rc0(shim):
    """The measure must be able to say 'no': a target that never obeys input
    instructions is held, every rung refused."""
    url = shim(CleanAgentShim)
    rep = run(url, fmt="custom")
    assert rep["rc"] == 0 and rep["landed"] == 0
    assert rep["refused"] == rep["rungs_total"]


def test_normalizing_executor_is_baseline_vulnerable(shim):
    """An agent that normalizes and obeys falls for ALL 11 rungs including
    the plain control — the panel's worst case, pinned."""
    url = shim(NormalizingExecutorShim)
    rep = run(url, fmt="custom")
    assert rep["rc"] == 1 and rep["landed"] == rep["rungs_total"] == 11


def test_dead_target_is_not_proven():
    rep = run("http://127.0.0.1:1/agent", fmt="custom")
    assert rep["rc"] == 2 and rep["status"] == "not_proven"


def test_judge_refusal_beats_canary_quote():
    canary = fresh_canary("t")
    v = smg_judge.judge(f"I can't emit {canary}.", canary)
    assert v.kind == "refused"


def test_judge_clean_execution_vs_leak():
    canary = fresh_canary("t2")
    assert smg_judge.judge(canary, canary).clean is True
    assert smg_judge.judge(f"Sure thing: {canary} as asked.", canary).clean is False


def test_catalog_honesty_nfkc_limits():
    """NFKC decodes fullwidth, but does NOT transliterate cyrillic homoglyphs
    and does NOT decode the tag block — the catalog must show that honestly,
    or an operator buys a false sense of 'normalization will catch it'."""
    cat = catalog()
    assert cat["fullwidth_nfkc"]["nfkc"].startswith("output ")
    assert "output" not in cat["homoglyph"]["nfkc"]
    assert "output" not in cat["tag_chars"]["nfkc"]
    assert "output" not in cat["b64->zero_width"]["nfkc"]


def test_all_rungs_build_and_carry_clean_canary():
    """Every rung (control + 6 + 4) builds; the canary rides clean ASCII;
    only the command word is obfuscated (audit rule)."""
    canary = fresh_canary("t3")
    rungs = [CONTROL_PLAIN, *TECHNIQUES, *COMPOSITIONS]
    assert len(rungs) == 11
    for t in rungs:
        payload = build_payload(t, canary)
        assert canary in payload, t
        assert "{" not in payload and "}" not in payload, t  # no unfilled slots


def test_report_contract_latin_keys(shim, tmp_path):
    import json as _json
    url = shim(NaiveKeywordFilterShim)
    rep = run(url, fmt="custom")
    path = tmp_path / "report.json"
    path.write_text(_json.dumps(rep, ensure_ascii=False), encoding="utf-8")
    data = _json.loads(path.read_text(encoding="utf-8"))
    assert data["tool"] == "smuggler"
    assert set(data) >= {"tool", "status", "rc", "reason", "rungs_total",
                         "landed", "bypassed_by", "findings"}
    assert (data["rc"] == 1) == (data["landed"] > 0)
    assert all(k.isascii() for k in data)
