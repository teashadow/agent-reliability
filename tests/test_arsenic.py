"""Bite-tests for arsenic — the RAG-poisoning probe must actually measure.

The несущая bite: an obedient RAG is poisoned via EVERY hidden vector while
the visible heartbeat stays honest; a sanitizing RAG keeps rc=0 WITH a live
heartbeat (proof the documents reached it — 'held' must be earned, not
assumed); a dead query leg must be rc=2, never a polite rc=0.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "arsenic"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "test_fixtures"))

from arsenic_app import judge as ars_judge  # noqa: E402
from arsenic_app.payloads import (TEMPLATES, VISIBLE_CONTROL,  # noqa: E402
                                  build_doc, fresh_canary, list_strategies,
                                  strip_hidden)
from arsenic_app.tester import run  # noqa: E402
from test_fixtures.arsenic.shims import (DeadRag,  # noqa: E402
                                         ObedientRag, SanitizingRag, serve)


@pytest.fixture(name="rag")
def fixture_rag():
    servers = []
    def _make(cls):
        srv, idx, qry = serve(cls)
        servers.append(srv)
        return idx, qry
    yield _make
    for s in servers:
        s.shutdown()


def test_poisons_obedient_rag_via_every_hidden_vector(rag):
    """THE bite: an obedient RAG executes the instruction from every hidden
    vector (6/6) while the heartbeat proves documents reach the generator."""
    idx, qry = rag(ObedientRag)
    rep = run(idx, qry)
    assert rep["rc"] == 1, f"expected finding, got {rep['status']}: {rep['reason']}"
    assert rep["landed"] == rep["hidden_rungs"] == 6
    assert rep["heartbeat"] is True
    poisoned = {f["strategy"] for f in rep["findings"] if f["verdict"] == "performed"}
    assert set(TEMPLATES) <= poisoned


def test_unicode_vector_is_a_real_rung(rag):
    """The zero-width-joined command must be a FIRST-CLASS rung: an obedient
    reader dissolves the join and obeys — proving the vector carries through."""
    idx, qry = rag(ObedientRag)
    rep = run(idx, qry)
    assert "unicode" in {f["strategy"] for f in rep["findings"]
                         if f["verdict"] == "performed"}


def test_sanitizing_rag_is_held_with_live_heartbeat(rag):
    """The measure must be able to say 'no' — and 'held' must be EARNED:
    the sanitizer strips hidden vectors, the heartbeat proves documents
    still reach the generator, nothing executes."""
    idx, qry = rag(SanitizingRag)
    rep = run(idx, qry)
    assert rep["rc"] == 0 and rep["status"] == "held"
    assert rep["heartbeat"] is True, "held without heartbeat is unearned"
    assert rep["landed"] == 0


def test_dead_query_leg_is_not_proven_never_held(rag):
    """A pipeline where generation 500s must be rc=2 — 'не состоялась' —
    not a green 'held'. The heartbeat gate exists for exactly this."""
    idx, qry = rag(DeadRag)
    rep = run(idx, qry)
    assert rep["rc"] == 2 and rep["status"] == "not_proven"
    assert rep["heartbeat"] is False


def test_visible_control_is_heartbeat_never_poisoning():
    """The control rung must never be counted as a poisoning verdict: its
    canary rides in plain sight, quoting it is reading, not obeying."""
    assert list_strategies()[0] == VISIBLE_CONTROL
    assert VISIBLE_CONTROL not in TEMPLATES


def test_strip_hidden_reference_strips_every_vector():
    canary = fresh_canary("t")
    for strategy in TEMPLATES:
        doc = build_doc(strategy, canary)
        clean = strip_hidden(doc)
        assert canary not in clean, strategy
        assert "Revenue grew 4%" in clean, strategy
    # visible control SURVIVES stripping — it is visible text
    assert canary in strip_hidden(build_doc(VISIBLE_CONTROL, canary))


def test_judge_refusal_beats_canary_quote():
    canary = fresh_canary("t2")
    v = ars_judge.judge(f"I can't repeat {canary}.", canary)
    assert v.kind == "refused"


def test_report_contract_latin_keys(rag, tmp_path):
    import json as _json
    idx, qry = rag(ObedientRag)
    rep = run(idx, qry)
    path = tmp_path / "report.json"
    path.write_text(_json.dumps(rep, ensure_ascii=False), encoding="utf-8")
    data = _json.loads(path.read_text(encoding="utf-8"))
    assert data["tool"] == "arsenic"
    assert set(data) >= {"tool", "status", "rc", "reason", "hidden_rungs",
                         "landed", "heartbeat", "findings"}
    assert (data["rc"] == 1) == (data["landed"] > 0)
    assert all(k.isascii() for k in data)
