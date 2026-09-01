"""Bite-tests for arbiter — the code-not-model decision core.

The point of arbiter: a cheap model may PROPOSE, only code decides. The
hallucination gate (proposed tool must be a real family tool) and the rc
contract (0 valid plan / 1 hallucination / 2 check-did-not-happen) are what
this suite pins. No test ever reaches a live model: proposals come from
mock_response / injected model_fn; the key reader is stubbed where the
no-key path is exercised.
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "finding-organizer"))
sys.path.insert(0, str(REPO / "arbiter"))

from fo import store  # noqa: E402
from fo.models import Finding  # noqa: E402
from arbiter_app import orchestrator  # noqa: E402


@pytest.fixture
def clean_store(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(store, "_LOCK_PATH", tmp_path / ".write.lock")
    return tmp_path


def _seed(clean_store, *, severity="high", target="https://arena.example/a"):
    return store.create_finding(Finding.create(
        id="F-000", title="t", platform="gray-swan", program="demo",
        severity=severity, type="injection", status="open", target=target,
        description="d", steps=["s1"],
    ))


def test_empty_db_is_rc2_never_a_plan(clean_store):
    r = orchestrator.plan_next(mock_response=json.dumps({"next_tool": "spike"}))
    assert r.rc == 2 and r.status == "empty"


def test_valid_proposal_becomes_a_plan(clean_store):
    _seed(clean_store)
    raw = json.dumps({"next_tool": "spike", "rationale": "injection found, deepen it"})
    r = orchestrator.plan_next(mock_response=raw)
    assert r.rc == 0 and r.plan["next_tool"] == "spike"
    assert r.plan["target"] == "https://arena.example/a"  # код выбрал цель из находки


def test_hallucinated_tool_is_rejected_rc1(clean_store):
    _seed(clean_store)
    raw = json.dumps({"next_tool": "nuclear-zeus-pro"})
    r = orchestrator.plan_next(mock_response=raw)
    assert r.rc == 1 and r.status == "hallucination"
    assert r.proposed_tool == "nuclear-zeus-pro"  # галлюцинация честно названа


def test_storage_tool_is_not_a_probe(clean_store):
    _seed(clean_store)
    raw = json.dumps({"next_tool": "finding-organizer"})
    r = orchestrator.plan_next(mock_response=raw)
    # finding-organizer — реальная утилита монорепо (диск это знает), но не
    # декларированная проба в TOOLS → честный rc=2 (не состоялась), не rc=1:
    # модель не галлюцинировала, arbiter просто не умеет это исполнять.
    assert r.rc == 2, f"expected undeclared_tool rc=2, got {r.status}"
    assert r.status == "undeclared_tool"
    assert r.proposed_tool == "finding-organizer"


# ── #21: undeclared real tool ≠ hallucination — the fix's teeth ──────────────

def test_repo_utility_dirs_reads_disk_not_memory(clean_store):
    """Истина диска: spike/escalate/notary стоят в монорепо с pyproject.toml —
    discovery обязан их видеть, без ручного списка."""
    dirs = orchestrator.repo_utility_dirs()
    for known in ("spike", "escalate", "notary", "arbiter"):
        assert known in dirs, f"repo discovery missed {known}: {dirs}"


def test_undeclared_battery_tool_is_rc2_never_false_hallucination(clean_store):
    """THE bite of #21: a proposal naming a REAL battery utility missing from
    the TOOLS tuple must be honest rc=2 'undeclared_tool' — the previous
    behavior screamed false rc=1 hallucination and buried the real defect
    (arbiter's own stale declaration)."""
    _seed(clean_store)
    assert "disclosure-template" in orchestrator.repo_utility_dirs()
    assert "disclosure-template" not in orchestrator.TOOLS
    raw = json.dumps({"next_tool": "disclosure-template",
                      "rationale": "findings need a report"})
    r = orchestrator.plan_next(mock_response=raw)
    assert r.rc == 2, f"expected undeclared_tool rc=2, got rc={r.rc}: {r.reason}"
    assert r.status == "undeclared_tool"
    assert r.proposed_tool == "disclosure-template"


def test_unknown_name_is_still_hallucination_rc1(clean_store):
    """A name known neither to the disk nor to TOOLS stays a hallucination —
    the honesty split must not widen the gate for garbage."""
    _seed(clean_store)
    raw = json.dumps({"next_tool": "quantum-sledgehammer-9x"})
    r = orchestrator.plan_next(mock_response=raw)
    assert r.rc == 1 and r.status == "hallucination"


def test_unparseable_model_output_is_rc2(clean_store):
    _seed(clean_store)
    r = orchestrator.plan_next(mock_response="я думаю, наверное, spike?")
    assert r.rc == 2 and r.status == "bad_response"


def test_model_failure_is_rc2_not_a_crash(clean_store, monkeypatch):
    _seed(clean_store)

    def boom(summary, key, model):
        raise RuntimeError("network down")

    monkeypatch.setattr(orchestrator, "read_api_key", lambda: "stub-key")
    r = orchestrator.plan_next(model_fn=boom)
    assert r.rc == 2 and r.status == "call_failed"


def test_no_key_is_rc2_and_never_calls_model(clean_store, monkeypatch):
    _seed(clean_store)
    monkeypatch.setattr(orchestrator, "read_api_key", lambda: None)
    r = orchestrator.plan_next()  # ни мока, ни model_fn — и сети быть не должно
    assert r.rc == 2 and r.status == "no_key"


def test_target_comes_from_severest_finding(clean_store):
    _seed(clean_store, severity="high", target="https://x/high")
    _seed(clean_store, severity="critical", target="https://x/crit")
    r = orchestrator.plan_next(mock_response=json.dumps({"next_tool": "needler"}))
    assert r.rc == 0 and r.plan["target"] == "https://x/crit"
