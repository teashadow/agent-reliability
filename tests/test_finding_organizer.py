"""Bite-tests for finding-organizer (fo/) — the tracker must actually bite.

Rule of this suite (Nevis's gate): every test here makes the tool fail loudly
if its core guarantee breaks. Green with a broken tool is the same lie as a
green smoke over a red battery.

The store must never touch the operator's real data dir: the fixture redirects
both module constants (DATA_DIR and _LOCK_PATH — the lock path is bound at
import, patching DATA_DIR alone would still write the lock into $HOME).
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(
    0, str(pathlib.Path(__file__).resolve().parents[1] / "finding-organizer")
)

from fo import exporter, store  # noqa: E402
from fo.models import Finding  # noqa: E402


@pytest.fixture
def clean_store(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(store, "_LOCK_PATH", tmp_path / ".write.lock")
    return tmp_path


def _finding(**over) -> Finding:
    base = dict(
        id="F-000",  # create_finding выделяет настоящий id под локом
        title="вектор прошёл проверяющего",
        platform="gray-swan",
        program="demo-arena",
        severity="high",
        type="injection",
        status="open",
        target="https://arena.example/agent",
        description="проба, обязанная ломать",
        steps=["раз", "два"],
    )
    base.update(over)
    return Finding.create(**base)


def test_create_and_load_round_trip(clean_store):
    f = store.create_finding(_finding())
    g = store.load_finding(f.id)
    assert g.id == f.id
    assert g.title == "вектор прошёл проверяющего"
    assert g.severity == "high"
    assert g.steps == ["раз", "два"]
    assert g.source == "manual"


def test_ids_are_monotonic(clean_store):
    ids = [store.create_finding(_finding()).id for _ in range(3)]
    assert ids == ["F-001", "F-002", "F-003"]


def test_update_status_persists(clean_store):
    f = store.create_finding(_finding())
    g = store.update_status(f.id, "closed")
    assert g.status == "closed"
    assert store.load_finding(f.id).status == "closed"


def test_list_filters_by_status(clean_store):
    a = store.create_finding(_finding())
    b = store.create_finding(_finding())
    store.update_status(b.id, "closed")
    open_ids = [f.id for f in store.list_findings(status="open")]
    closed_ids = [f.id for f in store.list_findings(status="closed")]
    assert open_ids == [a.id]
    assert closed_ids == [b.id]


def test_exporter_markdown_carries_evidence(clean_store):
    f = store.create_finding(_finding(cvss="7.5", impact="полн. компрометация агента"))
    md = exporter.render_finding_markdown(f)
    assert f.id in md
    assert "high" in md
    assert "вектор прошёл проверяющего" in md
    for step in ("раз", "два"):
        assert step in md, f"экспортёр потерял шаг воспроизведения: {step!r}"
    assert "7.5" in md


def test_load_missing_raises(clean_store):
    with pytest.raises(FileNotFoundError):
        store.load_finding("F-999")


def test_ingest_tool_report_only_bites_and_is_idempotent(clean_store):
    """Семейный контракт: инструменты пишут в общую БД. ПРОШЁЛ — не находка;
    повторный отчёт не дублирует находку (идемпотентность по tool+target+вектор)."""
    report = {
        "инструмент": {"имя": "warden", "цель": "https://arena.example/agent"},
        "findings": [
            {"вердикт": "ПРОВАЛ", "вектор": "direct-injection", "почему": "гейт пропустил"},
            {"вердикт": "ПРОШЁЛ", "вектор": "noise-flood", "почему": "устоял"},
        ],
    }
    first = store.ingest_tool_report(report)
    assert len(first) == 1, "ПРОШЁЛ просочился в трекер как находка"
    hit = first[0]
    assert hit.source == "tool"
    assert hit.tool == "warden"
    assert hit.status == "queue"
    assert "direct-injection" in hit.title

    again = store.ingest_tool_report(report)
    assert [f.id for f in again] == [hit.id], "повторный отчёт задублировал находку"
    files = list(clean_store.glob("*.json"))
    assert len(files) == 1, f"в хранилище лежит {len(files)} находок, должна одна"
