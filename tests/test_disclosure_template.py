"""Bite-tests for disclosure-template (inkwell) — finding → valid disclosure report.

The contract: a finding-organizer-style JSON becomes a platform-valid
markdown report; scaffold placeholders must NOT survive where the finding
has data (a "[TARGET]" left in a submitted report is a machine tell), and
must STAY where there is no data (honesty about what is not known).
The LLM-attack taxonomy (VULN_TYPES) is the family's vocabulary — it must
cover the CWE mapping that the report promises.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "disclosure-template"))

from dt import catalog, renderer  # noqa: E402

FINDING = {
    "program": "demo-arena",
    "severity": "high",
    "target": "https://arena.example/agent",
    "description": "canary from input surfaced in output",
    "impact": "полная компрометация рантайма агента",
    "steps": ["plant canary", "ask agent", "canary returned"],
    "notes": "WARDEN-CANARY-bite",
}


def test_taxonomy_covers_every_type_with_cwe():
    for t in catalog.VULN_TYPES:
        assert t in catalog.SEVERITY_CWE, f"для {t} нет CWE — репорт обещает, а словарь молчит"


def test_validate_rejects_unknown_platform_and_type():
    with pytest.raises(ValueError):
        renderer.validate("github", "prompt-injection")
    with pytest.raises(ValueError):
        renderer.validate("h1", "sql-injection")


def test_known_types_are_llm_attack_class():
    for t in ("prompt-injection", "indirect-prompt-injection", "rag-poisoning",
              "excessive-agency", "mcp-sse-injection"):
        assert t in renderer.supported_types()


def test_render_report_fills_prose_and_drops_scaffold():
    md = renderer.render_report("h1", "prompt-injection", FINDING)
    assert "demo-arena" in md
    assert "canary from input surfaced in output" in md
    assert "полная компрометация рантайма агента" in md
    for step in ("plant canary", "ask agent"):
        assert step in md, "шаги воспроизведения потеряны"
    assert "HIGH" in md
    assert "[TARGET]" not in md, "каркас-заглушка пережил заполнение — машинный tell в репорте"


def test_render_report_carries_cwe():
    md = renderer.render_report("h1", "prompt-injection", FINDING)
    assert "CWE-1357" in md
    unmapped = renderer.render_report("h1", "tool-confusion", FINDING)
    assert "CWE-" in unmapped


def test_no_finding_keeps_scaffold_honestly():
    md = renderer.render_report("h1", "prompt-injection", None)
    assert md.strip(), "пустой репорт"
    assert "[TARGET]" in md, "без находки каркас обязан остаться каркасом"


def test_missing_steps_keep_scaffold_in_that_section():
    f = dict(FINDING, steps=[])
    md = renderer.render_report("h1", "prompt-injection", f)
    head, _, tail = md.partition("## Steps to Reproduce")
    assert tail.strip(), "секция steps исчезла"
    assert "canary from input surfaced in output" not in tail, "проза summary втекла в steps"


def test_write_template_writes_file(tmp_path):
    out = renderer.write_template("h1", "rag-poisoning",
                                  output_path=tmp_path / "r.md")
    assert out.exists() and out.read_text(encoding="utf-8").strip()
