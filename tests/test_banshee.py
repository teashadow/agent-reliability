"""Bite-tests for banshee — recon pipeline: the gate bites before any scan does.

The tool wraps external scanners (subfinder/httpx/nuclei). Real binaries are
NEVER needed here: PATH shims emit canned output, and the periscope
authorization gate is a shim whose exit codes mirror the contract
(0 in-scope · 1 out-of-scope · anything else = unknown → fail-safe deny).
The несущая property under test: **authorization runs before every external
call** — no program, out-of-scope target, or silent gate means nothing runs.
"""

from __future__ import annotations

import os
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
SHIMS = pathlib.Path(__file__).resolve().parent / "banshee_shims"
sys.path.insert(0, str(REPO / "banshee"))

from banshee_app import pipeline, storage  # noqa: E402


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", f"{SHIMS}:{os.environ.get('PATH', '')}")
    monkeypatch.setattr(pipeline, "PERISCOPE_CLI", str(SHIMS / "periscope"))
    monkeypatch.setattr(pipeline, "PERISCOPE_DIR", str(tmp_path))
    monkeypatch.setattr(storage, "RECON_ROOT", tmp_path / "recon")
    return tmp_path


def test_no_program_blocks_before_any_call(env):
    """Fail-safe: без scope-программы скан не начинается вообще."""
    with pytest.raises(pipeline.ScopeBlocked, match="НЕ сканирую"):
        pipeline.run_target("demo.example.com")
    assert not (env / "recon").exists() or not any((env / "recon").iterdir()), \
        "без программы что-то успело отсканировать"


def test_out_of_scope_denied(env):
    with pytest.raises(pipeline.ScopeBlocked, match="ВНЕ scope"):
        pipeline.run_target("evil.example.org", program="demo-program")


def test_silent_gate_is_fail_safe_deny(env):
    """Молчание перископа (неизвестный rc) = запрет, не пропуск."""
    with pytest.raises(pipeline.ScopeBlocked, match="неизвестен"):
        pipeline.run_target("demo.example.com", program="unknown-program")


def test_in_scope_run_produces_family_findings(env):
    run_dir = pipeline.run_target("demo.example.com", program="demo-program")
    v = pipeline.family_verdict(run_dir)
    assert v["verdict"] == "ПРОВАЛ" and v["rc"] == 1
    assert v["findings"][0]["вектор"] == "cve-2026-0001"
    assert v["счёт"]["live_hosts"] == 2
    assert "НЕ доказывает" in v["not_proven"]


def test_quick_run_clean_surface_is_not_a_finding(env, monkeypatch):
    monkeypatch.setenv("BANSHI_NUCLEI_QUIET", "1")
    run_dir = pipeline.run_target("demo.example.com", quick=True, program="demo-program")
    v = pipeline.family_verdict(run_dir)
    assert v["verdict"] == "ПРОШЁЛ" and v["rc"] == 0
    assert v["findings"] == []
    assert v["счёт"]["live_hosts"] == 2  # поверхность живая — это не находка


def test_verdict_on_missing_run_is_rc2(env):
    v = pipeline.family_verdict(None)
    assert v["verdict"] == "НЕ ПРОВЕРЕНО" and v["rc"] == 2
    v2 = pipeline.family_verdict(env / "recon" / "nope")
    assert v2["verdict"] == "НЕ ПРОВЕРЕНО" and v2["rc"] == 2
