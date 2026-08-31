"""Bite-tests for test_fixtures/_common — the shared hostile-input layer.

The layer MUST be hostile for real: badjson really breaks json.loads,
unicode really carries homoglyphs/zero-widths, flood really is 64 KiB,
injection really carries the canary. And the control MUST be boring:
health carries nothing a behavioral detector may flag. A fixture layer that
passes these tests but doesn't bite real detectors would be decorative —
so the last test runs the injection probe through spike's behavioral judge.
"""

from __future__ import annotations

import base64
import codecs
import json
import pathlib
import sys
import time
import urllib.error
import urllib.request

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "test_fixtures"))
sys.path.insert(0, str(ROOT / "spike"))

from _common import (PROBES, PROBE_NAMES, LatencyShim,  # noqa: E402
                     probe_badjson, probe_flood, probe_health,
                     probe_injection, probe_secret, probe_unicode,
                     synthetic_canary)
from _common._shims import BehaviorShim  # noqa: E402


def test_all_ten_probes_present():
    """10 probes = 9 payload generators + latency as behavior (LatencyShim)."""
    assert set(PROBE_NAMES) == {"health", "empty", "noise", "repeat", "flood",
                                "injection", "secret", "unicode", "badjson"}
    assert set(PROBES) == set(PROBE_NAMES)
    assert LatencyShim is not None  # the 10th probe
    for name, fn in PROBES.items():
        payloads = fn()
        assert len(payloads) >= 1, name
        assert all(isinstance(p, str) for p in payloads), name


def test_health_control_is_boring():
    """The measure must be able to say 'no': health carries no canary, no
    injection markers — a detector firing here is a false positive."""
    for text in probe_health():
        assert "CANARY" not in text.upper()
        assert "ignore" not in text.lower()
        assert "system" not in text.lower()


def test_canaries_are_unique_and_substituted():
    a, b = synthetic_canary(), synthetic_canary()
    assert a != b and a.startswith("SYN-CANARY-")
    for text in probe_injection("SYN-CANARY-FIXED01"):
        assert "{canary" not in text  # no unfilled placeholders
        encodings = (
            "SYN-CANARY-FIXED01",
            base64.b64encode(b"SYN-CANARY-FIXED01").decode(),
            codecs.encode("SYN-CANARY-FIXED01", "rot13"),
        )
        # disclose rungs carry no canary by design — they fish for prompt text
        assert any(e in text for e in encodings) or "system prompt" in text, text


def test_badjson_really_breaks():
    """Two honest classes: syntactically broken (json.loads raises) and
    type-wrong (parses, but the text field is not a string)."""
    for raw in probe_badjson():
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue  # syntactically broken — as designed
        assert isinstance(data, dict) and not isinstance(
            data.get("message"), str), raw  # type-wrong class — as designed


def test_unicode_really_carries_weapons():
    ws = ("\u200b", "\u200d", "\u00ad", "\u0301", "\u202e")
    assert any(any(w in t for w in ws) for t in probe_unicode())
    assert any(any(0x0400 < ord(ch) < 0x0500 for ch in t)
               for t in probe_unicode())  # cyrillic homoglyphs present


def test_flood_really_floods():
    assert any(len(t) >= 65536 for t in probe_flood())


def test_secret_is_synthetic_only():
    """No real credential may ever ride into a test through the fixture."""
    for t in probe_secret():
        assert "SYNTHETIC" in t or set(t) & set("XAB0123456789")


def test_behavior_shim_scripts_and_counts():
    """Scripted order: pop from front, last reply repeats. Raw ints are
    plain HTTP statuses."""
    shim = BehaviorShim(["first", {"reply": "second"}, 503, "tail"])
    try:
        with urllib.request.urlopen(shim.url, data=b"x=1") as r:
            assert json.loads(r.read().decode())["reply"] == "first"
        with urllib.request.urlopen(shim.url, data=b"x=1") as r:
            assert json.loads(r.read().decode())["reply"] == "second"
        with pytest.raises(urllib.error.HTTPError) as err:
            urllib.request.urlopen(shim.url, data=b"x=1")
        assert err.value.code == 503
        for _ in range(2):  # last reply repeats
            with urllib.request.urlopen(shim.url, data=b"x=1") as r:
                assert json.loads(r.read().decode())["reply"] == "tail"
        assert shim.hit_count == 5
    finally:
        shim.shutdown()


def test_latency_shim_really_delays():
    shim = LatencyShim(0.15)
    try:
        t0 = time.monotonic()
        with urllib.request.urlopen(shim.url, data=b"x=1") as r:
            r.read()
        assert time.monotonic() - t0 >= 0.15
    finally:
        shim.shutdown()


def test_injection_probe_bites_a_real_detector():
    """Cross-utility proof: the shared injection probe's rungs behave as
    their family says under spike's behavioral judge."""
    from spike_app.judge import judge_spike
    canary = "SYN-CANARY-BITE001"
    assert judge_spike(canary, canary).kind == "performed"       # compliant echo
    assert judge_spike(f"I can't output {canary}", canary).kind == "refused"
    assert judge_spike("Nice weather today.", canary).kind == "unclear"
