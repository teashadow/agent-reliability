"""Bite-tests for notary — the signed-authorization gate for irreversible mutations.

The несущая distinction here: rc=1 (checked, and the answer is NO) vs rc=2
(the check itself did not happen). rc=2 is the dangerous one — it looks like
rc=1. Both are refusals, but only rc=1 is a decision; the suite pins that
boundary, plus the honesty contract (to_dict carries not_proven).
"""

from __future__ import annotations

import pathlib
import sys
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "notary"))

from notary_app import gate  # noqa: E402

NOW = 1_800_000_000.0
SCOPE = ["delete_world", "publish_post"]


@pytest.fixture
def key_file(tmp_path, monkeypatch):
    key = b"test-key-do-not-use-in-prod-0123456789"
    p = tmp_path / "notary.key"
    p.write_bytes(key)
    monkeypatch.setenv("NOTARY_KEY_FILE", str(p))
    return key


def _request(key, *, action="delete_world", target="world:42",
             scope=None, ts=None, sig=None):
    ts = NOW if ts is None else ts
    scope = SCOPE if scope is None else scope
    s = gate.compute_sig(key, action, target, scope, ts) if sig is None else sig
    return {"action": action, "target": target, "scope": scope, "ts": ts, "sig": s}


def test_valid_request_allows(key_file):
    v = gate.evaluate(_request(key_file), now=NOW)
    assert v.rc == 0 and v.verdict == "ALLOW"


def test_tampered_target_denies(key_file):
    good = _request(key_file)
    good["target"] = "world:999"  # подпись осталась от world:42
    v = gate.evaluate(good, now=NOW)
    assert v.rc == 1 and v.verdict == "DENY"


def test_replay_outside_window_denies(key_file):
    v = gate.evaluate(_request(key_file, ts=NOW - 301), now=NOW)
    assert v.rc == 1 and v.verdict == "DENY"


def test_action_outside_scope_denies(key_file):
    v = gate.evaluate(_request(key_file, action="drop_all"), now=NOW)
    assert v.rc == 1 and v.verdict == "DENY"


def test_missing_field_is_indeterminate(key_file):
    r = _request(key_file)
    del r["scope"]
    v = gate.evaluate(r, now=NOW)
    assert v.rc == 2 and v.verdict == "INDETERMINATE"


def test_no_key_is_indeterminate_not_deny(tmp_path, monkeypatch):
    monkeypatch.delenv("NOTARY_KEY_FILE", raising=False)
    v = gate.evaluate({"action": "a", "target": "t", "scope": "*",
                       "ts": NOW, "sig": "00" * 32}, now=NOW)
    assert v.rc == 2 and v.verdict == "INDETERMINATE"


def test_rc1_and_rc2_stay_distinguishable(key_file):
    deny = gate.evaluate(_request(key_file, action="drop_all"), now=NOW)
    monkeypatch_none = {"action": "a", "target": "t", "scope": SCOPE, "ts": NOW}
    indet = gate.evaluate(monkeypatch_none, now=NOW)  # sig отсутствует → не состоялась
    assert deny.rc == 1 and indet.rc == 2
    assert deny.rc != indet.rc


def test_verdict_carries_not_proven(key_file):
    v = gate.evaluate(_request(key_file), now=NOW)
    d = v.to_dict()
    assert d["not_proven"], "честностный контракт (not_proven) выпал из вердикта"
    assert "НЕ доказывает" in d["not_proven"]
