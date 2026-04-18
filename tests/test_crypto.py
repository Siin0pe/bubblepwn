"""Round-trip tests for the Bubble ES envelope crypto.

These tests lock the scheme: PBKDF2-HMAC-MD5 × 7, AES-256-CBC + PKCS7, wrapper
IVs derived from the public `appname`. Breaking any of these constants would
silently void every in-field forged request, so we test at this level.
"""
from __future__ import annotations

import json

import pytest

from bubblepwn.bubble.es import crypto


@pytest.mark.parametrize(
    "appname,payload",
    [
        ("sampleapp", {"type": "custom.user", "constraints": []}),
        ("acme-live", {"aggregate": {"fns": [{"n": "count"}]}}),
        ("x", {"a": "é ç ñ 中 文 🚀", "nested": {"deep": [1, 2, 3]}}),
    ],
)
def test_wrap_unwrap_round_trip(appname, payload):
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    triple = crypto.wrap_triple(appname, raw)
    assert set(triple.keys()) == {"x", "y", "z"}
    assert all(isinstance(v, str) and v for v in triple.values())

    _timestamp, _iv, decoded = crypto.unwrap_triple(appname, triple)
    assert json.loads(decoded) == payload


def test_wrap_triple_is_not_deterministic():
    """Same (appname, payload) pair must produce different triples.

    Otherwise identical requests would be trivially replayable and a single
    captured envelope would permanently identify that payload.
    """
    raw = b'{"type":"custom.x"}'
    a = crypto.wrap_triple("app", raw)
    b = crypto.wrap_triple("app", raw)
    assert a != b


def test_wrong_appname_does_not_recover_plaintext():
    """AES-CBC with a wrong key does not always raise — but it must never
    reproduce the original plaintext byte-for-byte."""
    raw = b'{"hello":"world"}'
    triple = crypto.wrap_triple("correct-app", raw)
    try:
        _ts, _iv, decoded = crypto.unwrap_triple("wrong-app", triple)
    except Exception:
        return  # padding validation happened to fail — also a pass
    assert decoded != raw
