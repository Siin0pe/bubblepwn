"""Regression tests for the flow preset chains in ``shell._FLOW_PRESETS``.

``audit`` and ``exploit`` used to start directly at their namesake modules
(``config-audit``, ``es-audit analyze``). Run standalone that meant:

  - ``plugin-audit`` bailed with "No plugins in schema. Run `plugins` first"
  - ``es-audit analyze`` bailed with "Cannot determine appname. Run
    `fingerprint` first"

These tests lock the fix: the presets now self-contain their prereqs, and
``full = recon + audit + exploit`` drops the resulting duplicates instead of
re-running fingerprint three times.
"""
from __future__ import annotations

from bubblepwn.shell import _FLOW_PRESETS, _dedupe_steps


def _module_sequence(preset: str) -> list[str]:
    return [mod for mod, _args in _FLOW_PRESETS[preset]]


def test_audit_preset_runs_fingerprint_and_plugins_before_plugin_audit():
    seq = _module_sequence("audit")
    fp = seq.index("fingerprint")
    plugins = seq.index("plugins")
    plugin_audit = seq.index("plugin-audit")
    assert fp < plugin_audit, "fingerprint must precede plugin-audit"
    assert plugins < plugin_audit, "plugins must precede plugin-audit"


def test_exploit_preset_runs_fingerprint_before_es_audit():
    seq = _module_sequence("exploit")
    fp = seq.index("fingerprint")
    es = seq.index("es-audit")
    assert fp < es, "fingerprint must precede es-audit"
    assert "datatypes" in seq, "es-audit analyze needs the type list from datatypes"


def test_full_preset_does_not_duplicate_steps():
    # full = recon + audit + exploit. Each of those now carries fingerprint,
    # so a naive concat would run it 3×. _dedupe_steps keeps first-seen order.
    steps = _FLOW_PRESETS["full"]
    assert len(steps) == len(set((mod, tuple(args)) for mod, args in steps))


def test_full_preset_starts_with_fingerprint():
    # Dedup must preserve order — fingerprint comes from recon, which is first.
    assert _FLOW_PRESETS["full"][0][0] == "fingerprint"


def test_dedupe_preserves_first_occurrence_order():
    steps = [
        ("fingerprint", []),
        ("plugins", []),
        ("fingerprint", []),          # dup — should drop
        ("es-audit", ["analyze"]),
        ("es-audit", ["analyze"]),    # exact dup — should drop
        ("es-audit", ["probe"]),      # different args — should keep
    ]
    assert _dedupe_steps(steps) == [
        ("fingerprint", []),
        ("plugins", []),
        ("es-audit", ["analyze"]),
        ("es-audit", ["probe"]),
    ]
