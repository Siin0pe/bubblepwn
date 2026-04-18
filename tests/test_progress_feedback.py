"""Regression tests for the progress-feedback pass.

These don't test the rendering (Rich) — just the contracts we introduced so
future refactors don't silently regress back to silent-long-operations.
"""
from __future__ import annotations

import inspect

import pytest

from bubblepwn.bubble import workflow as wf


# ── snapshot_page progress_cb contract ────────────────────────────────────

def test_snapshot_page_exposes_progress_cb_kwarg():
    sig = inspect.signature(wf.snapshot_page)
    assert "progress_cb" in sig.parameters
    param = sig.parameters["progress_cb"]
    assert param.default is None
    assert param.kind == inspect.Parameter.KEYWORD_ONLY


# ── _sizeof human-readable formatter ──────────────────────────────────────

@pytest.mark.parametrize(
    "n,expected",
    [
        (0,               "0 B"),
        (512,             "512 B"),
        (1024,            "1.0 KB"),
        (1536,            "1.5 KB"),
        (1024 * 1024,     "1.0 MB"),
        (3_500_000,       "3.3 MB"),
    ],
)
def test_sizeof_human_readable(n, expected):
    assert wf._sizeof(n) == expected


# ── _safe_path_segment unaffected by progress changes ─────────────────────

def test_dumpone_still_protects_against_traversal():
    # Keep this regression alive — progress-feedback refactors should never
    # weaken the SEC-1 sanitiser.
    from bubblepwn.modules.es_audit import _safe_path_segment
    with pytest.raises(ValueError):
        _safe_path_segment("../../etc/passwd")


# ── update_cb contract on nested HTTP loops ───────────────────────────────

def test_extract_params_exposes_update_cb_kwarg():
    """Regression guard for the workflows --analyze / --fuzz silent gap.

    Without ``update_cb``, up to 20 silent POSTs per workflow happened
    inside a single outer bar tick — looked frozen.
    """
    from bubblepwn.modules.workflows import Workflows
    sig = inspect.signature(Workflows._extract_params)
    assert "update_cb" in sig.parameters
    assert sig.parameters["update_cb"].default is None
    assert sig.parameters["update_cb"].kind == inspect.Parameter.KEYWORD_ONLY


def test_enumerate_type_exposes_update_cb_kwarg():
    """Regression guard for the api-probe --enumerate silent gap.

    Without ``update_cb``, the pagination loop (up to 10 GETs per type)
    held the outer progress bar at the same tick — looked stuck.
    """
    from bubblepwn.modules.api_probe import ApiProbe
    sig = inspect.signature(ApiProbe._enumerate_type)
    assert "update_cb" in sig.parameters
    assert sig.parameters["update_cb"].default is None
    assert sig.parameters["update_cb"].kind == inspect.Parameter.KEYWORD_ONLY
