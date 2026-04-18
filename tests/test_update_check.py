"""Unit tests for the passive PyPI update check."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from bubblepwn import update_check
from bubblepwn.update_check import (
    check_for_update,
    is_newer,
    print_update_banner_if_any,
)


# ── is_newer ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "candidate,current,expected",
    [
        ("0.2.12", "0.2.11", True),
        ("0.3.0",  "0.2.99", True),
        ("1.0.0",  "0.99.99", True),
        ("0.2.11", "0.2.11", False),  # same version
        ("0.2.10", "0.2.11", False),  # older
        ("0.2.9",  "0.2.10", False),  # numeric ordering (9 < 10)
    ],
)
def test_is_newer(candidate, current, expected):
    assert is_newer(candidate, current) is expected


def test_is_newer_handles_prerelease_tail():
    # Our naive parser strips non-digit suffixes — ``0.2.11.dev1`` behaves
    # like ``0.2.11``.
    assert is_newer("0.2.12.dev0", "0.2.11") is True
    assert is_newer("0.2.11.dev0", "0.2.11") is False


def test_is_newer_rejects_garbage_without_raising():
    assert is_newer("not-a-version", "0.2.11") is False
    assert is_newer("0.2.11", "") is False
    assert is_newer("", "0.2.11") is False


# ── cache round-trip ──────────────────────────────────────────────────────

def test_cache_is_written_and_reused(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.setattr(update_check, "__version__", "0.2.11")
    calls: list[int] = []

    def fake_fetch():
        calls.append(1)
        return "0.2.12"

    monkeypatch.setattr(update_check, "_fetch_pypi_latest", fake_fetch)

    # First call: hits PyPI + writes cache, returns newer version.
    assert check_for_update() == "0.2.12"
    assert len(calls) == 1
    cache_file = tmp_path / "bubblepwn" / "version_check.json"
    assert cache_file.exists()

    # Second call: reads cache, no network hit.
    assert check_for_update() == "0.2.12"
    assert len(calls) == 1


def test_stale_cache_triggers_refetch(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.setattr(update_check, "__version__", "0.2.11")
    cache_file = tmp_path / "bubblepwn" / "version_check.json"
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    stale_ts = datetime.now(timezone.utc) - timedelta(days=3)
    cache_file.write_text(
        json.dumps({"checked_at": stale_ts.isoformat(),
                    "latest_version": "0.1.0"}),
        encoding="utf-8",
    )

    called: list[int] = []

    def fake_fetch():
        called.append(1)
        return "0.2.12"

    monkeypatch.setattr(update_check, "_fetch_pypi_latest", fake_fetch)
    assert check_for_update() == "0.2.12"
    assert called == [1]


def test_corrupt_cache_is_ignored(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.setattr(update_check, "__version__", "0.2.11")
    cache_file = tmp_path / "bubblepwn" / "version_check.json"
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text("{not json at all", encoding="utf-8")

    monkeypatch.setattr(update_check, "_fetch_pypi_latest", lambda: "0.2.12")
    # Must not raise and must end up falling through to the fetcher.
    assert check_for_update() == "0.2.12"


# ── env var guard ────────────────────────────────────────────────────────

def test_env_var_disables_check(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.setenv("BUBBLEPWN_NO_UPDATE_CHECK", "1")

    def boom():
        raise AssertionError("fetcher must not run when env var is set")

    monkeypatch.setattr(update_check, "_fetch_pypi_latest", boom)
    assert check_for_update() is None


def test_returns_none_when_current_is_latest(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.setattr(update_check, "__version__", "0.2.12")
    monkeypatch.setattr(update_check, "_fetch_pypi_latest", lambda: "0.2.12")
    assert check_for_update() is None


def test_returns_none_when_fetch_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.setattr(update_check, "_fetch_pypi_latest", lambda: None)
    assert check_for_update() is None


# ── print_update_banner_if_any ───────────────────────────────────────────

def test_banner_noop_when_not_tty(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdout.isatty", lambda: False)

    def boom():
        raise AssertionError("check must not run when stdout is not a TTY")

    monkeypatch.setattr(update_check, "check_for_update", boom)
    print_update_banner_if_any()
    assert capsys.readouterr().out == ""


def test_banner_silent_when_check_raises(monkeypatch):
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)

    def boom():
        raise RuntimeError("simulated")

    monkeypatch.setattr(update_check, "check_for_update", boom)
    # Must not raise — even if check_for_update blows up, the CLI keeps going.
    print_update_banner_if_any()
