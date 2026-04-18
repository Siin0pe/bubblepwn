"""Passive PyPI update check — prints a banner when a newer release exists.

Explicitly designed to never disrupt the CLI:

- 1.5 s timeout on the PyPI request
- Result cached for 24 h in ``~/.cache/bubblepwn/version_check.json``
  (respects ``XDG_CACHE_HOME``)
- Silent on every failure mode: no network, PyPI rate-limit, malformed
  JSON, cache-dir unwritable, version string unparseable
- Skipped entirely if ``stdout`` is not a TTY or if
  ``BUBBLEPWN_NO_UPDATE_CHECK=1`` is set in the environment (useful for
  CI / scripting)
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from bubblepwn import __version__

_PYPI_URL = "https://pypi.org/pypi/bubblepwn/json"
_CACHE_TTL = timedelta(hours=24)
_HTTP_TIMEOUT_S = 1.5


def _cache_path() -> Path:
    root = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(root) / "bubblepwn" / "version_check.json"


def _load_cache() -> Optional[dict]:
    path = _cache_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        checked = datetime.fromisoformat(data["checked_at"])
    except (json.JSONDecodeError, KeyError, ValueError, OSError):
        return None
    # Treat naive timestamps (missing tzinfo) as UTC — keeps old caches usable.
    if checked.tzinfo is None:
        checked = checked.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - checked > _CACHE_TTL:
        return None
    return data


def _save_cache(latest: str) -> None:
    path = _cache_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "latest_version": latest,
            }),
            encoding="utf-8",
        )
    except OSError:
        # Cache is best-effort — never crash on I/O issues (read-only FS,
        # permission errors, full disk…).
        pass


def _fetch_pypi_latest() -> Optional[str]:
    try:
        req = urllib.request.Request(
            _PYPI_URL,
            headers={"User-Agent": f"bubblepwn/{__version__}"},
        )
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_S) as resp:
            if resp.status != 200:
                return None
            payload = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError, OSError,
            TimeoutError, UnicodeDecodeError):
        return None
    info = payload.get("info") if isinstance(payload, dict) else None
    if not isinstance(info, dict):
        return None
    version = info.get("version")
    return version if isinstance(version, str) else None


def is_newer(candidate: str, current: str) -> bool:
    """Naive tuple-based version comparison.

    Strips non-numeric components so ``0.2.11.dev1`` still parses. Returns
    ``False`` on anything it can't interpret — unknown formats should
    never trigger a spurious "upgrade available" banner.
    """
    def _parts(v: str) -> tuple[int, ...]:
        out: list[int] = []
        for chunk in v.split("."):
            digits = ""
            for ch in chunk:
                if ch.isdigit():
                    digits += ch
                else:
                    break
            if not digits:
                break
            out.append(int(digits))
        return tuple(out)

    try:
        c, current_t = _parts(candidate), _parts(current)
    except (ValueError, AttributeError):
        return False
    if not c or not current_t:
        return False
    return c > current_t


def check_for_update() -> Optional[str]:
    """Return the latest version string if PyPI has something newer.

    Consults cache first; on miss, queries PyPI and saves the result.
    Any failure path returns ``None`` silently.
    """
    if os.environ.get("BUBBLEPWN_NO_UPDATE_CHECK"):
        return None
    cached = _load_cache()
    latest: Optional[str]
    if cached:
        latest = cached.get("latest_version")
    else:
        latest = _fetch_pypi_latest()
        if latest:
            _save_cache(latest)
    if not latest:
        return None
    return latest if is_newer(latest, __version__) else None


def print_update_banner_if_any() -> None:
    """Hook from the CLI root — renders the banner at most once per run."""
    if not sys.stdout.isatty():
        return
    try:
        newer = check_for_update()
    except Exception:
        # Defensive: even an unexpected error in the check must not break
        # the user's actual command.
        return
    if not newer:
        return
    try:
        from bubblepwn.ui import console
        console.print(
            f"[yellow]→[/] bubblepwn [bold]{newer}[/] available "
            f"(you have {__version__}). "
            f"[dim]pipx upgrade bubblepwn  ·  pip install -U bubblepwn  ·  "
            f"silence with BUBBLEPWN_NO_UPDATE_CHECK=1[/]"
        )
    except Exception:
        pass
