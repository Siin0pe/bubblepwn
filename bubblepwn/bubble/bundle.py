"""Bundle downloader with on-disk cache.

Bundle URLs are content-addressed (the SHA-256 is in the URL path), so using
the URL as cache key is safe: same URL → same content forever.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Optional

from bubblepwn.http import client

_DEFAULT_CACHE = Path.home() / ".cache" / "bubblepwn" / "bundles"


def cache_dir() -> Path:
    override = os.environ.get("BUBBLEPWN_CACHE_DIR")
    base = Path(override) if override else _DEFAULT_CACHE
    base.mkdir(parents=True, exist_ok=True)
    return base


def _key(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def cache_path(url: str) -> Path:
    return cache_dir() / _key(url)


def cached_read(url: str) -> Optional[bytes]:
    p = cache_path(url)
    return p.read_bytes() if p.exists() else None


async def fetch_bundle(
    url: str,
    *,
    cookies: Optional[dict[str, str]] = None,
    force: bool = False,
) -> bytes:
    """Return bundle bytes, using cache when possible."""
    p = cache_path(url)
    if not force and p.exists():
        return p.read_bytes()
    async with client(cookies=cookies) as c:
        resp = await c.get(url)
        resp.raise_for_status()
        data = resp.content
    p.write_bytes(data)
    return data


async def fetch_bundle_text(
    url: str,
    *,
    cookies: Optional[dict[str, str]] = None,
    force: bool = False,
) -> str:
    data = await fetch_bundle(url, cookies=cookies, force=force)
    return data.decode("utf-8", errors="ignore")


def load_local(url_like_path: str) -> Optional[str]:
    """Load a bundle directly from a local file path (used for testing)."""
    p = Path(url_like_path)
    return p.read_text(encoding="utf-8", errors="ignore") if p.exists() else None
