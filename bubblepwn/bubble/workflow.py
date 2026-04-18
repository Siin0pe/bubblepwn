"""Shared helpers to fetch + parse a Bubble page with its bundles.

Respects the env var ``BUBBLEPWN_LOCAL_DUMP`` to short-circuit HTTP with a
local mirror (used for testing against a cached `site_dump/<host>/` tree).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from bubblepwn.bubble import bundle as bundle_cache
from bubblepwn.bubble.api import BubbleAPI
from bubblepwn.bubble.parse import html as html_parse
from bubblepwn.context import Context


def _local_dump_root() -> Optional[Path]:
    v = os.environ.get("BUBBLEPWN_LOCAL_DUMP")
    return Path(v) if v else None


def _local_file_for_url(url: str) -> Optional[Path]:
    root = _local_dump_root()
    if root is None:
        return None
    p = urlparse(url)
    root_resolved = root.resolve()
    cand = (root / p.path.lstrip("/")).resolve()
    try:
        cand.relative_to(root_resolved)
    except ValueError:
        # Target URL path escaped the mirror root via `..` — refuse silently
        # and fall through to the live HTTP fetch.
        return None
    if cand.exists() and cand.is_file():
        return cand
    if cand.is_dir():
        idx = cand / "index.html"
        if idx.exists():
            return idx
    return None


async def _fetch_text(url: str, cookies: Optional[dict[str, str]] = None) -> str:
    local = _local_file_for_url(url)
    if local is not None:
        return local.read_text(encoding="utf-8", errors="ignore")
    return await bundle_cache.fetch_bundle_text(url, cookies=cookies)


async def _fetch_page_html(
    base_url: str, page: str = "", cookies: Optional[dict[str, str]] = None
) -> tuple[str, int]:
    """Return (html, status_code). Falls back to local dump if configured."""
    target = f"{base_url.rstrip('/')}/{page.strip('/')}".rstrip("/")
    local = _local_file_for_url(target + "/") or _local_file_for_url(target)
    if local is not None:
        return local.read_text(encoding="utf-8", errors="ignore"), 200
    api = BubbleAPI(base_url, cookies=cookies)
    resp = await api.fetch_page(page)
    return resp.text, resp.status_code


@dataclass
class PageSnapshot:
    page_name: str
    url: str
    status: int
    html: str
    bundle_urls: dict[str, str] = field(default_factory=dict)
    static_text: str = ""
    dynamic_text: str = ""


async def snapshot_page(
    ctx: Context,
    page: str = "",
    *,
    want_static: bool = True,
    want_dynamic: bool = True,
) -> PageSnapshot:
    """Fetch page HTML + static.js + dynamic.js (with cache)."""
    if ctx.target is None:
        raise RuntimeError("no target set")
    cookies = ctx.session.cookies if ctx.session else None
    base = ctx.target.url

    html, status = await _fetch_page_html(base, page, cookies=cookies)
    urls = html_parse.extract_bundle_urls(html, f"{base}/")
    pname = html_parse.extract_current_page_name(html) or page or "index"

    static_text = ""
    dynamic_text = ""
    if want_static and "static_js" in urls:
        static_text = await _fetch_text(urls["static_js"], cookies=cookies)
    if want_dynamic and "dynamic_js" in urls:
        dynamic_text = await _fetch_text(urls["dynamic_js"], cookies=cookies)

    return PageSnapshot(
        page_name=pname,
        url=f"{base}/{page.strip('/')}".rstrip("/") or base,
        status=status,
        html=html,
        bundle_urls=urls,
        static_text=static_text,
        dynamic_text=dynamic_text,
    )
