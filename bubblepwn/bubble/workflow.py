"""Shared helpers to fetch + parse a Bubble page with its bundles.

Respects the env var ``BUBBLEPWN_LOCAL_DUMP`` to short-circuit HTTP with a
local mirror (used for testing against a cached `site_dump/<host>/` tree).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional
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
    progress_cb: Optional[Callable[[str], None]] = None,
) -> PageSnapshot:
    """Fetch page HTML + static.js + dynamic.js (with cache).

    ``progress_cb`` is called with a short human-readable string before each
    network stage (``HTML``, ``static.js``, ``dynamic.js``) and once per
    stage with the payload size after it completes (e.g. ``static.js · 1.2 MB``).
    Callers running a spinner can wire this to ``status.update(...)`` so the
    user never sits in front of a frozen line while a 3 MB bundle downloads.
    """
    if ctx.target is None:
        raise RuntimeError("no target set")
    cookies = ctx.session.cookies if ctx.session else None
    base = ctx.target.url

    def _emit(msg: str) -> None:
        if progress_cb is not None:
            try:
                progress_cb(msg)
            except Exception:
                pass  # feedback is best-effort, never fatal

    _emit("HTML")
    html, status = await _fetch_page_html(base, page, cookies=cookies)
    _emit(f"HTML · {_sizeof(len(html))}")
    urls = html_parse.extract_bundle_urls(html, f"{base}/")
    pname = html_parse.extract_current_page_name(html) or page or "index"

    static_text = ""
    dynamic_text = ""
    if want_static and "static_js" in urls:
        _emit("static.js")
        static_text = await _fetch_text(urls["static_js"], cookies=cookies)
        _emit(f"static.js · {_sizeof(len(static_text))}")
    if want_dynamic and "dynamic_js" in urls:
        _emit("dynamic.js")
        dynamic_text = await _fetch_text(urls["dynamic_js"], cookies=cookies)
        _emit(f"dynamic.js · {_sizeof(len(dynamic_text))}")

    return PageSnapshot(
        page_name=pname,
        url=f"{base}/{page.strip('/')}".rstrip("/") or base,
        status=status,
        html=html,
        bundle_urls=urls,
        static_text=static_text,
        dynamic_text=dynamic_text,
    )


def _sizeof(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"
