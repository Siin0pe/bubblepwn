"""Parse a Bubble app's landing HTML to extract bundle URLs and globals."""
from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urljoin

_RE_SCRIPT_SRC = re.compile(r"""<script[^>]+src=['"]([^'"]+)""", re.I)
_RE_LINK_HREF = re.compile(r"""<link[^>]+href=['"]([^'"]+)""", re.I)
_RE_PAGE_NAME = re.compile(r"""window\.bubble_page_name\s*=\s*['"]([^'"]+)['"]""")
_RE_HEADERS_SRC = re.compile(r"plugin_main_headers_(\d+x\d+)")

BUNDLE_KINDS = ("early_js", "pre_run_jquery_js", "static_js", "dynamic_js", "run_js")


def extract_bundle_urls(html: str, base_url: str) -> dict[str, str]:
    """Return {kind: absolute_url} for the current page's bundles."""
    out: dict[str, str] = {}
    for src in _RE_SCRIPT_SRC.findall(html):
        for kind in BUNDLE_KINDS:
            if f"/package/{kind}/" in src:
                out[kind] = urljoin(base_url, _normalize(src))
                break
    for href in _RE_LINK_HREF.findall(html):
        if "/package/run_css/" in href:
            out["run_css"] = urljoin(base_url, _normalize(href))
    return out


def _normalize(url: str) -> str:
    if url.startswith("//"):
        return "https:" + url
    return url


def extract_current_page_name(html: str) -> Optional[str]:
    m = _RE_PAGE_NAME.search(html)
    return m.group(1) if m else None


def extract_plugin_header_ids(html: str) -> list[str]:
    return sorted(set(_RE_HEADERS_SRC.findall(html)))
