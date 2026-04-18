"""Extract Bubble app data from a `dynamic.js` bundle (page+locale specific).

The dynamic bundle holds:
- `application_language` + `translation_data` (locales)
- `preloaded['plugin/…']` + `preloaded['translation/plugin:…']` (ALL plugin IDs)
- `id_to_path` mapping (element id → `%p<page>.<path>…` hierarchy)
- `display_page(app, '<page_name>')` at the end confirms the current page.
"""
from __future__ import annotations

import json
import re
from typing import Optional

_RE_APP_LANG = re.compile(r"window\.application_language\s*=\s*['\"]([^'\"]+)['\"]")
_RE_TRANSLATION_LOCALE = re.compile(r"translation_data\['([a-z_]+)'\]")
_RE_DISPLAY_PAGE = re.compile(r"display_page\s*\(\s*app\s*,\s*['\"]([^'\"]+)['\"]")
_RE_PRELOADED = re.compile(r"preloaded\['([^']+)'\]")
_RE_PLUGIN_ENTRY = re.compile(
    r"(?:translation/plugin|plugin_header|app/plugin):([a-zA-Z0-9_]+)(?::([a-z_]+))?"
)
_RE_ID_TO_PATH_BLOCK = re.compile(r'"id_to_path"\s*:\s*(\{[^{}]*\})')


def parse_application_language(content: str) -> Optional[str]:
    m = _RE_APP_LANG.search(content)
    return m.group(1) if m else None


def parse_translation_locales(content: str) -> list[str]:
    return sorted(set(_RE_TRANSLATION_LOCALE.findall(content)))


def parse_display_page(content: str) -> Optional[str]:
    m = _RE_DISPLAY_PAGE.search(content)
    return m.group(1) if m else None


def parse_preloaded(content: str) -> list[str]:
    return sorted(set(_RE_PRELOADED.findall(content)))


def parse_plugin_entries(content: str) -> dict[str, set[str]]:
    """Return {plugin_id: {locale1, locale2, ...}} from all `preloaded` keys."""
    result: dict[str, set[str]] = {}
    for pre in parse_preloaded(content):
        m = _RE_PLUGIN_ENTRY.search(pre)
        if not m:
            continue
        pid, locale = m.group(1), m.group(2)
        bucket = result.setdefault(pid, set())
        if locale:
            bucket.add(locale)
    return result


def parse_id_to_path(content: str) -> dict[str, str]:
    """Best-effort JSON parse of the `"id_to_path":{...}` block.

    We bracket-match forward from the opening brace instead of using a regex
    because the object is large and the regex would be fragile.
    """
    idx = content.find('"id_to_path"')
    if idx < 0:
        return {}
    brace = content.find("{", idx)
    if brace < 0:
        return {}
    depth = 0
    end = None
    for i in range(brace, min(len(content), brace + 2_000_000)):
        ch = content[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end is None:
        return {}
    blob = content[brace:end]
    try:
        data = json.loads(blob)
        if not isinstance(data, dict):
            return {}
        return {k: v for k, v in data.items() if isinstance(v, str)}
    except json.JSONDecodeError:
        return {}
