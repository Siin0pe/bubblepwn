"""Extract Bubble app data from a `static.js` bundle.

The static.js bundle is page-specific (URL path includes the page name) and is
where Bubble ships most of the data: custom types, fields, element names,
hard-coded first-party plugins, and the watcher-cache describing the current page.
"""
from __future__ import annotations

import json
import re

BUBBLE_FIELD_TYPES = (
    "text",
    "number",
    "boolean",
    "date",
    "image",
    "file",
    "option",
    "list",
    "geographic_address",
    "user",
)

_RE_CUSTOM_TYPE = re.compile(r"\bcustom\.[a-z_][a-z_0-9]*")
_RE_FIELD = re.compile(
    rf"([a-z_][a-z_0-9]*?)___(?P<type>{'|'.join(BUBBLE_FIELD_TYPES)})(?![a-z_])"
)
_RE_HARDCODED_PLUGIN = re.compile(r"hardcoded_plugins\['([^']+)'\]")
_RE_WATCHER_PAGE_ID = re.compile(r'"([a-zA-Z0-9]{3,10})":\{"statics":\{"title":true')
_RE_WATCHER_PROPS_TITLE = re.compile(r'"props":\{"title":"([^"]+)"')
_RE_NAMED_BLOCK = re.compile(r'"name":"([a-zA-Z_][a-zA-Z0-9_ .\-]{1,80})"')

# DefaultValues entries in bubble_run_derived are the closest the bundle
# gets to a field catalogue. Each entry looks like:
#   {"name":"<raw_db_column>","value":"<bubble_type>","display":"<label>","deleted":null}
# The raw name is the DB column (encoded with the type as a suffix).
# The value is the canonical type (text, number, boolean, date, list.text,
# custom.<type>, list.custom.<type>, option.<set>, ...).
# The display is the editor-facing human label.
_RE_DEFAULT_VALUES_ENTRY = re.compile(
    r'\{\s*"name"\s*:\s*"([^"]+)"\s*,\s*'
    r'"value"\s*:\s*"([^"]+)"\s*,\s*'
    r'"display"\s*:\s*"([^"]*)"\s*'
    r'(?:,\s*"deleted"\s*:\s*(?:null|true|false))?\s*\}',
    re.DOTALL,
)

# Human-readable element type detection — Bubble ships properties on elements
# that strongly correlate with the element kind.
_ELEMENT_TYPE_HINTS = {
    "Button": ("button_text",),
    "Text": ("text", "rich_text"),
    "Input": ("placeholder", "initial_content", "input_type"),
    "Group": ("is_container",),
    "RepeatingGroup": ("data_source", "is_repeating_group"),
    "Image": ("image_url", "image_dynamic"),
    "Icon": ("icon",),
    "Popup": ("is_popup",),
    "FloatingGroup": ("floating_group_anchor",),
    "Shape": ("shape_type",),
    "Checkbox": ("default_checked",),
    "Dropdown": ("choices_source",),
    "SearchBox": ("search_box_placeholder",),
    "Link": ("destination_page",),
    "FileUploader": ("file_upload",),
    "DateTimePicker": ("date_picker", "use_calendar"),
    "Map": ("map_type", "center"),
    "HTML": ("html_content",),
}


def parse_custom_types(content: str) -> list[str]:
    """Return sorted unique `custom.<name>` strings present in the bundle."""
    return sorted(set(_RE_CUSTOM_TYPE.findall(content)))


def parse_fields(content: str) -> list[tuple[str, str]]:
    """Return sorted unique (field_name, field_type) tuples."""
    seen: set[tuple[str, str]] = set()
    for m in _RE_FIELD.finditer(content):
        seen.add((m.group(1), m.group("type")))
    return sorted(seen)


def parse_field_triples(content: str) -> list[dict[str, str]]:
    """Extract (name, value, display) triples from ``DefaultValues``.

    Flat fallback view — returns the full set of field triples regardless of
    their owning type. Preferred for a global catalogue summary.

    ``name``    — the raw DB column name (e.g. ``email___text``,
                  ``client_cr_ateur_custom_clients_base``). This encodes
                  the field type as a suffix.
    ``value``   — the canonical Bubble type (``text``, ``number``,
                  ``boolean``, ``date``, ``image``, ``file``,
                  ``option.<set>``, ``custom.<type>``, ``list.<anything>``).
    ``display`` — the editor-facing human label.

    For the ownership-aware view, see :func:`parse_default_values_by_type`.
    """
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for m in _RE_DEFAULT_VALUES_ENTRY.finditer(content):
        name = m.group(1)
        if name in seen:
            continue
        seen.add(name)
        out.append({
            "name": name,
            "value": m.group(2),
            "display": m.group(3),
        })
    return out


# Matches the RHS of ``... "function_name":"DefaultValues","args":[]}'] = <OBJ>``.
_RE_DEFAULT_VALUES_ASSIGN = re.compile(
    r'"DefaultValues"\s*,\s*"args"\s*:\s*\[\s*\]\s*\}\'\s*\]\s*=\s*(\{)',
    re.DOTALL,
)


def _extract_balanced_json_object(content: str, start: int) -> str | None:
    """Return the balanced JSON object starting at ``content[start] == '{'``.

    Scans character-by-character respecting string literals + escapes so it
    does not get fooled by braces inside quoted values. Returns ``None`` if
    the file ends before the object closes.
    """
    if start >= len(content) or content[start] != "{":
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(content)):
        ch = content[i]
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return content[start:i + 1]
    return None


def parse_default_values_by_type(content: str) -> dict[str, list[dict[str, str]]]:
    """Ownership-aware view of the Bubble ``DefaultValues`` catalogue.

    Bubble's bundle ships an object of the shape::

        {
          "action":          [{ name, value, display, deleted }, …],
          "<type_name>":     [{ name, value, display, deleted }, …],
          "_am_atelier":     [ … ],
          "clients_base":    [ … ],
          "user":            [ … ],
          ...
        }

    Keys other than ``"action"`` are custom type names — so every list here
    is the **exact field set of that owning type**. This is the only place
    in ``static.js`` that encodes the ``type → fields`` mapping we care
    about.

    Returns ``{type_name: [field_entries]}`` with ``deleted`` entries
    filtered out. Returns an empty dict on any parse failure (bundle
    truncated, JSON malformed, DefaultValues block absent).
    """
    m = _RE_DEFAULT_VALUES_ASSIGN.search(content)
    if not m:
        return {}
    raw = _extract_balanced_json_object(content, m.end() - 1)
    if raw is None:
        return {}
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(obj, dict):
        return {}

    out: dict[str, list[dict[str, str]]] = {}
    for type_name, entries in obj.items():
        if not isinstance(entries, list):
            continue
        kept: list[dict[str, str]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if entry.get("deleted") is True:
                continue
            name = entry.get("name")
            value = entry.get("value")
            if not isinstance(name, str) or not isinstance(value, str):
                continue
            display = entry.get("display")
            kept.append({
                "name": name,
                "value": value,
                "display": display if isinstance(display, str) else "",
            })
        if kept:
            out[type_name] = kept
    return out


def parse_hardcoded_plugins(content: str) -> list[str]:
    return sorted(set(_RE_HARDCODED_PLUGIN.findall(content)))


def parse_page_entries(content: str) -> list[dict[str, str]]:
    """Parse the `_bubble_watcher_cache` blob — entries with id + title.

    In practice `static.js` only lists the page it was compiled for, so this
    usually returns one entry. Multi-page discovery happens at module level by
    re-fetching other pages.
    """
    results: list[dict[str, str]] = []
    for m in _RE_WATCHER_PAGE_ID.finditer(content):
        tm = _RE_WATCHER_PROPS_TITLE.search(content, m.end(), m.end() + 4000)
        results.append({"id": m.group(1), "title": tm.group(1) if tm else ""})
    return results


def parse_named_blocks(content: str) -> list[str]:
    """All `"name":"…"` occurrences. Broad; callers filter as needed."""
    return sorted(set(_RE_NAMED_BLOCK.findall(content)))


def infer_element_type(block: str) -> str | None:
    """Given a snippet of JSON around an element, guess its Bubble type."""
    for kind, hints in _ELEMENT_TYPE_HINTS.items():
        if any(f'"{h}"' in block for h in hints):
            return kind
    return None
