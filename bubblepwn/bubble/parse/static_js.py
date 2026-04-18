"""Extract Bubble app data from a `static.js` bundle.

The static.js bundle is page-specific (URL path includes the page name) and is
where Bubble ships most of the data: custom types, fields, element names,
hard-coded first-party plugins, and the watcher-cache describing the current page.
"""
from __future__ import annotations

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
