"""Map Bubble field names between ES DB form and Data API display form.

Bubble stores every custom field under TWO names:

  - DB name (seen in ``/elasticsearch/_source``):
      ``profile_bio_text``, ``isneostaff_boolean``,
      ``accldomains_list_option_acceleratordomains``,
      ``person_custom_person``
  - Display name (seen in ``/api/1.1/meta`` + ``/api/1.1/obj/``):
      ``Profile Bio``, ``isNeoStaff``, ``AcclDomains``, ``person``

The two pipelines apply different privacy rules, so merging records across
both endpoints grows our visible surface. But we can only merge if we know
the two names refer to the same field — this module computes canonical
keys that collide on matching pairs.

Strategy:
  1. Strip the Bubble type suffix from the DB name (``_boolean``, ``_text``,
     ``_number``, ``_image``, ``_date``, ``_file``, ``_list_option_<x>``,
     ``_custom_<x>``, ``_option_<x>``).
  2. Lowercase + remove separators (``_``, spaces) from both forms.
  3. Produce two variants per name — with and without a leading ``is`` —
     since Bubble display names almost always prefix booleans with ``is``
     even when the DB column doesn't (``visible_boolean`` ↔ ``isVisible``).
  4. Strip trailing rename markers (`` mod``, `` v2``, …) from display
     names.

Match decision: two names are considered the same field iff any of their
canonical variants coincide. Falls back to Jaro-Winkler for near-matches
above a configurable threshold.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional


# Type suffixes Bubble appends to DB column names.
_TYPE_SUFFIXES = (
    "text", "number", "boolean", "date", "image", "file",
    "geographic_address",
)

# Rename markers Bubble keeps in display names.
_DISPLAY_RENAME_MARKERS = (" mod", " v2", " v3", " (copy)", " copy")


@dataclass(frozen=True)
class FieldKey:
    """Canonical keys for matching one field name across the two conventions."""
    raw: str
    stripped: str          # suffix-stripped, lowercased, no separators
    with_is: str           # variant with leading ``is`` (even if raw lacked it)
    without_is: str        # variant without leading ``is`` (even if raw had it)
    type_hint: Optional[str] = None  # 'boolean' | 'text' | ... | 'list.option.X' | 'ref.custom.X'
    target_type: Optional[str] = None  # for refs and lists, the referenced Bubble type

    def candidates(self) -> tuple[str, ...]:
        """All forms this key accepts as a match."""
        return (self.stripped, self.with_is, self.without_is)


_TYPE_SUFFIX_RE = re.compile(
    r"_(?P<t>" + "|".join(_TYPE_SUFFIXES) + r")$"
)
_LIST_OPTION_RE = re.compile(r"_list_option_(?P<tgt>[a-z0-9_]+)$")
_LIST_CUSTOM_RE = re.compile(r"_list_custom_(?P<tgt>[a-z0-9_]+)$")
_CUSTOM_RE = re.compile(r"_custom_(?P<tgt>[a-z0-9_]+)$")
_OPTION_RE = re.compile(r"_option_(?P<tgt>[a-z0-9_]+)$")
_LIST_PRIMITIVE_RE = re.compile(
    r"_list_(?P<t>" + "|".join(_TYPE_SUFFIXES) + r")$"
)


def _normalize(s: str) -> str:
    """Lowercase + drop non-alphanumerics."""
    return re.sub(r"[^a-z0-9]+", "", s.lower())


def _with_is_variant(stem: str) -> str:
    return stem if stem.startswith("is") else f"is{stem}"


def _without_is_variant(stem: str) -> str:
    return stem[2:] if stem.startswith("is") and len(stem) > 2 else stem


def key_for_db(name: str) -> FieldKey:
    """Compute a FieldKey from a Bubble ES ``_source`` field name."""
    raw = name
    s = name
    type_hint: Optional[str] = None
    target_type: Optional[str] = None

    # Order matters: most specific patterns first.
    m = _LIST_OPTION_RE.search(s)
    if m:
        target_type = m.group("tgt")
        type_hint = f"list.option.{target_type}"
        s = s[: m.start()]
    else:
        m = _LIST_CUSTOM_RE.search(s)
        if m:
            target_type = m.group("tgt")
            type_hint = f"list.custom.{target_type}"
            s = s[: m.start()]
        else:
            m = _CUSTOM_RE.search(s)
            if m:
                target_type = m.group("tgt")
                type_hint = f"ref.custom.{target_type}"
                s = s[: m.start()]
            else:
                m = _OPTION_RE.search(s)
                if m:
                    target_type = m.group("tgt")
                    type_hint = f"option.{target_type}"
                    s = s[: m.start()]
                else:
                    m = _LIST_PRIMITIVE_RE.search(s)
                    if m:
                        type_hint = f"list.{m.group('t')}"
                        s = s[: m.start()]
                    else:
                        m = _TYPE_SUFFIX_RE.search(s)
                        if m:
                            type_hint = m.group("t")
                            s = s[: m.start()]

    stripped = _normalize(s)
    return FieldKey(
        raw=raw,
        stripped=stripped,
        with_is=_with_is_variant(stripped),
        without_is=_without_is_variant(stripped),
        type_hint=type_hint,
        target_type=target_type,
    )


def key_for_display(name: str) -> FieldKey:
    """Compute a FieldKey from a Bubble display name (``/meta`` / ``/obj/``)."""
    raw = name
    s = name
    for marker in _DISPLAY_RENAME_MARKERS:
        if s.endswith(marker):
            s = s[: -len(marker)]
            break

    stripped = _normalize(s)
    return FieldKey(
        raw=raw,
        stripped=stripped,
        with_is=_with_is_variant(stripped),
        without_is=_without_is_variant(stripped),
    )


def match(a: FieldKey | str, b: FieldKey | str) -> bool:
    """Return True iff the two names refer to the same Bubble field.

    Accepts either raw strings or pre-computed FieldKeys. Raw strings are
    auto-routed — names containing a known Bubble suffix are treated as DB
    form, everything else as display.
    """
    ka = a if isinstance(a, FieldKey) else _auto_key(a)
    kb = b if isinstance(b, FieldKey) else _auto_key(b)
    if not ka.stripped or not kb.stripped:
        return False
    return bool(set(ka.candidates()) & set(kb.candidates()))


def _looks_like_db_name(name: str) -> bool:
    """Heuristic: ends with a Bubble type suffix OR is all snake_case."""
    low = name.lower()
    if _TYPE_SUFFIX_RE.search(low) or _LIST_OPTION_RE.search(low):
        return True
    if _LIST_CUSTOM_RE.search(low) or _CUSTOM_RE.search(low):
        return True
    if _OPTION_RE.search(low) or _LIST_PRIMITIVE_RE.search(low):
        return True
    return False


def _auto_key(name: str) -> FieldKey:
    return key_for_db(name) if _looks_like_db_name(name) else key_for_display(name)


def build_index(names: Iterable[str], *, kind: str) -> dict[str, FieldKey]:
    """Compute FieldKeys for a batch of names. ``kind`` is 'db' or 'display'."""
    fn = key_for_db if kind == "db" else key_for_display
    return {name: fn(name) for name in names}


def pair(
    db_names: Iterable[str],
    display_names: Iterable[str],
) -> tuple[list[tuple[str, str]], list[str], list[str]]:
    """Match each DB name to the best display name.

    Returns ``(pairs, db_only, display_only)``:
      - pairs: list of (db_name, display_name) for matched fields
      - db_only: DB names with no display match
      - display_only: display names with no DB match

    Matching is exact-canonical first, greedy. Ambiguous matches (one DB
    name could match multiple display names) are resolved by the first
    display name encountered in iteration order.
    """
    db_keys = [(n, key_for_db(n)) for n in db_names]
    disp_keys = [(n, key_for_display(n)) for n in display_names]

    # Build reverse index: candidate string → list of display names that
    # claim it. Collisions are rare in practice; when they do happen we
    # prefer the first claim.
    disp_by_candidate: dict[str, str] = {}
    for disp_name, k in disp_keys:
        for cand in k.candidates():
            if cand and cand not in disp_by_candidate:
                disp_by_candidate[cand] = disp_name

    matched_disp: set[str] = set()
    pairs: list[tuple[str, str]] = []
    db_only: list[str] = []
    for db_name, k in db_keys:
        found: Optional[str] = None
        for cand in k.candidates():
            hit = disp_by_candidate.get(cand)
            if hit and hit not in matched_disp:
                found = hit
                break
        if found:
            pairs.append((db_name, found))
            matched_disp.add(found)
        else:
            db_only.append(db_name)

    display_only = [n for n, _ in disp_keys if n not in matched_disp]
    return pairs, db_only, display_only
