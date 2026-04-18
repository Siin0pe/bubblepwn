"""Plugin metadata catalogue + live marketplace enrichment.

Two sources of truth, merged into the ``BubblePlugin`` model:

1. **Static catalogue** — hand-curated mapping for first-party Bubble bundles
   whose IDs are stable, readable slugs (``chartjs``, ``stripe``, ``select2``…).
   Applied offline on every run (no HTTP).

2. **Live marketplace lookup** — for third-party plugins whose IDs are opaque
   timestamp strings (``1497473108162x748064…``), fetch
   ``https://bubble.io/plugin/<id>`` and parse the Open Graph meta tags.
   Opt-in via ``run plugins --enrich`` so a routine ``fingerprint`` run
   never reaches bubble.io on its own.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Optional

from bubblepwn.bubble.schema import BubblePlugin


# ── 1. Static first-party catalogue ───────────────────────────────────────

#: Slug → metadata. Keys match the ``id`` we see in bundles / headers for
#: first-party plugins. Only fields we can set with high confidence live here;
#: the live lookup can fill in the rest for marketplace plugins.
FIRST_PARTY_CATALOG: dict[str, dict[str, str]] = {
    "ionic": {
        "display_name": "Ionicons",
        "vendor": "Ionic",
        "docs_url": "https://ionic.io/ionicons",
    },
    "chartjs": {
        "display_name": "Chart.js",
        "vendor": "Chart.js contributors",
        "docs_url": "https://www.chartjs.org/",
    },
    "select2": {
        "display_name": "Select2",
        "vendor": "Select2",
        "docs_url": "https://select2.org/",
    },
    "selectPDF": {
        "display_name": "SelectPdf",
        "vendor": "SelectPdf",
        "docs_url": "https://selectpdf.com/",
    },
    "draggableui": {
        "display_name": "Draggable UI",
        "vendor": "Bubble",
        "docs_url": "https://manual.bubble.io/",
    },
    "progressbar": {
        "display_name": "Progress Bar",
        "vendor": "Bubble",
        "docs_url": "https://manual.bubble.io/",
    },
    "apiconnector2": {
        "display_name": "API Connector",
        "vendor": "Bubble",
        "docs_url": (
            "https://manual.bubble.io/core-resources/api/the-api-connector"
        ),
    },
    "fullcalendar": {
        "display_name": "FullCalendar",
        "vendor": "Adam Shaw",
        "docs_url": "https://fullcalendar.io/",
    },
    "interactions": {
        "display_name": "Interactions",
        "vendor": "Bubble",
        "docs_url": "https://manual.bubble.io/",
    },
    "materialicons": {
        "display_name": "Material Icons",
        "vendor": "Google",
        "docs_url": "https://fonts.google.com/icons",
    },
    "multifileupload": {
        "display_name": "Multi-file Uploader",
        "vendor": "Bubble",
        "docs_url": "https://manual.bubble.io/",
    },
    "GoogleAnalytics": {
        "display_name": "Google Analytics",
        "vendor": "Google",
        "docs_url": "https://analytics.google.com/",
    },
    "stripe": {
        "display_name": "Stripe",
        "vendor": "Stripe",
        "docs_url": "https://stripe.com/docs",
    },
    "paypal": {
        "display_name": "PayPal",
        "vendor": "PayPal",
        "docs_url": "https://developer.paypal.com/",
    },
    "airtable": {
        "display_name": "Airtable",
        "vendor": "Airtable",
        "docs_url": "https://airtable.com/developers",
    },
    "googlemaps": {
        "display_name": "Google Maps",
        "vendor": "Google",
        "docs_url": "https://developers.google.com/maps",
    },
    "googlesignin": {
        "display_name": "Google Sign-In",
        "vendor": "Google",
        "docs_url": "https://developers.google.com/identity",
    },
    "facebook": {
        "display_name": "Facebook SDK",
        "vendor": "Meta",
        "docs_url": "https://developers.facebook.com/",
    },
}


# ── 2. Offline derivation from the ID format ──────────────────────────────

_TIMESTAMP_ID_RE = re.compile(r"^(\d{13})x\d+$")


def parse_timestamp_id(plugin_id: str) -> Optional[datetime]:
    """Return the author-side creation date embedded in a marketplace ID.

    Bubble marketplace plugins have IDs of the form
    ``<13-digit-ms-epoch>x<big-int>``. The prefix is the plugin's *first
    publication* timestamp in milliseconds since epoch. Returns ``None`` for
    first-party slugs (``chartjs``, ``stripe``…) that don't follow the
    pattern.
    """
    m = _TIMESTAMP_ID_RE.match(plugin_id)
    if m is None:
        return None
    try:
        return datetime.fromtimestamp(int(m.group(1)) / 1000, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def marketplace_url_for(plugin_id: str) -> Optional[str]:
    """Construct the canonical marketplace URL for a timestamp-format ID.

    Bubble resolves ``https://bubble.io/plugin/<id>`` to the full
    ``<slug>-<id>`` path via a 30x redirect, so we don't need the slug to
    produce a working link.
    """
    if parse_timestamp_id(plugin_id) is None:
        return None
    return f"https://bubble.io/plugin/{plugin_id}"


def enrich_offline(plugin: BubblePlugin) -> None:
    """Apply static catalogue + ID-derived metadata to *plugin* in place.

    Runs on every ``plugins`` invocation — no network. Only fills in empty
    fields so a prior live lookup is never overwritten.
    """
    meta = FIRST_PARTY_CATALOG.get(plugin.id)
    if meta:
        for k, v in meta.items():
            if not getattr(plugin, k, None):
                setattr(plugin, k, v)
    created = parse_timestamp_id(plugin.id)
    if created and plugin.created_at is None:
        plugin.created_at = created
    mk_url = marketplace_url_for(plugin.id)
    if mk_url and not plugin.marketplace_url:
        plugin.marketplace_url = mk_url


# ── 3. Live marketplace lookup ────────────────────────────────────────────

# Matches both orderings: property="og:title" content="…" OR content="…" property="og:title".
_OG_RE_PROP_FIRST = re.compile(
    r'<meta[^>]*property=["\']og:([a-z_:]+)["\'][^>]*content=["\']([^"\']*)',
    re.IGNORECASE,
)
_OG_RE_CONTENT_FIRST = re.compile(
    r'<meta[^>]*content=["\']([^"\']*)["\'][^>]*property=["\']og:([a-z_:]+)',
    re.IGNORECASE,
)


def extract_og_tags(html: str) -> dict[str, str]:
    """Return ``{og_prop: content}`` for every ``<meta property="og:…">`` tag.

    Handles both attribute orderings. Later occurrences do not overwrite
    earlier ones — the first tag wins, matching what a browser would see.
    """
    out: dict[str, str] = {}
    for prop, content in _OG_RE_PROP_FIRST.findall(html):
        out.setdefault(prop.lower(), content)
    for content, prop in _OG_RE_CONTENT_FIRST.findall(html):
        out.setdefault(prop.lower(), content)
    return out


async def enrich_online(plugin: BubblePlugin, http_client: Any) -> bool:
    """Fetch ``https://bubble.io/plugin/<id>`` and attach metadata.

    *http_client* is a ``bubblepwn.http.Client`` already opened by the caller
    so rate-limiting, retries and cookies apply uniformly.

    Returns ``True`` on a successful enrichment (at least one meta field
    gained), ``False`` otherwise. Never raises — network errors and missing
    pages just leave the plugin untouched.
    """
    url = marketplace_url_for(plugin.id)
    if url is None:
        return False
    try:
        r = await http_client.get(url)
    except Exception:
        return False
    if r.status_code != 200 or not r.text:
        return False
    tags = extract_og_tags(r.text)
    hit = False
    # og:title is typically "<Name> – Bubble Plugin" — strip the suffix.
    title = tags.get("title", "").strip()
    if title:
        if " – " in title:
            title = title.split(" – ", 1)[0].strip()
        elif " - " in title:
            title = title.split(" - ", 1)[0].strip()
        if title and not plugin.display_name:
            plugin.display_name = title
            hit = True
    desc = tags.get("description", "").strip()
    if desc and not plugin.description:
        plugin.description = desc
        hit = True
    og_url = tags.get("url", "").strip()
    if og_url:
        # Prefer the slugged URL over the bare ID one we built earlier.
        plugin.marketplace_url = og_url
        hit = True
    image = tags.get("image", "").strip()
    if image and not plugin.icon_url:
        plugin.icon_url = image
        hit = True
    return hit
