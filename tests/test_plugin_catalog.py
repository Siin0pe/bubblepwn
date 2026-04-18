"""Unit tests for the plugin catalogue + marketplace enrichment."""
from __future__ import annotations

from datetime import datetime, timezone

import httpx
import pytest

from bubblepwn.bubble.plugin_catalog import (
    FIRST_PARTY_CATALOG,
    enrich_offline,
    enrich_online,
    extract_og_tags,
    marketplace_url_for,
    parse_timestamp_id,
)
from bubblepwn.bubble.schema import BubblePlugin
from bubblepwn.http import Client, RateLimiter


# ── parse_timestamp_id ────────────────────────────────────────────────────

def test_parse_timestamp_id_decodes_epoch_ms():
    # Bubble stores milliseconds since the Unix epoch. Jun 14, 2017 ≈ 1497473108.
    dt = parse_timestamp_id("1497473108162x748064")
    assert dt is not None
    assert dt.tzinfo is not None
    assert dt.year == 2017


def test_parse_timestamp_id_rejects_non_timestamp():
    assert parse_timestamp_id("chartjs") is None
    assert parse_timestamp_id("stripe") is None
    assert parse_timestamp_id("") is None
    assert parse_timestamp_id("123x456") is None  # 3-digit prefix is not 13


def test_marketplace_url_only_for_timestamp_ids():
    assert marketplace_url_for("1497473108162x748064") == (
        "https://bubble.io/plugin/1497473108162x748064"
    )
    assert marketplace_url_for("chartjs") is None


# ── enrich_offline ────────────────────────────────────────────────────────

def test_enrich_offline_fills_first_party_catalog():
    p = BubblePlugin(id="chartjs", category="first_party")
    enrich_offline(p)
    assert p.display_name == "Chart.js"
    assert p.vendor == "Chart.js contributors"
    assert p.docs_url and "chartjs" in p.docs_url.lower()


def test_enrich_offline_derives_created_at_for_timestamp_ids():
    p = BubblePlugin(id="1497473108162x748064", category="third_party")
    enrich_offline(p)
    assert isinstance(p.created_at, datetime)
    assert p.marketplace_url == "https://bubble.io/plugin/1497473108162x748064"


def test_enrich_offline_does_not_overwrite_prefilled_fields():
    p = BubblePlugin(
        id="chartjs", category="first_party",
        display_name="Custom Name", vendor="Custom Vendor",
    )
    enrich_offline(p)
    assert p.display_name == "Custom Name"
    assert p.vendor == "Custom Vendor"


def test_enrich_offline_skips_unknown_plugins():
    p = BubblePlugin(id="totally-unknown", category="unknown")
    enrich_offline(p)
    assert p.display_name is None
    assert p.created_at is None
    assert p.marketplace_url is None


def test_catalog_entries_have_required_fields():
    # Every static entry must expose at least display_name + vendor + docs_url.
    for slug, meta in FIRST_PARTY_CATALOG.items():
        assert "display_name" in meta, f"{slug} missing display_name"
        assert "vendor" in meta, f"{slug} missing vendor"
        assert "docs_url" in meta, f"{slug} missing docs_url"
        assert meta["docs_url"].startswith(("http://", "https://"))


# ── extract_og_tags ───────────────────────────────────────────────────────

def test_extract_og_tags_handles_both_attribute_orderings():
    html = """
    <head>
      <meta property="og:title" content="Fancy Plugin">
      <meta content="A nice plugin" property="og:description">
      <meta property="og:url" content="https://bubble.io/plugin/fancy-xyz">
    </head>
    """
    tags = extract_og_tags(html)
    assert tags["title"] == "Fancy Plugin"
    assert tags["description"] == "A nice plugin"
    assert tags["url"] == "https://bubble.io/plugin/fancy-xyz"


def test_extract_og_tags_ignores_non_og_meta():
    html = '<meta property="twitter:title" content="No">'
    assert extract_og_tags(html) == {}


def test_extract_og_tags_first_occurrence_wins():
    html = (
        '<meta property="og:title" content="First">'
        '<meta property="og:title" content="Second">'
    )
    assert extract_og_tags(html)["title"] == "First"


# ── enrich_online (live marketplace mock) ────────────────────────────────

@pytest.mark.asyncio
async def test_enrich_online_parses_og_tags_from_marketplace_page():
    def handler(request: httpx.Request) -> httpx.Response:
        assert "1497473108162x748064" in str(request.url)
        body = """
        <html><head>
          <meta property="og:title" content="Rich Text Editor – Bubble Plugin">
          <meta property="og:description" content="A rich text editor.">
          <meta property="og:url" content="https://bubble.io/plugin/rich-text-editor-1497473108162x748064">
          <meta property="og:image" content="https://example.com/logo.png">
        </head></html>
        """
        return httpx.Response(200, text=body)

    c = Client(rate_limit=RateLimiter(0), retries=0)
    await c._client.aclose()
    c._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        p = BubblePlugin(id="1497473108162x748064", category="third_party")
        enrich_offline(p)
        ok = await enrich_online(p, c)
        assert ok is True
        assert p.display_name == "Rich Text Editor"
        assert p.description == "A rich text editor."
        assert p.marketplace_url.endswith("1497473108162x748064")
        assert p.icon_url == "https://example.com/logo.png"
    finally:
        await c.aclose()


@pytest.mark.asyncio
async def test_enrich_online_skips_non_timestamp_ids():
    c = Client(rate_limit=RateLimiter(0), retries=0)
    try:
        p = BubblePlugin(id="chartjs", category="first_party")
        # Should return False without even making a request.
        assert await enrich_online(p, c) is False
    finally:
        await c.aclose()


@pytest.mark.asyncio
async def test_enrich_online_tolerates_404():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="")

    c = Client(rate_limit=RateLimiter(0), retries=0)
    await c._client.aclose()
    c._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        p = BubblePlugin(id="1497473108162x748064", category="third_party")
        assert await enrich_online(p, c) is False
        # Plugin must stay untouched on failure.
        assert p.display_name is None
        assert p.description is None
    finally:
        await c.aclose()
