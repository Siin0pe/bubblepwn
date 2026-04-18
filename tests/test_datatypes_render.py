"""Rendering tests for the datatypes module.

Locks the separation between ``--list-fields`` (summary + breakdown +
exploration hints, **no full field table**) and ``--show-fields``
(one block per type with a Rule separator).
"""
from __future__ import annotations

import io

from rich.console import Console

from bubblepwn import ui as ui_module
from bubblepwn.bubble.schema import BubbleField, BubbleType
from bubblepwn.context import Context
from bubblepwn.modules.datatypes import DataTypes


def _capture(fn, *args, **kwargs) -> str:
    """Swap the shared rich Console for a captured one, run ``fn``, return output."""
    buf = io.StringIO()
    original = ui_module.console
    ui_module.console = Console(file=buf, width=120, record=True, force_terminal=False)
    # modules/datatypes imports console at module load, so patch there too
    import bubblepwn.modules.datatypes as dt_mod
    original_dt = dt_mod.console
    dt_mod.console = ui_module.console
    try:
        fn(*args, **kwargs)
    finally:
        ui_module.console = original
        dt_mod.console = original_dt
    return buf.getvalue()


def _make_ctx_with_pool():
    Context._reset()
    ctx = Context.get()
    ctx.set_target("https://example.bubble.io")
    ctx.settings["_field_triples"] = {
        "name___text":  {"name": "name___text",  "value": "text",          "display": "Name"},
        "age___number": {"name": "age___number", "value": "number",        "display": "Age"},
        "tags___text":  {"name": "tags___text",  "value": "list.text",     "display": "Tags"},
        "status___opt": {"name": "status___opt", "value": "option.status", "display": "Status"},
        "owner___cref": {"name": "owner___cref", "value": "custom.user",   "display": "Owner"},
    }
    return ctx


def test_list_fields_is_a_summary_not_a_full_table():
    """``--list-fields`` must output a compact summary.

    Anti-regression: the old rendering dumped every field as a
    ``display / value / raw column`` row, flooding the terminal on apps
    with hundreds of fields. We now want a category breakdown instead.
    """
    ctx = _make_ctx_with_pool()
    out = _capture(DataTypes()._render_field_pool, ctx)

    # Summary header is present.
    assert "5 field(s)" in out
    # Category breakdown shows up (at least the distinct Bubble buckets).
    assert "custom (ref)" in out
    assert "option" in out
    assert "list" in out
    # Exploration hints point at the right next command.
    assert "--show-fields" in out
    assert "--probe" in out
    # The raw DB column names used to be in the table — they must not
    # appear in the summary view any more.
    assert "name___text" not in out
    assert "owner___cref" not in out


def test_list_fields_handles_empty_pool():
    Context._reset()
    ctx = Context.get()
    ctx.set_target("https://example.bubble.io")
    ctx.settings["_field_triples"] = {}
    out = _capture(DataTypes()._render_field_pool, ctx)
    assert "No field triples" in out


def test_show_fields_renders_one_block_per_type():
    ctx = _make_ctx_with_pool()
    # Attach fields to two distinct types
    user = BubbleType(name="user", raw="user", namespace="system")
    user.add_field(BubbleField(name="name", type="text",
                               raw="name___text", source="obj"))
    ctx.schema.types["user"] = user
    company = BubbleType(name="company", raw="custom.company", namespace="custom")
    company.add_field(BubbleField(name="name", type="text",
                                  raw="name___text", source="obj"))
    ctx.schema.types["custom.company"] = company

    out = _capture(DataTypes()._render_fields_per_type, ctx)

    # Both type headers are present.
    assert "user" in out
    assert "custom.company" in out
    # Each block carries its own field count annotation.
    assert "1 field(s)" in out
    # Display label is resolved from the pool catalogue.
    assert "Name" in out


def test_show_fields_prompts_to_probe_when_no_fields_attached():
    Context._reset()
    ctx = Context.get()
    ctx.set_target("https://example.bubble.io")
    # Type present but no fields attached — the hint must nudge the user to
    # run --probe instead of showing an empty block.
    ctx.schema.types["user"] = BubbleType(
        name="user", raw="user", namespace="system",
    )
    out = _capture(DataTypes()._render_fields_per_type, ctx)
    assert "--probe" in out


def test_show_fields_only_type_renders_single_block():
    """``--type user`` in combination with ``--show-fields`` must render
    only the requested type's block and drop everything else."""
    ctx = _make_ctx_with_pool()
    user = BubbleType(name="user", raw="user", namespace="system")
    user.add_field(BubbleField(name="name", type="text",
                               raw="name___text", source="obj"))
    ctx.schema.types["user"] = user
    company = BubbleType(name="company", raw="custom.company", namespace="custom")
    company.add_field(BubbleField(name="ceo", type="text",
                                  raw="ceo___text", source="obj"))
    ctx.schema.types["custom.company"] = company

    out = _capture(
        DataTypes()._render_fields_per_type, ctx, only_type="user",
    )
    assert "user" in out
    # company block must NOT appear — the filter dropped it.
    assert "custom.company" not in out
    assert "ceo" not in out


def test_show_fields_only_type_missing_falls_back_to_helpful_message():
    ctx = _make_ctx_with_pool()
    # No types attached to the schema for "custom.missing"
    out = _capture(
        DataTypes()._render_fields_per_type, ctx, only_type="custom.missing",
    )
    assert "No fields attached" in out
    assert "--probe --type custom.missing" in out


def test_normalize_type_name_accepts_shorthand_and_canonical_forms():
    from bubblepwn.modules.datatypes import _normalize_type_name

    assert _normalize_type_name("user") == "user"
    assert _normalize_type_name("order") == "custom.order"
    assert _normalize_type_name("custom.order") == "custom.order"
    assert _normalize_type_name("option.status") == "option.status"
    assert _normalize_type_name("  user  ") == "user"
