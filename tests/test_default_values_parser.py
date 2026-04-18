"""Tests for ``parse_default_values_by_type`` — the ownership-aware static.js
field extractor introduced in v0.2.20.

Bubble's `static.js` exposes an object of the shape

    {"action": [...], "<type_name>": [...], "user": [...]}

where every key (besides ``action``) is an owning custom data type and its
value is the exact field set of that type. Recovering that structure turns
``run datatypes`` into a full schema dump **without** requiring ``--probe``
(Data API) — i.e. it works even when every privacy rule blocks the API.
"""
from __future__ import annotations

from bubblepwn.bubble.parse.static_js import (
    _extract_balanced_json_object,
    parse_default_values_by_type,
)


# Minimal bundle fixture mirroring the real layout we see in production:
# the DefaultValues assignment wrapped in the ``window['bubble_run_derived']``
# shape and keyed by owning type names. Includes one deleted field to prove
# we filter it out.
_DV = r'''
window['bubble_run_derived']['{"function_name":"DefaultValues","args":[]}'] = {
  "action": [
    {"name":"some_global_action_text","value":"text","display":"global","deleted":null}
  ],
  "user": [
    {"name":"email_text","value":"text","display":"Email","deleted":null},
    {"name":"twofa___boolean","value":"boolean","display":"2FA ?","deleted":null},
    {"name":"old_field_text","value":"text","display":"old","deleted":true}
  ],
  "clients_base": [
    {"name":"nom_text","value":"text","display":"Nom","deleted":null},
    {"name":"owner_custom_user","value":"custom.user","display":"Owner","deleted":null}
  ],
  "_csrd__mdr": [
    {"name":"esrs_custom_esrs","value":"custom.esrs","display":"ESRS","deleted":null}
  ]
}'''


def test_extract_balanced_json_object_respects_string_braces():
    src = '  {"k":"has {nested} quote","x":1}  tail'
    start = src.index("{")
    extracted = _extract_balanced_json_object(src, start)
    assert extracted == '{"k":"has {nested} quote","x":1}'


def test_extract_balanced_json_object_returns_none_when_unclosed():
    src = '{"k":1,'
    assert _extract_balanced_json_object(src, 0) is None


def test_parse_default_values_by_type_extracts_owning_type_fields():
    out = parse_default_values_by_type(_DV)
    assert set(out.keys()) == {"action", "user", "clients_base", "_csrd__mdr"}

    assert len(out["user"]) == 2  # deleted field dropped
    names = {e["name"] for e in out["user"]}
    assert names == {"email_text", "twofa___boolean"}

    clients = {e["name"]: e for e in out["clients_base"]}
    assert clients["owner_custom_user"]["value"] == "custom.user"
    assert clients["owner_custom_user"]["display"] == "Owner"


def test_parse_default_values_by_type_returns_empty_on_malformed_input():
    assert parse_default_values_by_type("just some HTML") == {}
    truncated = _DV[: _DV.index('"user"') + 20]
    assert parse_default_values_by_type(truncated) == {}


def test_parse_default_values_filters_non_string_entries():
    """Guard against malformed entries (e.g. integer values) being silently
    coerced into ``BubbleField``."""
    bad = r'''
window[...]['{"function_name":"DefaultValues","args":[]}'] = {
  "user": [
    {"name":123,"value":"text","display":"x","deleted":null},
    {"name":"ok_text","value":"text","display":"ok","deleted":null}
  ]
}'''
    out = parse_default_values_by_type(bad)
    assert out == {"user": [{"name": "ok_text", "value": "text", "display": "ok"}]}


def test_harvest_static_attaches_fields_to_types():
    from bubblepwn.context import Context
    from bubblepwn.modules.datatypes import _harvest_static

    Context._reset()
    ctx = Context.get()
    ctx.set_target("https://example.bubble.io")

    attached = _harvest_static(ctx, _DV, source_tag="static_js")
    # 2 user fields (deleted filtered) + 2 clients_base + 1 _csrd__mdr = 5
    assert attached == 5

    user = ctx.schema.types["user"]
    assert len(user.fields) == 2
    assert "email_text" in user.fields
    assert user.fields["email_text"].type == "text"
    assert "static_js_dv" in [f.source for f in user.fields.values()]

    clients = ctx.schema.types["custom.clients_base"]
    assert len(clients.fields) == 2
    assert clients.fields["owner_custom_user"].type == "custom.user"

    csrd = ctx.schema.types["custom._csrd__mdr"]
    assert len(csrd.fields) == 1


def test_harvest_static_idempotent_on_repeat_run():
    """Re-running the same harvest twice should not double the field set."""
    from bubblepwn.context import Context
    from bubblepwn.modules.datatypes import _harvest_static

    Context._reset()
    ctx = Context.get()
    ctx.set_target("https://example.bubble.io")

    first = _harvest_static(ctx, _DV, source_tag="static_js")
    second = _harvest_static(ctx, _DV, source_tag="static_js:page2")
    assert first > 0
    assert second == 0

    user = ctx.schema.types["user"]
    assert len(user.fields) == 2
