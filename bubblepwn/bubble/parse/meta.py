"""Parse Bubble's `/api/1.1/meta` response.

Real format (confirmed against `https://bubble.io/api/1.1/meta`):

    {
      "get":  ["typename1", "typename2", ...],
      "post": [
        {"endpoint": "login",
         "parameters": [{"key": "...", "value": "text", "optional": false, "param_in": "body"}],
         "method": "post",
         "auth_unecessary": true | "admin_only" | false,
         "return_btype": {"name": "text", "tags": "list.text", ...}}
      ]
    }

Swagger (`/api/1.1/meta/swagger.json`) is a separate endpoint in OpenAPI 2.0
format, only present if "Generate Swagger spec" is enabled.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class MetaEndpoint:
    endpoint: str
    method: str = "post"
    auth_unecessary: Any = False          # bool | "admin_only"
    parameters: list[dict[str, Any]] = field(default_factory=list)
    return_btype: dict[str, Any] = field(default_factory=dict)

    @property
    def is_public_no_auth(self) -> bool:
        return self.auth_unecessary is True


@dataclass
class MetaField:
    """One field of a Bubble data type as advertised by ``/api/1.1/meta``.

    Bubble publishes the DB↔display mapping directly here, so this is the
    authoritative source for matching ``_source`` keys (ES) with Data API
    keys. The ``id`` is the ES ``_source`` key; ``display`` is what the
    Data API returns.
    """
    id: str                # DB column name, e.g. ``profile_bio_text``
    display: str           # human name, e.g. ``Profile Bio``
    type: str = ""         # ``text``, ``boolean``, ``custom.company``, ``list.option.x``


@dataclass
class ParsedMeta:
    get_types: list[str] = field(default_factory=list)
    post_endpoints: list[MetaEndpoint] = field(default_factory=list)
    # Per-type fields — keys are type names as found in ``/meta`` (e.g.
    # ``user``, ``candidaterequest``). Empty if the meta body doesn't
    # include the ``types`` section (older Bubble versions / hidden).
    type_fields: dict[str, list[MetaField]] = field(default_factory=dict)

    def no_auth_workflows(self) -> list[MetaEndpoint]:
        return [e for e in self.post_endpoints if e.is_public_no_auth]

    def admin_only_workflows(self) -> list[MetaEndpoint]:
        return [e for e in self.post_endpoints if e.auth_unecessary == "admin_only"]

    def fields_for(self, type_name: str) -> list[MetaField]:
        """Return the field list for a type (``user``, ``custom.x`` or ``x``)."""
        if type_name in self.type_fields:
            return self.type_fields[type_name]
        # Accept both ``custom.foo`` and ``foo``.
        bare = type_name.split(".", 1)[1] if "." in type_name else type_name
        return self.type_fields.get(bare, [])

    def display_to_id(self, type_name: str) -> dict[str, str]:
        """Lookup table mapping display names → DB ids for a type."""
        return {f.display: f.id for f in self.fields_for(type_name) if f.display}

    def id_to_display(self, type_name: str) -> dict[str, str]:
        """Lookup table mapping DB ids → display names for a type."""
        return {f.id: f.display for f in self.fields_for(type_name) if f.display}


def parse_meta(body: Any) -> ParsedMeta:
    """Parse the raw meta JSON body into a ParsedMeta object."""
    if not isinstance(body, dict):
        return ParsedMeta()

    raw_get = body.get("get")
    get_types = [t for t in raw_get if isinstance(t, str)] if isinstance(raw_get, list) else []

    raw_post = body.get("post")
    endpoints: list[MetaEndpoint] = []
    if isinstance(raw_post, list):
        for item in raw_post:
            if not isinstance(item, dict):
                continue
            endpoints.append(
                MetaEndpoint(
                    endpoint=str(item.get("endpoint", "")),
                    method=str(item.get("method", "post")),
                    auth_unecessary=item.get("auth_unecessary", False),
                    parameters=item.get("parameters") or [],
                    return_btype=item.get("return_btype") or {},
                )
            )

    # ``types`` section (Bubble versions from ~2024 onwards) — publishes
    # the DB↔display mapping explicitly for each custom type.
    type_fields: dict[str, list[MetaField]] = {}
    raw_types = body.get("types")
    if isinstance(raw_types, dict):
        for tname, tentry in raw_types.items():
            if not isinstance(tentry, dict):
                continue
            raw_fields = tentry.get("fields")
            if not isinstance(raw_fields, list):
                continue
            fields_: list[MetaField] = []
            for f in raw_fields:
                if not isinstance(f, dict):
                    continue
                fid = str(f.get("id") or "")
                disp = str(f.get("display") or "")
                ftype = str(f.get("type") or "")
                if fid or disp:
                    fields_.append(MetaField(id=fid, display=disp, type=ftype))
            if fields_:
                type_fields[str(tname)] = fields_

    return ParsedMeta(
        get_types=get_types,
        post_endpoints=endpoints,
        type_fields=type_fields,
    )


def split_bubble_type(value: str) -> tuple[bool, str]:
    """Parse a type string like 'list.custom.thing' → (is_list, base_type)."""
    is_list = value.startswith("list.")
    base = value[5:] if is_list else value
    return is_list, base
