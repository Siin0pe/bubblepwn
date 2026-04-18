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
from typing import Any, Optional


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
class ParsedMeta:
    get_types: list[str] = field(default_factory=list)
    post_endpoints: list[MetaEndpoint] = field(default_factory=list)

    def no_auth_workflows(self) -> list[MetaEndpoint]:
        return [e for e in self.post_endpoints if e.is_public_no_auth]

    def admin_only_workflows(self) -> list[MetaEndpoint]:
        return [e for e in self.post_endpoints if e.auth_unecessary == "admin_only"]


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
    return ParsedMeta(get_types=get_types, post_endpoints=endpoints)


def split_bubble_type(value: str) -> tuple[bool, str]:
    """Parse a type string like 'list.custom.thing' → (is_list, base_type)."""
    is_list = value.startswith("list.")
    base = value[5:] if is_list else value
    return is_list, base
