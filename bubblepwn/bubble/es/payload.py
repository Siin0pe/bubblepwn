"""Payload builders for the Bubble Elasticsearch endpoints.

Real payload shapes confirmed against live traffic (see
``secc/site_dump`` and the test harness in ``test_aggregate.py``):

Search::

    {"appname": "<app>", "app_version": "live", "type": "custom.<type>",
     "constraints": [], "sorts_list": [], "from": 0, "search_path": "<json>",
     "situation": "initial search", "n": 100}

Aggregate (count-only, no records)::

    {"appname": "<app>", "app_version": "live", "type": "custom.<type>",
     "constraints": [], "aggregate": {"fns": [{"n": "count"}]},
     "search_path": "<json>"}

Maggregate (batch)::

    {"appname": "<app>", "app_version": "live",
     "aggregates": [<one-aggregate-payload>, ...]}
"""
from __future__ import annotations

import json
from typing import Any, Optional


def default_search_path() -> str:
    """A generic ``search_path`` the server accepts.

    Bubble doesn't strictly validate this field — any syntactically plausible
    ``DataSource`` value passes.
    """
    return json.dumps(
        {
            "constructor_name": "DataSource",
            "args": [{"type": "raw", "value": "Search"}],
        },
        separators=(",", ":"),
    )


def build_search(
    appname: str,
    type_name: str,
    *,
    app_version: str = "live",
    n: int = 100,
    from_: int = 0,
    constraints: Optional[list[dict[str, Any]]] = None,
    sorts_list: Optional[list[dict[str, Any]]] = None,
    search_path: Optional[str] = None,
    situation: str = "initial search",
) -> dict[str, Any]:
    return {
        "appname": appname,
        "app_version": app_version,
        "type": type_name,
        "constraints": constraints or [],
        "sorts_list": sorts_list or [],
        "from": from_,
        "search_path": search_path or default_search_path(),
        "situation": situation,
        "n": n,
    }


def build_aggregate_count(
    appname: str,
    type_name: str,
    *,
    app_version: str = "live",
    constraints: Optional[list[dict[str, Any]]] = None,
    search_path: Optional[str] = None,
) -> dict[str, Any]:
    return {
        "appname": appname,
        "app_version": app_version,
        "type": type_name,
        "constraints": constraints or [],
        "aggregate": {"fns": [{"n": "count"}]},
        "search_path": search_path or default_search_path(),
    }


def build_maggregate_counts(
    appname: str,
    type_names: list[str],
    *,
    app_version: str = "live",
    search_path: Optional[str] = None,
) -> dict[str, Any]:
    """Batch count for many types in a single request."""
    sp = search_path or default_search_path()
    aggregates = [
        {
            "appname": appname,
            "app_version": app_version,
            "type": t,
            "constraints": [],
            "aggregate": {"fns": [{"n": "count"}]},
            "search_path": sp,
        }
        for t in type_names
    ]
    return {
        "appname": appname,
        "app_version": app_version,
        "aggregates": aggregates,
    }
