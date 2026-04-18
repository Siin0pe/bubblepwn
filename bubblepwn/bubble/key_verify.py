"""Verify whether a leaked API key is actually abusable.

Currently supports Google Maps / Google Cloud keys (``AIza...``). Tests each
key against ~10 different Google Maps APIs and classifies each response:

  * ``OPEN``              — valid response (``status=OK`` / ``ZERO_RESULTS``)
  * ``REFERER_RESTRICTED``— HTTP referrer check rejected our request
  * ``IP_RESTRICTED``     — source IP not on the allowlist
  * ``API_NOT_ENABLED``   — this key cannot use this API, but key itself is valid
  * ``INVALID_KEY``       — key format invalid / revoked
  * ``QUOTA_EXCEEDED``    — ``OVER_QUERY_LIMIT`` / ``OVER_DAILY_LIMIT``
  * ``BILLING_DISABLED``  — key valid but project has no billing account
  * ``UNKNOWN(<status>)`` — unhandled response status
  * ``ERROR(<type>)``     — network/transport error

Overall verdict is ``ABUSABLE`` if at least one API returns ``OPEN``.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Optional

import httpx

_ENDPOINTS: dict[str, str] = {
    "geocode":        "https://maps.googleapis.com/maps/api/geocode/json?address=NYC&key={k}",
    "places_text":    "https://maps.googleapis.com/maps/api/place/textsearch/json?query=pizza&key={k}",
    "places_auto":    "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=p&key={k}",
    "directions":     "https://maps.googleapis.com/maps/api/directions/json?origin=NYC&destination=Boston&key={k}",
    "distmatrix":     "https://maps.googleapis.com/maps/api/distancematrix/json?origins=NYC&destinations=Boston&key={k}",
    "elevation":      "https://maps.googleapis.com/maps/api/elevation/json?locations=45,-73&key={k}",
    "timezone":       "https://maps.googleapis.com/maps/api/timezone/json?location=45,-73&timestamp=1700000000&key={k}",
    "streetview_meta":"https://maps.googleapis.com/maps/api/streetview/metadata?location=45,-73&key={k}",
    "roads":          "https://roads.googleapis.com/v1/nearestRoads?points=60.17,24.94&key={k}",
    "jsapi":          "https://maps.googleapis.com/maps/api/js?key={k}",
}


@dataclass
class KeyCheckResult:
    key: str
    per_api: dict[str, str] = field(default_factory=dict)
    verdict: str = "UNKNOWN"
    open_apis: list[str] = field(default_factory=list)

    def abusable(self) -> bool:
        return self.verdict == "ABUSABLE"


def _classify_json(body_text: str) -> str:
    try:
        j = json.loads(body_text)
    except Exception:
        return "UNKNOWN(nonjson)"
    if not isinstance(j, dict):
        return "UNKNOWN(shape)"
    status_raw = j.get("status")
    if status_raw is None:
        err = j.get("error")
        if isinstance(err, dict):
            status_raw = err.get("status")
    status = str(status_raw or "").upper()
    err = j.get("error_message")
    if not err and isinstance(j.get("error"), dict):
        err = j["error"].get("message")
    msg = str(err or "").lower()

    if status in ("OK", "ZERO_RESULTS"):
        return "OPEN"
    if "referer" in msg:
        return "REFERER_RESTRICTED"
    if "ip" in msg and "address" in msg:
        return "IP_RESTRICTED"
    if "not authorized" in msg or "not enabled" in msg:
        return "API_NOT_ENABLED"
    if "invalid" in msg or status == "INVALID_REQUEST" and "key" in msg:
        return "INVALID_KEY"
    if "billing" in msg:
        return "BILLING_DISABLED"
    if status.startswith("OVER_"):
        return "QUOTA_EXCEEDED"
    return f"UNKNOWN({status or 'noStatus'})"


def _classify_js(body_text: str) -> str:
    b = body_text.lower()
    if "invalidkeymaperror" in b:
        return "INVALID_KEY"
    if "refererotallowedmap" in b or "referernotallowed" in b:
        return "REFERER_RESTRICTED"
    if "apinotactivatedmap" in b:
        return "API_NOT_ENABLED"
    if "google.maps" in b or "function(" in b:
        return "OPEN"
    return "UNKNOWN(js)"


async def _test_one(
    client: httpx.AsyncClient, name: str, url: str
) -> str:
    try:
        r = await client.get(url, timeout=15.0)
    except httpx.HTTPError as exc:
        return f"ERROR({exc.__class__.__name__})"
    # Static Maps / Street View binary responses — use status + content-type
    if r.headers.get("content-type", "").startswith("image/"):
        if r.status_code == 200 and len(r.content) > 10_000:
            return "OPEN"
        return "RESTRICTED_IMAGE"
    if name == "jsapi":
        return _classify_js(r.text)
    return _classify_json(r.text)


async def verify_google_maps_key(
    key: str, *, referer: Optional[str] = None
) -> KeyCheckResult:
    headers = {"Referer": referer} if referer else {}
    result = KeyCheckResult(key=key)
    async with httpx.AsyncClient(headers=headers, follow_redirects=True) as client:
        tasks = {
            name: asyncio.create_task(_test_one(client, name, tmpl.format(k=key)))
            for name, tmpl in _ENDPOINTS.items()
        }
        for name, task in tasks.items():
            result.per_api[name] = await task
    result.open_apis = [
        n for n, v in result.per_api.items() if v == "OPEN"
    ]
    result.verdict = "ABUSABLE" if result.open_apis else "RESTRICTED"
    return result


def is_google_key(value: str) -> bool:
    return value.startswith("AIza") and len(value) == 39
