"""HTTP transport for Bubble Elasticsearch endpoints.

Wraps payload encryption + request sending. Supports both ``live`` and
``test`` branches and all the known endpoints (``search``, ``aggregate``,
``maggregate``, ``msearch``, ``bulk_watch``, ``mget``).
"""
from __future__ import annotations

import json
from typing import Any, Optional

from bubblepwn.bubble.es import crypto
from bubblepwn.http import client


class EsTransport:
    def __init__(
        self,
        base_url: str,
        appname: str,
        *,
        cookies: Optional[dict[str, str]] = None,
        branch: str = "live",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.appname = appname
        self.cookies = cookies or {}
        if branch not in ("live", "test"):
            raise ValueError("branch must be 'live' or 'test'")
        self.branch = branch

    def _url(self, endpoint: str) -> str:
        prefix = (
            self.base_url
            if self.branch == "live"
            else f"{self.base_url}/version-test"
        )
        return f"{prefix}/elasticsearch/{endpoint.lstrip('/')}"

    async def request(
        self, endpoint: str, payload: dict[str, Any]
    ) -> tuple[int, Any]:
        """Send an encrypted request. Returns ``(status_code, body)`` where
        ``body`` is parsed JSON when available, else raw text."""
        body_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        triple = crypto.wrap_triple(self.appname, body_bytes)
        headers = {
            "X-Bubble-Appname": self.appname,
            "Content-Type": "application/json",
        }
        async with client(cookies=self.cookies, headers=headers) as c:
            r = await c.post(self._url(endpoint), json=triple)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, r.text
