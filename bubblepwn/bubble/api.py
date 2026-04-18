"""Thin HTTP client for Bubble.io API endpoints.

Supports the two branches Bubble exposes:
  - ``live`` → ``/api/1.1/<path>``
  - ``test`` → ``/version-test/api/1.1/<path>``
"""
from __future__ import annotations

from typing import Any, Optional

import httpx

from bubblepwn.http import client


class BubbleAPI:
    def __init__(
        self,
        base_url: str,
        cookies: Optional[dict[str, str]] = None,
        branch: str = "live",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.cookies = cookies or {}
        if branch not in ("live", "test"):
            raise ValueError(f"invalid branch: {branch}")
        self.branch = branch

    # ── URL helpers ──────────────────────────────────────────────────────

    @property
    def api_root(self) -> str:
        if self.branch == "live":
            return f"{self.base_url}/api/1.1"
        return f"{self.base_url}/version-test/api/1.1"

    @property
    def branch_root(self) -> str:
        if self.branch == "live":
            return self.base_url
        return f"{self.base_url}/version-test"

    # ── Page / bootstrap ─────────────────────────────────────────────────

    async def fetch_page(self, page: str = "") -> httpx.Response:
        url = f"{self.branch_root}/{page}".rstrip("/") or self.branch_root
        async with client(cookies=self.cookies) as c:
            return await c.get(url)

    async def init_data(self, location: Optional[str] = None) -> Any:
        loc = location or f"{self.branch_root}/"
        url = f"{self.api_root}/init/data"
        async with client(cookies=self.cookies) as c:
            r = await c.get(url, params={"location": loc})
            r.raise_for_status()
            return r.json()

    # ── Data API — introspection ─────────────────────────────────────────

    async def meta(self) -> tuple[int, Optional[dict[str, Any]]]:
        """Return (status_code, body) for `/api/1.1/meta`."""
        url = f"{self.api_root}/meta"
        async with client(cookies=self.cookies) as c:
            r = await c.get(url)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, None

    async def meta_swagger(self) -> tuple[int, Optional[dict[str, Any]]]:
        """Return (status_code, body) for `/api/1.1/meta/swagger.json`."""
        url = f"{self.api_root}/meta/swagger.json"
        async with client(cookies=self.cookies) as c:
            r = await c.get(url)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, None

    # ── Data API — CRUD ──────────────────────────────────────────────────

    async def obj(
        self,
        type_name: str,
        *,
        limit: int = 1,
        cursor: int = 0,
        constraints: Optional[list[dict[str, Any]]] = None,
    ) -> tuple[int, Optional[dict[str, Any]]]:
        url = f"{self.api_root}/obj/{type_name}"
        params: dict[str, Any] = {"limit": limit, "cursor": cursor}
        if constraints is not None:
            import json as _json
            params["constraints"] = _json.dumps(constraints)
        async with client(cookies=self.cookies) as c:
            r = await c.get(url, params=params)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, None

    async def obj_by_id(
        self, type_name: str, record_id: str
    ) -> tuple[int, Optional[dict[str, Any]]]:
        url = f"{self.api_root}/obj/{type_name}/{record_id}"
        async with client(cookies=self.cookies) as c:
            r = await c.get(url)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, None

    async def options(self, path: str) -> tuple[int, dict[str, str]]:
        """Send an OPTIONS request to a Bubble API path. Returns (status, headers)."""
        url = f"{self.api_root}/{path.lstrip('/')}"
        async with client(cookies=self.cookies) as c:
            r = await c.request("OPTIONS", url)
        return r.status_code, dict(r.headers)

    # ── Workflow API ─────────────────────────────────────────────────────

    async def workflow(
        self,
        name: str,
        *,
        method: str = "POST",
        body: Optional[dict[str, Any]] = None,
    ) -> tuple[int, Optional[dict[str, Any]]]:
        url = f"{self.api_root}/wf/{name}"
        async with client(cookies=self.cookies) as c:
            if method.upper() == "GET":
                r = await c.get(url)
            else:
                r = await c.post(url, json=body or {})
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, None

    # ── Adjacent / internal endpoints ────────────────────────────────────

    async def user_heartbeat(self) -> tuple[int, Optional[dict[str, Any]]]:
        url = f"{self.branch_root}/user/hi"
        async with client(cookies=self.cookies) as c:
            r = await c.get(url)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, None

    async def elasticsearch_probe(self, path: str = "msearch") -> tuple[int, str]:
        """Send an empty POST to /elasticsearch/<path>. Returns (status, body_text)."""
        url = f"{self.branch_root}/elasticsearch/{path.lstrip('/')}"
        async with client(cookies=self.cookies) as c:
            r = await c.post(url, json={})
        return r.status_code, r.text[:500]
