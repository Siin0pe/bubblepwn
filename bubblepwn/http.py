from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

import httpx

from bubblepwn.config import settings


class RateLimiter:
    def __init__(self, rps: float) -> None:
        self.interval = 1.0 / rps if rps > 0 else 0.0
        self._lock = asyncio.Lock()
        self._last = 0.0

    async def acquire(self) -> None:
        if self.interval <= 0:
            return
        async with self._lock:
            loop = asyncio.get_event_loop()
            now = loop.time()
            wait = self._last + self.interval - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = loop.time()


class Client:
    """Thin async HTTP wrapper: rate-limit, proxy, session cookies."""

    def __init__(
        self,
        rate_limit: Optional[RateLimiter] = None,
        cookies: Optional[dict[str, str]] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> None:
        self._limiter = rate_limit or RateLimiter(settings.rate_limit_rps)
        base_headers = {"User-Agent": settings.user_agent}
        if headers:
            base_headers.update(headers)
        self._client = httpx.AsyncClient(
            headers=base_headers,
            cookies=cookies or {},
            timeout=settings.timeout_s,
            verify=settings.verify_tls,
            proxy=settings.proxy,
            follow_redirects=True,
            http2=False,
        )

    async def request(self, method: str, url: str, **kw) -> httpx.Response:
        await self._limiter.acquire()
        return await self._client.request(method, url, **kw)

    async def get(self, url: str, **kw) -> httpx.Response:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw) -> httpx.Response:
        return await self.request("POST", url, **kw)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "Client":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()


@asynccontextmanager
async def client(
    cookies: Optional[dict[str, str]] = None,
    headers: Optional[dict[str, str]] = None,
) -> AsyncIterator[Client]:
    c = Client(cookies=cookies, headers=headers)
    try:
        yield c
    finally:
        await c.aclose()
