from __future__ import annotations

import asyncio
import random
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


_RETRY_STATUSES: frozenset[int] = frozenset({429, 502, 503, 504})
_RETRY_EXCEPTIONS: tuple[type[BaseException], ...] = (
    httpx.TimeoutException,
    httpx.ConnectError,
    httpx.ReadError,
    httpx.RemoteProtocolError,
)


class Client:
    """Thin async HTTP wrapper: rate-limit, proxy, session cookies, retries.

    Transient failures (network timeouts, connection resets, 429/502/503/504)
    are retried with exponential backoff. Non-retriable 4xx responses are
    returned as-is so callers can branch on status codes.
    """

    def __init__(
        self,
        rate_limit: Optional[RateLimiter] = None,
        cookies: Optional[dict[str, str]] = None,
        headers: Optional[dict[str, str]] = None,
        *,
        follow_redirects: bool = True,
        timeout: Optional[float] = None,
        retries: int = 2,
    ) -> None:
        self._limiter = rate_limit or RateLimiter(settings.rate_limit_rps)
        self._retries = max(0, retries)
        base_headers = {"User-Agent": settings.user_agent}
        if headers:
            base_headers.update(headers)
        self._client = httpx.AsyncClient(
            headers=base_headers,
            cookies=cookies or {},
            timeout=timeout if timeout is not None else settings.timeout_s,
            verify=settings.verify_tls,
            proxy=settings.proxy,
            follow_redirects=follow_redirects,
            http2=False,
        )

    async def request(
        self, method: str, url: str, *, retries: Optional[int] = None, **kw
    ) -> httpx.Response:
        attempts = self._retries if retries is None else max(0, retries)
        last_exc: Optional[BaseException] = None
        for attempt in range(attempts + 1):
            await self._limiter.acquire()
            try:
                r = await self._client.request(method, url, **kw)
            except _RETRY_EXCEPTIONS as exc:
                last_exc = exc
                if attempt < attempts:
                    await _backoff(attempt)
                    continue
                raise
            if r.status_code in _RETRY_STATUSES and attempt < attempts:
                await _backoff(attempt)
                continue
            return r
        if last_exc is not None:  # pragma: no cover — defensive
            raise last_exc
        raise RuntimeError("retry loop exhausted")

    async def get(self, url: str, **kw) -> httpx.Response:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw) -> httpx.Response:
        return await self.request("POST", url, **kw)

    async def head(self, url: str, **kw) -> httpx.Response:
        return await self.request("HEAD", url, **kw)

    async def options(self, url: str, **kw) -> httpx.Response:
        return await self.request("OPTIONS", url, **kw)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "Client":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()


async def _backoff(attempt: int) -> None:
    delay = 0.5 * (2 ** attempt) + random.uniform(0, 0.25)
    await asyncio.sleep(delay)


@asynccontextmanager
async def client(
    cookies: Optional[dict[str, str]] = None,
    headers: Optional[dict[str, str]] = None,
    *,
    follow_redirects: bool = True,
    timeout: Optional[float] = None,
    retries: int = 2,
) -> AsyncIterator[Client]:
    c = Client(
        cookies=cookies,
        headers=headers,
        follow_redirects=follow_redirects,
        timeout=timeout,
        retries=retries,
    )
    try:
        yield c
    finally:
        await c.aclose()
