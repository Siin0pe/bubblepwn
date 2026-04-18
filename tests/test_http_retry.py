"""Unit tests for the HTTP retry wrapper in ``bubblepwn.http``.

We inject ``httpx.MockTransport`` into the inner ``AsyncClient`` to deterministically
drive 503 → 200 / timeout → success scenarios without touching the network.
"""
from __future__ import annotations

import httpx
import pytest

from bubblepwn.http import Client, RateLimiter


def _make_client_with_transport(transport: httpx.MockTransport, retries: int = 2) -> Client:
    c = Client(rate_limit=RateLimiter(0), retries=retries)
    # Swap the real AsyncClient for one backed by the mock transport. We still
    # benefit from the wrapper's retry + rate-limit logic.
    import asyncio

    asyncio.get_event_loop().run_until_complete(c._client.aclose())
    c._client = httpx.AsyncClient(transport=transport)
    return c


@pytest.mark.asyncio
async def test_retry_on_503_then_success():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 2:
            return httpx.Response(503)
        return httpx.Response(200, json={"ok": True})

    c = Client(rate_limit=RateLimiter(0), retries=2)
    await c._client.aclose()
    c._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        r = await c.get("http://x/test")
        assert r.status_code == 200
        assert calls["n"] == 2
    finally:
        await c.aclose()


@pytest.mark.asyncio
async def test_retry_exhausted_returns_last_error_status():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503)

    c = Client(rate_limit=RateLimiter(0), retries=2)
    await c._client.aclose()
    c._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        r = await c.get("http://x/test")
        # After exhausting retries we return the last response instead of raising.
        assert r.status_code == 503
        assert calls["n"] == 3  # 1 initial + 2 retries
    finally:
        await c.aclose()


@pytest.mark.asyncio
async def test_no_retry_on_4xx_client_error():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(404)

    c = Client(rate_limit=RateLimiter(0), retries=3)
    await c._client.aclose()
    c._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        r = await c.get("http://x/test")
        assert r.status_code == 404
        assert calls["n"] == 1
    finally:
        await c.aclose()


@pytest.mark.asyncio
async def test_retry_on_timeout_exception():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 2:
            raise httpx.ReadTimeout("simulated")
        return httpx.Response(200)

    c = Client(rate_limit=RateLimiter(0), retries=2)
    await c._client.aclose()
    c._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        r = await c.get("http://x/test")
        assert r.status_code == 200
        assert calls["n"] == 2
    finally:
        await c.aclose()
