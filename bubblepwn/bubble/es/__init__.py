"""Bubble Elasticsearch — crypto primitives, payload builders, transport.

Implements the request envelope scheme disclosed publicly in April 2025
(GBHackers):
  - Endpoint: ``/elasticsearch/{search,aggregate,maggregate,bulk_watch,...}``
  - Protocol: request body is ``{"x": b64, "y": b64, "z": b64}``
  - ``y`` carries the session timestamp, wrapped with a static IV seed ``po9``
  - ``x`` carries the session IV material, wrapped with a static IV seed ``fl1``
  - ``z`` carries the actual JSON payload, encrypted with keys derived from
    the unwrapped timestamp + IV material + ``appname`` (public header)
  - KDF: PBKDF2-HMAC-MD5 · 7 iterations — ridiculously weak
  - Cipher: AES-256-CBC · PKCS7

Knowing the public ``X-Bubble-Appname`` header value is enough to forge any
request. We re-implement the primitives from scratch (no dependency on the
unlicensed ``pop_n_bubble`` PoC).
"""
from bubblepwn.bubble.es import crypto, payload
from bubblepwn.bubble.es.transport import EsTransport

__all__ = ["crypto", "payload", "EsTransport"]
