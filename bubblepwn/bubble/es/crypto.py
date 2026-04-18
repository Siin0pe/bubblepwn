"""AES-CBC + PBKDF2-HMAC-MD5 primitives for the Bubble ES endpoints.

Everything here is a straight re-implementation of the publicly documented
scheme. No upstream code is imported; only standard crypto primitives from
the ``cryptography`` library.
"""
from __future__ import annotations

import base64
import secrets
import time
from hashlib import pbkdf2_hmac

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ── Constants hardcoded in Bubble's JS (shared across all apps) ──────────
_IV_SEED_Y = b"po9"   # wraps the timestamp (y ciphertext)
_IV_SEED_X = b"fl1"   # wraps the IV material (x ciphertext)

_KDF_ITERS = 7        # PBKDF2 iterations — weak by design (~microsecond cost)
_KEY_LEN = 32         # AES-256
_IV_LEN = 16          # AES block size


# ── Low-level helpers ────────────────────────────────────────────────────

def _derive(material: bytes, salt: bytes, dklen: int) -> bytes:
    return pbkdf2_hmac("md5", material, salt, _KDF_ITERS, dklen=dklen)


def _pkcs7_pad(data: bytes) -> bytes:
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    n = data[-1]
    if 1 <= n <= 16 and data[-n:] == bytes([n]) * n:
        return data[:-n]
    return data


def _aes_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.CBC(iv))
    e = c.encryptor()
    return e.update(_pkcs7_pad(data)) + e.finalize()


def _aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.CBC(iv))
    d = c.decryptor()
    return d.update(data) + d.finalize()


# ── Derivations ──────────────────────────────────────────────────────────

def _wrap_key(appname: str) -> bytes:
    app_b = appname.encode("utf-8")
    return _derive(app_b, app_b, _KEY_LEN)


def _wrap_iv_y(appname: str) -> bytes:
    return _derive(_IV_SEED_Y, appname.encode("utf-8"), _IV_LEN)


def _wrap_iv_x(appname: str) -> bytes:
    return _derive(_IV_SEED_X, appname.encode("utf-8"), _IV_LEN)


def _outer_key(appname: str, timestamp: bytes) -> bytes:
    app_b = appname.encode("utf-8")
    return _derive(app_b + timestamp, app_b, _KEY_LEN)


def _outer_iv(appname: str, iv_material: bytes) -> bytes:
    return _derive(iv_material, appname.encode("utf-8"), _IV_LEN)


# ── Public API ───────────────────────────────────────────────────────────

def gen_timestamp() -> bytes:
    """Generate a fresh session timestamp (milliseconds since epoch)."""
    return str(int(time.time() * 1000)).encode("utf-8")


def gen_iv_material() -> bytes:
    """Generate a random IV seed mimicking JS `Math.random()` output."""
    r = secrets.randbits(54) / (1 << 54)
    return f"{r:.17f}".encode("utf-8")


def wrap_triple(
    appname: str,
    payload_bytes: bytes,
    *,
    timestamp: bytes | None = None,
    iv_material: bytes | None = None,
) -> dict[str, str]:
    """Return the ``{x, y, z}`` base64 triple for an encrypted Bubble ES request.

    Server-side cleanup conventions (mirrored from the reference decrypter):

    * ``y`` plaintext contains a ``_1`` internal marker. The server strips
      ``_1`` then any trailing ``\\x01`` PKCS7 padding bytes, yielding the
      clean timestamp used for outer-key derivation.
    * ``x`` plaintext is a string whose PKCS7 padding bytes happen to be
      exactly ``\\r`` (0x0d, pad=13), ``\\x0e`` (pad=14) or ``\\x0f`` (pad=15)
      — because Bubble chooses iv_material lengths 19/18/17 so the padding
      falls into the "strip-safe" set ``{\\r, \\x0e, \\x0f}``. The server
      strips those bytes to recover the clean iv_material.

    We always use a 13-byte timestamp (wrapped as ``timestamp + b"_1"``, so
    the plaintext is 15 bytes and PKCS7 adds exactly one ``\\x01``) and a
    19-byte iv_material (PKCS7 adds thirteen ``\\r``). Outer-key / outer-iv
    derivations use the **clean** values — same as what the server computes.
    """
    if timestamp is None:
        timestamp = gen_timestamp()
    if iv_material is None:
        iv_material = gen_iv_material()

    wrap_k = _wrap_key(appname)
    y_plain = timestamp + b"_1"
    y_ct = _aes_cbc_encrypt(y_plain, wrap_k, _wrap_iv_y(appname))
    x_ct = _aes_cbc_encrypt(iv_material, wrap_k, _wrap_iv_x(appname))
    z_ct = _aes_cbc_encrypt(
        payload_bytes,
        _outer_key(appname, timestamp),
        _outer_iv(appname, iv_material),
    )
    return {
        "y": base64.b64encode(y_ct).decode("ascii"),
        "x": base64.b64encode(x_ct).decode("ascii"),
        "z": base64.b64encode(z_ct).decode("ascii"),
    }


def unwrap_triple(
    appname: str, triple: dict[str, str]
) -> tuple[bytes, bytes, bytes]:
    """Decrypt a ``{x, y, z}`` triple into ``(timestamp, iv_material, payload)``."""
    wrap_k = _wrap_key(appname)
    y_pt = _aes_cbc_decrypt(
        base64.b64decode(triple["y"]), wrap_k, _wrap_iv_y(appname)
    )
    x_pt = _aes_cbc_decrypt(
        base64.b64decode(triple["x"]), wrap_k, _wrap_iv_x(appname)
    )
    # Reverse the server's cleanup: strip _1 marker, then any \x01 padding.
    timestamp = y_pt.replace(b"_1", b"")
    while timestamp.endswith(b"\x01"):
        timestamp = timestamp[:-1]
    # Reverse iv_material cleanup: strip the PKCS7-selected markers.
    iv_material = (
        x_pt.replace(b"\r", b"")
        .replace(b"\x0e", b"")
        .replace(b"\x0f", b"")
    )

    payload_pt = _aes_cbc_decrypt(
        base64.b64decode(triple["z"]),
        _outer_key(appname, timestamp),
        _outer_iv(appname, iv_material),
    )
    return timestamp, iv_material, _pkcs7_unpad(payload_pt)
