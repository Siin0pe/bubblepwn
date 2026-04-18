# Recipes

This page documents typical end-to-end sessions. None of the commands here
are destructive by default — mutating operations (`files type-fuzz`,
`es-audit dumpall`, `workflows invoke/fuzz`) are gated behind explicit
flags.

## 1. Quick triage

A five-minute readout to decide whether a target is worth a deeper look.

```
bubblepwn ❯ target https://app.example.com
bubblepwn ❯ run fingerprint
bubblepwn ❯ run secrets --verify-keys
bubblepwn ❯ run config-audit headers
bubblepwn ❯ findings
```

What you get:

- Bubble confirmation + app id + tokens captured
- Any leaked third-party secrets + the Google Maps key verdict
  (`ABUSABLE` vs `RESTRICTED`)
- Security header ratings

## 2. Full audit in one command

Runs recon + audit + exploit (analysis-only) sequentially, then writes a
consolidated report.

```
bubblepwn ❯ target https://app.example.com
bubblepwn ❯ flow full --export out/audit-2026-04.html --checkpoint
```

`--checkpoint` writes one JSON snapshot per step under
`out/<host>/checkpoints/` so you can inspect intermediate state or resume
analysis later.

## 3. Authenticated comparison

Some privacy-rule misconfigurations only surface when you compare
authenticated and anonymous responses.

```
bubblepwn ❯ target https://app.example.com
bubblepwn ❯ session load bubble_session.json
bubblepwn ❯ run fingerprint
bubblepwn ❯ run datatypes
bubblepwn ❯ run es-audit analyze --compare --field-leak
```

`--compare` re-runs the `/aggregate` count for every type with the session
cookies. A type whose anonymous count equals the authenticated count is
flagged as a possible always-true or empty-equals-empty rule.

`--field-leak` pulls one record per exposed type and lists the visible
`_source` keys. Keys with sensitive-looking names (email, siret, iban,
token, password, stripe) raise a dedicated high-severity finding.

## 4. Targeted type dump

After identifying an exposed type:

```
bubblepwn ❯ run es-audit analyze
[…]
custom.order                    245       EXPOSED
[…]
bubblepwn ❯ run es-audit dumpone custom.order
```

Writes `out/<host>/es/custom.order.jsonl` (one record per line, UTF-8).

## 5. Workflow API deep dive

```
bubblepwn ❯ run workflows analyze --deep-params --max 200
```

The `--deep-params` pass iterates on `400 MISSING_DATA` responses to
reconstruct the full parameter schema of each public workflow without ever
reading `/api/1.1/meta` (useful when `meta` is disabled).

Temp-password exploits are checked automatically: workflow names matching
`reset|forgot|temp|password` whose response contains a password-like field
raise a high-severity finding.

Active invocation (risky — can mutate state):

```
bubblepwn ❯ run workflows invoke reset_password --body '{"email":"admin@example.com"}'
bubblepwn ❯ run workflows compare reset_password --body '{"email":"admin@example.com"}'
```

`compare` POSTs the same body anonymously and with the session cookies;
identical 2xx responses indicate the workflow likely ignores privacy rules.

## 6. File storage review

```
bubblepwn ❯ run files enumerate                 # harvest URLs from HTML + bundles + records
bubblepwn ❯ run files test-public               # GET each URL anonymously
bubblepwn ❯ run files upload-probe              # test /fileupload/geturl anon
```

`upload-probe` does NOT upload anything — it only sends a JSON body to
`/fileupload/geturl`. The endpoint's response (presigned credentials vs
400 vs 401 vs 404) is enough to classify exposure.

To confirm absence of server-side file-type filtering:

```
bubblepwn ❯ run files type-fuzz --confirm
```

This tries `.html`, `.svg`, `.js` file types. Still no upload actually
completes — `/fileupload/geturl` returning a URL proves the filter is
absent.

## 7. CI-style automation

One-shot execution from the command line:

```bash
bubblepwn run fingerprint https://app.example.com
bubblepwn run secrets https://app.example.com
```

For a full scripted audit, drive the shell via a Python snippet:

```python
import asyncio
from bubblepwn.context import Context
from bubblepwn.modules import registry
from bubblepwn.report import write_report

async def audit(url: str) -> None:
    ctx = Context.get()
    ctx.set_target(url)
    for name in ("fingerprint", "plugins", "pages", "datatypes",
                 "elements", "secrets", "config-audit",
                 "plugin-audit", "api-probe", "es-audit"):
        await registry.get(name).run(ctx, argv=[])
    write_report(ctx, f"out/{ctx.target.host}.html")

asyncio.run(audit("https://app.example.com"))
```

## 8. Offline replay

Set `BUBBLEPWN_LOCAL_DUMP` to a directory that mirrors the target host
(e.g. `site_dump/app.example.com/`). `snapshot_page()` and
`fetch_bundle_text()` will read from disk when a matching path exists and
fall back to HTTP otherwise. Useful for regression tests and for scanning
without touching the live target.

```bash
export BUBBLEPWN_LOCAL_DUMP=/path/to/mirror
bubblepwn
```

## 9. Reporting and handoff

At any point:

```
bubblepwn ❯ report out/interim.md
bubblepwn ❯ export out/raw.json        # plain findings dump
```

The rendered report (`.md` / `.html`) contains four sections:

1. Summary — finding counts per severity.
2. Target fingerprint — app/env/version, flags, session tokens, public
   keys, infrastructure, page metadata.
3. Application schema — data types, pages, plugins.
4. Findings — one sub-section per severity level, each finding numbered
   `F-NNN` with module, timestamp, detail, and a truncated JSON payload.
