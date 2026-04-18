# bubblepwn

Offensive security toolkit for Bubble.io applications — 12 modules covering
reconnaissance, configuration audit, and data extraction, driven from a single
interactive CLI. Includes a working implementation of the Elasticsearch crypto
bypass publicly disclosed in April 2025.

**Author:** [@Siin0pe](https://github.com/Siin0pe) · **License:** MIT

## Features

**Reconnaissance (read-only, passive)**

- `fingerprint` — detect Bubble.io, extract `appname`, session tokens, API keys, CDN/infra
- `plugins` — enumerate Bubble plugins (first-party + marketplace), optionally enrich from the Bubble plugin store
- `datatypes` — list every custom data type and its fields from `static.js` + `/init/data`
- `pages` — enumerate Bubble pages via wordlist (live + `/version-test/`)
- `elements` — rebuild the UI element tree from `dynamic.js`
- `secrets` — scan HTML + bundles for tokens, API keys, URL secrets; verify exposed Google keys

**Audit (active, read-only probing)**

- `config-audit` — security headers, public-editor check, live vs `/version-test/` diff
- `plugin-audit` — flag deprecated / leak-prone plugins, detect third-party data-leak hosts
- `api-probe` — map the Data API and Workflow API surface (meta, obj, wf, swagger)
- `files` — enumerate S3/CDN URLs, test anon access, probe `/fileupload`, optional type-fuzz

**Exploit**

- `es-audit` — Elasticsearch crypto bypass: probe, analyze, dump, forge, encrypt/decrypt
- `workflows` — audit workflow API, detect anon-reachable and temp-password-leaking workflows

**Reporting**

- One `Context` collects findings across every module
- Export as Markdown, HTML, or JSON from a single `report` command
- Optional `--checkpoint` snapshots after each step

## Install

Requires Python 3.11+.

```bash
pipx install bubblepwn
```

Verify:

```bash
bubblepwn --version
bubblepwn modules
```

Reports and dumps land under `./out/` by default, so run `bubblepwn` from the
directory you want the artefacts written to.

## Usage

Three paths, from simplest to most complete.

### 1. Quick fingerprint

Single module, one-shot, no state to manage. Good for confirming a target is a
Bubble.io app and grabbing the `appname`, session tokens, keys, and infra:

```bash
bubblepwn run fingerprint https://app.example.com
```

### 2. Full audit + report

Run every module (recon → audit → exploit) in the right order and export a
structured report:

```bash
bubblepwn flow full https://app.example.com --export out/report.html
```

`.md`, `.html`, and `.json` are all supported — the extension picks the format.
Add `--open` to pop the report in your browser when the flow finishes.

Shorter variants:

```bash
bubblepwn flow recon   https://app.example.com    # passive only
bubblepwn flow audit   https://app.example.com    # + active probing
bubblepwn flow crypto  https://app.example.com    # ES bypass end-to-end
bubblepwn report       https://app.example.com out/report.html   # alias for `flow full --export`
```

### 3. Interactive shell

For iterative work — pick modules, inspect findings, export at the end:

```bash
bubblepwn                                  # launches the REPL
```

```
bubblepwn ❯ target https://app.example.com
bubblepwn ❯ session load session.json          # optional, authenticated session
bubblepwn ❯ modules                             # list modules by phase
bubblepwn ❯ help es-audit                       # module-specific help
bubblepwn ❯ flow recon                          # chain modules
bubblepwn ❯ run es-audit analyze --field-leak   # single module with flags
bubblepwn ❯ findings                            # review what was captured
bubblepwn ❯ report out/session.html
```

Tab-completion works on commands, modules, and targets. History persists to
`~/.bubblepwn_history`.

## Flow presets

| Preset      | Chain                                                                                                                 |
| ----------- | --------------------------------------------------------------------------------------------------------------------- |
| `recon`   | fingerprint → plugins → pages → datatypes → elements → secrets                                                   |
| `audit`   | fingerprint → plugins → config-audit → plugin-audit → api-probe → files (enumerate / test-public / upload-probe) |
| `crypto`  | fingerprint → datatypes → es-audit probe → es-audit analyze --field-leak                                           |
| `exploit` | fingerprint → datatypes → es-audit analyze → workflows analyze                                                     |
| `full`    | recon + audit + exploit (deduplicated)                                                                                |

Every preset accepts `--export <path>`, `--open`, and `--checkpoint`.

## Environment

| Variable                        | Effect                                                                                                                                            |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BUBBLEPWN_LOCAL_DUMP=<dir>`  | Offline mode. HTTP fetches fall back to files in that directory when a matching path exists. Useful for regression tests against a cached mirror. |
| `BUBBLEPWN_CACHE_DIR=<dir>`   | Override the default bundle cache location (`~/.cache/bubblepwn/bundles`).                                                                      |
| `BUBBLEPWN_NO_UPDATE_CHECK=1` | Disable the passive PyPI update check at startup (also auto-skipped when `stdout` is not a TTY).                                                |

## Documentation

- [`docs/cli.md`](docs/cli.md) — shell command reference
- [`docs/modules.md`](docs/modules.md) — module-by-module reference
- [`docs/workflows.md`](docs/workflows.md) — recipes and end-to-end sessions
- [`docs/architecture.md`](docs/architecture.md) — code map for contributors
- [`docs/crypto.md`](docs/crypto.md) — Elasticsearch crypto protocol

## Elasticsearch crypto bypass

Short version: every Bubble SPA encrypts its Elasticsearch requests into a
three-part envelope `{x, y, z}` before sending them, but the entire derivation
hinges on a value every client receives in plaintext — the `appname` slug. The
scheme was reverse-engineered and published in April 2025 by Lucca & Pedro
([`demon-i386/pop_n_bubble`](https://github.com/demon-i386/pop_n_bubble),
[GBHackers coverage](https://gbhackers.com/bubble-io-0-day-flaw/)).

- Cipher: AES-256-CBC + PKCS7
- KDF: PBKDF2-HMAC-MD5 with **7 iterations**, `appname` as salt
- Constant IV seeds `po9` / `fl1`, identical across every Bubble app
- No authentication on the endpoint itself — Bubble has not issued a patch

`bubblepwn` re-implements the primitives from scratch (no upstream code) and
exposes them through `es-audit`: `probe`, `analyze`, `dumpone`, `dumpall`,
`query`, `encrypt`, `decrypt`. See [`docs/crypto.md`](docs/crypto.md) for the
full protocol spec and [`docs/modules.md#es-audit`](docs/modules.md) for the
subcommand reference.

## Contributing

Ideas, bug reports, and new modules are very welcome.

- **Bug reports / feature requests**: open an [issue](../../issues) with the
  (anonymised) target context, the command you ran, and the output.
- **New modules**: follow the short guide in
  [`docs/architecture.md`](docs/architecture.md#adding-a-module). Anything
  dropped into `bubblepwn/modules/` is auto-discovered.
- **Pull requests**: keep them focused, match existing patterns, and add a
  one-line entry to the relevant `docs/*.md` when user-visible.

The project is intentionally small — reading three or four modules is enough to
get the conventions.

## Disclaimer & authorized use

`bubblepwn` is an offensive security research tool. Running it implies
acceptance of the terms below.

- **Authorized testing only.** Use `bubblepwn` only against systems you own or
  that you have prior written authorization to test (formal engagement,
  bug-bounty scope, CTF, training lab).
- **Unauthorized use is prohibited** and is the sole responsibility of the end
  user. The author accepts no liability for it.
- **Public disclosure.** The Elasticsearch bypass targets a Bubble.io flaw that
  was **publicly disclosed in April 2025** by Lucca & Pedro; this project
  re-implements the primitives from the public specification independently.
- **No affiliation.** `bubblepwn` is not affiliated with, endorsed by, or
  sponsored by Bubble Group, Inc.
- **No warranty.** Software provided "as is" per the MIT
  [`LICENSE`](LICENSE).

### Responsible disclosure

- **Vulnerability in a Bubble.io app you discover with this tool**: report it
  privately to the application owner with a reasonable fix window (typically
  90 days) before any public disclosure.

## Credits

- **Tool design and implementation:** [@Siin0pe](https://github.com/Siin0pe).
- **Cryptographic scheme research:** Pablo and Lucca, published April 2025 via
  [`demon-i386/pop_n_bubble`](https://github.com/demon-i386/pop_n_bubble) with
  coverage from GBHackers, Cyberpress, SecurityOnline, and TechNADU.
  `bubblepwn` re-implements the primitives independently and
  wraps them in eleven additional modules covering the rest of the Bubble.io
  attack surface.
