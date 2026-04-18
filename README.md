# bubblepwn

Offensive security toolkit for Bubble.io applications, built around a
publicly disclosed cryptographic flaw in Bubble's internal Elasticsearch
API. Knowing the public `X-Bubble-Appname` header of a Bubble app is enough
to forge any request against `/elasticsearch/{search,aggregate,msearch,
maggregate,mget,bulk_watch}` and read any data type without a correctly
configured privacy rule.

**Author:** [@Siin0pe](https://github.com/Siin0pe)
**Based on:** Pablo's research on the Bubble.io Elasticsearch 0-day
([`demon-i386/pop_n_bubble`](https://github.com/demon-i386/pop_n_bubble),
GBHackers, April 2025) + independent research into the surrounding
Bubble attack surface.

## The core exploit

Bubble's SPA encrypts every Elasticsearch request into a three-part envelope
`{x, y, z}` before sending it. The scheme was reverse-engineered and
published in April 2025 (Lucca & Pedro,
[`demon-i386/pop_n_bubble`](https://github.com/demon-i386/pop_n_bubble),
[GBHackers](https://gbhackers.com/bubble-io-0-day-flaw/)). The entire
derivation collapses onto a value that every client receives in plaintext —
the `appname` slug:

- Cipher: AES-256-CBC with PKCS7
- KDF: PBKDF2-HMAC-MD5 with **7 iterations** and `appname` as salt
- Constant IV seeds `po9` and `fl1`, identical across every Bubble app
- No authentication on the endpoint itself

The server therefore accepts any forged triple, and the response comes back
in plaintext JSON. Bubble has not issued a patch.

`bubblepwn` rewrites the primitives from scratch (no dependency on the
unlicensed reference PoC) and wraps them in an interactive CLI focused on
three use cases:

1. **Prove the exploit** on a live target (`es-audit probe`).
2. **Measure the blast radius** by counting records on every data type
   through `/aggregate` — one round-trip per type, ~56 bytes per response
   (`es-audit analyze`).
3. **Exfiltrate data** by paginating `/search` (`es-audit dumpone`,
   `es-audit dumpall`).

The crypto primitives are also exposed as utilities — `decrypt` a captured
triple, `encrypt` an arbitrary payload, `query` any ES endpoint with a
custom JSON body. See [`docs/crypto.md`](docs/crypto.md) for the full
protocol specification and [`docs/modules.md`](docs/modules.md#es-audit)
for the module reference.

## Everything else

The eleven other modules exist to support the core exploit:

- `fingerprint` captures the `appname` and the session tokens.
- `datatypes` enumerates every `custom.*` type discoverable in the
  `static.js` bundle, feeding the exploit with targets.
- `secrets`, `config-audit`, `plugin-audit`, `api-probe`, `files`,
  `workflows` cover adjacent attack surfaces (tokens in bundles,
  misconfigured workflows, open `/fileupload`, etc.).

Every finding — from the crypto bypass and the supporting modules alike —
lands in a single `Context` and can be exported as a structured report
(Markdown / HTML / JSON).

## Install

Requires Python 3.11+. Three install paths, pick the one that matches your
setup. All of them install a `bubblepwn` console script on `PATH` so you can
run the tool from any directory inside the environment.

### From a git clone (editable, recommended for development)

```bash
git clone https://github.com/Siin0pe/bubblepwn.git
cd bubblepwn
pip install -e .
bubblepwn --version
```

### From GitHub directly

```bash
pip install "git+https://github.com/Siin0pe/bubblepwn.git@v0.2.0"
# or the latest main:
pip install "git+https://github.com/Siin0pe/bubblepwn.git"
```

For the private repo during early access, add your GitHub token:

```bash
pip install "git+https://<TOKEN>@github.com/Siin0pe/bubblepwn.git@v0.2.0"
```

### With `pipx` (isolated environment, binary on PATH)

```bash
pipx install "git+https://github.com/Siin0pe/bubblepwn.git"
bubblepwn                     # launch the shell from anywhere
```

### Verify

```bash
bubblepwn --version
bubblepwn modules
```

### Dump artefacts

Reports, checkpoints, ES dumps, and the SQLite rebuild land under `./out/` by
default — run the tool in whichever working directory you want the artefacts
to be written to.

## Documentation

- [`docs/cli.md`](docs/cli.md) — shell command reference
- [`docs/modules.md`](docs/modules.md) — module-by-module reference
- [`docs/workflows.md`](docs/workflows.md) — recipes and end-to-end sessions
- [`docs/architecture.md`](docs/architecture.md) — code map for contributors
- [`docs/crypto.md`](docs/crypto.md) — Elasticsearch crypto internals

## Quick start — demonstrate the exploit

One-shot proof of exploitability against a live app:

```bash
bubblepwn flow crypto https://app.example.com --export out/crypto.html
```

This runs, in order:

1. `fingerprint`   — captures `X-Bubble-Appname`, session tokens, app flags.
2. `datatypes`     — parses `static.js` to enumerate every custom data type.
3. `es-audit probe` — sends one forged `/aggregate` count request; a 200 with
   a `count` field confirms the crypto envelope is accepted.
4. `es-audit analyze --field-leak` — counts records on every type
   anonymously and lists the visible `_source` keys on exposed types.

The report names every leaking type with its record count and flags
sensitive-looking field names (email, siret, iban, token, password,
stripe).

Interactive equivalent:

```
bubblepwn ❯ target https://app.example.com
bubblepwn ❯ flow crypto
bubblepwn ❯ report out/crypto.html
```

## Interactive shell

```bash
bubblepwn                       # launch the shell
```

Typical session:

```
bubblepwn ❯ target https://app.example.com
bubblepwn ❯ session load session.json              # optional
bubblepwn ❯ modules                                 # list modules by phase
bubblepwn ❯ help es-audit                           # show flags + examples
bubblepwn ❯ flow crypto                             # the core demo
bubblepwn ❯ run es-audit dumpone custom.user        # paginate a type
bubblepwn ❯ run es-audit query search '<json>'      # forge any ES request
bubblepwn ❯ report out/report.html
```

## Modules

| Phase   | Module         | Purpose |
|---------|----------------|---------|
| recon   | `fingerprint`  | Detect Bubble.io; extract `appname`, session tokens, keys, infra |
| recon   | `plugins`      | Enumerate Bubble plugins (first-party + marketplace) |
| recon   | `datatypes`    | List custom types + fields (static.js + `/init/data`) |
| recon   | `pages`        | Enumerate Bubble pages via wordlist |
| recon   | `elements`     | Rebuild the UI element tree from `dynamic.js` |
| recon   | `secrets`      | Scan HTML + bundles for tokens, API keys, URL secrets |
| audit   | `config-audit` | Security headers + public-editor probe + live/test diff |
| audit   | `plugin-audit` | Deprecated / leak-prone plugins and hosts |
| audit   | `api-probe`    | Data API + Workflow API surface (meta, obj, wf, swagger) |
| audit   | `files`        | S3/CDN enumeration and `/fileupload` probes |
| **exploit** | **`es-audit`** | **Elasticsearch crypto 0-day: probe, count, dump, forge, encrypt/decrypt** |
| exploit | `workflows`    | Workflow API audit (analyze, invoke, fuzz, compare) |

## Flow presets

```
flow crypto   — fingerprint + datatypes + es-audit probe + es-audit analyze
flow recon    — passive reconnaissance
flow audit    — active probing (GET/OPTIONS only)
flow exploit  — es-audit + workflows
flow full     — recon + audit + exploit
```

Append `--export <path>` to write a report at the end. Append
`--checkpoint` to snapshot findings after each step under
`./out/<host>/checkpoints/`.

## Report formats

`report <path>` and `flow ... --export <path>` pick the format from the
file extension:

- `.md`   — GitHub-flavoured Markdown
- `.html` — self-contained HTML with inline CSS
- `.json` — full report payload

## Environment

| Variable | Effect |
|---|---|
| `BUBBLEPWN_LOCAL_DUMP=<dir>` | Offline mode. HTTP fetches fall back to files in that directory when a matching path exists — useful for regression tests against a cached mirror. |
| `BUBBLEPWN_CACHE_DIR=<dir>`  | Override the default bundle cache location (`~/.cache/bubblepwn/bundles`). |

## Contributing

Ideas, bug reports, and new modules are very welcome.

- **Bug reports / feature requests**: open an
  [issue](../../issues). Include the target context (anonymised), the
  command you ran, and the output or stack trace.
- **New modules**: follow the short guide in
  [`docs/architecture.md`](docs/architecture.md#adding-a-module). The
  module registry auto-discovers anything dropped into
  `bubblepwn/modules/`.
- **Research notes**: the pentest taxonomy in `docs/modules.md` is open
  to expansion — new Bubble internal endpoints, bypass primitives, or
  supporting attack surfaces are fair game.
- **Pull requests**: keep them focused, match existing patterns, and add
  a one-line entry to the relevant `docs/*.md` when user-visible.

The project is intentionally small — ~15 files in `bubblepwn/`, no heavy
framework. Reading three or four modules is enough to get the conventions.

## Disclaimer

Use against assets you own or are explicitly authorised to test. The
cryptographic endpoint is public and unpatched, which does not grant the
right to exfiltrate data from third parties.

## Credits

- **Tool design and implementation:** [@Siin0pe](https://github.com/Siin0pe).
- **Cryptographic scheme research:** Pablo (and Lucca), published April 2025
  via [`demon-i386/pop_n_bubble`](https://github.com/demon-i386/pop_n_bubble)
  with coverage from GBHackers, Cyberpress, SecurityOnline, and TechNADU.
  `bubblepwn` re-implements the primitives independently (no upstream code)
  and wraps them in twelve additional modules covering the rest of the
  Bubble.io attack surface.
- **Additional research:** desk research on Bubble's Data API, Workflow API,
  file storage, plugin ecosystem, option-set leaks, and configuration
  pitfalls.
