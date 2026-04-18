# Module reference

All modules implement `bubblepwn.modules.base.Module`. They are auto-discovered
at import time and registered into the shared registry. Each module is tagged
with a `category` (`recon`, `audit`, or `exploit`) that drives shell grouping
and the `flow` presets.

Common conventions:

- **Flags** are parsed with `parse_flags()`. Accepts `--key value`,
  `--key=value`, and `--flag` (→ `True`). Dashes in keys become underscores
  in the parsed dict.
- **Schema accumulation**: every module reads from and writes to the shared
  `ctx.schema` (`BubbleSchema`). Running modules in order enriches the
  schema; the `flow` presets are calibrated for this.
- **Findings**: modules emit structured `Finding` objects via
  `ctx.add_finding()`. Severities: `critical`, `high`, `medium`, `low`, `info`.

---

## Recon phase

Passive reconnaissance. No state changes, minimal request volume.

### `fingerprint`

Confirms the target is a Bubble.io application and extracts all public
metadata from the landing HTML.

- **Flags**: —
- **Example**: `run fingerprint`

Extracts:

- Detection score (0–100) with per-signal breakdown
- App id, environment name, app version, current page name, locale
- Session tokens: `bubble_session_uid`, `bubble_plp_token`,
  `bubble_page_load_id`
- Public keys: Google Maps, Google Analytics (GA4 / UA), GTM, Stripe
  publishable keys
- Page metadata: title, description, Open Graph tags, canonical, favicon,
  language
- Infrastructure: bubble CDN bucket, CloudFront domains, S3 buckets,
  third-party script hosts
- Plugins (coarse): timestamp ids from `headers_source_maps`, mentioned
  libraries
- Bundle hashes per kind (`static_js`, `dynamic_js`, `run_js`, `run_css`,
  `early_js`, `pre_run_jquery_js`)

Findings: detection finding (info), Google Maps key exposure (low),
additional Google API keys (medium), test-environment detection (medium).

### `plugins`

Enumerates every Bubble plugin referenced by the application.

- **Flags**: `--page <name>`, `--enrich`
- **Example**: `run plugins --enrich`

Sources combined:

1. HTML `plugin_main_headers_<id>` entries (15 ids in the reference dump).
2. `static.js` → `hardcoded_plugins['<name>']` (Bubble first-party plugins
   such as `ionic`, `chartjs`, `select2`, `selectPDF`, `draggableui`,
   `progressbar`, `apiconnector2`, `fullcalendar`, `interactions`,
   `materialicons`, `multifileupload`).
3. `dynamic.js` → `preloaded['translation/plugin:<id>:<locale>']` — the most
   complete source (all third-party plugins with their preloaded locales).

Classifies each plugin as `first_party`, `third_party`, `library`, or
`unknown` and records the sources and translation locales.

#### Enrichment

Every detected plugin is decorated with the most useful metadata we can
resolve:

- **Offline** (always on):
  - First-party slugs (`chartjs`, `stripe`, `select2`, …) are mapped to a
    built-in catalogue → `display_name`, `vendor`, `docs_url`.
  - Marketplace timestamp IDs (`<13-digit-ms>x<big-int>`) yield a
    `created_at` date (first publication, parsed from the ID) and a
    canonical `marketplace_url` (`https://bubble.io/plugin/<id>` — Bubble
    redirects to the slugged version).

- **Online** (`--enrich`, opt-in): one HTTPS request per third-party
  plugin to `bubble.io/plugin/<id>`; the response's
  `<meta property="og:*">` tags populate `display_name`, `description`,
  `icon_url`, and the slugged `marketplace_url`. Failures (404, timeout)
  are silently ignored — the plugin keeps whatever the offline pass gave it.

The enriched fields flow through to `plugins` / `plugin-audit` findings
and are rendered as a table in the Markdown / HTML reports, with the
marketplace URL exposed as a clickable link.

### `datatypes`

Lists Bubble custom data types and their fields.

- **Flags**: `--probe`, `--fetch-all`, `--list-fields`, `--show-fields`,
  `--type <name>`, `--export-type <name>`
- **Example**: `run datatypes --probe --show-fields --type user`

Primary source (v0.2.20+): the `static.js` **DefaultValues** block is
keyed by owning type — `{<type_name>: [field_entries]}` — so every page's
bundle ships the exact `type → fields` mapping for a slice of the app.
No Data API call, no session, no `--probe` required to get per-type
fields. A full `--fetch-all` walks every page's bundle and merges them.

Sources, in priority order:

1. `static.js` — `custom.<type_name>` references + the **DefaultValues**
   catalogue (a global list of `{name, value, display}` triples: raw DB
   column, canonical Bubble type, human label). These field triples are
   **not** attached to a specific type — Bubble does not encode ownership
   in the bundle. Use `--list-fields` to view the flat catalogue.
2. `/api/1.1/init/data` — populates the `user` type with the current
   user's field names, inferring types from the key suffix convention.
3. (`--probe`) `/api/1.1/meta` — canonical schema if the Data API is
   open. Emits a **medium** finding if the endpoint responds.
4. (`--probe`) `/api/1.1/obj/<type>?limit=1` — confirms privacy exposure
   **and** extracts real field names from the returned record. Emits a
   **high** finding listing types readable anonymously.
5. (`--fetch-all`) Refetches each known page's `static.js` and merges
   the types + field triples parsed from every page.
6. (`--export-type <name>`) Paginates `/api/1.1/obj/<name>` anonymously
   until exhaustion and stores every record on the schema's
   `sample_records`.

Rendering flags:

- `--list-fields` — prints the flat DefaultValues catalogue (display
  label · canonical type · raw DB column). Owner type is unknown.
- `--show-fields` — prints one table per type that has mapped fields
  (from `init/data` or `--probe`), merged with the DefaultValues
  catalogue so each row shows the Bubble type + human label.

### `pages`

Enumerates Bubble pages via wordlist probing.

- **Flags**: `--fetch-all`, `--include-test`, `--wordlist <file>`
- **Example**: `run pages --fetch-all`

Uses a built-in wordlist of common names (login, signup, dashboard, admin,
etc.) plus any file supplied with `--wordlist`. For each candidate, a GET
is sent and the response inspected:

- Bundle paths returned by the server include the real page name; a mismatch
  between the requested name and the served page indicates a redirect to
  `/index`.
- `--fetch-all` downloads `static.js` + `dynamic.js` for each discovered
  page, enabling downstream enrichment (by `datatypes`, `elements`).
- `--include-test` also probes `/version-test/<page>`. Emits a **medium**
  finding if test-branch pages are reachable without HTTP Basic Auth.

### `elements`

Rebuilds the UI element hierarchy of each page without a browser.

- **Flags**: `--fetch-all`, positional `<page-name>`
- **Example**: `run elements --fetch-all`

Strategy (purely HTTP-based, no Playwright):

1. Parse `dynamic.js` → `id_to_path` dictionary mapping each element id to
   its `%p<n>.<ancestor>.%el.<parent>...` path.
2. Parse `static.js` for `{"name":"...","bubble_id":"..."}` neighbourhoods
   to enrich ids with human names.
3. Reconstruct parent/child relationships by splitting the path.

Renders as a Rich `Tree`, one per page. With `--fetch-all`, processes every
page already present in `ctx.schema.pages`.

### `secrets`

Scans HTML and JS bundles for tokens, API keys, and URL-embedded secrets.

- **Flags**: `--include-runtime`, `--fetch-all`, `--verify-keys`,
  `--min-severity <lvl>`
- **Example**: `run secrets --verify-keys`

Detection rules (`bubblepwn/bubble/secrets.py`):

- Third-party high-confidence tokens: Stripe (`sk_live_`, `rk_live_`,
  `whsec_`, `sk_test_`), OpenAI (`sk-`, `sk-proj-`), Anthropic (`sk-ant-`),
  Google (`AIza…`), AWS access keys (`AKIA`/`ASIA`), GitHub PATs, Slack
  tokens, SendGrid, Mailgun, Twilio, JWT, PEM private keys.
- Bubble-specific, context-gated: 64-hex API tokens (must appear near
  `bearer` / `api_token` / `bubble_api` within 140 chars to avoid matching
  every SHA-256 in the bundle), user session ids (`\d{13}x\d{15,20}`).
- URL-embedded secrets: `?api_key=…`, `?token=…`, `?bearer=…`, Basic Auth in
  URL.
- API Connector response schema cache: standard OAuth-ish fields
  (`access_token`, `refresh_token`, `id_token`, `bearer_token`, `session_id`,
  `client_secret`) — Tier 6.4.
- Option Set attribute values (context-gated on `OptionSet` /
  `option_set`) — Tier 6.1.

With `--verify-keys`, each matched Google key is tested against ~10 Google
Maps APIs to classify restrictions (`OPEN` / `REFERER_RESTRICTED` /
`API_NOT_ENABLED` / `INVALID_KEY` / `QUOTA_EXCEEDED` / `BILLING_DISABLED`).
A key reaching `OPEN` on any API triggers a **high** finding
(`ABUSABLE` verdict).

`--include-runtime` also scans `run.js` (3+ MB, mostly framework — lower
signal-to-noise).

---

## Audit phase

Active probing, GET/OPTIONS only. No writes, no state changes.

### `config-audit`

- **Subcommands**: `headers`, `editor`, `version-diff`, `all`
- **Flags**: `--app-id <slug>`, `--page <name>`, `--pages a,b,c`
- **Example**: `run config-audit all`

`headers`: fetches the target root and rates six response headers
(`strict-transport-security`, `content-security-policy`, `x-frame-options`,
`x-content-type-options`, `referrer-policy`, `permissions-policy`).
Fingerprint-leak headers (`x-powered-by`, `x-bubble-perf`, `cf-ray`, etc.)
are listed in a secondary panel.

`editor`: probes `https://bubble.io/page?name=<page>&id=<app_id>&version=<v>`
for both `live` and `test`. Distinguishes `APP_NOT_FOUND` (404),
`PUBLIC_EDITOR` (editor markers present without login wall),
`LOGIN_REQUIRED`, and `EDITOR_PAGE_NO_LOGIN_SIGN`. Emits a **critical**
finding on `PUBLIC_EDITOR`.

`version-diff`: for each known page, GETs `<base>/<page>` and
`<base>/version-test/<page>`, records status codes, whether test requires
Basic Auth, and whether bundle hashes differ. Emits a **high** finding if
test-branch pages are reachable anonymously.

`all`: runs `headers`, then `editor`, then `version-diff`.

### `plugin-audit`

- **Subcommands**: `check`, `leaks`, `all`
- **Flags**: `--list <file>`, `--max-age-days <N>`
- **Example**: `run plugin-audit all`

`check`: cross-references every plugin in `ctx.schema.plugins` against the
built-in `deprecated_plugins.txt` wordlist (plus any file passed via
`--list`). Plugins whose timestamp id decodes to more than
`--max-age-days` days ago (default 3 years) are flagged as **old**.

`leaks`: classifies every host from `ctx.target.fingerprint.infra
.third_party_script_hosts` using the built-in `sketchy_plugin_hosts.txt`
(analytics vendors, session-replay tools, ad networks, error/APM services).
Unknown hosts are listed separately, and raw `*.s3.amazonaws.com` domains
are flagged as **medium** (supply-chain risk).

### `api-probe`

- **Flags**: `--include-test`, `--methods`, `--idor`, `--workflows`,
  `--enumerate`, `--max-types <N>`
- **Example**: `run api-probe --include-test --idor`

Audits the Bubble Data API + Workflow API surface:

1. `GET /api/1.1/meta` — parses the `{get, post}` envelope, registers every
   type from `get`, flags every `post.endpoint` with
   `auth_unecessary: true` as a **high** finding (workflows exposed
   without auth).
2. `GET /api/1.1/meta/swagger.json` — flag **medium** if present.
3. For each type (up to `--max-types`, default 50): `GET /api/1.1/obj/<type>?limit=1`.
   Open types are tallied into a **high** finding.
4. (`--idor`) Re-GET the first record via `/obj/<type>/<id>` to detect
   search-vs-direct privacy-rule asymmetry.
5. (`--methods`) `OPTIONS /obj/<type>` records the `Allow:` header (method
   asymmetry).
6. (`--workflows`) Actively invokes every no-auth workflow from meta with
   an empty POST body. Successful 2xx responses are flagged **critical**.
7. `/elasticsearch/msearch` + `/user/hi` probes.
8. (`--include-test`) Runs the full battery a second time under
   `/version-test/`.

### `files`

- **Subcommands**: `enumerate`, `test-public`, `upload-probe`, `type-fuzz`
- **Flags**: `--max <N>`, `--confirm`
- **Example**: `run files enumerate`  (then `test-public`, `upload-probe`)

`enumerate`: walks the current HTML, static/dynamic bundles, and every
sample record stored in the schema to collect URLs matching Bubble's file
patterns (`s3.amazonaws.com/appforest_uf/*`, `*.cdn.bubble.io/*`). Results
are stashed in `ctx.settings["_files_discovered"]`.

`test-public`: sends HEAD (falls back to GET on 30x/405) against each URL
anonymously. For every CDN URL, also tests the direct `s3.amazonaws.com`
origin as a CDN-bypass check. 200 responses are flagged **high**, CDN
bypasses **medium**.

`upload-probe`: POSTs a small `{public:true, ...}` payload to
`/fileupload/geturl` without auth. Classification:

- 2xx + `amazonaws` in body → **critical** (presigned S3 credentials
  returned anonymously).
- 400 with Bubble `ClientError` → **medium** (endpoint reachable, requires
  specific `serialized_context` / `element_id`).
- 401 / 403 → restricted.
- 404 → disabled.

`type-fuzz --confirm`: **opt-in, mutating**. Sends successive
`/fileupload/geturl` requests declaring `.html`, `.svg`, `.js` file types to
confirm the server does not enforce MIME restrictions. The actual S3 PUT is
not performed — the mere return of a presigned URL already proves the
absence of server-side filtering (stored-XSS vector on the CDN).

---

## Exploit phase

Mutating operations and / or bulk data extraction. Opt-in.

### `es-audit`

Exploits the Bubble Elasticsearch crypto bypass
([`docs/crypto.md`](./crypto.md)): `X-Bubble-Appname` is the only "secret",
PBKDF2-MD5 × 7 and constant wrapper IVs `po9` / `fl1` are shared across
every Bubble app. The module rewrites the primitives from scratch and
exposes them as eight subcommands covering the full spectrum from
proof-of-exploit to bulk exfiltration.

- **Subcommands**: `probe`, `analyze`, `dumpone <type>`, `dumpall`,
  `sqlite [path]`, `query <endpoint> '<json>'`, `encrypt '<json>'`,
  `decrypt <y> <x> <z>`
- **Flags**: `--compare`, `--field-leak`, `--batch`, `--branch test`,
  `--endpoint aggregate|search`, `--type <name>`, `--types t1,t2`,
  `--confirm`, `--auth`, `--batch-size <N>`, `--max <N>`,
  `--appname <slug>`, `--sqlite`
- **Example**: `run es-audit analyze --type user --field-leak`

#### `probe`

Minimal proof-of-exploit. Sends **one** forged `/elasticsearch/aggregate`
request with a `{fns: [{n: "count"}]}` payload against a known type
(the first custom type from the schema, or `user` as fallback).

A 200 response with a `count` field in the body is sufficient evidence
that (a) the `X-Bubble-Appname` envelope is accepted and (b) the endpoint
is reachable without authentication — emits a **critical** finding
immediately and prints the exact record count.

Use this as a 10-second sanity check before running the full `analyze`.

#### `analyze`

The default mode. Iterates over every type in `ctx.schema.types` and sends
one count-only request per type. ~56 bytes per response (vs ~670 for a
single-record `search`) — hundreds of types can be swept in seconds.

Findings:

- **critical** — summary finding listing every exposed type with its count
  and the total record volume leakable anonymously.
- **high** — per-type "tautology suspect" finding when anonymous and
  authenticated counts match (requires `--compare`).
- **high** — per-type "sensitive fields visible" finding when
  `--field-leak` is active (see below).

Flags:

- `--type <name>` — **single-table mode**: run analyze against exactly
  one type (skips the full schema iteration). Use this to focus an
  audit on a specific table, e.g. `run es-audit analyze --type user
  --field-leak`.
- `--types a,b,c` — restrict to a comma-separated list of types
  (overrides the schema-derived list).
- `--compare` — also query with `ctx.session.cookies`; required for
  tautology / empty-equals-empty detection.
- `--field-leak` — for every exposed type, pull one record via `/search`
  and list the visible `_source` keys. Sensitive-looking field names
  (email, phone, siret, iban, token, password, stripe) trigger an
  additional **high** finding.
- `--batch` — use `/maggregate` to batch all counts in a single HTTP
  request. Falls back to sequential on length mismatch.
- `--endpoint aggregate|search` — pick the ES endpoint used for
  counting (default: `aggregate`; `search` falls back to `hits.total`).
- `--appname <slug>` — override the appname read from the schema.

#### `dumpone <type>`

Paginates `/search` (`from` + `n=1000` by default) until `at_end: true`
and writes `out/<host>/es/<type>.jsonl`, one record per line. Emits a
**high** finding when run anonymously.

Flags: `--batch-size <N>` (default 1000), `--max <N>` (cap records),
`--auth` (use loaded session cookies).

#### `dumpall`

Runs an aggregate pass to identify exposed types, then calls `dumpone`
for each. Gated behind `--confirm` due to data-volume risk.

Flags:

- `--type <name>` / `--types a,b,c` — dump only a specific type or a
  comma-separated list (skips the initial discovery sweep).
- `--sqlite` — after the dump finishes, automatically build the SQLite
  database (see `sqlite` subcommand below).
- `--batch-size <N>`, `--max <N>`, `--auth` — forwarded to each
  underlying `dumpone`.

#### `sqlite [path]`

Rebuild a SQLite database from the JSONL dumps in `out/<host>/es/`. One
table per Bubble data type. Column types are inferred from Bubble's
field naming convention (`_number`, `_boolean`, `_date`, `___<type>`)
and from the JSON shape seen in the records.

Reference-style Bubble fields (`<creator_id>__LOOKUP__<target_id>`) get
a companion `<field>__ref_id` column containing the extracted target
id — so foreign-key joins across tables are direct:

```sql
SELECT d.title_text, u.email_text
FROM t_custom_doc d
JOIN t_user u ON d."Created By__ref_id" = u._id;
```

Flags:

- `--type <name>` — rebuild only a single type's table (must already
  have a JSONL dump on disk).
- Default output path: `out/<host>/es.sqlite`. Pass a positional path
  to override.

#### `query <endpoint> '<json>'`

Power-user escape hatch. Encrypts an arbitrary JSON payload into a
`{x, y, z}` triple and sends it to any Elasticsearch endpoint — `search`,
`aggregate`, `msearch`, `maggregate`, `mget`, `bulk_watch`. Prints the raw
decoded response.

```
run es-audit query aggregate '{"appname":"SLUG","app_version":"live","type":"custom.x","constraints":[],"aggregate":{"fns":[{"n":"count"}]},"search_path":"{}"}'
```

Useful for trying constraint injection, cursor enumeration beyond the
built-in limits, or probing endpoints that `analyze` / `dumpone` don't
target directly (`/bulk_watch`, `/mget`).

#### `encrypt '<json>' [--appname <slug>]`

Utility: encrypt a plaintext JSON payload into a `{y, x, z}` triple
without sending anything. Prints the base64-encoded triple. Useful for
scripting custom attack flows externally or feeding another tool (Burp,
curl).

Appname is read from `--appname` or from `ctx.schema.env_name` (populated
by `fingerprint`).

#### `decrypt <y> <x> <z> --appname <slug>`

Utility: decrypt a captured triple. Prints the timestamp, iv_material,
and the decoded JSON payload. Works offline — no target required, no
network traffic. Let the analyst inspect payloads captured in Burp /
devtools against any Bubble app.

### `workflows`

- **Subcommands**: `analyze`, `invoke <name>`, `fuzz <name>`, `compare <name>`
- **Flags**: `--wordlist <file>`, `--max <N>`, `--deep-params`,
  `--include-test`, `--body '<json>'`, `--branch test`, `--auth`
- **Example**: `run workflows analyze --deep-params`

`analyze`: probes candidate workflow names via empty POST. Sources:
`/meta.post[].endpoint`, the built-in 95-entry wordlist, any file supplied
via `--wordlist`, and snake-case identifiers extracted from the JS bundle
that match auth / password / reset / admin keywords. Classification:

| Label | HTTP | Meaning |
|---|---|---|
| `BLOCKED` | 404 | absent or private |
| `AUTH`    | 401 / 403 | exists, auth required |
| `MISSING` | 400 + `MISSING_DATA` | exists, first missing param leaked |
| `INVALID` | 400 (other) | exists, invalid payload |
| `OPEN_OK` | 2xx | executed anonymously (**critical**) |
| `ERROR`   | network | unreachable |

With `--deep-params`, iterates on 400 responses to reconstruct the full
parameter list of each workflow by filling placeholders one at a time.

Automatic temp-password leak scan: regex on every response body for
`"password"`, `"temp_pass"`, `"reset_token"` fields. A match is rendered
inline and added to the findings with **critical** severity when combined
with a reset-related workflow name.

`invoke <name>`: utility — POST / GET the workflow with a user-supplied
`--body '<json>'`. Prints status + body.

`fuzz <name>`: learns the workflow's parameters via `analyze` logic, then
sweeps each parameter with `null`, empty string, string-that-looks-like-a-
number, `"true"`, 10 000-char text, `-1`, `2^53-1`, special characters,
SQL-like injection, deeply nested list. Records every response.

`compare <name>`: POSTs the same body anonymously and with the session
cookies. If both return 2xx with identical bodies, a **high** finding
("possible `Ignore privacy rules`") is emitted.
