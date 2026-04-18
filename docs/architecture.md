# Architecture

A short map of the code for contributors and module authors.

## Package layout

```
bubblepwn/
├── __main__.py          entry point
├── cli.py               Typer app (subcommands + root callback)
├── shell.py             interactive REPL (prompt_toolkit)
├── ui.py                Rich console helpers (banner, tables, panels)
├── config.py            pydantic `Settings` (env + .env)
├── context.py           `Context` singleton: target, session, findings, schema
├── http.py              shared async HTTP client with rate-limiter
├── logging.py           structlog + Rich handler
├── bubble/              Bubble-specific helpers (domain layer)
│   ├── api.py           `BubbleAPI`: meta, obj, wf, elasticsearch
│   ├── bundle.py        download + cache of /package/* bundles
│   ├── workflow.py      `snapshot_page()` + `BUBBLEPWN_LOCAL_DUMP` fallback
│   ├── schema.py        pydantic models (BubbleType, Field, Page, Element, Plugin)
│   ├── secrets.py       regex rules + scanner
│   ├── key_verify.py    Google Maps key verification
│   ├── es/              Elasticsearch endpoints
│   │   ├── crypto.py        PBKDF2-MD5 × 7 + AES-CBC + wrap_triple / unwrap_triple
│   │   ├── payload.py       search / aggregate / maggregate builders
│   │   └── transport.py     EsTransport (branch-aware)
│   ├── parse/           bundle + HTML parsers
│   │   ├── html.py          bundle URL extraction
│   │   ├── static_js.py     types, fields, plugins, watcher-cache, named blocks
│   │   ├── dynamic_js.py    id_to_path, translations, plugin preload entries
│   │   ├── meta.py          /api/1.1/meta parser ({get, post})
│   │   └── workflow_names.py  heuristic extraction of workflow-like names
│   └── wordlists/       built-in wordlists (+ load(name) helper)
├── modules/
│   ├── base.py          `Module` ABC + `Registry` + `register` decorator + `parse_flags`
│   ├── __init__.py      auto-discovery
│   ├── fingerprint.py   recon
│   ├── plugins.py
│   ├── datatypes.py
│   ├── pages.py
│   ├── elements.py
│   ├── secrets.py
│   ├── config_audit.py  audit
│   ├── plugin_audit.py
│   ├── api_probe.py
│   ├── files.py
│   ├── es_audit.py      exploit
│   └── workflows.py
└── report/
    ├── generator.py     build a `Report` dataclass from the `Context`
    ├── markdown.py      render_markdown
    ├── html_render.py   render_html (self-contained CSS)
    ├── json_render.py   render_json
    └── writer.py        write_report(ctx, path) — picks format by extension
```

## Core contracts

### `Module`

```python
class Module(ABC):
    name: str
    description: str
    category: str               # recon | audit | exploit
    subcommands: tuple[str, ...]
    flags: tuple[str, ...]
    example: str
    needs_auth: bool

    @abstractmethod
    async def run(self, ctx: Context, **kwargs) -> None: ...
```

`run` receives the raw argv list under the `argv` kwarg. Use
`parse_flags(argv)` for flag parsing.

### `Context`

A singleton (`Context.get()`) that owns:

- `target: Optional[Target]` — host, url, scheme, free-form `fingerprint`
  dict populated by the `fingerprint` module
- `session: Optional[Session]` — loaded cookies + arbitrary storage
- `findings: list[Finding]` — append-only via `ctx.add_finding()`
- `settings: dict[str, Any]` — runtime overrides (`set` shell command)
- `schema: BubbleSchema` — cumulative structured state used by every
  module: types, pages, elements, plugins

Switching targets resets the schema.

### `BubbleSchema`

```python
class BubbleSchema(BaseModel):
    app_id: Optional[str]
    app_version: Optional[str]
    env_name: Optional[str]
    page_name_current: Optional[str]
    locale: Optional[str]
    types: dict[str, BubbleType]
    pages: dict[str, BubblePage]
    elements: dict[str, BubbleElement]
    plugins: dict[str, BubblePlugin]
```

Mutation is done through idempotent `upsert_*` methods that merge new
information into existing entries without overwriting known values with
`None`.

### `Finding`

```python
class Finding(BaseModel):
    module: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    title: str
    detail: str = ""
    data: dict[str, Any] = {}
    ts: datetime = utcnow()
```

### `BubbleAPI`

Stateless wrapper around Bubble endpoints with a `branch` flag
(`live` or `test`). Exposes `init_data`, `meta`, `meta_swagger`, `obj`,
`obj_by_id`, `workflow`, `elasticsearch_probe`, `user_heartbeat`.

### `EsTransport`

Wraps encryption + HTTP for the four Elasticsearch endpoints
(`search`, `aggregate`, `msearch`, `maggregate`). Builds a `{x, y, z}`
triple via `crypto.wrap_triple()` for each request.

## Adding a module

Modules are auto-discovered at import time; you don't need to register
them anywhere but the decorator.

1. Create `bubblepwn/modules/<name>.py`.
2. Subclass `Module`, set `name` / `description` / `category` /
   `subcommands` / `flags` / `example`.
3. Decorate with `@register`.
4. Implement `async def run(self, ctx, **kwargs)`.
5. Parse flags with `parse_flags(kwargs.get("argv", []))`.
6. Emit `Finding` objects via `ctx.add_finding()` and mutate
   `ctx.schema` via the `upsert_*` helpers.
7. Restart the shell — auto-discovery picks the module up on import.

A new module idea? Open an issue first to align on scope and where it
fits in the `recon / audit / exploit` taxonomy.

## Report pipeline

```
Context ──build_report()──▶ Report (dataclass)
Report ──render_markdown── text
Report ──render_html    ── text
Report ──render_json    ── text
write_report(ctx, path)     picks renderer by path.suffix
```

The `Report` dataclass is deliberately flat (plain dicts + primitives) so
that `render_json` is trivial (`dataclasses.asdict`) and downstream tools
can consume the JSON without knowing the Python types.

## Cache locations

| Artefact | Default path | Override |
|---|---|---|
| Bundle cache        | `~/.cache/bubblepwn/bundles/`     | `BUBBLEPWN_CACHE_DIR` |
| REPL history        | `~/.bubblepwn_history`            | — |
| ES dumps            | `./out/<host>/es/*.jsonl`         | — |
| Checkpoints         | `./out/<host>/checkpoints/*.json` | — |
| Reports             | wherever `report`/`--export` points | — |

## Testing posture

No test suite ships yet. Two approaches are used in development:

- **Round-trip crypto tests**: `crypto.wrap_triple` / `unwrap_triple` on
  known-good inputs to confirm server compatibility.
- **Offline replay**: set `BUBBLEPWN_LOCAL_DUMP` to a mirror directory
  (produced by any static dumper of your choice) to drive the modules
  without touching the live target.
