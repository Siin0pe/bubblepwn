# CLI reference

`bubblepwn` runs either as an interactive shell or as a one-shot command.

## One-shot invocation

```bash
bubblepwn                                          # launch the interactive shell
bubblepwn shell                                    # same as above
bubblepwn modules                                  # list modules and exit
bubblepwn run <module> <url> [--session <file>] [--report <path>] [--open] [module args...]
bubblepwn flow <preset> <url> [--session <file>] [--export <path>] [--open] [--checkpoint]
bubblepwn report <url> <path> [--session <file>] [--open]
bubblepwn --version | -V                           # print the version and exit
bubblepwn --verbose | -v ...                       # enable debug-level logs (incl. httpx)
```

Each subcommand accepts its own `--help`:

```bash
bubblepwn run --help
bubblepwn flow --help
bubblepwn report --help
```

### Root flags

| Flag | Effect |
|---|---|
| `--version` / `-V` | Print the version and exit. |
| `--verbose` / `-v` | Enable DEBUG-level logs. By default `httpx`, `httpcore`, `h11`, `urllib3`, `asyncio` are silenced for readability — `--verbose` restores them. |

### Per-command flags

| Command | Flag | Effect |
|---|---|---|
| `run`    | `--session <file>` | Load cookies/storage from a JSON file before running. |
| `run`    | `--report <path>`  | Write a structured report (`.md` / `.html` / `.json`) after the run. |
| `run`    | `--open`           | Open the generated report in the default browser. |
| `flow`   | `--session <file>` | Load cookies/storage from a JSON file. |
| `flow`   | `--export <path>`  | Write a structured report at the end of the flow. |
| `flow`   | `--open`           | Open the exported report in the default browser. |
| `flow`   | `--checkpoint`     | Write a findings snapshot after each step under `out/<host>/checkpoints/`. |
| `report` | `--session <file>` | Load cookies/storage before running the full flow. |
| `report` | `--open`           | Open the generated report in the default browser. |

`bubblepwn report <url> <path>` is shorthand for `flow full <url> --export <path>`.

Anything after `bubblepwn run <module> <url>` that is not one of the options
above is forwarded as-is to the module's own flag parser:

```bash
bubblepwn run es-audit https://app.cible.io analyze --compare --type user
bubblepwn run secrets   https://app.cible.io --verify-keys --min-severity medium
bubblepwn run workflows https://app.cible.io analyze --deep-params
```

---

## Interactive shell commands

All commands below are typed at the `bubblepwn ❯` prompt.

### `target <url>`

Set the current target. Accepts a bare host (`app.example.com`) — the scheme
is normalised to `https`. Switching to a different host resets the cumulative
schema stored on the context.

```
bubblepwn ❯ target https://app.example.com
bubblepwn ❯ target                       # prints the current target, or "no target"
```

### `session <subcommand> [file]`

Manage an authenticated session. The session object carries cookies and an
arbitrary `storage` blob; modules read `ctx.session.cookies` when they need
to authenticate requests.

| Subcommand | Syntax | Effect |
|---|---|---|
| `load`  | `session load <file>`  | Load cookies/storage from a JSON file. Accepts Playwright-style `{"cookies":[{"name":..,"value":..}]}` exports. |
| `save`  | `session save <file>`  | Persist the current session to disk. |
| `clear` | `session clear`        | Drop the session from the context. |
| `show`  | `session show`         | Print a JSON summary of the current session. |

### `modules`

List every registered module, grouped by phase (RECON / AUDIT / EXPLOIT)
with a one-line description and a copy-paste example.

### `help [<module> | flow]`

Without argument, print the command reference. With `flow`, break down every
flow preset into its ordered list of module calls. With a module name, print
the full help panel for that module: subcommands, flags, example, notes.

```
bubblepwn ❯ help
bubblepwn ❯ help flow
bubblepwn ❯ help es-audit
```

### `run <module> [args...]`

Execute a single module against the current target. Arguments after the
module name are passed as `argv` to the module's `run` method and parsed
with the shared flag parser (`--key value`, `--key=value`, `--flag`).

```
bubblepwn ❯ run fingerprint
bubblepwn ❯ run secrets --verify-keys --min-severity medium
bubblepwn ❯ run es-audit analyze --compare
bubblepwn ❯ run es-audit analyze --type user --field-leak   # single-table audit
bubblepwn ❯ run datatypes --probe --show-fields             # detailed per-type fields
bubblepwn ❯ run es-audit dumpall --confirm --sqlite         # dump + rebuild SQLite
```

### Focused single-table audit

Every heavy subcommand of `es-audit` accepts `--type <name>` to restrict
work to one data type:

```
bubblepwn ❯ run es-audit analyze --type user --field-leak
bubblepwn ❯ run es-audit dumpall --type user --confirm
bubblepwn ❯ run es-audit sqlite --type user
```

Handy for pointed audits (e.g. only the `user` table) or for smoke-
testing a specific finding before rerunning a full flow.

### `flow <preset> [--export <path>] [--open] [--checkpoint]`

Chain several modules in sequence.

| Preset   | Modules (in order) |
|---|---|
| crypto   | fingerprint, datatypes, es-audit probe, es-audit analyze --field-leak |
| recon    | fingerprint, plugins, pages, datatypes, elements, secrets |
| audit    | config-audit all, plugin-audit all, api-probe, files (enumerate, test-public, upload-probe) |
| exploit  | es-audit analyze, workflows analyze |
| full     | recon → audit → exploit |

Options:

- `--export <path>` — write a structured report at the end. The format is
  chosen by the file extension (`.md`, `.html`, `.json`).
- `--open` — after exporting, open the report in the default browser.
- `--checkpoint` — write a findings snapshot after each step under
  `out/<host>/checkpoints/NN_<module>.json`.

A failing step does not abort the flow; the error is printed and execution
continues with the next step.

```
bubblepwn ❯ flow recon
bubblepwn ❯ flow crypto --export out/crypto.html --open
bubblepwn ❯ flow full --export out/audit.html --checkpoint
```

### `report <path> [--open]`

Export the current context (target + findings + schema) as a structured
report. Does not run any module. Format picked by extension.

```
bubblepwn ❯ report out/report.md
bubblepwn ❯ report out/report.html --open
bubblepwn ❯ report out/report.json
```

### `findings`

Print the list of findings accumulated in this session, ordered by insertion
with their severity, module, and title.

### `context`

Print a concise snapshot of the internal state: current target, session
status, number of findings, runtime settings.

### `export <path>`

Dump the raw findings array plus the serialised `Target` model as JSON.
This is a plain data dump — use `report` for a formatted security report.

### `set <key> <value>`

Set a runtime value in `ctx.settings`. Modules can read these as overrides.
Values are stored as strings.

### `clear`

Clear the terminal screen.

### `exit` / `quit` / Ctrl-D

Leave the shell. The session is NOT auto-saved — use `session save <file>`
first if you want to persist it.

---

## Environment variables

| Variable | Effect |
|---|---|
| `BUBBLEPWN_LOCAL_DUMP` | If set to a directory, `snapshot_page()` and bundle fetches first try to read from that directory before making an HTTP request. Lets you replay a scan offline against a cached mirror. |
| `BUBBLEPWN_CACHE_DIR`  | Override the bundle cache location. Default: `~/.cache/bubblepwn/bundles`. |
| `BUBBLEPWN_*`          | Any other `BUBBLEPWN_<KEY>` maps to a pydantic `Settings` field (see `bubblepwn/config.py`). |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Normal exit. |
| 1 | Unhandled exception during module run. |
| 2 | Invalid command-line arguments (e.g. unknown module in one-shot mode). |
