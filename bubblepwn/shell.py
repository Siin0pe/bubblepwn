from __future__ import annotations

import asyncio
import json
import shlex
from pathlib import Path
from typing import Any, Callable

from typing import Optional

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.history import FileHistory
from prompt_toolkit.patch_stdout import patch_stdout

from bubblepwn.context import Context, Session
from bubblepwn.modules import registry
from bubblepwn.modules.base import parse_flags
from bubblepwn.report import write_report
from bubblepwn.ui import console, findings_table, module_help, modules_table, panel

HISTORY_PATH = Path.home() / ".bubblepwn_history"

_HELP_HEADER = (
    "[bold cyan]bubblepwn[/] [dim]· Bubble.io pentest toolkit[/]"
)

_HELP_SECTIONS: list[tuple[str, list[tuple[str, str]]]] = [
    (
        "Quick start",
        [
            ("target <url>", "step 1 — point at the target app (sets "
                              "ctx.target, resets the schema)"),
            ("flow crypto", "step 2 — fingerprint → datatypes → forge an "
                             "ES probe to confirm the target accepts it"),
            ("flow full --export out/audit.html --open",
             "step 3 — run every recon/audit/exploit module and open the "
             "rendered HTML report"),
        ],
    ),
    (
        "Target & session",
        [
            ("target <url>",
             "set the current target (e.g. `target https://app.example.com`); "
             "wipes the previous schema"),
            ("target",
             "with no argument, print the currently-set target"),
            ("session load <file>",
             "load cookies from a JSON file — use to run authenticated "
             "probes (IDOR, workflows compare, …)"),
            ("session save <file>",
             "persist the current session to disk"),
            ("session show",
             "display the loaded session (cookies + any stored storage)"),
            ("session clear",
             "drop the loaded session — subsequent calls go back to anon"),
        ],
    ),
    (
        "Discover & run",
        [
            ("modules",
             "list every registered module grouped by phase (recon / audit "
             "/ exploit) with its one-line description and example"),
            ("help <module>",
             "detailed help for one module — subcommands, flags, notes, "
             "and a copy-paste example"),
            ("help flow",
             "break down every flow preset into its ordered list of "
             "module calls"),
            ("run <module> [args...]",
             "run one module against the current target — `args` are "
             "forwarded to the module (subcommand first, then flags)"),
            ("flow <preset> [--export <path>] [--open] [--checkpoint]",
             "chain a curated list of modules for a whole phase; "
             "`--export` writes a report at the end, `--open` launches "
             "it in the browser, `--checkpoint` snapshots findings "
             "after each step"),
        ],
    ),
    (
        "Output & reporting",
        [
            ("context",
             "show the live state: target, session, findings count, "
             "settings bag (ctx.settings)"),
            ("findings",
             "list all findings accumulated this session (# · severity · "
             "module · title)"),
            ("report <path> [--open]",
             "export a structured report — format picked by extension "
             "([cyan].md[/] · [cyan].html[/] · [cyan].json[/]); "
             "[cyan]--open[/] launches it in the default browser"),
            ("export <path>",
             "raw JSON dump of findings + target — machine-readable, "
             "no formatting"),
        ],
    ),
    (
        "Utility",
        [
            ("set <key> <value>",
             "write a runtime setting (stored on [dim]ctx.settings[/]) — "
             "modules read from the same dict"),
            ("clear",
             "clear the screen"),
            ("exit | quit | Ctrl-D",
             "leave the shell (session is NOT auto-saved — use "
             "`session save` first if needed)"),
        ],
    ),
]

_HELP_PRESETS: list[tuple[str, str, str, str]] = [
    (
        "crypto", "red bold",
        "run the Elasticsearch crypto bypass end-to-end",
        "fingerprint → datatypes → es-audit probe → es-audit analyze --field-leak",
    ),
    (
        "recon", "green",
        "passive reconnaissance — zero state changes, minimal traffic",
        "fingerprint → plugins → pages → datatypes → elements → secrets",
    ),
    (
        "audit", "yellow",
        "active probing — GET/OPTIONS only, read-only",
        "config-audit all → plugin-audit all → api-probe → files enumerate/test-public/upload-probe",
    ),
    (
        "exploit", "red",
        "mutating operations — opt-in subcommands for data extraction",
        "es-audit analyze → workflows analyze",
    ),
    (
        "full", "bold",
        "all three phases back-to-back",
        "recon + audit + exploit",
    ),
]

_HELP_FOOTER = (
    "[dim]docs/cli.md  ·  docs/modules.md  ·  docs/workflows.md  ·  "
    "docs/architecture.md  ·  docs/crypto.md[/]\n"
    "[dim italic]Ideas, bug reports, new modules? "
    "Open an issue or PR on GitHub — contributions welcome.[/]"
)


def _render_help() -> None:
    from rich.table import Table

    console.print()
    console.print(_HELP_HEADER)
    console.print()

    for title, rows in _HELP_SECTIONS:
        table = Table(
            title=f"[bold cyan]{title}[/]",
            title_justify="left",
            show_header=False,
            box=None,
            padding=(0, 2),
            pad_edge=False,
        )
        table.add_column(style="cyan", no_wrap=True)
        table.add_column(overflow="fold")
        for cmd, desc in rows:
            table.add_row(cmd, desc)
        console.print(table)
        console.print()

    console.print("[bold cyan]Flow presets[/]")
    console.print("[dim]  usage: flow <preset> [--export <path>] [--checkpoint][/]\n")
    preset_table = Table(show_header=False, box=None, padding=(0, 2), pad_edge=False)
    preset_table.add_column(no_wrap=True)
    preset_table.add_column(overflow="fold")
    for name, color, tagline, chain in _HELP_PRESETS:
        preset_table.add_row(
            f"[{color}]{name}[/]",
            f"{tagline}\n[dim]{chain}[/]",
        )
    console.print(preset_table)
    console.print()
    console.print(_HELP_FOOTER)
    console.print()


def _render_flow_help() -> None:
    from rich.panel import Panel

    console.print()
    console.print("[bold cyan]flow presets[/]  [dim]— chain modules for a phase[/]")
    console.print(
        "[dim]usage: flow <preset> [--export <path.md|.html|.json>] [--checkpoint][/]"
    )
    console.print()
    for name, color, tagline, _chain in _HELP_PRESETS:
        steps = _FLOW_PRESETS.get(name) or []
        body = [f"[dim]{tagline}[/]", "", f"[bold]modules ({len(steps)}):[/]"]
        for i, (mod_name, mod_args) in enumerate(steps, 1):
            arg_str = (" " + " ".join(mod_args)) if mod_args else ""
            body.append(f"  {i:>2}. [cyan]run {mod_name}{arg_str}[/]")
        console.print(
            Panel.fit("\n".join(body), title=f"flow {name}", border_style=color)
        )
    console.print(
        "[dim]--export <path>   write a structured report (.md / .html / .json) "
        "at the end of the flow[/]"
    )
    console.print(
        "[dim]--checkpoint      write findings snapshots after each step "
        "under ./out/<host>/checkpoints/[/]"
    )
    console.print()


def _build_completer() -> NestedCompleter:
    run_dict: dict[str, Any] = {m: None for m in registry.names()} or {}
    help_dict: dict[str, Any] = {m: None for m in registry.names()} or {}
    flow_dict: dict[str, Any] = {
        p: None for p in ("crypto", "recon", "audit", "exploit", "full")
    }
    return NestedCompleter.from_nested_dict(
        {
            "target": None,
            "session": {"load": None, "save": None, "clear": None, "show": None},
            "modules": None,
            "run": run_dict,
            "flow": flow_dict,
            "help": help_dict,
            "context": None,
            "findings": None,
            "report": None,
            "export": None,
            "set": None,
            "clear": None,
            "exit": None,
            "quit": None,
        }
    )


def _prompt(ctx: Context) -> ANSI:
    target = ctx.target.host if ctx.target else "no target"
    sess = "*" if ctx.session else ""
    return ANSI(
        f"\x1b[1;36mbubblepwn\x1b[0m "
        f"(\x1b[33m{target}\x1b[0m{sess}) ❯ "
    )


async def run_shell(ctx: Context) -> None:
    session = PromptSession(
        history=FileHistory(str(HISTORY_PATH)),
        completer=_build_completer(),
        complete_while_typing=True,
    )
    panel(
        "Welcome",
        "Interactive pentest shell. Type [bold]help[/] for commands, "
        "[bold]exit[/] (or Ctrl-D) to leave.",
        style="cyan",
    )
    while True:
        try:
            with patch_stdout():
                raw = await session.prompt_async(_prompt(ctx))
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]bye.[/]")
            return

        line = raw.strip()
        if not line:
            continue
        try:
            parts = shlex.split(line)
        except ValueError as exc:
            console.print(f"[red]parse error:[/] {exc}")
            continue

        cmd, *args = parts
        handler = COMMANDS.get(cmd.lower())
        if handler is None:
            console.print(f"[red]unknown command:[/] {cmd}  (type [bold]help[/])")
            continue
        try:
            result = handler(ctx, args)
            if asyncio.iscoroutine(result):
                await result
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]bye.[/]")
            return
        except Exception as exc:
            console.print(f"[red]error:[/] {exc}")


# -- command handlers ---------------------------------------------------------


def _cmd_target(ctx: Context, args: list[str]) -> None:
    if not args:
        if ctx.target:
            console.print(f"current target: [cyan]{ctx.target.url}[/]")
        else:
            console.print("[yellow]no target set[/]")
        return
    t = ctx.set_target(args[0])
    console.print(f"[green]✓[/] target = [cyan]{t.url}[/]")


def _cmd_modules(ctx: Context, args: list[str]) -> None:
    modules_table(registry.all())


async def _cmd_run(ctx: Context, args: list[str]) -> None:
    if not args:
        console.print("[red]usage:[/] run <module> [args...]")
        return
    name, *rest = args
    mod = registry.get(name)
    if mod is None:
        console.print(f"[red]unknown module:[/] {name}")
        return
    if ctx.target is None:
        console.print("[red]no target set.[/] use `target <url>` first")
        return
    await mod.run(ctx, argv=rest)


def _cmd_context(ctx: Context, args: list[str]) -> None:
    body = (
        f"target   : {ctx.target.url if ctx.target else '-'}\n"
        f"session  : {'loaded (' + str(len(ctx.session.cookies)) + ' cookies)' if ctx.session else '-'}\n"
        f"findings : {len(ctx.findings)}\n"
        f"settings : {ctx.settings or '-'}\n"
    )
    panel("context", body, style="magenta")


def _cmd_findings(ctx: Context, args: list[str]) -> None:
    findings_table(ctx.findings)


def _cmd_export(ctx: Context, args: list[str]) -> None:
    if not args:
        console.print("[red]usage:[/] export <path>")
        return
    path = Path(args[0])
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "target": ctx.target.model_dump() if ctx.target else None,
        "findings": [f.model_dump(mode="json") for f in ctx.findings],
    }
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    console.print(f"[green]✓[/] exported → [cyan]{path}[/]")


def _cmd_session(ctx: Context, args: list[str]) -> None:
    if not args:
        console.print("[red]usage:[/] session {load|save|clear|show} [file]")
        return
    sub, *rest = args
    sub = sub.lower()

    if sub == "show":
        if ctx.session is None:
            console.print("[yellow]no session loaded[/]")
        else:
            panel("session", ctx.session.model_dump_json(indent=2), style="magenta")
    elif sub == "clear":
        ctx.session = None
        console.print("[green]✓[/] session cleared")
    elif sub == "load":
        if not rest:
            console.print("[red]usage:[/] session load <file>")
            return
        p = Path(rest[0])
        data = json.loads(p.read_text(encoding="utf-8"))
        cookies = {c["name"]: c["value"] for c in data.get("cookies", []) if "name" in c}
        ctx.session = Session(path=str(p), cookies=cookies, storage=data)
        console.print(f"[green]✓[/] session loaded ({len(cookies)} cookies)")
    elif sub == "save":
        if ctx.session is None:
            console.print("[yellow]no session to save[/]")
            return
        if not rest:
            console.print("[red]usage:[/] session save <file>")
            return
        p = Path(rest[0])
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(ctx.session.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"[green]✓[/] session saved → [cyan]{p}[/]")
    else:
        console.print(f"[red]unknown subcommand:[/] {sub}")


def _cmd_set(ctx: Context, args: list[str]) -> None:
    if len(args) < 2:
        console.print("[red]usage:[/] set <key> <value>")
        return
    key, *rest = args
    value = " ".join(rest)
    ctx.settings[key] = value
    console.print(f"[green]✓[/] {key} = {value}")


def _cmd_clear(ctx: Context, args: list[str]) -> None:
    console.clear()


def _cmd_help(ctx: Context, args: list[str]) -> None:
    if not args:
        _render_help()
        return
    topic = args[0].lower()
    if topic in ("flow", "flows", "presets"):
        _render_flow_help()
        return
    mod = registry.get(topic)
    if mod is None:
        console.print(
            f"[red]unknown help topic:[/] {topic}  "
            "(try [cyan]modules[/] for the module list, "
            "or [cyan]help flow[/] for presets)"
        )
        return
    module_help(mod)


# ── flow presets ──────────────────────────────────────────────────────────

_FLOW_PRESETS: dict[str, list[tuple[str, list[str]]]] = {
    "crypto": [
        ("fingerprint", []),
        ("datatypes", []),
        ("es-audit", ["probe"]),
        ("es-audit", ["analyze", "--field-leak"]),
    ],
    "recon": [
        ("fingerprint", []),
        ("plugins", []),
        ("pages", []),
        ("datatypes", []),
        ("elements", []),
        ("secrets", []),
    ],
    "audit": [
        ("config-audit", ["all"]),
        ("plugin-audit", ["all"]),
        ("api-probe", []),
        ("files", ["enumerate"]),
        ("files", ["test-public"]),
        ("files", ["upload-probe"]),
    ],
    "exploit": [
        ("es-audit", ["analyze"]),
        ("workflows", ["analyze"]),
    ],
}
_FLOW_PRESETS["full"] = (
    _FLOW_PRESETS["recon"]
    + _FLOW_PRESETS["audit"]
    + _FLOW_PRESETS["exploit"]
)


async def _cmd_flow(ctx: Context, args: list[str]) -> None:
    if not args:
        console.print(
            "[red]usage:[/] flow <preset> [--export <path>] [--checkpoint]  "
            "(preset: [red bold]crypto[/] | [green]recon[/] | "
            "[yellow]audit[/] | [red]exploit[/] | [bold]full[/])"
        )
        return

    flags, positional = parse_flags(args)
    if not positional:
        console.print("[red]missing preset name[/]")
        return
    preset = positional[0].lower()
    steps = _FLOW_PRESETS.get(preset)
    if steps is None:
        console.print(
            f"[red]unknown preset:[/] {preset}  "
            "(crypto|recon|audit|exploit|full)"
        )
        return
    if ctx.target is None:
        console.print("[red]no target set.[/] use `target <url>` first")
        return

    export_path = flags.get("export")
    checkpoint = bool(flags.get("checkpoint"))
    checkpoint_dir: Optional[Path] = None
    if checkpoint:
        checkpoint_dir = Path("out") / ctx.target.host / "checkpoints"
        checkpoint_dir.mkdir(parents=True, exist_ok=True)

    panel(
        f"flow · {preset}",
        (
            f"{len(steps)} step(s)  ·  target=[cyan]{ctx.target.url}[/]"
            + (f"\nexport → [cyan]{export_path}[/]" if export_path else "")
            + (f"\ncheckpoints → [cyan]{checkpoint_dir}[/]" if checkpoint_dir else "")
        ),
        style="cyan",
    )

    for i, (mod_name, mod_args) in enumerate(steps, 1):
        mod = registry.get(mod_name)
        if mod is None:
            console.print(f"[yellow]skip[/] [{i}/{len(steps)}] {mod_name} (not registered)")
            continue
        console.print(
            f"\n[bold cyan]━━━ [{i}/{len(steps)}] run {mod_name} "
            f"{' '.join(mod_args)}[/]"
        )
        try:
            await mod.run(ctx, argv=list(mod_args))
        except Exception as exc:
            console.print(f"[red]step failed:[/] {exc}")
            continue

        if checkpoint_dir is not None:
            safe = mod_name.replace("/", "_")
            suffix = f"_{'_'.join(mod_args)}" if mod_args else ""
            cp_path = checkpoint_dir / f"{i:02d}_{safe}{suffix}.json"
            payload = {
                "step": f"{i}/{len(steps)}",
                "module": mod_name,
                "args": list(mod_args),
                "findings_count": len(ctx.findings),
                "schema_counts": {
                    "types": len(ctx.schema.types),
                    "pages": len(ctx.schema.pages),
                    "plugins": len(ctx.schema.plugins),
                    "elements": len(ctx.schema.elements),
                },
                "findings": [f.model_dump(mode="json") for f in ctx.findings],
            }
            cp_path.write_text(
                json.dumps(payload, indent=2, default=str), encoding="utf-8"
            )
            console.print(f"  [dim]checkpoint →[/] [cyan]{cp_path}[/]")

    if export_path:
        try:
            written = write_report(ctx, str(export_path))
        except Exception as exc:
            console.print(f"[red]report export failed:[/] {exc}")
        else:
            console.print(
                f"\n[green]✓[/] {len(ctx.findings)} finding(s) written"
            )
            _announce_report(written, open_in_browser=bool(flags.get("open")))


def _cmd_report(ctx: Context, args: list[str]) -> None:
    if not args:
        console.print(
            "[red]usage:[/] report <path> [--open]   "
            "(format picked by extension: .md | .html | .json)"
        )
        return
    if ctx.target is None:
        console.print("[red]no target set.[/]")
        return
    flags, positional = parse_flags(args)
    if not positional:
        console.print("[red]usage:[/] report <path> [--open]")
        return
    try:
        path = write_report(ctx, positional[0])
    except Exception as exc:
        console.print(f"[red]report failed:[/] {exc}")
        return
    _announce_report(path, open_in_browser=bool(flags.get("open")))


def _announce_report(path: Path, *, open_in_browser: bool = False) -> None:
    """Print a clickable file:// link and optionally open the report."""
    try:
        uri = Path(path).resolve().as_uri()
    except Exception:
        uri = str(path)
    console.print(
        f"[green]✓[/] report → [link={uri}][cyan]{path}[/][/]  "
        f"[dim]({uri})[/]"
    )
    if open_in_browser:
        import webbrowser

        try:
            webbrowser.open(uri)
            console.print("[dim]opened in default browser[/]")
        except Exception as exc:
            console.print(f"[yellow]could not auto-open:[/] {exc}")


def _cmd_exit(ctx: Context, args: list[str]) -> None:
    raise EOFError()


COMMANDS: dict[str, Callable] = {
    "target": _cmd_target,
    "modules": _cmd_modules,
    "run": _cmd_run,
    "flow": _cmd_flow,
    "report": _cmd_report,
    "context": _cmd_context,
    "findings": _cmd_findings,
    "export": _cmd_export,
    "session": _cmd_session,
    "set": _cmd_set,
    "clear": _cmd_clear,
    "help": _cmd_help,
    "exit": _cmd_exit,
    "quit": _cmd_exit,
}
