from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer

from bubblepwn import __version__
from bubblepwn.context import Context, Session
from bubblepwn.logging import setup_logging
from bubblepwn.modules import registry
from bubblepwn.ui import banner, console, modules_table
from bubblepwn.update_check import print_update_banner_if_any

app = typer.Typer(
    name="bubblepwn",
    help="Interactive pentest toolkit for Bubble.io applications.",
    no_args_is_help=False,
    rich_markup_mode="rich",
    add_completion=False,
)


def _load_session(ctx: Context, path: Optional[str]) -> None:
    if not path:
        return
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    cookies = {c["name"]: c["value"] for c in data.get("cookies", []) if "name" in c}
    ctx.session = Session(path=str(p), cookies=cookies, storage=data)
    console.print(f"[green]✓[/] session loaded ({len(cookies)} cookies)")


def _announce(path: Path, *, open_in_browser: bool = False) -> None:
    try:
        uri = Path(path).resolve().as_uri()
    except Exception:
        uri = str(path)
    console.print(f"[green]✓[/] report → [link={uri}][cyan]{path}[/][/]  [dim]({uri})[/]")
    if open_in_browser:
        import webbrowser

        try:
            webbrowser.open(uri)
            console.print("[dim]opened in default browser[/]")
        except Exception as exc:
            console.print(f"[yellow]could not auto-open:[/] {exc}")


def _write_report_if_asked(
    ctx: Context, path: Optional[str], *, open_in_browser: bool = False
) -> None:
    if not path:
        return
    from bubblepwn.report import write_report

    written = write_report(ctx, path)
    _announce(written, open_in_browser=open_in_browser)


@app.callback(invoke_without_command=True)
def _root(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-V", help="Show version and exit."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logs."),
) -> None:
    setup_logging(debug=verbose)
    if version:
        console.print(f"bubblepwn {__version__}")
        print_update_banner_if_any()
        raise typer.Exit()
    print_update_banner_if_any()
    if ctx.invoked_subcommand is None:
        banner()
        from bubblepwn.shell import run_shell

        asyncio.run(run_shell(Context.get()))


@app.command("shell")
def _shell() -> None:
    """Launch the interactive shell (default when no command is given)."""
    banner()
    from bubblepwn.shell import run_shell

    asyncio.run(run_shell(Context.get()))


@app.command("modules")
def _modules() -> None:
    """List registered modules grouped by phase and exit."""
    modules_table(registry.all())


@app.command(
    "run",
    context_settings={
        "allow_extra_args": True,
        "ignore_unknown_options": True,
    },
)
def _run(
    ctx: typer.Context,
    module: str = typer.Argument(..., help="Module name (see `bubblepwn modules`)."),
    target: str = typer.Argument(..., help="Target URL."),
    session_file: Optional[str] = typer.Option(
        None, "--session", help="Load a session JSON file before running."
    ),
    report: Optional[str] = typer.Option(
        None, "--report", help="Write a structured report (.md/.html/.json) after the run."
    ),
    open_report: bool = typer.Option(
        False, "--open", help="Open the generated report in the default browser."
    ),
) -> None:
    """Run a single module against a target (one-shot, no shell).

    Any remaining arguments after --session / --report / --open are forwarded
    to the module's own flag parser:

      [b]bubblepwn run es-audit https://app.cible.io analyze --compare[/b]

      [b]bubblepwn run secrets https://app.cible.io --verify-keys[/b]

      [b]bubblepwn run workflows https://app.cible.io analyze --deep-params[/b]
    """
    mod = registry.get(module)
    if mod is None:
        console.print(
            f"[red]Unknown module:[/] {module}  "
            "(use [cyan]bubblepwn modules[/] to list available ones)"
        )
        raise typer.Exit(code=2)
    context = Context.get()
    context.set_target(target)
    _load_session(context, session_file)

    argv = list(ctx.args)
    try:
        asyncio.run(mod.run(context, argv=argv))
    except Exception as exc:
        console.print(f"[red]module failed:[/] {exc}")
        raise typer.Exit(code=1)

    _write_report_if_asked(context, report, open_in_browser=open_report)


@app.command(
    "flow",
    context_settings={
        "allow_extra_args": True,
        "ignore_unknown_options": True,
    },
)
def _flow(
    ctx: typer.Context,
    preset: str = typer.Argument(..., help="crypto | recon | audit | exploit | full"),
    target: str = typer.Argument(..., help="Target URL."),
    session_file: Optional[str] = typer.Option(None, "--session"),
    export: Optional[str] = typer.Option(
        None, "--export", help="Write a structured report at the end of the flow."
    ),
    open_report: bool = typer.Option(
        False, "--open", help="Open the exported report in the default browser."
    ),
    checkpoint: bool = typer.Option(
        False, "--checkpoint", help="Write findings snapshots after each step."
    ),
) -> None:
    """Run a flow preset against a target (one-shot, no shell).

      [b]bubblepwn flow recon https://app.cible.io[/b]

      [b]bubblepwn flow full https://app.cible.io --export out/audit.html --open[/b]

      [b]bubblepwn flow exploit https://app.cible.io --session session.json[/b]
    """
    from bubblepwn.shell import _cmd_flow

    context = Context.get()
    context.set_target(target)
    _load_session(context, session_file)

    flow_argv: list[str] = [preset]
    if export:
        flow_argv += ["--export", export]
    if open_report:
        flow_argv.append("--open")
    if checkpoint:
        flow_argv.append("--checkpoint")
    try:
        asyncio.run(_cmd_flow(context, flow_argv))
    except Exception as exc:
        console.print(f"[red]flow failed:[/] {exc}")
        raise typer.Exit(code=1)


@app.command("report")
def _report(
    target: str = typer.Argument(..., help="Target URL."),
    path: str = typer.Argument(..., help="Output path (.md / .html / .json)."),
    session_file: Optional[str] = typer.Option(None, "--session"),
    open_report: bool = typer.Option(
        False, "--open", help="Open the generated report in the default browser."
    ),
) -> None:
    """Shorthand for `flow full --export <path>` — run every recon, audit,
    and exploit module against the target and write a structured report.

    Format is picked by the file extension (`.md` / `.html` / `.json`).

      [b]bubblepwn report https://app.cible.io out/audit.html --open[/b]

      [b]bubblepwn report https://app.cible.io out/audit.json --session session.json[/b]
    """
    from bubblepwn.shell import _cmd_flow

    context = Context.get()
    context.set_target(target)
    _load_session(context, session_file)
    argv = ["full", "--export", path]
    if open_report:
        argv.append("--open")
    try:
        asyncio.run(_cmd_flow(context, argv))
    except Exception as exc:
        console.print(f"[red]report failed:[/] {exc}")
        raise typer.Exit(code=1)
