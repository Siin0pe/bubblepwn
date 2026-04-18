from __future__ import annotations

from contextlib import contextmanager
from typing import Iterable, Iterator, Union

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from bubblepwn import __version__

console = Console()


class _NoopTracker:
    """Stand-in yielded when an iteration is too small to warrant a bar."""

    def advance(self, n: int = 1) -> None: ...

    def set_description(self, text: str) -> None: ...


class _Tracker:
    def __init__(self, progress: Progress, task_id: int) -> None:
        self._progress = progress
        self._task_id = task_id

    def advance(self, n: int = 1) -> None:
        self._progress.advance(self._task_id, n)

    def set_description(self, text: str) -> None:
        self._progress.update(self._task_id, description=text)


@contextmanager
def progress_iter(
    description: str, total: int
) -> Iterator[Union[_Tracker, _NoopTracker]]:
    """Yield a progress tracker for a long iteration.

    For tiny loops (``total < 3``) a no-op tracker is yielded so small modules
    stay visually silent. For real loops, a single animated line is shown
    (spinner · description · bar · M/N · elapsed) and cleared when the block
    exits. Summary output is expected to come after the context block.
    """
    if total < 3:
        yield _NoopTracker()
        return
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[cyan]{task.description}[/]"),
        BarColumn(bar_width=28, complete_style="cyan", finished_style="green"),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task_id = progress.add_task(description, total=total)
        yield _Tracker(progress, task_id)


BANNER = r"""
 _           _     _     _
| |__  _   _| |__ | |__ | | ___ _ ____      ___
| '_ \| | | | '_ \| '_ \| |/ _ \ '_ \ \ /\ / / |
| |_) | |_| | |_) | |_) | |  __/ |_) \ V  V /| |
|_.__/ \__,_|_.__/|_.__/|_|\___| .__/ \_/\_/ |_|
                               |_|
"""


def banner() -> None:
    console.print(Text(BANNER, style="bold cyan"))
    console.print(
        Text(f"  v{__version__}  Bubble.io pentest toolkit", style="dim italic"),
    )
    console.print(Text("  by @Siin0pe", style="dim"))
    console.print(
        Text(
            "  Contributions welcome — open an issue or PR on GitHub",
            style="dim italic",
        ),
    )
    console.print()


_CATEGORY_META = {
    "recon":   ("RECON",   "green",  "passive · no state changes"),
    "audit":   ("AUDIT",   "yellow", "active probing · read-only"),
    "exploit": ("EXPLOIT", "red",    "mutating · data extraction"),
}


def modules_table(mods: Iterable) -> None:
    mods = list(mods)
    if not mods:
        console.print("[yellow]No modules registered.[/]")
        return

    # Group by category in fixed order.
    by_cat: dict[str, list] = {"recon": [], "audit": [], "exploit": []}
    for m in mods:
        by_cat.setdefault(m.category, []).append(m)

    for cat in ("recon", "audit", "exploit"):
        items = by_cat.get(cat) or []
        if not items:
            continue
        title_label, color, tagline = _CATEGORY_META.get(
            cat, (cat.upper(), "white", "")
        )
        table = Table(
            title=f"[{color}]{title_label}[/]  [dim]— {tagline}[/]",
            title_justify="left",
            header_style=f"bold {color}",
            border_style="dim",
            show_lines=False,
        )
        table.add_column("Module", style=color, no_wrap=True)
        table.add_column("Description")
        table.add_column("Example", overflow="fold", style="dim")
        for m in sorted(items, key=lambda x: x.name):
            table.add_row(m.name, m.description, m.example or "-")
        console.print(table)
        console.print()

    # Any modules whose category wasn't one of the known ones
    unknown = [m for m in mods if m.category not in _CATEGORY_META]
    if unknown:
        table = Table(
            title="[dim]OTHER[/]",
            title_justify="left",
            header_style="bold",
            border_style="dim",
        )
        table.add_column("Module", no_wrap=True)
        table.add_column("Description")
        for m in sorted(unknown, key=lambda x: x.name):
            table.add_row(m.name, m.description)
        console.print(table)


def module_help(mod) -> None:
    """Render the detailed help for a single module."""
    body_lines = [
        f"[bold cyan]{mod.name}[/]  [dim]· {mod.category}[/]",
        "",
        mod.description,
        "",
    ]
    if mod.subcommands:
        body_lines.append("[bold]Subcommands:[/]")
        for sc in mod.subcommands:
            body_lines.append(f"  • {sc}")
        body_lines.append("")
    if mod.flags:
        body_lines.append("[bold]Flags:[/]")
        for fl in mod.flags:
            body_lines.append(f"  • {fl}")
        body_lines.append("")
    if mod.example:
        body_lines.append("[bold]Example:[/]")
        body_lines.append(f"  [dim]>[/] {mod.example}")
    console.print(Panel.fit(
        "\n".join(body_lines),
        title=f"help · {mod.name}",
        border_style={
            "recon": "green", "audit": "yellow", "exploit": "red"
        }.get(mod.category, "cyan"),
    ))


def findings_table(findings: Iterable) -> None:
    items = list(findings)
    if not items:
        console.print("[yellow]No findings yet.[/]")
        return
    table = Table(title="Findings", header_style="bold", border_style="dim")
    table.add_column("#", style="dim", justify="right")
    table.add_column("Sev", justify="center")
    table.add_column("Module", style="cyan")
    table.add_column("Title")
    sev_color = {
        "critical": "red1",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "green",
    }
    for i, f in enumerate(items):
        color = sev_color.get(f.severity, "white")
        table.add_row(str(i), f"[{color}]{f.severity}[/]", f.module, f.title)
    console.print(table)


def panel(title: str, body: str, style: str = "cyan") -> None:
    console.print(Panel.fit(body, title=title, border_style=style))
