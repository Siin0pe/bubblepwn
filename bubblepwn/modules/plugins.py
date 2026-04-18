"""Plugins module — list Bubble plugins used by the target.

Combines 3 sources:
  1. HTML `plugin_main_headers_<id>` (already seen by fingerprint) — gives
     timestamp IDs of third-party / custom plugins loaded on the page.
  2. `static.js` `hardcoded_plugins['<name>']` — first-party Bubble plugins.
  3. `dynamic.js` `preloaded['translation/plugin:<id>:<locale>']` — the most
     complete list: every plugin for which a translation was preloaded.
"""
from __future__ import annotations

from typing import Any

from bubblepwn.bubble.parse import dynamic_js, html as html_parse, static_js
from bubblepwn.bubble.workflow import snapshot_page
from bubblepwn.context import Context, Finding
from bubblepwn.modules.base import Module, parse_flags, register
from bubblepwn.ui import console, panel

FIRST_PARTY_NAMES = {
    "ionic", "chartjs", "select2", "selectPDF", "draggableui", "progressbar",
    "apiconnector2", "fullcalendar", "interactions", "materialicons",
    "multifileupload", "GoogleAnalytics", "stripe", "paypal", "airtable",
    "googlemaps", "googlesignin", "facebook",
}


def _classify(pid: str) -> str:
    if pid in FIRST_PARTY_NAMES:
        return "first_party"
    # Bubble marketplace plugin IDs follow `<ms_timestamp>x<big_num>`
    if "x" in pid and pid.split("x")[0].isdigit():
        return "third_party"
    return "unknown"


@register
class Plugins(Module):
    name = "plugins"
    description = "Enumerate Bubble plugins from HTML + static.js + dynamic.js."
    needs_auth = False
    category = "recon"
    subcommands = ()
    flags = ("--page <name>",)
    example = "run plugins"

    async def run(self, ctx: Context, **kwargs: Any) -> None:
        if ctx.target is None:
            console.print("[red]No target set.[/] Use `target <url>` first.")
            return
        argv: list[str] = kwargs.get("argv", [])
        flags, _ = parse_flags(argv)

        page = flags.get("page", "")
        with console.status(
            f"[cyan]Fetching page + bundles[/] ({page or 'index'})…", spinner="dots"
        ):
            snap = await snapshot_page(ctx, page=str(page) if page else "")

        # 1. HTML header IDs (already collected by fingerprint, re-collect to be standalone)
        header_ids = html_parse.extract_plugin_header_ids(snap.html)
        for pid in header_ids:
            ctx.schema.upsert_plugin(pid, source="html", category=_classify(pid))

        # 2. static.js hardcoded first-party plugins
        hardcoded = static_js.parse_hardcoded_plugins(snap.static_text) if snap.static_text else []
        for name in hardcoded:
            ctx.schema.upsert_plugin(name, source="static_js", category="first_party")

        # 3. dynamic.js preloaded plugin IDs (most complete)
        entries = (
            dynamic_js.parse_plugin_entries(snap.dynamic_text) if snap.dynamic_text else {}
        )
        for pid, locales in entries.items():
            p = ctx.schema.upsert_plugin(pid, source="dynamic_js", category=_classify(pid))
            for loc in locales:
                if loc not in p.translations_loaded:
                    p.translations_loaded.append(loc)

        self._render(ctx)
        self._push_findings(ctx)

    def _render(self, ctx: Context) -> None:
        from rich.table import Table

        plugins = list(ctx.schema.plugins.values())
        if not plugins:
            console.print("[yellow]No plugins detected.[/]")
            return

        counts: dict[str, int] = {}
        for p in plugins:
            counts[p.category] = counts.get(p.category, 0) + 1
        summary = "   ".join(
            f"[bold]{cat}[/]: {n}" for cat, n in sorted(counts.items())
        )
        panel("Plugins summary", f"{len(plugins)} total — {summary}", style="cyan")

        table = Table(header_style="bold cyan", border_style="dim")
        table.add_column("ID / name", style="cyan", no_wrap=True, overflow="fold")
        table.add_column("Category", style="magenta")
        table.add_column("Sources")
        table.add_column("Translations", overflow="fold")
        order = {"first_party": 0, "third_party": 1, "library": 2, "unknown": 3}
        for p in sorted(plugins, key=lambda x: (order.get(x.category, 9), x.id)):
            table.add_row(
                p.id,
                p.category,
                ",".join(p.sources),
                ",".join(p.translations_loaded) or "-",
            )
        console.print(table)

    def _push_findings(self, ctx: Context) -> None:
        plugins = ctx.schema.plugins
        tp = [p for p in plugins.values() if p.category == "third_party"]
        fp = [p for p in plugins.values() if p.category == "first_party"]
        ctx.add_finding(Finding(
            module=self.name,
            severity="info",
            title=f"{len(plugins)} plugins detected ({len(fp)} first-party, {len(tp)} third-party)",
            data={
                "first_party": [p.id for p in fp],
                "third_party": [p.id for p in tp],
            },
        ))
