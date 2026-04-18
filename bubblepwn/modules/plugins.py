"""Plugins module — list Bubble plugins used by the target.

Combines 3 sources:
  1. HTML `plugin_main_headers_<id>` (already seen by fingerprint) — gives
     timestamp IDs of third-party / custom plugins loaded on the page.
  2. `static.js` `hardcoded_plugins['<name>']` — first-party Bubble plugins.
  3. `dynamic.js` `preloaded['translation/plugin:<id>:<locale>']` — the most
     complete list: every plugin for which a translation was preloaded.

Every detected plugin is then enriched:
  - **Offline** (always): static first-party catalogue + creation date /
    marketplace URL derived from the timestamp ID.
  - **Online** (``--enrich``): fetch ``https://bubble.io/plugin/<id>`` and
    parse ``<meta property="og:*">`` tags to recover the human-readable name,
    vendor description, and slugged URL.
"""
from __future__ import annotations

from typing import Any

from bubblepwn.bubble.parse import dynamic_js, html as html_parse, static_js
from bubblepwn.bubble.plugin_catalog import (
    FIRST_PARTY_CATALOG,
    enrich_offline,
    enrich_online,
)
from bubblepwn.bubble.workflow import snapshot_page
from bubblepwn.context import Context, Finding
from bubblepwn.http import client as http_client
from bubblepwn.modules.base import Module, parse_flags, register
from bubblepwn.ui import console, panel, progress_iter

#: First-party plugin IDs we recognise by name (slugs, not timestamp IDs).
FIRST_PARTY_NAMES = frozenset(FIRST_PARTY_CATALOG.keys())


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
    flags = (
        ("--page <name>", "probe a specific page instead of index — plugin "
                          "sets can differ per page"),
        ("--enrich", "look up every third-party plugin on the Bubble "
                     "marketplace (one HTTPS request per ID) to recover "
                     "its human name, vendor, and description — opt-in "
                     "because it hits bubble.io"),
    )
    example = "run plugins --enrich"
    long_help = (
        "Parses hardcoded_plugins[] references in static.js, header "
        "<script src=\"…/plugin_main_headers_<id>/…\"> tags in the HTML, "
        "and known first-party bundles. Each plugin is tagged as "
        "`first_party`, `third_party`, or `unknown`, then enriched with "
        "metadata: first-party entries hit a built-in catalogue; "
        "third-party IDs derive their creation date from the 13-digit "
        "timestamp prefix and can optionally be looked up on the Bubble "
        "marketplace (`--enrich`) to fetch name/vendor/description. "
        "Feeds plugin-audit."
    )

    async def run(self, ctx: Context, **kwargs: Any) -> None:
        if ctx.target is None:
            console.print("[red]No target set.[/] Use `target <url>` first.")
            return
        argv: list[str] = kwargs.get("argv", [])
        flags, _ = parse_flags(argv)

        page = flags.get("page", "")
        do_enrich = bool(flags.get("enrich"))

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

        # Offline enrichment — always runs, no network.
        for p in ctx.schema.plugins.values():
            enrich_offline(p)

        # Online enrichment — opt-in; hits bubble.io once per third-party plugin.
        if do_enrich:
            await self._enrich_marketplace(ctx)

        self._render(ctx)
        self._push_findings(ctx)

    async def _enrich_marketplace(self, ctx: Context) -> None:
        third_party = [
            p for p in ctx.schema.plugins.values() if p.category == "third_party"
        ]
        if not third_party:
            return
        hits = 0
        async with http_client() as c:
            with progress_iter(
                "Looking up marketplace metadata", len(third_party)
            ) as bar:
                for p in third_party:
                    bar.set_description(f"GET bubble.io/plugin/{p.id[:32]}…")
                    ok = await enrich_online(p, c)
                    hits += 1 if ok else 0
                    bar.advance()
        console.print(
            f"[dim]marketplace enrichment: {hits}/{len(third_party)} resolved[/]"
        )

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
        table.add_column("Name", overflow="fold")
        table.add_column("Vendor", overflow="fold")
        table.add_column("Category", style="magenta")
        table.add_column("Created", style="dim", no_wrap=True)
        table.add_column("Link", overflow="fold")
        order = {"first_party": 0, "third_party": 1, "library": 2, "unknown": 3}
        for p in sorted(plugins, key=lambda x: (order.get(x.category, 9), x.id)):
            link = p.marketplace_url or p.docs_url or ""
            link_cell = (
                f"[link={link}][cyan]{_shorten_url(link)}[/][/]" if link else "-"
            )
            created = (
                p.created_at.strftime("%Y-%m-%d") if p.created_at else "-"
            )
            table.add_row(
                p.id,
                p.display_name or "-",
                p.vendor or "-",
                p.category,
                created,
                link_cell,
            )
        console.print(table)

    def _push_findings(self, ctx: Context) -> None:
        plugins = ctx.schema.plugins
        tp = [p for p in plugins.values() if p.category == "third_party"]
        fp = [p for p in plugins.values() if p.category == "first_party"]

        def _summary(p):
            """Pick the most useful label for a finding payload entry."""
            if p.display_name and p.vendor:
                return f"{p.display_name} ({p.vendor}) — {p.id}"
            if p.display_name:
                return f"{p.display_name} — {p.id}"
            return p.id

        ctx.add_finding(Finding(
            module=self.name,
            severity="info",
            title=f"{len(plugins)} plugins detected ({len(fp)} first-party, {len(tp)} third-party)",
            data={
                "first_party": [_summary(p) for p in fp],
                "third_party": [_summary(p) for p in tp],
            },
        ))


def _shorten_url(url: str, max_len: int = 48) -> str:
    if not url or len(url) <= max_len:
        return url
    return url[: max_len - 1] + "…"
