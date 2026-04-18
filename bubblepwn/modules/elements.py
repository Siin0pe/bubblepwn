"""Elements module — enumerate Bubble UI elements of each page.

Purely HTTP-based (no browser). For each page we:

  1. Download `dynamic.js` → parse the `id_to_path` JSON which maps every
     element ID to its path in the page hierarchy:
         "bTcoV0" → "%p3.bTNDC.%el.bTcoz0.%el.bTcoz0.%el.bUlBl"
     This gives us the complete element inventory + parent chain.
  2. Download `static.js` → we know named elements show up as `"name":"xxx"`
     near their element-id blocks. We heuristically extract names that look
     like element labels.
  3. Combine: build a tree per page (root = `%p<n>`), enriched with names
     when matchable.

With `--fetch-all`, repeats this for every page already in the schema.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from bubblepwn.bubble.parse import dynamic_js
from bubblepwn.bubble.workflow import snapshot_page
from bubblepwn.context import Context, Finding
from bubblepwn.modules.base import Module, parse_flags, register
from bubblepwn.ui import console, panel

_RE_BUBBLE_ID = re.compile(r"^[a-zA-Z0-9]{3,10}$")


def _split_path(path: str) -> tuple[str, list[str]]:
    """Split `%p3.bTNDC.%el.bTcoz0.%el.bUlBl` → ('p3', ['bTNDC','bTcoz0','bUlBl'])."""
    if not path:
        return "", []
    page_prefix = ""
    if path.startswith("%p"):
        first_dot = path.find(".")
        if first_dot < 0:
            return path[1:], []
        page_prefix = path[1:first_dot]
        rest = path[first_dot + 1 :]
    else:
        rest = path
    parts = [p for p in rest.split(".") if p and not p.startswith("%")]
    return page_prefix, parts


def _name_map_from_static(static_text: str, ids: set[str]) -> dict[str, str]:
    """Heuristic: look for `"bubble_id":"<id>"` or name-adjacent blocks."""
    if not static_text:
        return {}
    found: dict[str, str] = {}
    # Pattern: {"name":"...","bubble_id":"<id>"}
    for m in re.finditer(
        r'"name":"([a-zA-Z_][a-zA-Z0-9_ .\-]{1,80})"[^{}]{0,300}?"bubble_id":"([a-zA-Z0-9]{3,10})"',
        static_text,
    ):
        name, bid = m.group(1), m.group(2)
        if bid in ids and bid not in found:
            found[bid] = name
    # Pattern: {"bubble_id":"<id>",..."name":"..."}
    for m in re.finditer(
        r'"bubble_id":"([a-zA-Z0-9]{3,10})"[^{}]{0,300}?"name":"([a-zA-Z_][a-zA-Z0-9_ .\-]{1,80})"',
        static_text,
    ):
        bid, name = m.group(1), m.group(2)
        if bid in ids and bid not in found:
            found[bid] = name
    return found


@register
class Elements(Module):
    name = "elements"
    description = "Enumerate Bubble UI elements per page (static.js + dynamic.js)."
    needs_auth = False
    category = "recon"
    subcommands = (
        ("<page-name>", "restrict enumeration to a single page (default: "
                        "current page from fingerprint)"),
    )
    flags = (
        ("--fetch-all", "snapshot every known page and merge elements "
                        "across the whole app"),
    )
    example = "run elements --fetch-all"
    long_help = (
        "Pulls element names, types, and bindings from each page's "
        "static.js + dynamic.js. Element type is inferred from Bubble's "
        "property hints (button_text → Button, placeholder → Input, …). "
        "Useful to map the UI surface onto the data model found by "
        "`datatypes`."
    )

    async def run(self, ctx: Context, **kwargs: Any) -> None:
        if ctx.target is None:
            console.print("[red]No target set.[/] Use `target <url>` first.")
            return
        argv: list[str] = kwargs.get("argv", [])
        flags, positional = parse_flags(argv)

        fetch_all = bool(flags.get("fetch_all", False))
        target_page = positional[0] if positional else (flags.get("page") or "")

        pages_to_process: list[str]
        if fetch_all and ctx.schema.pages:
            pages_to_process = list(ctx.schema.pages.keys())
        elif target_page:
            pages_to_process = [str(target_page)]
        else:
            pages_to_process = [ctx.schema.page_name_current or ""]

        for page in pages_to_process:
            with console.status(
                f"[cyan]Analyzing page[/] {page or 'index'}…", spinner="dots"
            ):
                snap = await snapshot_page(ctx, page=page)
            self._analyze_page(ctx, snap.page_name, snap.static_text, snap.dynamic_text)

        self._render(ctx, pages_to_process)
        self._push_findings(ctx)

    def _analyze_page(
        self,
        ctx: Context,
        page_name: str,
        static_text: str,
        dynamic_text: str,
    ) -> None:
        id_to_path = dynamic_js.parse_id_to_path(dynamic_text) if dynamic_text else {}
        if not id_to_path:
            console.print(f"[yellow]![/] {page_name}: no id_to_path found in dynamic.js")
            return

        ids = {k for k in id_to_path if _RE_BUBBLE_ID.match(k)}
        names = _name_map_from_static(static_text, ids) if static_text else {}

        for bid, path in id_to_path.items():
            if not _RE_BUBBLE_ID.match(bid):
                continue
            _, ancestors = _split_path(path)
            parent = ancestors[-1] if ancestors else None
            ctx.schema.upsert_element(
                bid,
                path=path,
                parent_id=parent,
                page_name=page_name,
                name=names.get(bid),
            )

        console.print(
            f"  [green]✓[/] {page_name}: {len(ids)} elements, {len(names)} named"
        )

    def _render(self, ctx: Context, pages: list[str]) -> None:
        from rich.tree import Tree

        if not ctx.schema.elements:
            console.print("[yellow]No elements detected.[/]")
            return

        panel(
            "Elements",
            f"{len(ctx.schema.elements)} total across {len(set(e.page_name for e in ctx.schema.elements.values() if e.page_name))} page(s)",
            style="cyan",
        )

        for page in pages:
            page_elems = [
                e for e in ctx.schema.elements.values() if e.page_name == page
            ]
            if not page_elems:
                continue
            tree = Tree(f"[bold yellow]page [cyan]{page}[/] · {len(page_elems)} elems[/]")
            # Build parent → children map
            children: dict[Optional[str], list] = {}
            for e in page_elems:
                children.setdefault(e.parent_id, []).append(e)
            # Roots = elements whose parent_id is not in the page set
            page_ids = {e.id for e in page_elems}
            roots = [e for e in page_elems if e.parent_id not in page_ids]

            def _add(branch, elem, depth=0):
                label = f"[cyan]{elem.id}[/]"
                if elem.name:
                    label += f"  [white]{elem.name}[/]"
                sub = branch.add(label)
                if depth < 10:
                    for child in children.get(elem.id, []):
                        _add(sub, child, depth + 1)

            # Only show up to 40 roots to avoid screen flooding
            for root in roots[:40]:
                _add(tree, root)
            if len(roots) > 40:
                tree.add(f"[dim]… {len(roots) - 40} more roots[/]")
            console.print(tree)

    def _push_findings(self, ctx: Context) -> None:
        per_page: dict[str, int] = {}
        for e in ctx.schema.elements.values():
            if e.page_name:
                per_page[e.page_name] = per_page.get(e.page_name, 0) + 1
        ctx.add_finding(Finding(
            module=self.name,
            severity="info",
            title=f"{len(ctx.schema.elements)} UI elements mapped",
            data={"per_page": per_page},
        ))
