"""Data types module — list custom Bubble types + their fields.

Sources (in priority order):
  1. `static.js`: all `custom.<name>` references + triple-underscore fields
     (`<field>___<type>`) already compiled into the bundle.
  2. `/api/1.1/init/data`: current user object → confirms field names/types on
     the `user` type.
  3. `/api/1.1/meta` (opt-in `--probe`): canonical Data API schema if the app
     exposes it.
  4. `/api/1.1/obj/<type>?limit=1` (opt-in `--probe`): confirms privacy rules
     and pulls 1 sample record per type.

With `--fetch-all`, re-snapshots every page in the schema to accumulate types
and fields from page-specific `static.js` bundles.
"""
from __future__ import annotations

from typing import Any

from bubblepwn.bubble.api import BubbleAPI
from bubblepwn.bubble.parse import static_js
from bubblepwn.bubble.schema import BubbleField
from bubblepwn.bubble.workflow import snapshot_page
from bubblepwn.context import Context, Finding
from bubblepwn.modules.base import Module, parse_flags, register
from bubblepwn.ui import console, panel


def _harvest_static(ctx: Context, static_text: str, source_tag: str) -> int:
    """Pull custom types + fields from a static.js blob. Returns fields added."""
    for raw in static_js.parse_custom_types(static_text):
        ctx.schema.upsert_type(raw, source=source_tag)

    added = 0
    for fname, ftype in static_js.parse_fields(static_text):
        t = ctx.schema.upsert_type("user", source=source_tag)
        raw = f"{fname}___{ftype}"
        if fname not in t.fields:
            t.add_field(BubbleField(name=fname, type=ftype, raw=raw, source=source_tag))
            added += 1
    return added


def _harvest_init_data(ctx: Context, init_body: Any) -> int:
    added = 0
    if not isinstance(init_body, list):
        return 0
    for entry in init_body:
        if not isinstance(entry, dict):
            continue
        tname = entry.get("type") or entry.get("_type")
        data = entry.get("data") if isinstance(entry.get("data"), dict) else entry
        if not tname or not isinstance(data, dict):
            continue
        t = ctx.schema.upsert_type(tname, source="init_data")
        for k, v in data.items():
            if "___" in k:
                fname, _, ftype = k.rpartition("___")
                if fname and ftype and fname not in t.fields:
                    t.add_field(
                        BubbleField(name=fname, type=ftype, raw=k, source="init_data")
                    )
                    added += 1
    return added


@register
class DataTypes(Module):
    name = "datatypes"
    description = "List Bubble data types + fields (static.js, init/data, Data API probes)."
    needs_auth = False
    category = "recon"
    subcommands = ()
    flags = ("--probe", "--fetch-all", "--export-type <name>")
    example = "run datatypes --probe"

    async def run(self, ctx: Context, **kwargs: Any) -> None:
        if ctx.target is None:
            console.print("[red]No target set.[/] Use `target <url>` first.")
            return
        argv: list[str] = kwargs.get("argv", [])
        flags, positional = parse_flags(argv)

        probe = bool(flags.get("probe", False))
        fetch_all = bool(flags.get("fetch_all", False))
        export_type = flags.get("export_type")

        # 1. Snapshot current page
        with console.status("[cyan]Fetching page + static.js[/]", spinner="dots"):
            snap = await snapshot_page(ctx, want_dynamic=False)
        if snap.static_text:
            _harvest_static(ctx, snap.static_text, source_tag="static_js")

        # 1b. Optionally fetch-all: re-snapshot every page we know so far.
        if fetch_all:
            known_pages = [p for p in ctx.schema.pages if p != snap.page_name]
            if known_pages:
                console.print(
                    f"[cyan]→[/] fetch-all: refreshing {len(known_pages)} additional pages"
                )
                for pname in known_pages:
                    try:
                        sub = await snapshot_page(ctx, page=pname, want_dynamic=False)
                        if sub.static_text:
                            _harvest_static(
                                ctx, sub.static_text, source_tag=f"static_js:{pname}"
                            )
                    except Exception as exc:
                        console.print(f"  [yellow]![/] {pname}: {exc}")

        # 2. init/data
        cookies = ctx.session.cookies if ctx.session else None
        api = BubbleAPI(ctx.target.url, cookies=cookies)
        try:
            init_body = await api.init_data()
            added = _harvest_init_data(ctx, init_body)
            console.print(f"[green]✓[/] init/data parsed  (+{added} fields)")
        except Exception as exc:
            console.print(f"[yellow]![/] init/data failed: {exc}")

        # 3. Optional probes
        if probe:
            await self._probe_meta(ctx, api)
            await self._probe_obj(ctx, api)

        # 4. Optional export
        if export_type:
            await self._export_type(ctx, api, str(export_type))

        self._render(ctx)
        self._push_findings(ctx)

    async def _probe_meta(self, ctx: Context, api: BubbleAPI) -> None:
        from bubblepwn.bubble.parse.meta import parse_meta

        console.print("[cyan]→[/] probing /api/1.1/meta …")
        status, body = await api.meta()
        if status != 200 or body is None:
            console.print(f"  [dim]meta not reachable (status={status})[/]")
            return
        parsed = parse_meta(body)
        for tname in parsed.get_types:
            raw = tname if tname == "user" else f"custom.{tname}"
            ctx.schema.upsert_type(raw, source="meta")
        no_auth = parsed.no_auth_workflows()
        console.print(
            f"  [green]✓[/] meta → {len(parsed.get_types)} types, "
            f"{len(parsed.post_endpoints)} endpoints, "
            f"{len(no_auth)} no-auth workflows"
        )
        ctx.add_finding(Finding(
            module=self.name,
            severity="medium",
            title="Bubble Data API /api/1.1/meta is publicly reachable",
            detail=(
                f"Schema lists {len(parsed.get_types)} types + "
                f"{len(parsed.post_endpoints)} endpoints anonymously."
            ),
        ))
        if no_auth:
            ctx.add_finding(Finding(
                module=self.name,
                severity="high",
                title=f"{len(no_auth)} workflow(s) exposed without auth",
                detail=", ".join(e.endpoint for e in no_auth[:10]),
                data={"endpoints": [e.endpoint for e in no_auth]},
            ))

    async def _probe_obj(self, ctx: Context, api: BubbleAPI) -> None:
        tested = 0
        open_types: list[str] = []
        for raw, t in list(ctx.schema.types.items()):
            if t.data_api_open is True:
                continue
            type_path = raw.split(".", 1)[1] if raw.startswith("custom.") else raw
            status, body = await api.obj(type_path, limit=1)
            tested += 1
            t.data_api_open = status == 200
            if status == 200:
                open_types.append(raw)
                if isinstance(body, dict):
                    resp = body.get("response") or {}
                    for rec in (resp.get("results") or [])[:1]:
                        if isinstance(rec, dict):
                            t.sample_records.append(rec)
        console.print(
            f"  [green]✓[/] obj probe → {tested} types tested, "
            f"{len(open_types)} accessible"
        )
        if open_types:
            ctx.add_finding(Finding(
                module=self.name,
                severity="high",
                title=f"{len(open_types)} data types readable via /api/1.1/obj/ without auth",
                detail="Check privacy rules — every listed type returned 200.",
                data={"types": open_types[:50]},
            ))

    async def _export_type(self, ctx: Context, api: BubbleAPI, type_name: str) -> None:
        console.print(f"[cyan]→[/] exporting records for [bold]{type_name}[/] …")
        cursor = 0
        total = 0
        records: list[dict] = []
        while True:
            status, body = await api.obj(type_name, limit=100, cursor=cursor)
            if status != 200 or not isinstance(body, dict):
                console.print(f"  [yellow]stopped:[/] status={status}")
                break
            resp = body.get("response") or {}
            batch = resp.get("results") or []
            if not batch:
                break
            records.extend(batch)
            total += len(batch)
            if len(batch) < 100:
                break
            cursor += 100
        raw = f"custom.{type_name}" if type_name != "user" else "user"
        t = ctx.schema.upsert_type(raw, source="export")
        t.sample_records = records
        console.print(f"  [green]✓[/] {total} records exported")

    def _render(self, ctx: Context) -> None:
        from rich.table import Table

        types = list(ctx.schema.types.values())
        if not types:
            console.print("[yellow]No data types detected.[/]")
            return

        panel(
            "Data types",
            f"{len(types)} types · {sum(len(t.fields) for t in types)} fields",
            style="cyan",
        )
        table = Table(header_style="bold cyan", border_style="dim")
        table.add_column("Type", style="cyan", no_wrap=True)
        table.add_column("NS", style="magenta")
        table.add_column("Fields", justify="right")
        table.add_column("API", style="red", justify="center")
        table.add_column("Sources", overflow="fold")
        for t in sorted(types, key=lambda x: x.raw):
            api_mark = (
                "✓" if t.data_api_open is True
                else "✗" if t.data_api_open is False
                else "-"
            )
            table.add_row(
                t.name,
                t.namespace,
                str(len(t.fields)),
                api_mark,
                ",".join(t.sources),
            )
        console.print(table)

    def _push_findings(self, ctx: Context) -> None:
        n_types = len(ctx.schema.types)
        n_fields = sum(len(t.fields) for t in ctx.schema.types.values())
        ctx.add_finding(Finding(
            module=self.name,
            severity="info",
            title=f"{n_types} data types, {n_fields} fields discovered",
        ))
