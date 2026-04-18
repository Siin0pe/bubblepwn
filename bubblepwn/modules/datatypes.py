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


def _normalize_type_name(raw: str) -> str:
    """Accept ``user`` / ``foo`` / ``custom.foo`` / ``option.bar`` uniformly.

    Mirrors the convention used by ``es-audit --type``: the ``user`` type is
    native, explicit namespaces (``custom.`` / ``option.``) stay as-is, and
    anything else is assumed to be a ``custom.`` slug.
    """
    raw = raw.strip()
    if raw == "user" or raw.startswith("custom.") or raw.startswith("option."):
        return raw
    return f"custom.{raw}"


def _harvest_static(ctx: Context, static_text: str, source_tag: str) -> int:
    """Pull custom types and the global field pool from a static.js blob.

    Bubble's ``<field>___<type>`` naming convention is scoped per data type
    but the owning type is **not** encoded in the pattern itself — so the
    regex matches all fields across all types without telling us who owns
    which. Attributing every match to the ``user`` type (as earlier
    versions did) was a bug: it lumped hundreds of unrelated fields on the
    user record.

    Accurate field → type ownership comes from:

    - ``/api/1.1/init/data`` (always tried) — populates the current user
      type with its real fields.
    - ``/api/1.1/meta`` + ``/api/1.1/obj/<type>`` (``--probe``) — populates
      every type whose record is readable anonymously.

    This function now collects the raw field patterns into
    ``ctx.settings["_field_pool"]`` purely for reporting (``N field patterns
    discovered in bundle``) and does NOT attach them to any specific type.
    Returns the number of new patterns added to the pool.
    """
    for raw in static_js.parse_custom_types(static_text):
        ctx.schema.upsert_type(raw, source=source_tag)

    # The `user` type is native to every Bubble app — register it even if
    # no `custom.user` reference shows up in the bundle, so it appears in
    # the output regardless of whether the current user is logged in.
    ctx.schema.upsert_type("user", source=source_tag)

    # 1) Light pool: (field_name, field_type) from the triple-underscore regex
    pool = ctx.settings.setdefault("_field_pool", set())
    before = len(pool)
    for fname, ftype in static_js.parse_fields(static_text):
        pool.add((fname, ftype))

    # 2) Rich pool: (name, value, display) triples from DefaultValues —
    #    includes human labels + canonical Bubble type strings
    #    (list.custom.X, option.X, etc.). Stored as a dict keyed by the
    #    raw DB column so later snapshots can merge without dupes.
    rich = ctx.settings.setdefault("_field_triples", {})
    for triple in static_js.parse_field_triples(static_text):
        rich.setdefault(triple["name"], triple)

    return len(pool) - before


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
    flags = (
        ("--probe", "call /api/1.1/meta and /api/1.1/obj/<type> to map "
                    "per-type fields (confirms privacy rules too)"),
        ("--fetch-all", "re-snapshot every known page so DefaultValues from "
                        "other pages' static.js get merged"),
        ("--list-fields", "summary of fields seen in static.js — count + "
                          "breakdown by Bubble type category. Cheap overview "
                          "with hints on how to drill down"),
        ("--show-fields", "one block per type: field name, Bubble type, "
                          "display label, source — needs --probe or init/data "
                          "to have attached fields to types"),
        ("--type <name>", "restrict --probe and --show-fields to a single "
                          "type. Accepts bare (`user`) or canonical "
                          "(`custom.user`) form"),
        ("--export-type <name>", "paginate /api/1.1/obj/<name> and save every "
                                 "record onto the type's sample_records"),
    )
    example = "run datatypes --probe --show-fields --type user"
    long_help = (
        "Sources, in priority order: (1) static.js — `custom.*` refs + the "
        "DefaultValues catalogue (raw DB column, canonical Bubble type, "
        "display label); (2) /api/1.1/init/data — field shape for the "
        "current user type; (3) --probe → /api/1.1/meta + /obj/<type> "
        "for privacy rules + a sample record per type. The triple-"
        "underscore fields seen in static.js are NOT attached to a type "
        "(Bubble doesn't encode ownership) — use --probe to attach them."
    )

    async def run(self, ctx: Context, **kwargs: Any) -> None:
        if ctx.target is None:
            console.print("[red]No target set.[/] Use `target <url>` first.")
            return
        argv: list[str] = kwargs.get("argv", [])
        flags, positional = parse_flags(argv)

        probe = bool(flags.get("probe", False))
        fetch_all = bool(flags.get("fetch_all", False))
        list_fields = bool(flags.get("list_fields", False))
        show_fields = bool(flags.get("show_fields", False))
        export_type = flags.get("export_type")
        type_filter_raw = flags.get("type")
        type_filter = (
            _normalize_type_name(str(type_filter_raw))
            if isinstance(type_filter_raw, str) and type_filter_raw.strip()
            else None
        )

        # 1. Snapshot current page
        with console.status("[cyan]Fetching page + static.js[/]", spinner="dots") as st:
            snap = await snapshot_page(
                ctx, want_dynamic=False,
                progress_cb=lambda m: st.update(f"[cyan]index[/] — {m}"),
            )
        if snap.static_text:
            _harvest_static(ctx, snap.static_text, source_tag="static_js")

        # 1b. Optionally fetch-all: re-snapshot every page we know so far.
        if fetch_all:
            known_pages = [p for p in ctx.schema.pages if p != snap.page_name]
            if known_pages:
                from bubblepwn.ui import progress_iter
                with progress_iter(
                    "fetch-all (static.js per page)", len(known_pages)
                ) as bar:
                    for pname in known_pages:
                        bar.set_description(f"page {pname}")
                        try:
                            sub = await snapshot_page(ctx, page=pname, want_dynamic=False)
                            if sub.static_text:
                                _harvest_static(
                                    ctx, sub.static_text,
                                    source_tag=f"static_js:{pname}",
                                )
                        except Exception as exc:
                            console.print(f"  [yellow]![/] {pname}: {exc}")
                        bar.advance()

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
            await self._probe_obj(ctx, api, only_type=type_filter)

        # 4. Optional export
        if export_type:
            await self._export_type(ctx, api, str(export_type))

        self._render(ctx)
        if show_fields:
            self._render_fields_per_type(ctx, only_type=type_filter)
        if list_fields:
            self._render_field_pool(ctx)
        self._push_findings(ctx)

    def _render_fields_per_type(
        self, ctx: Context, *, only_type: str | None = None
    ) -> None:
        """Per-type detailed field view — merges probe results with
        the static.js DefaultValues catalogue for human labels.

        Each type with known fields (from ``init/data`` or ``--probe``) is
        rendered as its own block (horizontal rule + table) showing every
        field with:
          - Field name (user-facing key stripped from the ``___<type>`` suffix)
          - Bubble type (``text``, ``boolean``, ``custom.X``, ``list.X``,
            ``option.X``, ...)
          - Display label (from static.js if available)
          - Source (``obj``, ``init_data``, ``meta``)

        Fields not known per-type (i.e. the type was never probed) do not
        appear here — use ``--list-fields`` for the count summary and
        exploration hints.
        """
        from rich.rule import Rule
        from rich.table import Table

        rich_pool: dict[str, dict[str, str]] = (
            ctx.settings.get("_field_triples") or {}
        )

        types_with_fields = [
            t for t in ctx.schema.types.values() if t.fields
        ]
        if only_type:
            types_with_fields = [
                t for t in types_with_fields if t.raw == only_type
            ]
            if not types_with_fields:
                console.print(
                    f"[yellow]No fields attached to[/] [cyan]{only_type}[/]. "
                    "Is the type name correct? Run "
                    f"[cyan]run datatypes --probe --type {only_type}[/] first."
                )
                return
        if not types_with_fields:
            console.print(
                "[yellow]No per-type fields known.[/] Run "
                "[cyan]run datatypes --probe[/] first (Data API required). "
                "Use [cyan]--list-fields[/] for the count summary from "
                "static.js."
            )
            return

        total_fields = sum(len(t.fields) for t in types_with_fields)
        panel(
            "Fields per type",
            f"{len(types_with_fields)} type(s) with known fields · "
            f"{total_fields} field(s) total",
            style="cyan",
        )

        for t in sorted(types_with_fields, key=lambda x: x.raw):
            console.print()
            console.print(Rule(
                f"[bold cyan]{t.raw}[/] [dim]· {t.namespace} · "
                f"{len(t.fields)} field(s)[/]",
                style="cyan",
                align="left",
            ))
            table = Table(header_style="bold", border_style="dim")
            table.add_column("Field", style="cyan", no_wrap=True)
            table.add_column("Bubble type", style="magenta", no_wrap=True)
            table.add_column("Display label", overflow="fold")
            table.add_column("Source", style="dim", no_wrap=True)
            for fname in sorted(t.fields.keys()):
                field = t.fields[fname]
                # Look up the display label from the DefaultValues catalogue
                # by the raw DB column name (that's the match key)
                triple = rich_pool.get(field.raw)
                if triple:
                    display = triple.get("display") or "[dim]—[/]"
                    canon_type = triple.get("value") or field.type
                else:
                    display = "[dim]—[/]"
                    canon_type = field.type
                table.add_row(fname, canon_type, display, field.source)
            console.print(table)

    def _render_field_pool(self, ctx: Context) -> None:
        """Compact summary of the static.js DefaultValues catalogue.

        Emits:
          - a total count of fields seen in the bundle,
          - a breakdown by Bubble type category (text / number / list.* /
            option.* / custom.* refs / …),
          - exploration hints (``--show-fields`` for per-type blocks,
            ``--probe`` to attach fields to their owning type).

        This is intentionally small — the full flat table proved overwhelming
        on apps with hundreds of fields and duplicated what ``--show-fields``
        already renders per-type. For the detailed per-type view, use
        ``--show-fields``.
        """
        rich_pool: dict[str, dict[str, str]] = (
            ctx.settings.get("_field_triples") or {}
        )
        if not rich_pool:
            console.print(
                "[yellow]No field triples captured from static.js.[/] "
                "(The DefaultValues block may not be present on this page — "
                "try `run pages --fetch-all` first to enrich the bundle cache.)"
            )
            return

        # Bucket entries by their Bubble type category.
        buckets: dict[str, int] = {}
        for e in rich_pool.values():
            val = (e.get("value") or "").strip()
            if not val:
                cat = "other"
            elif val.startswith("list."):
                cat = "list"
            elif val.startswith("option."):
                cat = "option"
            elif val.startswith("custom."):
                cat = "custom (ref)"
            else:
                cat = val  # primitive: text, number, boolean, date, …
            buckets[cat] = buckets.get(cat, 0) + 1

        total = len(rich_pool)
        panel(
            "Fields discovered in static.js",
            f"{total} field(s) in the DefaultValues catalogue "
            "[dim](owning type not encoded — use --show-fields for attached "
            "fields)[/]",
            style="cyan",
        )

        # Breakdown table (by count desc, then name).
        from rich.table import Table
        breakdown = Table(
            header_style="bold cyan", border_style="dim", show_edge=False,
        )
        breakdown.add_column("Category", style="magenta", no_wrap=True)
        breakdown.add_column("Count", justify="right")
        for cat, n in sorted(buckets.items(), key=lambda kv: (-kv[1], kv[0])):
            breakdown.add_row(cat, str(n))
        console.print(breakdown)

        console.print(
            "\n[dim]To explore further:[/]\n"
            "  [cyan]run datatypes --show-fields --type <name>[/]   "
            "fields of one table (block with labels)\n"
            "  [cyan]run datatypes --show-fields[/]                 "
            "one block per type with display labels\n"
            "  [cyan]run datatypes --probe --type <name>[/]         "
            "attach static.js fields to that single type via /obj/\n"
            "  [cyan]run datatypes --probe[/]                       "
            "attach static.js fields to every type (full Data API sweep)\n"
            "  [cyan]run datatypes --export-type <name>[/]          "
            "paginate /obj/<name> and dump all records onto the type"
        )

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

    async def _probe_obj(
        self, ctx: Context, api: BubbleAPI, *, only_type: str | None = None
    ) -> None:
        tested = 0
        open_types: list[str] = []
        fields_added = 0
        items = list(ctx.schema.types.items())
        if only_type:
            items = [(raw, t) for raw, t in items if raw == only_type]
            if not items:
                console.print(
                    f"  [yellow]![/] --type {only_type} not in the schema "
                    "yet — fetch static.js first (run pages or datatypes "
                    "without --type)."
                )
                return
        # Skip types already probed in a previous run so the feedback counter
        # reflects actual work done.
        to_probe = [(raw, t) for raw, t in items if t.data_api_open is not True]
        if not to_probe:
            console.print(
                "  [dim]obj probe skipped (every type already confirmed)[/]"
            )
            return

        console.print(
            f"[cyan]→[/] probing /api/1.1/obj/ on {len(to_probe)} type(s)…"
        )
        from bubblepwn.ui import progress_iter
        with progress_iter(
            f"obj probe ({len(to_probe)} types)", len(to_probe)
        ) as bar:
            for raw, t in to_probe:
                type_path = (
                    raw.split(".", 1)[1] if raw.startswith("custom.") else raw
                )
                bar.set_description(f"/obj/{type_path}")
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
                                # Extract fields from the record's keys. Bubble
                                # returns fields under their raw DB names like
                                # ``<name>___<type>`` for typed custom fields,
                                # plus system keys (``_id``, ``Created Date``,
                                # ``Modified Date``, ``_type``, ``Created By``).
                                for key in rec:
                                    if key in t.fields:
                                        continue
                                    if "___" in key:
                                        fname, _, ftype = key.rpartition("___")
                                        if fname and ftype:
                                            t.add_field(BubbleField(
                                                name=fname, type=ftype,
                                                raw=key, source="obj",
                                            ))
                                            fields_added += 1
                                            continue
                                    # System / implicit fields — keep them so
                                    # the user sees the full shape of the record.
                                    t.add_field(BubbleField(
                                        name=key, type="system",
                                        raw=key, source="obj",
                                    ))
                                    fields_added += 1
                bar.advance()
        console.print(
            f"  [green]✓[/] obj probe → {tested} types tested, "
            f"{len(open_types)} accessible, +{fields_added} field(s) mapped"
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

        total_fields = sum(len(t.fields) for t in types)
        pool_size = len(ctx.settings.get("_field_pool") or ())
        summary = f"{len(types)} types · {total_fields} fields mapped to a type"
        if pool_size:
            summary += (
                f" · {pool_size} field patterns seen in static.js without a "
                "known owner"
            )
        panel("Data types", summary, style="cyan")

        types_without_fields = sum(1 for t in types if not t.fields)
        if types_without_fields and types_without_fields == len(types) - (
            1 if any(t.raw == "user" and t.fields for t in types) else 0
        ):
            console.print(
                "[dim]Field counts are available only for types populated by "
                "`/api/1.1/init/data` or by `--probe` (Data API). "
                "Run `[cyan]run datatypes --probe[/]` to probe "
                "`/api/1.1/meta` and `/api/1.1/obj/<type>` for accurate "
                "per-type field lists.[/]"
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
            n = len(t.fields)
            fields_cell = str(n) if n else "[dim]0[/]"
            table.add_row(
                t.name,
                t.namespace,
                fields_cell,
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
