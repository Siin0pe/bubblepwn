"""API Probe module — comprehensive Bubble Data API + Workflow API audit.

Covers: (2.1) Data API open, (2.2) Swagger exposed, + bonus checks:
  - Workflow API public/no-auth endpoints
  - Method asymmetry (OPTIONS)
  - IDOR on `/obj/<type>/<id>`
  - `/version-test/` branch probing (`--include-test`)
  - Cursor-based enumeration (`--enumerate`)
  - Adjacent endpoints (`/elasticsearch/msearch`, `/user/hi`)

All probes are GET/OPTIONS by default (read-only). `--methods` activates
POST probes; `--workflows` actively invokes no-auth workflows; neither is
enabled by default for safety.
"""
from __future__ import annotations

from typing import Any, Optional

from bubblepwn.bubble.api import BubbleAPI
from bubblepwn.bubble.parse.meta import ParsedMeta, parse_meta
from bubblepwn.bubble.schema import BubbleField
from bubblepwn.context import Context, Finding
from bubblepwn.modules.base import Module, parse_flags, register
from bubblepwn.ui import console, panel, progress_iter


@register
class ApiProbe(Module):
    name = "api-probe"
    description = "Audit Bubble Data API + Workflow API surface (meta, obj, wf, swagger)."
    needs_auth = False
    category = "audit"
    subcommands = ()
    flags = (
        "--include-test", "--methods", "--idor", "--workflows",
        "--enumerate", "--max-types <N>",
    )
    example = "run api-probe --include-test --idor"

    async def run(self, ctx: Context, **kwargs: Any) -> None:
        if ctx.target is None:
            console.print("[red]No target set.[/] Use `target <url>` first.")
            return
        argv: list[str] = kwargs.get("argv", [])
        flags, _ = parse_flags(argv)

        include_test = bool(flags.get("include_test"))
        active_methods = bool(flags.get("methods"))
        check_idor = bool(flags.get("idor"))
        invoke_workflows = bool(flags.get("workflows"))
        enumerate_types = bool(flags.get("enumerate"))
        max_types = int(flags.get("max_types", 50))

        cookies = ctx.session.cookies if ctx.session else None
        branches = ["live"] + (["test"] if include_test else [])

        for branch in branches:
            panel(f"Branch: {branch}", f"{ctx.target.url}  ·  /{'version-test' if branch=='test' else ''}/api/1.1/", style="cyan")
            api = BubbleAPI(ctx.target.url, cookies=cookies, branch=branch)
            await self._probe_branch(
                ctx, api, branch,
                active_methods=active_methods,
                check_idor=check_idor,
                invoke_workflows=invoke_workflows,
                enumerate_types=enumerate_types,
                max_types=max_types,
            )

        self._push_summary(ctx)

    # ── per-branch orchestrator ──────────────────────────────────────────

    async def _probe_branch(
        self,
        ctx: Context,
        api: BubbleAPI,
        branch: str,
        *,
        active_methods: bool,
        check_idor: bool,
        invoke_workflows: bool,
        enumerate_types: bool,
        max_types: int,
    ) -> None:
        meta = await self._probe_meta(ctx, api, branch)
        await self._probe_swagger(ctx, api, branch)

        if not meta or not meta.get_types:
            console.print("  [dim]no types listed in meta — skipping obj probes[/]")
            return

        await self._probe_obj_types(
            ctx, api, branch, meta,
            active_methods=active_methods,
            check_idor=check_idor,
            enumerate_types=enumerate_types,
            max_types=max_types,
        )

        if invoke_workflows:
            await self._invoke_no_auth_workflows(ctx, api, branch, meta)

        await self._probe_adjacent(ctx, api, branch)

    # ── meta probes ──────────────────────────────────────────────────────

    async def _probe_meta(
        self, ctx: Context, api: BubbleAPI, branch: str
    ) -> Optional[ParsedMeta]:
        status, body = await api.meta()
        if status != 200 or body is None:
            console.print(f"  [dim]meta[/] → [yellow]{status}[/]  (API disabled)")
            return None
        parsed = parse_meta(body)
        console.print(
            f"  [green]✓[/] meta → {len(parsed.get_types)} types · "
            f"{len(parsed.post_endpoints)} endpoints · "
            f"{len(parsed.no_auth_workflows())} no-auth workflows"
        )
        # Register all types into schema
        for tname in parsed.get_types:
            raw = tname if tname == "user" else f"custom.{tname}"
            ctx.schema.upsert_type(raw, source=f"meta:{branch}")

        ctx.add_finding(Finding(
            module=self.name,
            severity="medium",
            title=f"/api/1.1/meta reachable anonymously ({branch})",
            detail=f"{len(parsed.get_types)} types + {len(parsed.post_endpoints)} endpoints exposed.",
            data={"branch": branch},
        ))
        no_auth = parsed.no_auth_workflows()
        if no_auth:
            ctx.add_finding(Finding(
                module=self.name,
                severity="high",
                title=f"{len(no_auth)} no-auth workflow(s) exposed ({branch})",
                detail=", ".join(e.endpoint for e in no_auth[:10]),
                data={"branch": branch, "endpoints": [e.endpoint for e in no_auth]},
            ))
        return parsed

    async def _probe_swagger(self, ctx: Context, api: BubbleAPI, branch: str) -> None:
        status, body = await api.meta_swagger()
        if status == 200 and isinstance(body, dict) and "swagger" in body:
            console.print("  [green]✓[/] swagger.json → [red]exposed[/]")
            ctx.add_finding(Finding(
                module=self.name,
                severity="medium",
                title=f"OpenAPI/Swagger spec publicly reachable ({branch})",
                detail="GET /api/1.1/meta/swagger.json returned a full Swagger document.",
                data={"branch": branch, "host": body.get("host"), "basePath": body.get("basePath")},
            ))
        else:
            console.print(f"  [dim]swagger.json[/] → [yellow]{status}[/]")

    # ── obj probes ───────────────────────────────────────────────────────

    async def _probe_obj_types(
        self,
        ctx: Context,
        api: BubbleAPI,
        branch: str,
        meta: ParsedMeta,
        *,
        active_methods: bool,
        check_idor: bool,
        enumerate_types: bool,
        max_types: int,
    ) -> None:
        tested = 0
        open_types: list[tuple[str, int]] = []
        idor_hits: list[str] = []

        candidates = meta.get_types[:max_types]
        console.print(f"  [cyan]→[/] testing {len(candidates)} types via /obj/")

        with progress_iter(f"/obj/ ({branch})", len(candidates)) as bar:
            for tname in candidates:
                bar.set_description(f"/obj/ · {tname[:40]}")
                raw = tname if tname == "user" else f"custom.{tname}"
                t = ctx.schema.upsert_type(raw, source=f"obj:{branch}")
                status, body = await api.obj(tname, limit=1)
                tested += 1
                if status != 200:
                    t.data_api_open = False
                    bar.advance()
                    continue

                t.data_api_open = True
                count = 0
                first_id: Optional[str] = None
                if isinstance(body, dict):
                    resp = body.get("response") or {}
                    count = resp.get("count") or 0
                    remaining = resp.get("remaining") or 0
                    results = resp.get("results") or []
                    if results and isinstance(results[0], dict):
                        t.sample_records.append(results[0])
                        first_id = results[0].get("_id")
                        for k in results[0]:
                            if k not in t.fields:
                                t.add_field(BubbleField(
                                    name=k, type="unknown", raw=k, source=f"obj:{branch}"
                                ))
                    total = count + remaining
                    open_types.append((tname, total))

                    if enumerate_types and total > 1:
                        await self._enumerate_type(api, t, tname, total)

                if check_idor and first_id:
                    s2, _ = await api.obj_by_id(tname, first_id)
                    if s2 == 200:
                        idor_hits.append(tname)

                if active_methods:
                    await self._method_asymmetry(api, tname, t)

                bar.advance()

        if open_types:
            ctx.add_finding(Finding(
                module=self.name,
                severity="high",
                title=f"{len(open_types)} data type(s) readable anonymously on {branch}",
                detail="Biggest: " + ", ".join(
                    f"{n}({t})" for n, t in sorted(open_types, key=lambda x: -x[1])[:8]
                ),
                data={"branch": branch, "types": open_types},
            ))
        if idor_hits:
            ctx.add_finding(Finding(
                module=self.name,
                severity="medium",
                title=f"{len(idor_hits)} type(s) allow direct /obj/<id> fetch",
                detail="Bubble privacy rules are evaluated separately on search vs direct GET — verify both paths have the same restrictions.",
                data={"branch": branch, "types": idor_hits},
            ))
        console.print(
            f"  [green]✓[/] obj → {tested} tested · {len(open_types)} open"
            + (f" · {len(idor_hits)} IDOR" if check_idor else "")
        )

    async def _enumerate_type(
        self, api: BubbleAPI, t: Any, tname: str, total: int
    ) -> None:
        # Cap at 1000 records to avoid runaway pulls
        cap = min(total, 1000)
        cursor = 0
        while cursor < cap:
            status, body = await api.obj(tname, limit=100, cursor=cursor)
            if status != 200 or not isinstance(body, dict):
                break
            results = (body.get("response") or {}).get("results") or []
            if not results:
                break
            t.sample_records.extend(results)
            cursor += len(results)
            if len(results) < 100:
                break

    async def _method_asymmetry(
        self, api: BubbleAPI, tname: str, t: Any
    ) -> None:
        """Send OPTIONS to discover which methods Bubble accepts on /obj/<type>."""
        status, headers = await api.options(f"obj/{tname}")
        allow = headers.get("allow") or headers.get("Allow") or ""
        if allow:
            t.sample_records.append({"_method_allow": allow})  # tag via record bag

    # ── workflow API ─────────────────────────────────────────────────────

    async def _invoke_no_auth_workflows(
        self, ctx: Context, api: BubbleAPI, branch: str, meta: ParsedMeta
    ) -> None:
        executed: list[tuple[str, int]] = []
        for ep in meta.no_auth_workflows()[:25]:
            status, _body = await api.workflow(ep.endpoint, body={})
            executed.append((ep.endpoint, status))
        ok = [e for e in executed if 200 <= e[1] < 300]
        if ok:
            ctx.add_finding(Finding(
                module=self.name,
                severity="critical",
                title=f"{len(ok)} no-auth workflow(s) actually execute without auth on {branch}",
                detail=", ".join(f"{n}={s}" for n, s in ok[:8]),
                data={"branch": branch, "executed": ok},
            ))
        console.print(f"  [green]✓[/] wf → {len(executed)} invoked · {len(ok)} returned 2xx")

    # ── adjacent endpoints ───────────────────────────────────────────────

    async def _probe_adjacent(self, ctx: Context, api: BubbleAPI, branch: str) -> None:
        s_hi, _ = await api.user_heartbeat()
        s_es, _body = await api.elasticsearch_probe("msearch")
        console.print(f"  [dim]user/hi[/]={s_hi}  [dim]elasticsearch/msearch[/]={s_es}")
        if s_es == 200:
            ctx.add_finding(Finding(
                module=self.name,
                severity="medium",
                title=f"/elasticsearch/msearch accepts anonymous POST ({branch})",
                detail="Rare — usually requires a session. Worth fuzzing the query envelope.",
                data={"branch": branch},
            ))

    # ── summary ──────────────────────────────────────────────────────────

    def _push_summary(self, ctx: Context) -> None:
        open_types = [t for t in ctx.schema.types.values() if t.data_api_open is True]
        console.print()
        panel(
            "api-probe summary",
            (
                f"[bold]types open on Data API[/]: {len(open_types)}\n"
                f"[bold]types total[/]           : {len(ctx.schema.types)}\n"
            ),
            style="green" if not open_types else "yellow",
        )
