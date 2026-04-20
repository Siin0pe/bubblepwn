"""Workflows module — audit Bubble API workflows (``/api/1.1/wf/<name>``).

Covers Tier 3 of the Bubble pentest taxonomy:

  - 3.1 Public workflows without auth → enumeration via wordlist + bundle names
  - 3.2 "Ignore privacy rules" — anon vs auth response diff (``compare``)
  - 3.3 Unvalidated parameters — basic type-mismatch / null / overflow fuzz
  - 3.4 Temporary password exploits — probe reset/password workflows, scan the
        response for password-like leaks

Subcommands:
  workflows analyze         (default) — probe candidate names, classify each
  workflows invoke <name>              — utility POST with --body '<json>'
  workflows fuzz <name>                — sweep type mismatches / extremes
  workflows compare <name>             — anon vs auth, diff response bodies

Response classifications (Tier 3.1):
  MISSING   → 400 body signals missing param                  (EXISTS)
  INVALID   → 400 body signals invalid value                  (EXISTS)
  AUTH      → 401 / 403                                       (EXISTS, auth)
  OPEN_OK   → 2xx                                             (EXECUTED, no auth)
  BLOCKED   → 404                                             (absent or private)
  ERROR     → network / unparseable
"""
from __future__ import annotations

import json
import re
from typing import Any, Optional

from bubblepwn.bubble.api import BubbleAPI
from bubblepwn.bubble.parse import workflow_names as wf_parse
from bubblepwn.bubble.parse.meta import parse_meta
from bubblepwn.bubble.wordlists import load as load_wordlist
from bubblepwn.bubble.workflow import snapshot_page
from bubblepwn.context import Context, Finding
from bubblepwn.modules.base import Module, parse_flags, register
from bubblepwn.ui import console, panel, progress_iter

# Bubble surfaces the missing/invalid param name in several shapes:
#
#   "Missing parameter for workflow X: parameter code"          (unquoted)
#   "Missing parameter 'code'"                                  (single quotes)
#   "Missing data: parameter \"code\""                          (double quotes)
#   "Invalid value for parameter code"                           (unquoted)
#   "Invalid value for parameter 'code' (must be number)"       (single quotes)
#
# The old regexes required quotes and lost the hint on Bubble's most common
# format (unquoted `parameter <name>`). The broader patterns below take the
# first identifier-shaped token after ``parameter``.
_MISSING_RE = re.compile(
    # Anchor on "missing parameter" or "missing data" / "missing required
    # parameter" (Bubble uses all three across versions).
    r"missing\s+(?:required\s+)?(?:parameter|data)"
    # Optional "for workflow <name>" clause that precedes the colon.
    r"(?:\s+for\s+workflow\s+\S+)?"
    # Any whitespace / colon / comma / dash between the anchor and the
    # param name itself.
    r"[:,\s\-–—]+"
    # Optional second "parameter" keyword (the long-form shape).
    r"(?:parameter\s+)?"
    # The identifier, optionally wrapped in single or double quotes.
    r"['\"`]?([a-zA-Z_][a-zA-Z0-9_]*)['\"`]?",
    re.I,
)
_INVALID_RE = re.compile(
    r"(?:invalid|bad|wrong)(?:\s+value)?(?:\s+for)?\s+parameter\s+"
    r"['\"`]?([a-zA-Z_][a-zA-Z0-9_]*)['\"`]?",
    re.I,
)
_PASSWORD_LEAK_RE = re.compile(
    r'"(?:password|temp_pass|temporary_password|new_password|reset_token|token)"\s*:\s*"([^"]{6,})"',
    re.I,
)
_HEX64_IN_RESP_RE = re.compile(r"\b[a-f0-9]{48,96}\b")

# Common first-parameter guesses for workflows where Bubble refused the
# empty body but didn't name the missing param in an extractable way.
# One successful probe unblocks the server — it then names the *next*
# required param. Picking fields that are ubiquitous in Bubble apps
# (auth flows, CRUD on `user`) maximises the hit rate with minimal
# request volume.
_COMMON_SEEDS = (
    "email", "user_id", "id", "code", "token", "password",
    "name", "user", "data", "value", "query", "text",
    "phone", "username", "key", "type",
)


def _classify(status: int, body: Any) -> tuple[str, Optional[str]]:
    """Return ``(label, hint)``. ``hint`` is a missing/invalid param name
    when extractable, else a short human-readable excerpt of the body so
    the caller can surface it in the UI without re-parsing the response.

    Labels (ordered most to least interesting for a defender):
      - ``OPEN_OK``  200/2xx                     — workflow ran anon, bad
      - ``NOT_RUN``  400 NOT_RUN                 — workflow exists, condition
                                                    not met (still reachable)
      - ``MISSING``  400 missing parameter       — workflow exists, needs args
      - ``INVALID``  400 invalid parameter       — workflow exists, needs
                                                    typed args
      - ``AUTH``     401/403                     — workflow exists, auth-gated
      - ``BLOCKED``  404                         — no such workflow
      - ``ERROR``    5xx / transport             — unclassifiable
    """
    if status == 404:
        return "BLOCKED", None
    if status in (401, 403):
        return "AUTH", None
    if 200 <= status < 300:
        return "OPEN_OK", None
    if 400 <= status < 500:
        # Run regex on the *raw* message string (not the JSON-dumped
        # payload) so embedded quotes aren't mangled by escape sequences.
        message = _extract_bubble_message(body) or ""
        lower_all = (message + " " + (
            json.dumps(body) if not isinstance(body, str) else body
        )).lower()

        # Bubble-specific: condition-gated workflows reach the endpoint
        # but refuse to execute. The workflow is effectively reachable
        # anon — fuzzing may bypass the condition.
        if "not_run" in lower_all or "workflow won't run" in lower_all:
            return "NOT_RUN", message or None

        m = _MISSING_RE.search(message) if message else None
        if m:
            return "MISSING", m.group(1)
        if "missing_data" in lower_all or "missing parameter" in lower_all:
            return "MISSING", message or None
        m = _INVALID_RE.search(message) if message else None
        if m:
            return "INVALID", m.group(1)
        return "INVALID", message or None
    return "ERROR", None


def _extract_bubble_message(body: Any) -> Optional[str]:
    """Pull the ``message`` field from a Bubble error response.

    Bubble returns either ``{"message": "..."}`` or
    ``{"body": {"message": "..."}}`` depending on the failure class. Either
    way the human-readable hint is the first place to display when param
    extraction fails.
    """
    if isinstance(body, dict):
        if isinstance(body.get("message"), str):
            return body["message"][:160]
        inner = body.get("body")
        if isinstance(inner, dict) and isinstance(inner.get("message"), str):
            return inner["message"][:160]
    if isinstance(body, str):
        return body[:160]
    return None


def _sev(label: str) -> str:
    return {
        "OPEN_OK": "critical",
        "NOT_RUN": "low",
        "MISSING": "medium",
        "INVALID": "medium",
        "AUTH":    "info",
        "BLOCKED": "info",
        "ERROR":   "info",
    }.get(label, "info")


@register
class Workflows(Module):
    name = "workflows"
    description = (
        "Audit Bubble API workflows (/api/1.1/wf/): enumerate, extract params, "
        "detect temp-password leaks, fuzz, diff anon vs auth."
    )
    needs_auth = False
    category = "exploit"
    subcommands = (
        ("analyze", "enumerate exposed backend workflows from meta + "
                    "wordlist, extract params from bundles, detect "
                    "temp-password emails and no-auth endpoints"),
        ("invoke <name>", "call /api/1.1/wf/<name> once with the JSON "
                          "body from --body (or `{}`)"),
        ("fuzz <name>", "brute-force parameter names for a given "
                        "workflow to surface hidden required fields"),
        ("compare <name>", "call the same workflow anon and "
                           "authenticated — diff responses to find "
                           "auth-bypass / privilege-escalation bugs"),
    )
    flags = (
        ("--wordlist <file>", "custom workflow name list — one per line "
                              "(default: built-in Bubble list)"),
        ("--max <N>", "cap the number of workflow names probed. "
                      "Omit to probe every candidate (default behaviour)."),
        ("--deep-params", "analyze: also fetch dynamic.js to widen the "
                          "param-extraction regex"),
        ("--include-test", "also probe /version-test/ branch"),
        ("--body '<json>'", "invoke / fuzz: JSON payload sent to the "
                            "workflow (default: `{}`)"),
        ("--branch test", "target the /version-test/ branch"),
        ("--auth", "use ctx.session cookies on the request "
                   "(implicit for `compare`)"),
    )
    example = "run workflows analyze --deep-params"
    long_help = (
        "`analyze` is the main read-only pass: enumerates endpoints, "
        "surfaces params, classifies severity (temp-password emails, "
        "no-auth, test-branch-only…). `invoke` / `fuzz` / `compare` are "
        "active — only run them with authorization."
    )

    async def run(self, ctx: Context, **kwargs: Any) -> None:
        if ctx.target is None:
            console.print("[red]No target set.[/]")
            return
        argv: list[str] = kwargs.get("argv", [])
        flags, positional = parse_flags(argv)
        sub = positional[0].lower() if positional else "analyze"

        cookies_anon: Optional[dict[str, str]] = None
        cookies_auth = ctx.session.cookies if ctx.session else None

        if sub == "analyze":
            await self._analyze(ctx, cookies_anon, cookies_auth, flags)
        elif sub == "invoke":
            if len(positional) < 2:
                console.print("[red]usage:[/] run workflows invoke <name> [--body '<json>']")
                return
            await self._invoke(ctx, positional[1], flags)
        elif sub == "fuzz":
            if len(positional) < 2:
                console.print("[red]usage:[/] run workflows fuzz <name>")
                return
            await self._fuzz(ctx, positional[1], flags)
        elif sub == "compare":
            if len(positional) < 2 or not cookies_auth:
                console.print(
                    "[red]usage:[/] run workflows compare <name>  "
                    "(requires `session load <file>`)"
                )
                return
            await self._compare(ctx, positional[1], cookies_auth, flags)
        else:
            console.print(f"[red]unknown subcommand:[/] {sub}")

    # ── analyze ──────────────────────────────────────────────────────────

    async def _analyze(
        self,
        ctx: Context,
        cookies_anon: Optional[dict[str, str]],
        cookies_auth: Optional[dict[str, str]],
        flags: dict[str, Any],
    ) -> None:
        include_test = bool(flags.get("include_test"))
        deep_params = bool(flags.get("deep_params"))
        # --max is opt-in only: passing it caps the candidate list,
        # omitting it probes every single candidate discovered. The
        # previous default of 200 silently dropped workflows — we'd
        # rather the scan take longer than miss them.
        raw_max = flags.get("max")
        max_candidates: Optional[int] = (
            int(raw_max) if isinstance(raw_max, (int, str)) and str(raw_max).strip()
            else None
        )
        user_wordlist = flags.get("wordlist")

        candidates = await self._collect_candidates(
            ctx, extra_wordlist=str(user_wordlist) if user_wordlist else None
        )
        if max_candidates is not None and len(candidates) > max_candidates:
            console.print(
                f"[dim]--max {max_candidates} · probing {max_candidates}/"
                f"{len(candidates)} candidates (drop the flag to probe all)[/]"
            )
            candidates = candidates[:max_candidates]

        panel(
            "Workflows — analyze",
            f"{len(candidates)} candidate(s) · include_test={include_test} · "
            f"deep_params={deep_params}",
            style="cyan",
        )

        branches = ["live"] + (["test"] if include_test else [])
        rows: list[dict[str, Any]] = []
        total = len(candidates) * len(branches)
        with progress_iter("Probing workflows", total) as bar:
            for branch in branches:
                api = BubbleAPI(ctx.target.url, cookies=cookies_anon, branch=branch)
                for name in candidates:
                    bar.set_description(f"[{branch}] {name[:40]}")
                    res = await self._probe_once(api, name, body={})
                    row = {
                        "branch": branch,
                        "name": name,
                        **res,
                        "params": [],
                    }
                    if (
                        deep_params
                        and res["label"] in ("MISSING", "INVALID", "NOT_RUN")
                    ):
                        row["params"] = await self._extract_params(
                            api, name, res.get("hint"),
                            update_cb=lambda m, n=name, b=branch: bar.set_description(
                                f"{b} · {n[:40]} · {m}"
                            ),
                        )
                    rows.append(row)
                    bar.advance()

        self._render_analyze(rows)
        self._push_findings_analyze(ctx, rows)

    async def _collect_candidates(
        self, ctx: Context, extra_wordlist: Optional[str] = None
    ) -> list[str]:
        seen: dict[str, None] = {}

        # 1) Workflows named in /api/1.1/meta, if we can reach it
        api = BubbleAPI(ctx.target.url, branch="live")
        status, body = await api.meta()
        if status == 200 and isinstance(body, dict):
            parsed = parse_meta(body)
            for ep in parsed.post_endpoints:
                if ep.endpoint:
                    seen.setdefault(ep.endpoint, None)

        # 2) Built-in wordlist
        for name in load_wordlist("workflows"):
            seen.setdefault(name, None)

        # 3) Extra wordlist supplied by the user
        if extra_wordlist:
            from pathlib import Path
            p = Path(extra_wordlist)
            if p.exists():
                for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        seen.setdefault(line, None)

        # 4) Bundle extraction (explicit URL references + heuristic snake_case)
        try:
            snap = await snapshot_page(ctx)
            for text in (snap.static_text, snap.dynamic_text, snap.html):
                if not text:
                    continue
                for n in wf_parse.extract_workflow_url_names(text):
                    seen.setdefault(n, None)
                for n in wf_parse.extract_interesting_snake_names(text):
                    seen.setdefault(n, None)
        except Exception as exc:
            console.print(f"[yellow]bundle extraction skipped:[/] {exc}")

        return list(seen.keys())

    async def _probe_once(
        self, api: BubbleAPI, name: str, *, body: dict[str, Any]
    ) -> dict[str, Any]:
        status, resp = await api.workflow(name, method="POST", body=body)
        label, hint = _classify(status, resp)
        return {
            "status": status,
            "label": label,
            "hint": hint,
            "body": resp,
        }

    async def _extract_params(
        self,
        api: BubbleAPI,
        name: str,
        seed_param: Optional[str],
        max_iter: int = 20,
        *,
        update_cb: Optional[Any] = None,
    ) -> list[dict[str, str]]:
        """Iteratively POST with placeholder values to learn expected params.

        Bubble's 400 response names the first missing/invalid parameter. We
        fill it with a typed placeholder and re-post until we stop getting
        MISSING/INVALID labels.

        When ``seed_param`` is ``None`` (regex failed to extract a hint),
        fall back to a short list of common Bubble param names
        (``email``, ``user_id``, ``id``, ``code``, ``token``…) — posting
        with one of them set often unblocks the server and it names the
        *next* missing param in the response. The extraction then
        proceeds as usual.

        ``update_cb`` receives a short string after each probe (``learning
        params · N`` etc.) so the caller — typically an outer progress bar
        or a console.status — can surface activity. Up to ``max_iter`` (20)
        HTTP round-trips per workflow, which would otherwise sit silent.
        """
        body: dict[str, Any] = {}
        params: list[dict[str, str]] = []
        seeds: list[str]
        if seed_param:
            seeds = [seed_param]
        else:
            seeds = list(_COMMON_SEEDS)

        iter_i = 0
        while iter_i < max_iter and seeds:
            current = seeds.pop(0)
            if current in body:
                continue
            body[current] = "bubblepwn-probe"
            iter_i += 1
            if update_cb is not None:
                try:
                    update_cb(f"learning params · {iter_i} ({current})")
                except Exception:
                    pass
            status, resp = await api.workflow(name, method="POST", body=body)
            label, hint = _classify(status, resp)
            params.append({
                "name": current,
                "after_status": str(status),
                "after_label": label,
            })
            if label not in ("MISSING", "INVALID", "NOT_RUN"):
                # Either OPEN_OK (great — we found the minimum args) or
                # AUTH/BLOCKED/ERROR (no point going further).
                break
            # Server named the next missing param → prioritise it.
            if hint and hint not in body:
                seeds.insert(0, hint)
            elif not seeds and not seed_param:
                # Seed list exhausted without a hit — stop rather than
                # spam the server with random probes.
                break
        return params

    def _render_analyze(self, rows: list[dict[str, Any]]) -> None:
        from rich.table import Table
        if not rows:
            console.print("[yellow]No candidates probed.[/]")
            return

        # Only show rows that indicate existence (drop BLOCKED / ERROR)
        interesting = [r for r in rows if r["label"] not in ("BLOCKED", "ERROR")]
        if not interesting:
            console.print("[green]All probes returned 404/error — no workflow surfaced.[/]")
            return

        table = Table(header_style="bold cyan", border_style="dim")
        table.add_column("Branch", style="magenta", no_wrap=True)
        table.add_column("Workflow", style="cyan", no_wrap=True, overflow="fold")
        table.add_column("Status", justify="right")
        table.add_column("Class", style="bold")
        table.add_column("First hint / params", overflow="fold")

        style_for = {
            "OPEN_OK": "red bold",
            "NOT_RUN": "cyan",
            "MISSING": "yellow",
            "INVALID": "yellow",
            "AUTH": "blue",
        }
        # Sort order: most actionable label first, then by branch/name.
        label_rank = {
            "OPEN_OK": 0, "MISSING": 1, "INVALID": 2,
            "NOT_RUN": 3, "AUTH": 4,
        }
        interesting.sort(
            key=lambda r: (
                label_rank.get(r["label"], 9), r["branch"], r["name"],
            )
        )
        for r in interesting:
            cls = r["label"]
            params = r.get("params") or []
            params_txt = ",".join(p["name"] for p in params)
            hint = r.get("hint") or ""
            # When extraction happened, show what we learned; otherwise
            # surface the raw Bubble message so the user can see why the
            # server refused the request and iterate on it manually.
            hint_column = params_txt or hint or ""
            table.add_row(
                r["branch"],
                r["name"],
                str(r["status"]),
                f"[{style_for.get(cls, 'white')}]{cls}[/]",
                hint_column,
            )
        console.print(table)

        # Temp-password leak scan on every response body
        leaks = []
        for r in rows:
            body_text = json.dumps(r["body"]) if not isinstance(r["body"], str) else r["body"]
            for m in _PASSWORD_LEAK_RE.finditer(body_text):
                leaks.append((r["name"], m.group(0)[:120]))
        if leaks:
            console.print()
            panel(
                "🚨 Password/token leaked in response body",
                "\n".join(f"  [red]{n}[/]  →  {leak}" for n, leak in leaks[:10]),
                style="red",
            )

    def _push_findings_analyze(
        self, ctx: Context, rows: list[dict[str, Any]]
    ) -> None:
        open_ok = [r for r in rows if r["label"] == "OPEN_OK"]
        missing = [r for r in rows if r["label"] == "MISSING"]
        not_run = [r for r in rows if r["label"] == "NOT_RUN"]
        auth = [r for r in rows if r["label"] == "AUTH"]

        if open_ok:
            ctx.add_finding(Finding(
                module=self.name,
                severity="critical",
                title=f"{len(open_ok)} workflow(s) execute anonymously (2xx on empty POST)",
                detail=", ".join(
                    f"{r['name']}[{r['branch']}]" for r in open_ok[:10]
                ),
                data={"workflows": [{"name": r["name"], "branch": r["branch"]} for r in open_ok]},
            ))
        if missing:
            ctx.add_finding(Finding(
                module=self.name,
                severity="medium",
                title=(
                    f"{len(missing)} workflow(s) reachable without auth; param "
                    "schema leaked via 400 MISSING_DATA"
                ),
                data={
                    "workflows": [
                        {"name": r["name"], "branch": r["branch"], "first_param": r.get("hint")}
                        for r in missing
                    ]
                },
            ))
        if not_run:
            ctx.add_finding(Finding(
                module=self.name,
                severity="low",
                title=(
                    f"{len(not_run)} workflow(s) reachable anon but gated by a "
                    "condition (NOT_RUN) — conditions bypassable via fuzz"
                ),
                detail=(
                    "Bubble confirmed the workflow exists and accepts POSTs "
                    "without auth, but a precondition (triggering criterion) "
                    "refused to run. Run `workflows fuzz <name>` with varied "
                    "payloads to attempt bypass."
                ),
                data={
                    "workflows": [
                        {"name": r["name"], "branch": r["branch"], "message": r.get("hint")}
                        for r in not_run
                    ]
                },
            ))
        # Temp-password flag: any workflow whose name matches password/reset/temp
        suspect = [
            r for r in (missing + open_ok + auth)
            if re.search(r"(pass|reset|forgot|temp|token|magic)", r["name"], re.I)
        ]
        if suspect:
            ctx.add_finding(Finding(
                module=self.name,
                severity="high",
                title=f"{len(suspect)} password/token-related workflow(s) exposed",
                detail=", ".join(r["name"] for r in suspect[:10]),
                data={"workflows": [r["name"] for r in suspect]},
            ))

    # ── invoke ───────────────────────────────────────────────────────────

    async def _invoke(self, ctx: Context, name: str, flags: dict[str, Any]) -> None:
        body_raw = flags.get("body") or "{}"
        method = str(flags.get("method", "POST")).upper()
        branch = "test" if flags.get("branch") == "test" else "live"
        try:
            body = json.loads(str(body_raw))
        except json.JSONDecodeError as exc:
            console.print(f"[red]invalid --body JSON:[/] {exc}")
            return
        cookies = ctx.session.cookies if ctx.session and flags.get("auth") else None
        api = BubbleAPI(ctx.target.url, cookies=cookies, branch=branch)
        status, resp = await api.workflow(name, method=method, body=body)
        panel(
            f"{method} /api/1.1/wf/{name}  [branch={branch}]",
            f"status={status}\n\n"
            + (json.dumps(resp, indent=2, ensure_ascii=False) if not isinstance(resp, str) else resp)[:3000],
            style="cyan",
        )

    # ── fuzz ─────────────────────────────────────────────────────────────

    async def _fuzz(self, ctx: Context, name: str, flags: dict[str, Any]) -> None:
        branch = "test" if flags.get("branch") == "test" else "live"
        cookies = ctx.session.cookies if ctx.session and flags.get("auth") else None
        api = BubbleAPI(ctx.target.url, cookies=cookies, branch=branch)

        console.print(f"[cyan]fuzzing[/] /api/1.1/wf/{name}  [branch={branch}]")

        # Stage 1 — learn parameters
        with console.status(
            f"[cyan]learning params of {name}[/]", spinner="dots"
        ) as st:
            base = await self._probe_once(api, name, body={})
            params = await self._extract_params(
                api, name, base.get("hint") or "",
                update_cb=lambda m: st.update(f"[cyan]learning params of {name}[/] — {m}"),
            )
        param_names = [p["name"] for p in params]
        console.print(f"  learned params: {param_names or '(none)'}")

        # Stage 2 — fuzz each param in isolation
        payloads = [
            ("null",   None),
            ("empty",  ""),
            ("number_string", "1234"),
            ("bool_string",   "true"),
            ("huge_text", "x" * 10_000),
            ("neg_one", -1),
            ("max_int", 2**53 - 1),
            ("special_chars", "<'\"%>&{{}}"),
            ("sql_like", "' OR '1'='1"),
            ("deep_list", [[[1, 2, 3]] * 10] * 10),
        ]
        from rich.table import Table
        table = Table(header_style="bold cyan", border_style="dim")
        table.add_column("Param")
        table.add_column("Case")
        table.add_column("Status", justify="right")
        table.add_column("Label")
        table.add_column("Body snippet", overflow="fold", style="dim")

        total_probes = len(param_names) * len(payloads)
        from bubblepwn.ui import progress_iter
        with progress_iter(
            f"fuzzing {name} ({len(param_names)} params × {len(payloads)} cases)",
            total_probes,
        ) as bar:
            for pname in param_names:
                for case, val in payloads:
                    bar.set_description(f"{pname} · {case}")
                    body = {p: "bubblepwn-probe" for p in param_names}
                    body[pname] = val
                    res = await self._probe_once(api, name, body=body)
                    snippet = (
                        json.dumps(res["body"])
                        if not isinstance(res["body"], str)
                        else res["body"]
                    )[:80]
                    table.add_row(
                        pname, case, str(res["status"]), res["label"], snippet
                    )
                    bar.advance()
        console.print(table)

    # ── compare ──────────────────────────────────────────────────────────

    async def _compare(
        self,
        ctx: Context,
        name: str,
        cookies_auth: dict[str, str],
        flags: dict[str, Any],
    ) -> None:
        branch = "test" if flags.get("branch") == "test" else "live"
        body_raw = flags.get("body") or "{}"
        try:
            body = json.loads(str(body_raw))
        except json.JSONDecodeError as exc:
            console.print(f"[red]invalid --body JSON:[/] {exc}")
            return

        api_anon = BubbleAPI(ctx.target.url, branch=branch)
        api_auth = BubbleAPI(ctx.target.url, cookies=cookies_auth, branch=branch)
        s_anon, r_anon = await api_anon.workflow(name, method="POST", body=body)
        s_auth, r_auth = await api_auth.workflow(name, method="POST", body=body)

        txt_anon = json.dumps(r_anon, ensure_ascii=False, indent=2) if not isinstance(r_anon, str) else r_anon
        txt_auth = json.dumps(r_auth, ensure_ascii=False, indent=2) if not isinstance(r_auth, str) else r_auth

        panel(
            f"/api/1.1/wf/{name}  compare anon vs auth",
            (
                f"[bold]anon[/] status={s_anon}\n{txt_anon[:1500]}\n\n"
                f"[bold]auth[/] status={s_auth}\n{txt_auth[:1500]}"
            ),
            style="cyan" if s_anon != s_auth else "yellow",
        )
        if s_anon == 200 and s_anon == s_auth and txt_anon == txt_auth:
            ctx.add_finding(Finding(
                module=self.name,
                severity="high",
                title=f"{name} returns identical data anon vs auth — possible 'Ignore privacy rules'",
                data={"workflow": name, "status": s_anon},
            ))
