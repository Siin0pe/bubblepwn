"""Config audit — Tier 5 (app configuration misconfigs).

Subcommands:
  config-audit editor       — probe bubble.io/page?id=<app>&version=<v>
                               to detect publicly-viewable app editor (5.2).
  config-audit headers      — deep security-header audit on the target root
                               (X-Frame-Options, CSP, HSTS, etc. — 5.3).
  config-audit version-diff — diff each schema page between /live and
                               /version-test (status, headers, bundles) (5.1).
"""
from __future__ import annotations

from typing import Any, Optional

import httpx

from bubblepwn.bubble.api import BubbleAPI
from bubblepwn.bubble.parse import html as html_parse
from bubblepwn.bubble.workflow import snapshot_page
from bubblepwn.context import Context, Finding
from bubblepwn.http import client
from bubblepwn.modules.base import Module, parse_flags, register
from bubblepwn.ui import console, panel, progress_iter


# ── Security header rubric ──────────────────────────────────────────────

_HEADER_RUBRIC: list[tuple[str, str, str]] = [
    # (header_name, expected_contains, severity_if_missing)
    ("strict-transport-security", "max-age", "medium"),
    ("content-security-policy",   "",        "medium"),
    ("x-frame-options",           "",        "low"),  # superseded by CSP frame-ancestors but still useful
    ("x-content-type-options",    "nosniff", "low"),
    ("referrer-policy",           "",        "low"),
    ("permissions-policy",        "",        "low"),
]


def _header_verdict(name: str, value: Optional[str]) -> tuple[str, str]:
    if value is None or value.strip() == "":
        return ("MISSING", "")
    lower = value.lower()
    if name == "strict-transport-security":
        if "includesubdomains" in lower and "preload" in lower:
            return ("STRONG", value)
        if "max-age" in lower:
            # check max-age value
            import re
            m = re.search(r"max-age=(\d+)", lower)
            if m and int(m.group(1)) >= 31536000:
                return ("OK", value)
            return ("WEAK", value)
        return ("WEAK", value)
    if name == "content-security-policy":
        directives = [d.strip().split(" ", 1)[0] for d in value.split(";") if d.strip()]
        score = sum(1 for d in ("default-src", "script-src", "frame-ancestors", "object-src") if d in directives)
        if score >= 3:
            return ("STRONG", value)
        if score >= 1:
            return ("WEAK", value)
        return ("PERMISSIVE", value)
    if name == "x-frame-options":
        if lower in ("deny", "sameorigin"):
            return ("OK", value)
        return ("WEAK", value)
    if name == "x-content-type-options":
        return ("OK" if lower == "nosniff" else "WEAK", value)
    return ("OK", value)


@register
class ConfigAudit(Module):
    name = "config-audit"
    description = (
        "Audit Bubble app configuration: editor visibility, security headers, "
        "live vs version-test diff."
    )
    needs_auth = False
    category = "audit"
    subcommands = ("headers", "editor", "version-diff", "all")
    flags = ("--app-id <slug>", "--page <name>", "--pages a,b,c")
    example = "run config-audit all"

    async def run(self, ctx: Context, **kwargs: Any) -> None:
        if ctx.target is None:
            console.print("[red]No target set.[/]")
            return
        argv: list[str] = kwargs.get("argv", [])
        flags, positional = parse_flags(argv)
        sub = positional[0].lower() if positional else "headers"

        if sub == "editor":
            await self._editor(ctx, flags)
        elif sub == "headers":
            await self._headers(ctx, flags)
        elif sub == "version-diff":
            await self._version_diff(ctx, flags)
        elif sub == "all":
            await self._headers(ctx, flags)
            await self._editor(ctx, flags)
            await self._version_diff(ctx, flags)
        else:
            console.print(f"[red]unknown subcommand:[/] {sub}  (editor|headers|version-diff|all)")

    # ── editor ───────────────────────────────────────────────────────────

    async def _editor(self, ctx: Context, flags: dict[str, Any]) -> None:
        app_id = str(flags.get("app_id") or ctx.schema.env_name or "")
        if not app_id:
            console.print(
                "[red]no app_id known.[/] Run `fingerprint` first "
                "or pass `--app-id <slug>`."
            )
            return
        page = str(flags.get("page") or "index")
        panel(
            "config-audit — editor probe",
            f"app_id={app_id}  ·  page={page}",
            style="cyan",
        )

        for version in ("live", "test"):
            url = f"https://bubble.io/page?name={page}&id={app_id}&version={version}"
            try:
                async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as c:
                    r = await c.get(url)
            except Exception as exc:
                console.print(f"  [yellow]![/] {version}: {exc}")
                continue
            body = r.text
            # Heuristic detection: a publicly-viewable editor exposes specific
            # JS globals that a private editor blanks out on the client side.
            is_editor_page = "Bubble Editor" in body or "bubble_editor" in body.lower()
            login_wall = (
                "sign in" in body.lower()
                or "log in" in body.lower()
                or "/login" in body.lower()
            )
            public_markers = any(m in body for m in (
                '"editors":{', '"workflows":{', '"data_types":{', '"privacy_rules":{'
            ))
            verdict = "UNKNOWN"
            if r.status_code == 404:
                verdict = "APP_NOT_FOUND"
            elif public_markers:
                verdict = "PUBLIC_EDITOR"
            elif is_editor_page and login_wall:
                verdict = "LOGIN_REQUIRED"
            elif is_editor_page:
                verdict = "EDITOR_PAGE_NO_LOGIN_SIGN"

            console.print(
                f"  [cyan]{version}[/]  status={r.status_code}  "
                f"verdict=[bold]{verdict}[/]  size={len(body)}B"
            )
            if verdict == "PUBLIC_EDITOR":
                ctx.add_finding(Finding(
                    module=self.name,
                    severity="critical",
                    title=f"App editor publicly viewable ({version})",
                    detail=(
                        f"GET {url} exposes editor internals (workflows, "
                        "data types, privacy rules). Setting "
                        "'Define who can see and modify the app editor' is "
                        "not 'Private app'."
                    ),
                    data={"url": url, "version": version, "size": len(body)},
                ))

    # ── headers ──────────────────────────────────────────────────────────

    async def _headers(self, ctx: Context, flags: dict[str, Any]) -> None:
        target_url = ctx.target.url
        async with client() as c:
            r = await c.get(target_url)
        panel(
            "config-audit — security headers",
            f"GET {target_url}  ·  status={r.status_code}",
            style="cyan",
        )
        from rich.table import Table
        table = Table(header_style="bold cyan", border_style="dim")
        table.add_column("Header", style="cyan", no_wrap=True)
        table.add_column("Verdict", style="bold")
        table.add_column("Value", overflow="fold")
        missing_strong: list[str] = []
        for name, _hint, sev in _HEADER_RUBRIC:
            value = r.headers.get(name)
            verdict, shown = _header_verdict(name, value)
            style = {
                "STRONG": "green", "OK": "green",
                "WEAK": "yellow", "PERMISSIVE": "yellow",
                "MISSING": "red",
            }.get(verdict, "white")
            table.add_row(name, f"[{style}]{verdict}[/]", shown or "-")
            if verdict in ("MISSING", "WEAK", "PERMISSIVE") and sev in ("medium", "high"):
                missing_strong.append(f"{name}={verdict}")
        console.print(table)

        # Informational headers worth logging
        info_headers = (
            "server", "x-powered-by", "x-bubble-perf",
            "x-bubble-capacity-used", "via", "x-cache", "cf-ray",
        )
        fingerprint_headers = {
            h: r.headers[h] for h in info_headers if h in r.headers
        }
        if fingerprint_headers:
            panel(
                "Fingerprint-leak headers",
                "\n".join(f"{k}: {v}" for k, v in fingerprint_headers.items()),
                style="dim",
            )

        if missing_strong:
            ctx.add_finding(Finding(
                module=self.name,
                severity="medium",
                title=f"{len(missing_strong)} security header(s) missing or weak",
                detail=", ".join(missing_strong),
                data={"headers": missing_strong, "raw": dict(r.headers)},
            ))

    # ── version-diff ─────────────────────────────────────────────────────

    async def _version_diff(self, ctx: Context, flags: dict[str, Any]) -> None:
        pages = list(ctx.schema.pages.keys())
        explicit = flags.get("pages")
        if isinstance(explicit, str):
            pages = [p.strip() for p in explicit.split(",") if p.strip()]
        if not pages:
            pages = [ctx.schema.page_name_current or "index"]

        panel(
            "config-audit — version-diff",
            f"{len(pages)} page(s) · live vs /version-test/",
            style="cyan",
        )

        base = ctx.target.url.rstrip("/")
        cookies = ctx.session.cookies if ctx.session else None
        differences: list[dict[str, Any]] = []

        with progress_iter("Diffing live vs test", len(pages)) as bar:
            for page in pages:
                bar.set_description(f"diff · /{page}")
                live_url = f"{base}/{page.strip('/')}".rstrip("/")
                test_url = f"{base}/version-test/{page.strip('/')}".rstrip("/")
                try:
                    async with client(cookies=cookies) as c:
                        rlive = await c.get(live_url)
                        rtest = await c.get(test_url)
                except Exception:
                    bar.advance()
                    continue

                live_urls = html_parse.extract_bundle_urls(rlive.text, live_url + "/")
                test_urls = html_parse.extract_bundle_urls(rtest.text, test_url + "/")

                test_requires_basic = (
                    rtest.status_code == 401
                    and "basic" in rtest.headers.get("www-authenticate", "").lower()
                )
                static_diff = live_urls.get("static_js") != test_urls.get("static_js")

                differences.append({
                    "page": page,
                    "live_status": rlive.status_code,
                    "test_status": rtest.status_code,
                    "test_requires_basic": test_requires_basic,
                    "static_js_diff": static_diff,
                    "live_size": len(rlive.content),
                    "test_size": len(rtest.content),
                })
                bar.advance()

        from rich.table import Table
        if differences:
            table = Table(header_style="bold cyan", border_style="dim")
            table.add_column("Page", style="cyan", no_wrap=True)
            table.add_column("live", justify="right")
            table.add_column("test", justify="right")
            table.add_column("basic", justify="center")
            table.add_column("static.js diff", justify="center")
            for d in differences:
                table.add_row(
                    d["page"],
                    str(d["live_status"]),
                    str(d["test_status"]),
                    "yes" if d["test_requires_basic"] else "no",
                    "yes" if d["static_js_diff"] else "no",
                )
            console.print(table)

        leakable = [
            d for d in differences
            if d["test_status"] == 200 and not d["test_requires_basic"]
        ]
        if leakable:
            ctx.add_finding(Finding(
                module=self.name,
                severity="high",
                title=(
                    f"/version-test/ reachable anonymously on "
                    f"{len(leakable)} page(s)"
                ),
                detail=(
                    "Bubble's 'Password-protect development version' setting is "
                    "off. Dev data, workflows, and privacy rules may diverge "
                    "from live."
                ),
                data={"pages": [d["page"] for d in leakable]},
            ))
