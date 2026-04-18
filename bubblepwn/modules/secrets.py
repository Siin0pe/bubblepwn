"""Secrets module — scan HTML + JS bundles for tokens and API keys.

Scans (by default):
  - landing HTML
  - `static.js` (usually holds API Connector configs when `Private: false`)
  - `dynamic.js` (per-page bundle)

With `--include-runtime`, also scans `run.js` (3+ MB framework code; lower ROI).
With `--fetch-all`, re-runs the scan on every page already in the schema.
"""
from __future__ import annotations

from typing import Any

from bubblepwn.bubble import bundle as bundle_cache
from bubblepwn.bubble import secrets as sec
from bubblepwn.bubble.workflow import snapshot_page, _fetch_text
from bubblepwn.context import Context, Finding
from bubblepwn.modules.base import Module, parse_flags, register
from bubblepwn.ui import console, panel

_SEV_STYLE = {
    "critical": "red on white",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}


@register
class Secrets(Module):
    name = "secrets"
    description = "Scan HTML + static.js + dynamic.js for tokens, API keys, and URL secrets."
    needs_auth = False
    category = "recon"
    subcommands = ()
    flags = ("--include-runtime", "--fetch-all", "--verify-keys", "--min-severity <lvl>")
    example = "run secrets --verify-keys"

    async def run(self, ctx: Context, **kwargs: Any) -> None:
        if ctx.target is None:
            console.print("[red]No target set.[/] Use `target <url>` first.")
            return
        argv: list[str] = kwargs.get("argv", [])
        flags, _ = parse_flags(argv)

        include_runtime = bool(flags.get("include_runtime"))
        fetch_all = bool(flags.get("fetch_all"))
        verify_keys = bool(flags.get("verify_keys"))
        min_sev = str(flags.get("min_severity", "low")).lower()

        pages = list(ctx.schema.pages.keys()) if fetch_all and ctx.schema.pages else [""]
        all_matches: list[sec.SecretMatch] = []
        scanned_files: list[str] = []

        cookies = ctx.session.cookies if ctx.session else None

        for page in pages:
            label = page or (ctx.schema.page_name_current or "index")
            with console.status(f"[cyan]scanning {label}…[/]", spinner="dots"):
                snap = await snapshot_page(ctx, page=page)

            targets = [
                (f"html:{label}", snap.html),
                (f"static_js:{label}", snap.static_text),
                (f"dynamic_js:{label}", snap.dynamic_text),
            ]
            if include_runtime and "run_js" in snap.bundle_urls:
                try:
                    run_text = await _fetch_text(snap.bundle_urls["run_js"], cookies=cookies)
                    targets.append((f"run_js:{label}", run_text))
                except Exception as exc:
                    console.print(f"  [yellow]![/] run.js fetch failed: {exc}")

            for source, content in targets:
                if not content:
                    continue
                scanned_files.append(source)
                matches = sec.scan(content, source=source)
                all_matches.extend(matches)

        # Filter by min severity
        sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        threshold = sev_order.get(min_sev, 1)
        filtered = [m for m in all_matches if sev_order.get(m.severity, 0) >= threshold]

        verify_map: dict[str, Any] = {}
        if verify_keys:
            verify_map = await self._verify_keys(all_matches)

        self._render(scanned_files, all_matches, filtered, threshold_label=min_sev, verify=verify_map)
        self._push_findings(ctx, all_matches, verify=verify_map)

    async def _verify_keys(
        self, matches: list[sec.SecretMatch]
    ) -> dict[str, Any]:
        """Call external verifiers on matched keys. Returns {value: result}."""
        from bubblepwn.bubble.key_verify import is_google_key, verify_google_maps_key

        google_values = sorted({m.value for m in matches if m.category == "Google" and is_google_key(m.value)})
        if not google_values:
            return {}

        console.print(
            f"[cyan]→[/] verifying {len(google_values)} Google key(s) "
            f"against ~10 Google APIs each…"
        )
        results: dict[str, Any] = {}
        for key in google_values:
            res = await verify_google_maps_key(key)
            results[key] = res
            verdict_style = "red" if res.abusable() else "green"
            console.print(
                f"  [{verdict_style}]{res.verdict}[/] {key[:16]}… "
                f"open={','.join(res.open_apis) or '-'}"
            )
        return results

    # ── rendering ────────────────────────────────────────────────────────

    def _render(
        self,
        scanned_files: list[str],
        all_matches: list[sec.SecretMatch],
        filtered: list[sec.SecretMatch],
        threshold_label: str,
        verify: dict[str, Any] | None = None,
    ) -> None:
        verify = verify or {}
        panel(
            "Secrets scan",
            f"scanned {len(scanned_files)} source(s)  ·  "
            f"{len(all_matches)} total match(es)  ·  "
            f"{len(filtered)} above threshold ({threshold_label})"
            + (f"  ·  verified {len(verify)} key(s)" if verify else ""),
            style="cyan",
        )
        if not filtered:
            console.print("[green]No secrets above threshold.[/]")
            return

        from rich.table import Table

        by_cat: dict[str, int] = {}
        for m in all_matches:
            by_cat[m.category] = by_cat.get(m.category, 0) + 1
        console.print(
            "By category: "
            + "  ".join(f"[bold]{c}[/]={n}" for c, n in sorted(by_cat.items()))
        )

        table = Table(header_style="bold", border_style="dim")
        table.add_column("Sev", justify="center")
        table.add_column("Category", style="cyan", no_wrap=True)
        table.add_column("Rule", style="magenta", no_wrap=True)
        table.add_column("Value", overflow="fold")
        table.add_column("Source", style="dim", no_wrap=True)
        if verify:
            table.add_column("Key status", overflow="fold")
        table.add_column("Context", overflow="fold", style="dim")
        for m in filtered[:50]:
            val = m.value if len(m.value) <= 60 else f"{m.value[:56]}…"
            style = _SEV_STYLE.get(m.severity, "white")
            row = [
                f"[{style}]{m.severity}[/]",
                m.category,
                m.rule,
                val,
                m.source,
            ]
            if verify:
                v = verify.get(m.value)
                if v is None:
                    row.append("-")
                else:
                    verdict_style = "red bold" if v.abusable() else "green"
                    open_s = ",".join(v.open_apis[:4]) or "-"
                    row.append(f"[{verdict_style}]{v.verdict}[/]  open=[{open_s}]")
            row.append(m.context[:80])
            table.add_row(*row)
        console.print(table)
        if len(filtered) > 50:
            console.print(f"[dim]… {len(filtered) - 50} more matches truncated[/]")

    # ── findings ─────────────────────────────────────────────────────────

    def _push_findings(
        self,
        ctx: Context,
        matches: list[sec.SecretMatch],
        verify: dict[str, Any] | None = None,
    ) -> None:
        verify = verify or {}
        if not matches:
            return
        by_cat: dict[str, int] = {}
        for m in matches:
            by_cat[m.category] = by_cat.get(m.category, 0) + 1
        ctx.add_finding(Finding(
            module=self.name,
            severity="info",
            title=f"{len(matches)} secret-like pattern(s) matched across bundles",
            data={"by_category": by_cat},
        ))
        seen_values: set[str] = set()
        for m in matches:
            if m.value in seen_values:
                continue
            seen_values.add(m.value)
            base_sev = m.severity

            # Upgrade Google matches when verification says ABUSABLE
            v = verify.get(m.value)
            if v is not None and v.abusable():
                ctx.add_finding(Finding(
                    module=self.name,
                    severity="high",
                    title=f"Google key is abusable ({len(v.open_apis)} API(s) open)",
                    detail=(
                        f"Key accepted without restriction on: "
                        f"{', '.join(v.open_apis)}. Any third party can use "
                        f"this key for quota-draining attacks billed to the "
                        f"project owner."
                    ),
                    data={
                        "value": m.value,
                        "open_apis": v.open_apis,
                        "per_api": v.per_api,
                        "source": m.source,
                    },
                ))
                continue

            if base_sev in ("critical", "high"):
                ctx.add_finding(Finding(
                    module=self.name,
                    severity=base_sev,
                    title=f"{m.category} secret exposed ({m.rule})",
                    detail=m.context[:200],
                    data={
                        "value": m.value,
                        "source": m.source,
                        "offset": m.offset,
                        "verification": (
                            {"verdict": v.verdict, "per_api": v.per_api}
                            if v is not None else None
                        ),
                    },
                ))
