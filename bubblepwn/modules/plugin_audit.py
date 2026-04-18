"""Plugin audit — Tier 8 (third-party plugin risk).

Subcommands:
  plugin-audit check  — cross-ref detected plugins against a known-bad list
                         (built-in + --list <file>) and flag "old" IDs whose
                         timestamp is older than N days (default 365*3).
  plugin-audit leaks  — analyze third-party script hosts for data-collection
                         services (analytics, session replay, ad-tech) and
                         flag unexpected hosts (e.g. raw *.s3.amazonaws.com).
"""
from __future__ import annotations

import fnmatch
import re
import time
from pathlib import Path
from typing import Any

from bubblepwn.bubble.wordlists import load as load_wordlist
from bubblepwn.context import Context, Finding
from bubblepwn.modules.base import Module, parse_flags, register
from bubblepwn.ui import console, panel


_TIMESTAMP_ID = re.compile(r"^(\d{13})x\d+$")


def _classify_host(host: str, sketchy: list[str]) -> tuple[str, str]:
    """(category, matched_pattern_or_empty).

    Categories:
      - analytics  — hits the built-in sketchy list
      - s3_raw     — raw *.s3.amazonaws.com or *.s3-*.amazonaws.com host
      - cdn        — well-known CDN (jsdelivr, unpkg, cloudflare, googleapis)
      - unknown    — anything else; worth flagging
    """
    lower = host.lower()
    for pat in sketchy:
        if fnmatch.fnmatch(lower, pat.lower()):
            return ("analytics", pat)
    if re.search(r"\.s3[\.\-][a-z0-9\-]*\.amazonaws\.com$", lower):
        return ("s3_raw", "")
    if any(
        lower.endswith(suffix)
        for suffix in (
            "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
            "fonts.googleapis.com", "fonts.gstatic.com", "ajax.googleapis.com",
            "cdn.bubble.io",
        )
    ) or re.search(r"\.cdn\.bubble\.io$", lower):
        return ("cdn", "")
    return ("unknown", "")


@register
class PluginAudit(Module):
    name = "plugin-audit"
    description = (
        "Audit third-party plugins: flag deprecated/known-bad plugins + "
        "detect client-side data leaks to external hosts."
    )
    needs_auth = False
    category = "audit"
    subcommands = ("check", "leaks", "all")
    flags = ("--list <file>", "--max-age-days <N>")
    example = "run plugin-audit all"

    async def run(self, ctx: Context, **kwargs: Any) -> None:
        if ctx.target is None:
            console.print("[red]No target set.[/]")
            return
        argv: list[str] = kwargs.get("argv", [])
        flags, positional = parse_flags(argv)
        sub = positional[0].lower() if positional else "check"

        if sub == "check":
            await self._check(ctx, flags)
        elif sub == "leaks":
            await self._leaks(ctx, flags)
        elif sub == "all":
            await self._check(ctx, flags)
            await self._leaks(ctx, flags)
        else:
            console.print(f"[red]unknown subcommand:[/] {sub}  (check|leaks|all)")

    # ── check ────────────────────────────────────────────────────────────

    async def _check(self, ctx: Context, flags: dict[str, Any]) -> None:
        if not ctx.schema.plugins:
            console.print(
                "[yellow]No plugins in schema.[/] Run `plugins` module first."
            )
            return

        bad_list: dict[str, dict[str, str]] = {}
        for entry in load_wordlist("deprecated_plugins"):
            parts = entry.split()
            name = parts[0]
            sev = parts[1] if len(parts) > 1 else "medium"
            note = " ".join(parts[2:]) if len(parts) > 2 else ""
            bad_list[name] = {"severity": sev, "note": note}
        extra = flags.get("list")
        if isinstance(extra, str):
            p = Path(extra)
            if p.exists():
                for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    bad_list[parts[0]] = {
                        "severity": parts[1] if len(parts) > 1 else "medium",
                        "note": " ".join(parts[2:]) if len(parts) > 2 else "",
                    }

        max_age_days = int(flags.get("max_age_days", 365 * 3))
        cutoff_ms = int((time.time() - max_age_days * 86400) * 1000)

        from rich.table import Table
        table = Table(header_style="bold cyan", border_style="dim")
        table.add_column("Plugin", style="cyan", no_wrap=True, overflow="fold")
        table.add_column("Category")
        table.add_column("Age", justify="right")
        table.add_column("Flag", style="bold")
        table.add_column("Note", overflow="fold", style="dim")

        flagged: list[dict[str, str]] = []
        for p in sorted(ctx.schema.plugins.values(), key=lambda x: (x.category, x.id)):
            flag = ""
            note = ""
            age = "-"

            if p.id in bad_list:
                entry = bad_list[p.id]
                flag = "[red]KNOWN-BAD[/]"
                note = entry.get("note", "") or "(on deprecated list)"
                flagged.append({
                    "id": p.id, "category": p.category,
                    "reason": "known-bad", "note": note,
                    "severity": entry.get("severity", "medium"),
                })
            else:
                m = _TIMESTAMP_ID.match(p.id)
                if m:
                    ts_ms = int(m.group(1))
                    age_days = (int(time.time() * 1000) - ts_ms) // 86400000
                    age = f"{age_days}d"
                    if ts_ms < cutoff_ms:
                        flag = "[yellow]OLD[/]"
                        note = f"created {age_days} days ago"
                        flagged.append({
                            "id": p.id, "category": p.category,
                            "reason": "old", "note": note,
                            "severity": "low",
                        })

            table.add_row(p.id, p.category, age, flag or "-", note)

        panel(
            "plugin-audit — check",
            f"{len(ctx.schema.plugins)} plugins · "
            f"{len(flagged)} flagged (max_age_days={max_age_days})",
            style="cyan",
        )
        console.print(table)

        if flagged:
            known_bad = [f for f in flagged if f["reason"] == "known-bad"]
            old = [f for f in flagged if f["reason"] == "old"]
            if known_bad:
                ctx.add_finding(Finding(
                    module=self.name,
                    severity="medium",
                    title=f"{len(known_bad)} plugin(s) matched known-bad list",
                    detail=", ".join(f["id"] for f in known_bad[:10]),
                    data={"plugins": known_bad},
                ))
            if old:
                ctx.add_finding(Finding(
                    module=self.name,
                    severity="low",
                    title=f"{len(old)} plugin(s) older than {max_age_days} days",
                    data={"plugins": [f["id"] for f in old]},
                ))

    # ── leaks ────────────────────────────────────────────────────────────

    async def _leaks(self, ctx: Context, flags: dict[str, Any]) -> None:
        hosts = set(
            ctx.target.fingerprint.get("infra", {}).get("third_party_script_hosts", [])
        )
        # Fallback: also scan script_count if we haven't populated infra
        if not hosts:
            console.print(
                "[yellow]No third_party_script_hosts in fingerprint.[/] "
                "Run `fingerprint` first."
            )
            return

        sketchy = load_wordlist("sketchy_plugin_hosts")
        # Turn glob-like entries into fnmatch-compatible patterns (already are).

        from rich.table import Table
        table = Table(header_style="bold cyan", border_style="dim")
        table.add_column("Host", style="cyan", overflow="fold")
        table.add_column("Category", style="bold")
        table.add_column("Matched rule", overflow="fold", style="dim")

        by_cat: dict[str, list[str]] = {
            "analytics": [], "s3_raw": [], "cdn": [], "unknown": [],
        }
        style_for = {
            "analytics": "yellow",
            "s3_raw": "red",
            "cdn": "green",
            "unknown": "yellow",
        }
        for host in sorted(hosts):
            cat, rule = _classify_host(host, sketchy)
            by_cat[cat].append(host)
            table.add_row(
                host,
                f"[{style_for.get(cat, 'white')}]{cat}[/]",
                rule,
            )
        panel(
            "plugin-audit — data-leak hosts",
            f"{len(hosts)} third-party host(s) · "
            f"analytics={len(by_cat['analytics'])}  s3={len(by_cat['s3_raw'])}  "
            f"cdn={len(by_cat['cdn'])}  unknown={len(by_cat['unknown'])}",
            style="cyan",
        )
        console.print(table)

        if by_cat["analytics"]:
            ctx.add_finding(Finding(
                module=self.name,
                severity="info",
                title=f"{len(by_cat['analytics'])} analytics/tracking host(s) loaded",
                detail="Client-side events (page views, clicks, inputs) are "
                       "sent to external vendors. Usually intentional, but "
                       "worth disclosing in the pentest report.",
                data={"hosts": by_cat["analytics"]},
            ))
        if by_cat["s3_raw"]:
            ctx.add_finding(Finding(
                module=self.name,
                severity="medium",
                title=f"{len(by_cat['s3_raw'])} raw S3 host(s) serving scripts",
                detail=(
                    "Scripts loaded from unbranded S3 buckets — supply-chain "
                    "risk if the bucket is hijackable or the scripts mutable."
                ),
                data={"hosts": by_cat["s3_raw"]},
            ))
        if by_cat["unknown"]:
            ctx.add_finding(Finding(
                module=self.name,
                severity="low",
                title=f"{len(by_cat['unknown'])} unclassified third-party host(s)",
                detail="Review manually — likely plugin vendors.",
                data={"hosts": by_cat["unknown"]},
            ))
