"""Pages module — enumerate Bubble pages of the target.

Strategy:
  1. Always include the current page (from `bubble_page_name`).
  2. HEAD/GET-probe a built-in wordlist of common page names (`index`, `login`,
     `signup`, `dashboard`, `admin`, `profile`, `settings`, `404`, …) plus any
     user-supplied `--wordlist`.
  3. For each candidate, detect whether Bubble served it (bundle URLs present
     for that specific page name) or whether it was bounced to index.
  4. With `--fetch-all`, download each discovered page's `static.js` +
     `dynamic.js` so downstream modules (datatypes, elements) can enrich from
     them.
  5. With `--include-test`, also probe `/version-test/<page>` (a common
     misconfig — dev env reachable).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from bubblepwn.bubble.workflow import snapshot_page
from bubblepwn.context import Context, Finding
from bubblepwn.modules.base import Module, parse_flags, register
from bubblepwn.ui import console, panel, progress_iter

DEFAULT_WORDLIST = (
    "index", "home", "login", "signup", "register", "signin", "sign_in",
    "sign_up", "reset_password", "forgot_password", "dashboard", "admin",
    "admin_panel", "profile", "account", "settings", "preferences",
    "onboarding", "welcome", "search", "explore", "browse", "pricing",
    "billing", "checkout", "cart", "contact", "support", "help", "faq",
    "terms", "privacy", "about", "404", "500", "error", "logout",
)


def _bundle_page_from_url(url: str) -> str:
    """Extract the page name embedded in a bundle URL path.

    Bubble bundle URLs look like:
      /package/static_js/<hash>/<env>/<version>/<page>/xnull/.../static.js
    """
    parts = url.split("/")
    try:
        # The segment right after <env>/<version> is the page name.
        i = parts.index("static_js")
        # parts[i+1] = hash, parts[i+2] = env, parts[i+3] = version, parts[i+4] = page
        if len(parts) > i + 4:
            return parts[i + 4]
    except ValueError:
        pass
    return ""


@register
class Pages(Module):
    name = "pages"
    description = "Enumerate Bubble pages via wordlist probing (+ optional fetch-all)."
    needs_auth = False
    category = "recon"
    subcommands = ()
    flags = (
        ("--fetch-all", "snapshot every discovered page to harvest its "
                        "static.js (expands the type/field catalogue)"),
        ("--include-test", "also probe the /version-test/ branch (if any)"),
        ("--wordlist <file>", "custom path list — one relative path per line "
                              "(defaults to the built-in Bubble wordlist)"),
    )
    example = "run pages --fetch-all"
    long_help = (
        "Wordlist-probes the live app for standard Bubble page paths "
        "(index, login, dashboard, admin, …) and pulls the page_name out "
        "of each hit's HTML. Pair with `--fetch-all` so other modules can "
        "harvest page-specific bundles later."
    )

    async def run(self, ctx: Context, **kwargs: Any) -> None:
        if ctx.target is None:
            console.print("[red]No target set.[/] Use `target <url>` first.")
            return
        argv: list[str] = kwargs.get("argv", [])
        flags, _ = parse_flags(argv)

        fetch_all = bool(flags.get("fetch_all", False))
        include_test = bool(flags.get("include_test", False))
        user_wordlist = flags.get("wordlist")

        candidates = list(DEFAULT_WORDLIST)
        if isinstance(user_wordlist, str):
            p = Path(user_wordlist)
            if p.exists():
                extras = [
                    line.strip()
                    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines()
                    if line.strip() and not line.strip().startswith("#")
                ]
                candidates.extend(extras)
        # dedupe preserving order
        seen: dict[str, None] = {}
        for c in candidates:
            seen.setdefault(c, None)
        candidates = list(seen)

        panel(
            "Page probe",
            f"candidates: {len(candidates)} · fetch_all={fetch_all} · "
            f"include_test={include_test}",
            style="cyan",
        )

        discovered: list[str] = []
        errors: list[tuple[str, str]] = []
        with progress_iter("Probing pages", len(candidates)) as bar:
            for page in candidates:
                bar.set_description(f"Probing pages · /{page}")
                try:
                    snap = await snapshot_page(
                        ctx, page=page,
                        want_static=fetch_all, want_dynamic=fetch_all,
                    )
                except Exception as exc:
                    errors.append((page, str(exc)))
                    bar.advance()
                    continue
                served_page = snap.page_name
                bundle_page = (
                    _bundle_page_from_url(snap.bundle_urls.get("static_js", ""))
                    or served_page
                )
                matched = bundle_page == page or served_page == page
                if matched:
                    discovered.append(page)
                    ctx.schema.upsert_page(
                        name=page,
                        url=snap.url,
                        status=snap.status,
                        title=None,
                        static_js_url=snap.bundle_urls.get("static_js"),
                        dynamic_js_url=snap.bundle_urls.get("dynamic_js"),
                    )
                bar.advance()

        console.print(
            f"[green]✓[/] {len(discovered)} page(s) matched · "
            f"{len(candidates) - len(discovered) - len(errors)} redirected · "
            f"{len(errors)} errored"
        )

        # include-test: probe /version-test/<page> for a handful of pages
        if include_test and discovered:
            await self._probe_version_test(ctx, discovered[:5])

        self._render(ctx)
        ctx.add_finding(Finding(
            module=self.name,
            severity="info",
            title=f"{len(discovered)} pages discovered",
            data={"pages": discovered},
        ))

    async def _probe_version_test(self, ctx: Context, pages: list[str]) -> None:
        """Try to fetch /version-test/<page> — flag if reachable."""
        console.print("[cyan]→[/] probing /version-test/ …")
        test_accessible: list[str] = []
        for pg in pages:
            try:
                snap = await snapshot_page(ctx, page=f"version-test/{pg}", want_static=False, want_dynamic=False)
                if snap.status == 200 and "bubble_page_name" in snap.html:
                    test_accessible.append(pg)
                    console.print(f"  [red]✓[/] /version-test/{pg} reachable")
            except Exception:
                pass
        if test_accessible:
            ctx.add_finding(Finding(
                module=self.name,
                severity="medium",
                title=f"/version-test/ exposes {len(test_accessible)} page(s) anonymously",
                detail="Dev/test environment is publicly reachable — common Bubble misconfig.",
                data={"pages": test_accessible},
            ))

    def _render(self, ctx: Context) -> None:
        from rich.table import Table

        pages = list(ctx.schema.pages.values())
        if not pages:
            console.print("[yellow]No pages discovered.[/]")
            return
        table = Table(
            title=f"Discovered pages ({len(pages)})",
            header_style="bold cyan",
            border_style="dim",
        )
        table.add_column("Name", style="cyan", no_wrap=True)
        table.add_column("Title", overflow="fold")
        table.add_column("Status", justify="right")
        table.add_column("URL", overflow="fold")
        for p in sorted(pages, key=lambda x: x.name):
            table.add_row(
                p.name,
                p.title or "-",
                str(p.status) if p.status is not None else "-",
                p.url or "-",
            )
        console.print(table)
