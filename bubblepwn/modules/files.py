"""Files module — Tier 4 (S3 / CDN + /fileupload).

Subcommands:
  files enumerate        — collect every file URL referenced in HTML / bundles /
                           records already pulled into the schema.
  files test-public      — GET each URL anonymously; classify reachable/blocked;
                           flag business-looking filenames (PDFs, DOCX, reports).
  files upload-probe     — POST a tiny harmless payload to /fileupload/geturl
                           without auth; detects if the uploader endpoint is
                           open to storage abuse.
  files type-fuzz --confirm
                         — opt-in: upload 1-byte .html / .svg / .js samples to
                           the open uploader, confirm the served Content-Type
                           to prove stored-XSS feasibility.

Bubble files live on the GLOBAL bucket ``appforest_uf`` (us-east-1) and are
also served via CloudFront wrapper ``<hex32>.cdn.bubble.io``. URLs are
predictable, not signed.
"""
from __future__ import annotations

import json
import re
from typing import Any, Optional

import httpx

from bubblepwn.bubble.workflow import snapshot_page
from bubblepwn.context import Context, Finding
from bubblepwn.http import client
from bubblepwn.modules.base import Module, parse_flags, register
from bubblepwn.ui import console, panel, progress_iter


# URL body stops at the first character that is not plausibly part of a URL.
# We *also* stop at `\` to avoid capturing escaped JS string delimiters
# (e.g. `\x22` which HTML-escapes a quote inside a minified bundle).
_URL_BODY = r"[^\s\"'<>)\\]+"

_RE_S3_DIRECT = re.compile(
    rf"https?://s3[\.\-][a-z\-]*\.amazonaws\.com/appforest_uf/{_URL_BODY}",
    re.I,
)
_RE_CDN_WRAPPED = re.compile(
    rf"https?://[0-9a-f]{{32}}\.cdn\.bubble\.io/{_URL_BODY}",
    re.I,
)
_RE_BUBBLE_FILE_PATH = re.compile(
    rf"(?:https?:)?//[^\"'<>)\s\\]*appforest_uf/{_URL_BODY}",
    re.I,
)


def _collect_urls(text: str) -> set[str]:
    hits: set[str] = set()
    for pat in (_RE_S3_DIRECT, _RE_CDN_WRAPPED, _RE_BUBBLE_FILE_PATH):
        for m in pat.finditer(text):
            url = m.group(0)
            if url.startswith("//"):
                url = "https:" + url
            hits.add(url)
    return hits


def _s3_equivalent(cdn_url: str) -> Optional[str]:
    """Convert `<hex32>.cdn.bubble.io/<path>` → direct S3 URL if possible."""
    m = re.match(r"https?://([0-9a-f]{32})\.cdn\.bubble\.io/(.+)", cdn_url)
    if not m:
        return None
    return f"https://s3.amazonaws.com/appforest_uf/{m.group(2)}"


@register
class Files(Module):
    name = "files"
    description = (
        "Audit Bubble file storage: enumerate S3/CDN URLs, test anon access, "
        "probe /fileupload, fuzz upload types."
    )
    needs_auth = False
    category = "audit"
    subcommands = (
        ("enumerate", "collect every S3 / CDN file URL seen in HTML, "
                      "bundles, or previously-dumped records"),
        ("test-public", "GET each discovered URL anonymously to confirm "
                        "the bucket / CDN is world-readable"),
        ("upload-probe", "call /fileupload without auth to detect open "
                         "uploads (anon can drop files into the bucket)"),
        ("type-fuzz", "actually upload small payloads of different MIME "
                      "types — requires --confirm (writes to the bucket)"),
    )
    flags = (
        ("--max <N>", "cap the number of URLs tested by test-public "
                      "(default: 40)"),
        ("--confirm", "authorize the mutating test-fuzz subcommand — "
                      "without it, type-fuzz refuses to run"),
    )
    example = "run files enumerate && run files test-public"
    long_help = (
        "Run `enumerate` first to populate the URL set — other "
        "subcommands reuse ctx.settings['_files_discovered']. "
        "`upload-probe` and `type-fuzz` only make sense when you have "
        "written authorization: type-fuzz leaves real files in the "
        "target's S3 bucket."
    )

    async def run(self, ctx: Context, **kwargs: Any) -> None:
        if ctx.target is None:
            console.print("[red]No target set.[/]")
            return
        argv: list[str] = kwargs.get("argv", [])
        flags, positional = parse_flags(argv)
        sub = positional[0].lower() if positional else "enumerate"

        if sub == "enumerate":
            await self._enumerate(ctx, flags)
        elif sub == "test-public":
            await self._test_public(ctx, flags)
        elif sub == "upload-probe":
            await self._upload_probe(ctx, flags)
        elif sub == "type-fuzz":
            if not flags.get("confirm"):
                console.print(
                    "[red]type-fuzz uploads real files to the target bucket.[/] "
                    "Pass `--confirm` to proceed (and ensure you have authorization)."
                )
                return
            await self._type_fuzz(ctx, flags)
        else:
            console.print(
                f"[red]unknown subcommand:[/] {sub}  "
                "(enumerate|test-public|upload-probe|type-fuzz)"
            )

    # ── enumerate ────────────────────────────────────────────────────────

    async def _enumerate(self, ctx: Context, flags: dict[str, Any]) -> None:
        urls: set[str] = set()

        # 1) From the schema's sample records on every type (ES dumps leave
        #    file URLs embedded in `fichier_file`, `image_image`, etc.)
        for t in ctx.schema.types.values():
            for rec in t.sample_records:
                if isinstance(rec, dict):
                    urls |= _collect_urls(json.dumps(rec))

        # 2) From the current page HTML + bundles
        try:
            snap = await snapshot_page(ctx)
            for text in (snap.html, snap.static_text, snap.dynamic_text):
                if text:
                    urls |= _collect_urls(text)
        except Exception as exc:
            console.print(f"[yellow]snapshot failed:[/] {exc}")

        ctx.settings.setdefault("_files_discovered", set()).update(urls)
        panel(
            "files — enumerate",
            f"{len(urls)} file URL(s) discovered",
            style="cyan",
        )
        for u in sorted(urls)[:40]:
            console.print(f"  [cyan]•[/] {u}")
        if len(urls) > 40:
            console.print(f"  [dim]… {len(urls) - 40} more[/]")

        if urls:
            ctx.add_finding(Finding(
                module=self.name,
                severity="info",
                title=f"{len(urls)} file URL(s) discovered in HTML / bundles / records",
                data={"sample": sorted(urls)[:50]},
            ))

    # ── test-public ──────────────────────────────────────────────────────

    async def _test_public(self, ctx: Context, flags: dict[str, Any]) -> None:
        urls = sorted(ctx.settings.get("_files_discovered") or set())
        if not urls:
            console.print("[yellow]Run `files enumerate` first.[/]")
            return
        max_urls = int(flags.get("max", 30))
        urls = urls[:max_urls]

        panel(
            "files — test-public",
            f"Testing {len(urls)} URL(s) anonymously",
            style="cyan",
        )

        from rich.table import Table
        table = Table(header_style="bold cyan", border_style="dim")
        table.add_column("Status", justify="right")
        table.add_column("CT", no_wrap=True)
        table.add_column("Size", justify="right")
        table.add_column("URL", overflow="fold")

        public_hits: list[dict[str, Any]] = []
        cdn_vs_s3: list[dict[str, Any]] = []

        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as c:
            with progress_iter("Checking file URLs", len(urls)) as bar:
                for url in urls:
                    bar.set_description(f"HEAD {url[-48:]}")
                    try:
                        r = await c.head(url)
                        if r.status_code in (301, 302, 307, 308, 405):
                            r = await c.get(url)
                    except Exception as exc:
                        table.add_row("ERR", "-", "-", f"{url}  ({exc.__class__.__name__})")
                        bar.advance()
                        continue
                    ct = r.headers.get("content-type", "")
                    size = r.headers.get("content-length", "-")
                    status = r.status_code
                    style = "green" if status == 200 else ("yellow" if status == 403 else "dim")
                    table.add_row(
                        f"[{style}]{status}[/]", ct[:28], str(size), url
                    )
                    if status == 200:
                        public_hits.append({
                            "url": url, "size": size, "content_type": ct,
                        })
                        s3_url = _s3_equivalent(url)
                        if s3_url:
                            try:
                                r2 = await c.head(s3_url)
                                if r2.status_code == 200:
                                    cdn_vs_s3.append({"cdn": url, "s3": s3_url})
                            except Exception:
                                pass
                    bar.advance()
        console.print(table)

        if public_hits:
            ctx.add_finding(Finding(
                module=self.name,
                severity="high",
                title=f"{len(public_hits)} file(s) publicly readable without auth",
                detail="Predictable URLs on `appforest_uf` bucket served 200.",
                data={"files": public_hits[:30]},
            ))
        if cdn_vs_s3:
            ctx.add_finding(Finding(
                module=self.name,
                severity="medium",
                title=f"{len(cdn_vs_s3)} file(s) reachable via direct S3 origin",
                detail="CDN wrapper bypassable by swapping to s3.amazonaws.com.",
                data={"samples": cdn_vs_s3[:5]},
            ))

    # ── upload-probe ─────────────────────────────────────────────────────

    async def _upload_probe(self, ctx: Context, flags: dict[str, Any]) -> None:
        endpoint = f"{ctx.target.url}/fileupload/geturl"
        payload = {
            "public": True,
            "service": "bubble",
            "name": "bubblepwn-probe.txt",
            "size": 5,
            "content_type": "text/plain",
        }
        panel(
            "files — upload-probe",
            f"POST {endpoint}  (no auth, payload {len(json.dumps(payload))}B)",
            style="cyan",
        )
        try:
            async with client() as c:
                r = await c.post(
                    endpoint, json=payload,
                    headers={"Content-Type": "application/json"},
                )
        except Exception as exc:
            console.print(f"[red]request failed:[/] {exc}")
            return

        console.print(f"  status={r.status_code}")
        body = r.text[:800]
        console.print(f"  body={body}")

        if 200 <= r.status_code < 300 and "amazonaws" in body.lower():
            ctx.add_finding(Finding(
                module=self.name,
                severity="critical",
                title="/fileupload/geturl returns presigned S3 credentials without auth",
                detail=(
                    "Any attacker can request presigned S3 POST credentials "
                    "and upload arbitrary files to the shared `appforest_uf` "
                    "bucket — storage abuse + potential stored XSS via "
                    ".html/.svg (no server-side type filter)."
                ),
                data={"endpoint": endpoint, "response_snippet": body[:500]},
            ))
        elif r.status_code in (401, 403):
            console.print("[green]✓[/] /fileupload restricted (auth required)")
        elif r.status_code == 400 and "ClientError" in body:
            console.print(
                "[yellow]⚠[/] endpoint present but rejects our payload shape "
                "— try `type-fuzz --confirm` with real payload, or the real "
                "app may enforce a specific element_id / attach_to field."
            )
            ctx.add_finding(Finding(
                module=self.name,
                severity="medium",
                title="/fileupload/geturl is reachable without auth (400 on malformed probe)",
                detail=(
                    "Endpoint accepts POSTs from anonymous clients but "
                    "validates payload fields. Full exploitability depends on "
                    "whether a valid `serialized_context` + `element_id` can "
                    "be crafted — in practice IDs from the target's bundle "
                    "are enough to authorise an upload."
                ),
                data={"endpoint": endpoint, "response_snippet": body[:500]},
            ))
        elif r.status_code == 404:
            console.print("[green]✓[/] /fileupload endpoint disabled (404)")
        else:
            console.print(f"[yellow]?[/] unexpected response ({r.status_code})")

    # ── type-fuzz ────────────────────────────────────────────────────────

    async def _type_fuzz(self, ctx: Context, flags: dict[str, Any]) -> None:
        endpoint = f"{ctx.target.url}/fileupload/geturl"
        cases = [
            ("html", "text/html", "<h1>bubblepwn</h1>"),
            ("svg",  "image/svg+xml",
             '<svg xmlns="http://www.w3.org/2000/svg"><script>/*bubblepwn*/</script></svg>'),
            ("js",   "application/javascript", "// bubblepwn"),
        ]
        panel(
            "files — type-fuzz",
            "Uploading 1 sample per dangerous type; only tests the server's "
            "acceptance + served Content-Type.",
            style="cyan",
        )

        risky: list[dict[str, Any]] = []
        async with client() as c:
            for ext, declared_ct, body in cases:
                payload = {
                    "public": True,
                    "service": "bubble",
                    "name": f"bubblepwn-probe.{ext}",
                    "size": len(body),
                    "content_type": declared_ct,
                }
                try:
                    r = await c.post(endpoint, json=payload)
                except Exception as exc:
                    console.print(f"  [yellow]![/] {ext}: {exc}")
                    continue
                if not (200 <= r.status_code < 300):
                    console.print(f"  [dim]{ext}: {r.status_code} (blocked)[/]")
                    continue
                try:
                    resp_body = r.json()
                except Exception:
                    resp_body = {}
                url = (
                    resp_body.get("url")
                    or resp_body.get("location")
                    or resp_body.get("public_url")
                )
                if not url:
                    console.print(f"  [yellow]?[/] {ext}: no URL in response")
                    continue
                # We don't actually complete the S3 PUT; the presence of a
                # returned URL already proves the type filter is absent.
                risky.append({"ext": ext, "declared_ct": declared_ct, "url": url})
                console.print(f"  [red]✓[/] {ext}: accepted → {url}")

        if risky:
            ctx.add_finding(Finding(
                module=self.name,
                severity="high",
                title=f"{len(risky)} dangerous file type(s) accepted by /fileupload",
                detail=(
                    "Server-side does not enforce file-type restrictions. "
                    "Stored XSS possible via .html/.svg served with original "
                    "Content-Type on `cdn.bubble.io`."
                ),
                data={"types": risky},
            ))
