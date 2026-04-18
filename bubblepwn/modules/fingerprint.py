"""
Fingerprint module — detect Bubble.io and extract base info.

Sections:
  1. Detection signals + scoring
  2. Extractors (app / session / keys / meta / infra / plugins / bundles)
  3. Rendering (verdict panel + info tree)
  4. Findings
  5. Module class
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import urlparse

import httpx
from rich.tree import Tree

from bubblepwn.context import Context, Finding
from bubblepwn.http import client
from bubblepwn.modules.base import Module, register
from bubblepwn.ui import console, panel


# ─── 1. Detection signals ────────────────────────────────────────────────────

@dataclass(frozen=True)
class Signal:
    name: str
    pattern: re.Pattern[str]
    weight: int


SIGNALS: tuple[Signal, ...] = (
    # Strong — unique to Bubble
    Signal("window.bubble_session_uid", re.compile(r"window\.bubble_session_uid\s*="), 30),
    Signal("window.appquery = make_proxy(", re.compile(r"window\.appquery\s*=\s*make_proxy"), 30),
    Signal("/package/run_js/<sha256>", re.compile(r"/package/run_js/[a-f0-9]{64}"), 30),
    Signal("<hex>.cdn.bubble.io", re.compile(r"[a-f0-9]{32}\.cdn\.bubble\.io"), 25),
    # Medium
    Signal("window.bubble_page_load_id", re.compile(r"window\.bubble_page_load_id\s*="), 15),
    Signal("window.bubble_plp_token", re.compile(r"window\.bubble_plp_token\s*="), 15),
    Signal("window.Lib = new Proxy(", re.compile(r"window\.Lib\s*=\s*new\s+Proxy"), 15),
    Signal("/package/static_js/<sha256>", re.compile(r"/package/static_js/[a-f0-9]{64}"), 15),
    Signal("/package/early_js/<sha256>", re.compile(r"/package/early_js/[a-f0-9]{64}"), 15),
    # Weak
    Signal("_bubble_page_load_data", re.compile(r"_bubble_page_load_data"), 8),
    Signal("__bubble_module_mode", re.compile(r"__bubble_module_mode"), 5),
    Signal("bubble_is_leanjs", re.compile(r"bubble_is_leanjs"), 5),
)


def score_signals(html: str) -> tuple[int, list[str]]:
    hit: list[str] = []
    total = 0
    for sig in SIGNALS:
        if sig.pattern.search(html):
            hit.append(sig.name)
            total += sig.weight
    return min(total, 100), hit


def verdict_from_score(score: int) -> tuple[str, str]:
    if score >= 60:
        return "CONFIRMED", "green"
    if score >= 30:
        return "LIKELY", "yellow"
    if score >= 15:
        return "UNCERTAIN", "yellow"
    return "NOT BUBBLE", "red"


# ─── 2. Extractors ───────────────────────────────────────────────────────────

def _qvar(key: str) -> re.Pattern[str]:
    """Match `window.<key> = "..."` or `window.<key> = '...'`."""
    return re.compile(rf"window\.{re.escape(key)}\s*=\s*['\"]([^'\"]+)['\"]")


_RE_APP_VERSION = re.compile(
    r"app_version:\s*function\s*\(\)\s*\{\s*return\s+['\"]([^'\"]+)['\"]"
)
_RE_LAST_CHANGE = re.compile(
    r"last_change:\s*function\s*\(\)\s*\{\s*return\s+['\"]([^'\"]+)['\"]"
)
_RE_P = re.compile(r"window\._p\s*=\s*['\"](\{.*?\})['\"]\s*;")
_RE_MODULE_MODE = re.compile(r"window\.__bubble_module_mode\s*=\s*(true|false)")
_RE_ENV_FROM_CSS = re.compile(
    r"/package/run_css/[a-f0-9]{64}/([a-z0-9][a-z0-9_\-]*)/(live|test)/"
)
_RE_INIT_URL = re.compile(r"https?://[^'\"\s]+?/api/1\.1/init/data")
_RE_PLUGIN_ID = re.compile(r"plugin_main_headers_(\d+x\d+)")
_RE_BUBBLE_BUCKET = re.compile(r"([0-9a-f]{32})\.cdn\.bubble\.io")
_RE_CLOUDFRONT = re.compile(r"([a-z0-9][a-z0-9\-]*\.cloudfront\.net)")
_RE_S3 = re.compile(r"([a-z0-9][a-z0-9\-]*\.s3(?:[.-][a-z0-9\-]+)?\.amazonaws\.com)")
_RE_SCRIPT_SRC = re.compile(r"<script[^>]+src=['\"]([^'\"]+)", re.I)

_RE_GA4 = re.compile(r"\bG-[A-Z0-9]{6,12}\b")
_RE_UA = re.compile(r"\bUA-\d{4,12}-\d{1,4}\b")
_RE_GTM = re.compile(r"\bGTM-[A-Z0-9]{4,10}\b")
_RE_AIZA = re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")
_RE_STRIPE_PK = re.compile(r"\bpk_(?:live|test)_[0-9A-Za-z]{20,}\b")

_RE_TITLE = re.compile(r"<title[^>]*>([^<]+)</title>", re.I | re.S)
_RE_HTML_LANG = re.compile(r"<html[^>]+lang=['\"]([^'\"]+)", re.I)
_RE_CANONICAL = re.compile(
    r"<link[^>]+rel=['\"]canonical['\"][^>]*href=['\"]([^'\"]+)", re.I
)
_RE_FAVICON = re.compile(
    r"<link[^>]+rel=['\"](?:shortcut icon|icon)['\"][^>]*href=['\"]([^'\"]+)", re.I
)


def _meta(html: str, *, name: str | None = None, prop: str | None = None) -> str | None:
    attr = "name" if name else "property"
    value = name or prop
    m = re.search(
        rf"<meta\s+{attr}=['\"]{re.escape(value)}['\"][^>]*content=['\"]([^'\"]+)",
        html,
        re.I,
    )
    return m.group(1).strip() if m else None


def _unique(regex: re.Pattern[str], html: str) -> list[str]:
    return sorted(set(regex.findall(html)))


def extract_app(html: str) -> dict[str, Any]:
    info: dict[str, Any] = {}
    m = _qvar("bubble_page_name").search(html)
    if m:
        info["page_name"] = m.group(1)
    m = _RE_APP_VERSION.search(html)
    if m:
        info["app_version"] = m.group(1)
    m = _RE_LAST_CHANGE.search(html)
    if m:
        info["last_change"] = m.group(1)
    m = _RE_MODULE_MODE.search(html)
    if m:
        info["module_mode"] = m.group(1) == "true"
    m = _RE_P.search(html)
    if m:
        try:
            flags = json.loads(m.group(1))
            info["app_id"] = flags.pop("id", None)
            info["flags"] = flags
        except json.JSONDecodeError:
            info["_p_raw"] = m.group(1)
    m = _RE_ENV_FROM_CSS.search(html)
    if m:
        info["env_name"] = m.group(1)
        info.setdefault("app_version", m.group(2))
    m = _RE_INIT_URL.search(html)
    if m:
        info["init_endpoint"] = m.group(0)
    return info


def extract_session(html: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for key in ("bubble_session_uid", "bubble_page_load_id", "bubble_plp_token"):
        m = _qvar(key).search(html)
        if m:
            out[key] = m.group(1)
    return out


def extract_keys(html: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    gm = None
    m = _qvar("gm_key").search(html)
    if m:
        gm = m.group(1)
        out["google_maps"] = gm
    for label, rx in (
        ("google_analytics_ga4", _RE_GA4),
        ("google_analytics_ua", _RE_UA),
        ("google_tag_manager", _RE_GTM),
        ("stripe_publishable", _RE_STRIPE_PK),
    ):
        hits = _unique(rx, html)
        if hits:
            out[label] = hits
    others = [k for k in _unique(_RE_AIZA, html) if k != gm]
    if others:
        out["other_google_api_keys"] = others
    return out


def extract_meta(html: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    m = _RE_TITLE.search(html)
    if m:
        out["title"] = m.group(1).strip()
    for name in ("description", "twitter:title", "twitter:description"):
        v = _meta(html, name=name)
        if v:
            out[name] = v[:300]
    for prop in ("og:title", "og:site_name", "og:type", "og:url", "og:image", "og:description"):
        v = _meta(html, prop=prop)
        if v:
            out[prop] = v[:300]
    m = _RE_HTML_LANG.search(html)
    if m:
        out["html_lang"] = m.group(1)
    m = _RE_CANONICAL.search(html)
    if m:
        out["canonical"] = m.group(1)
    m = _RE_FAVICON.search(html)
    if m:
        out["favicon"] = m.group(1)
    return out


def extract_infra(html: str, final_url: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    host = urlparse(final_url).netloc

    buckets = _unique(_RE_BUBBLE_BUCKET, html)
    if buckets:
        out["bubble_cdn_buckets"] = buckets
    cf = _unique(_RE_CLOUDFRONT, html)
    if cf:
        out["cloudfront_domains"] = cf
    s3 = _unique(_RE_S3, html)
    if s3:
        out["s3_buckets"] = s3

    internal = 0
    external: set[str] = set()
    for src in _RE_SCRIPT_SRC.findall(html):
        src = src.strip()
        if src.startswith("//"):
            src = "https:" + src
        m = re.match(r"https?://([^/]+)", src)
        if m:
            h = m.group(1)
            if h == host:
                internal += 1
            else:
                external.add(h)
        else:
            internal += 1
    if external:
        out["third_party_script_hosts"] = sorted(external)
    out["script_count"] = {"internal": internal, "external": len(external)}
    return out


def extract_plugins(html: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    plugin_ids = _unique(_RE_PLUGIN_ID, html)
    if plugin_ids:
        out["plugin_ids"] = plugin_ids
        out["plugin_count"] = len(plugin_ids)

    known_libs = (
        "Chart.js", "ApexCharts", "PDFObject", "pdf.js", "Tippy",
        "lodash", "feather-icons", "Select2", "inputmask",
        "jquery-migrate", "Ionic", "classify",
    )
    mentioned = []
    for lib in known_libs:
        if re.search(rf"\b{re.escape(lib)}\b", html, re.I):
            mentioned.append(lib.lower())
    if mentioned:
        out["mentioned_libraries"] = sorted(set(mentioned))
    return out


def extract_bundles(html: str) -> dict[str, list[str]]:
    bundles: dict[str, list[str]] = {}
    kinds = ("early_js", "pre_run_jquery_js", "static_js", "dynamic_js", "run_js", "run_css")
    for kind in kinds:
        hashes = re.findall(rf"/package/{kind}/([a-f0-9]{{64}})", html)
        if hashes:
            seen: dict[str, None] = {}
            for h in hashes:
                seen.setdefault(h, None)
            bundles[kind] = list(seen)
    return bundles


# ─── 3. Rendering ────────────────────────────────────────────────────────────

def render_verdict(score: int, signals_hit: list[str], verdict: str, color: str) -> None:
    filled = score // 5
    bar = "█" * filled + "░" * (20 - filled)
    body_lines = [
        f"[bold {color}]{verdict}[/]   confidence [{color}]{score}/100[/]",
        f"[{color}]{bar}[/]",
        "",
        "[dim]signals matched:[/]",
    ]
    body_lines.extend(f"  [green]✓[/] {s}" for s in signals_hit)
    panel("Bubble.io detection", "\n".join(body_lines), style=color)


def _add_to_tree(branch: Tree, data: Any) -> None:
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, (dict, list)) and v:
                sub = branch.add(f"[cyan]{k}[/]")
                _add_to_tree(sub, v)
            else:
                branch.add(f"[cyan]{k}[/]: [white]{v}[/]")
    elif isinstance(data, list):
        for v in data:
            if isinstance(v, (dict, list)):
                sub = branch.add("·")
                _add_to_tree(sub, v)
            else:
                branch.add(f"[white]{v}[/]")


def render_info(info: dict[str, Any]) -> None:
    tree = Tree("[bold cyan]Bubble.io — extracted info[/]")
    order = ("app", "session", "keys", "meta", "infra", "plugins", "bundles")
    for cat in order:
        data = info.get(cat)
        if not data:
            continue
        branch = tree.add(f"[bold yellow]{cat}[/]")
        if cat == "bundles":
            shortened = {k: [f"{h[:12]}…" for h in v] for k, v in data.items()}
            _add_to_tree(branch, shortened)
        else:
            _add_to_tree(branch, data)
    console.print(tree)


# ─── Schema integration ──────────────────────────────────────────────────────

def populate_schema(ctx: Context, info: dict[str, Any]) -> None:
    """Push fingerprint output into the cumulative BubbleSchema on the context."""
    app = info.get("app") or {}
    if app.get("app_id"):
        ctx.schema.app_id = app["app_id"]
    if app.get("app_version"):
        ctx.schema.app_version = app["app_version"]
    if app.get("env_name"):
        ctx.schema.env_name = app["env_name"]
    if app.get("page_name"):
        ctx.schema.page_name_current = app["page_name"]
        ctx.schema.upsert_page(name=app["page_name"])

    plugins = info.get("plugins") or {}
    for pid in plugins.get("plugin_ids", []):
        ctx.schema.upsert_plugin(pid, source="html", category="third_party")
    for lib in plugins.get("mentioned_libraries", []):
        ctx.schema.upsert_plugin(lib, source="html", category="library")


# ─── 4. Findings ─────────────────────────────────────────────────────────────

def push_findings(ctx: Context, info: dict[str, Any], module_name: str) -> None:
    app = info.get("app", {})
    keys = info.get("keys", {})

    ctx.add_finding(Finding(
        module=module_name,
        severity="info",
        title="Bubble.io application fingerprinted",
        detail=(
            f"app_id={app.get('app_id', '?')} "
            f"version={app.get('app_version', '?')} "
            f"env={app.get('env_name', '?')}"
        ),
        data={"app": app, "session": info.get("session", {})},
    ))

    if keys.get("google_maps"):
        ctx.add_finding(Finding(
            module=module_name,
            severity="low",
            title="Google Maps API key exposed in HTML",
            detail="Public by design, but verify HTTP-referrer restriction on Google Cloud Console.",
            data={"key": keys["google_maps"]},
        ))

    others = keys.get("other_google_api_keys", [])
    if others:
        ctx.add_finding(Finding(
            module=module_name,
            severity="medium",
            title=f"{len(others)} additional Google API key(s) exposed",
            data={"keys": others},
        ))

    if keys.get("stripe_publishable"):
        ctx.add_finding(Finding(
            module=module_name,
            severity="info",
            title="Stripe publishable key exposed (normal for client code)",
            data={"keys": keys["stripe_publishable"]},
        ))

    if app.get("app_version") == "test":
        ctx.add_finding(Finding(
            module=module_name,
            severity="medium",
            title="App running on test environment (version=test)",
            detail="Test/dev env reachable from this URL — confirm this is expected.",
        ))


# ─── 5. Module class ─────────────────────────────────────────────────────────

@register
class Fingerprint(Module):
    name = "fingerprint"
    description = "Detect Bubble.io and extract app / session / keys / infra / plugins metadata."
    needs_auth = False
    category = "recon"
    subcommands = ()
    flags = ()
    example = "run fingerprint"

    async def run(self, ctx: Context, **kwargs: Any) -> None:
        if ctx.target is None:
            console.print("[red]No target set.[/] Use `target <url>` first.")
            return

        url = ctx.target.url
        cookies = ctx.session.cookies if ctx.session else None

        console.print(f"[cyan]→[/] GET [bold]{url}[/]")
        try:
            async with client(cookies=cookies) as c:
                with console.status("[cyan]fetching…[/]", spinner="dots"):
                    resp = await c.get(url)
        except httpx.HTTPError as exc:
            console.print(f"[red]request failed:[/] {exc}")
            ctx.add_finding(Finding(
                module=self.name,
                severity="info",
                title="HTTP request failed",
                detail=str(exc),
            ))
            return

        html = resp.text
        score, signals_hit = score_signals(html)
        verdict, color = verdict_from_score(score)
        render_verdict(score, signals_hit, verdict, color)

        if score < 15:
            ctx.add_finding(Finding(
                module=self.name,
                severity="info",
                title="Target does not appear to be a Bubble.io application",
                data={"score": score, "signals": signals_hit},
            ))
            return

        info: dict[str, Any] = {
            "app": extract_app(html),
            "session": extract_session(html),
            "keys": extract_keys(html),
            "meta": extract_meta(html),
            "infra": extract_infra(html, str(resp.url)),
            "plugins": extract_plugins(html),
            "bundles": extract_bundles(html),
        }
        ctx.target.fingerprint.update({
            "score": score,
            "verdict": verdict,
            **{k: v for k, v in info.items() if v},
        })
        populate_schema(ctx, info)

        render_info(info)
        push_findings(ctx, info, self.name)
        console.print(f"[dim]response: {resp.status_code} · {resp.url}[/]")


# ─── Offline helper (used for local verification against a cached HTML) ──────

def analyze_html(html: str, final_url: str = "https://example.com/") -> dict[str, Any]:
    score, signals_hit = score_signals(html)
    verdict, _ = verdict_from_score(score)
    return {
        "score": score,
        "verdict": verdict,
        "signals": signals_hit,
        "app": extract_app(html),
        "session": extract_session(html),
        "keys": extract_keys(html),
        "meta": extract_meta(html),
        "infra": extract_infra(html, final_url),
        "plugins": extract_plugins(html),
        "bundles": extract_bundles(html),
    }
