"""Render a Report as a self-contained HTML document. Neutral, CLI-ish style."""
from __future__ import annotations

import html as _html
import json
from typing import Any

from bubblepwn.report.generator import Report

_SEVERITIES = ("critical", "high", "medium", "low", "info")
_MAX_TYPES_TABLE = 20
_MAX_FINDING_DATA_CHARS = 1500


# Palette aligned on the CLI's Rich styles:
#   - accent cyan mirrors the shell prompt
#   - severity colours mirror the Rich panel borders
_CSS = """
:root {
  --fg: #1a1a1a;
  --fg-muted: #666;
  --fg-dim: #999;
  --bg: #ffffff;
  --bg-alt: #fafafa;
  --bg-code: #f4f4f4;
  --border: #e5e5e5;
  --accent: #0d7a8a;
  --crit: #b32b2f;
  --high: #d05a00;
  --medium: #998000;
  --low: #506d9b;
  --info: #888;
}
* { box-sizing: border-box; }
html, body { background: var(--bg); color: var(--fg); }
body {
  font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI",
               Helvetica, Arial, sans-serif;
  max-width: 880px;
  margin: 0 auto;
  padding: 3em 1.5em 4em;
  line-height: 1.55;
  font-size: 15px;
}
h1 {
  font-size: 1.55em;
  font-weight: 600;
  margin: 0 0 0.35em;
  letter-spacing: -0.01em;
}
.meta {
  color: var(--fg-muted);
  font-size: 0.86em;
  margin-bottom: 2.5em;
}
.meta code { font-size: 0.9em; }
h2 {
  font-size: 0.76em;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--accent);
  margin: 3em 0 1em;
  border-bottom: 1px solid var(--border);
  padding-bottom: 0.4em;
}
h3 {
  font-size: 1em;
  font-weight: 600;
  margin: 2em 0 0.6em;
}
h4 {
  font-size: 0.95em;
  font-weight: 600;
  margin: 0 0 0.3em;
  display: inline;
}
p { margin: 0.6em 0; }
code {
  font-family: "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  font-size: 0.86em;
  background: var(--bg-code);
  padding: 1px 5px;
  border-radius: 3px;
}
pre {
  font-family: "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  background: var(--bg-code);
  border: 1px solid var(--border);
  padding: 0.8em 1em;
  border-radius: 4px;
  font-size: 0.78em;
  line-height: 1.5;
  overflow-x: auto;
  max-height: 320px;
}
pre code { background: transparent; padding: 0; }
ul { padding-left: 1.4em; margin: 0.5em 0; }
li { margin: 0.2em 0; }
.pills { display: flex; gap: 0.45em; flex-wrap: wrap; margin: 0.8em 0 0.4em; }
.pill {
  display: inline-flex;
  align-items: center;
  gap: 0.4em;
  padding: 0.3em 0.8em;
  border-radius: 20px;
  font-size: 0.78em;
  background: var(--bg-alt);
  border: 1px solid var(--border);
  color: var(--fg-muted);
}
.pill strong { color: var(--fg); font-weight: 600; }
.pill.has-items.critical { background: #fdf0f1; border-color: var(--crit); color: var(--crit); }
.pill.has-items.high     { background: #fdf5ee; border-color: var(--high); color: var(--high); }
.pill.has-items.medium   { background: #fdfbeb; border-color: var(--medium); color: var(--medium); }
.pill.has-items.low      { background: #f1f5fb; border-color: var(--low); color: var(--low); }
.pill.has-items.critical strong,
.pill.has-items.high strong,
.pill.has-items.medium strong,
.pill.has-items.low strong { color: inherit; }
table {
  width: 100%;
  border-collapse: collapse;
  margin: 0.5em 0 1.4em;
  font-size: 0.92em;
}
th, td {
  padding: 0.5em 0.75em;
  text-align: left;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
th {
  font-weight: 600;
  color: var(--fg-muted);
  font-size: 0.78em;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}
tbody tr:last-child td { border-bottom: none; }
.finding {
  padding: 0.8em 1em;
  margin: 0.7em 0;
  border-left: 3px solid var(--border);
  background: var(--bg-alt);
  border-radius: 2px;
}
.finding.critical { border-left-color: var(--crit); }
.finding.high     { border-left-color: var(--high); }
.finding.medium   { border-left-color: var(--medium); }
.finding.low      { border-left-color: var(--low); }
.finding.info     { border-left-color: var(--info); background: transparent; padding: 0.35em 1em; }
.finding-head {
  display: flex;
  align-items: baseline;
  gap: 0.6em;
  flex-wrap: wrap;
  margin-bottom: 0.2em;
}
.fid {
  font-family: "SF Mono", Menlo, Consolas, monospace;
  color: var(--fg-muted);
  font-size: 0.85em;
}
.fmod { color: var(--fg-muted); font-size: 0.82em; }
.fsev {
  display: inline-block;
  padding: 1px 6px;
  font-size: 0.7em;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  font-weight: 600;
  border-radius: 2px;
  color: white;
}
.fsev.critical { background: var(--crit); }
.fsev.high     { background: var(--high); }
.fsev.medium   { background: var(--medium); }
.fsev.low      { background: var(--low); }
.fsev.info     { background: var(--info); }
.finding p { margin: 0.4em 0; font-size: 0.95em; }
.muted { color: var(--fg-muted); }
footer {
  margin-top: 3.5em;
  padding-top: 1.4em;
  border-top: 1px solid var(--border);
  color: var(--fg-dim);
  font-size: 0.8em;
}
"""


def _esc(s: Any) -> str:
    return _html.escape(str(s)) if s is not None else "&mdash;"


def _shorten(s: str, max_len: int = 64) -> str:
    if not s or len(s) <= max_len:
        return s
    return s[: max_len - 1] + "…"


def _fmt(v: Any) -> str:
    if v is None or v == "":
        return "&mdash;"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, (list, tuple)):
        if not v:
            return "&mdash;"
        return ", ".join(f"<code>{_esc(x)}</code>" for x in v)
    if isinstance(v, dict):
        parts = [f"<code>{_esc(k)}</code>={_fmt(vv)}" for k, vv in v.items()]
        return "; ".join(parts)
    return f"<code>{_esc(v)}</code>"


def _truncate(s: str, n: int) -> str:
    if len(s) <= n:
        return s
    return s[:n] + "\n... (truncated)"


def render_html(r: Report) -> str:
    buf: list[str] = []
    buf.append("<!DOCTYPE html>")
    buf.append('<html lang="en"><head>')
    buf.append('<meta charset="utf-8">')
    buf.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    buf.append(f"<title>{_esc(r.title)}</title>")
    buf.append(f"<style>{_CSS}</style>")
    buf.append("</head><body>")

    # ── Header ───────────────────────────────────────────────────────
    buf.append(f"<h1>{_esc(r.title)}</h1>")
    buf.append('<div class="meta">')
    buf.append(
        f"Target <code>{_esc(r.target_url)}</code> &middot; "
        f"generated {_esc(r.generated_at)} &middot; "
        f"bubblepwn {_esc(r.toolkit_version)}"
    )
    buf.append("</div>")

    # ── Summary ──────────────────────────────────────────────────────
    total = sum(r.summary.values())
    buf.append("<h2>Summary</h2>")
    buf.append(f"<p>{total} finding(s) recorded.</p>")
    buf.append('<div class="pills">')
    for sev in _SEVERITIES:
        count = r.summary.get(sev, 0)
        cls = f"pill {sev}" + (" has-items" if count > 0 else "")
        buf.append(f'<span class="{cls}">{sev} <strong>{count}</strong></span>')
    buf.append("</div>")

    # ── Target ───────────────────────────────────────────────────────
    fp = r.fingerprint
    verdict = fp.get("verdict") or "unknown"
    score = fp.get("score")
    app = fp.get("app") or {}
    flags = app.get("flags") or {}
    flag_summary = (
        ", ".join(k for k, v in flags.items() if v) if flags else "&mdash;"
    )

    plugin_by_cat: dict[str, int] = {}
    for p in r.plugins:
        plugin_by_cat[p["category"]] = plugin_by_cat.get(p["category"], 0) + 1
    plugin_summary = (
        ", ".join(
            f"{n} {c}" for c, n in sorted(plugin_by_cat.items(), key=lambda x: -x[1])
        )
        or "&mdash;"
    )

    buf.append("<h2>Target</h2>")
    buf.append("<table><tbody>")
    rows = [
        (
            "Framework",
            f"Bubble.io ({_esc(verdict)}"
            + (f", {score}/100" if score is not None else "")
            + ")",
        ),
        ("App ID", _fmt(fp.get("app_id"))),
        ("Environment", _fmt(fp.get("env_name"))),
        ("Version", _fmt(fp.get("app_version"))),
        ("Locale", _fmt(fp.get("locale"))),
        ("Current page", _fmt(fp.get("page_name_current"))),
        ("App flags", _esc(flag_summary) if flag_summary == "—" else flag_summary),
        ("Data types", str(r.schema_stats.get("types", 0))),
        ("Pages", str(r.schema_stats.get("pages", 0))),
        ("Plugins", f"{len(r.plugins)} ({plugin_summary})"),
        ("UI elements", str(r.schema_stats.get("elements", 0))),
    ]
    for k, v in rows:
        buf.append(f'<tr><th style="width: 28%">{_esc(k)}</th><td>{v}</td></tr>')
    buf.append("</tbody></table>")

    session = fp.get("session") or {}
    if session:
        buf.append("<h3>Session tokens captured</h3>")
        buf.append("<ul>")
        for k, v in sorted(session.items()):
            buf.append(f"<li><code>{_esc(k)}</code>: <code>{_esc(v)}</code></li>")
        buf.append("</ul>")

    keys = fp.get("keys") or {}
    if keys:
        buf.append("<h3>Public keys</h3>")
        buf.append("<ul>")
        for k, v in sorted(keys.items()):
            buf.append(f"<li>{_esc(k)}: {_fmt(v)}</li>")
        buf.append("</ul>")

    infra = fp.get("infra") or {}
    if infra:
        buf.append("<h3>Infrastructure</h3>")
        buf.append("<ul>")
        for k, v in infra.items():
            if isinstance(v, list) and not v:
                continue
            buf.append(f"<li>{_esc(k)}: {_fmt(v)}</li>")
        buf.append("</ul>")

    # ── Plugins ──────────────────────────────────────────────────────
    enriched = [
        p for p in r.plugins
        if p.get("display_name") or p.get("marketplace_url") or p.get("docs_url")
    ]
    if enriched:
        order = {"third_party": 0, "first_party": 1, "unknown": 2}
        enriched.sort(
            key=lambda p: (order.get(p.get("category", ""), 9),
                           p.get("display_name") or p.get("id") or "")
        )
        buf.append("<h3>Plugins</h3>")
        buf.append(
            "<table><thead><tr>"
            "<th>Name</th><th>Vendor</th><th>Category</th>"
            "<th>Created</th><th>Link</th>"
            "</tr></thead><tbody>"
        )
        for p in enriched:
            name = p.get("display_name") or p.get("id") or "—"
            vendor = p.get("vendor") or "—"
            cat = p.get("category", "—")
            created = (p.get("created_at") or "")[:10] or "—"
            link = p.get("marketplace_url") or p.get("docs_url") or ""
            link_cell = (
                f'<a href="{_esc(link)}" target="_blank" rel="noopener noreferrer">'
                f'{_esc(_shorten(link))}</a>'
                if link else "—"
            )
            desc = p.get("description")
            name_cell = (
                f'<strong>{_esc(name)}</strong>'
                + (
                    f'<div class="muted" style="font-size:0.85em">{_esc(desc)}</div>'
                    if desc else ""
                )
            )
            buf.append(
                f"<tr><td>{name_cell}</td>"
                f"<td>{_esc(vendor)}</td>"
                f"<td>{_esc(cat)}</td>"
                f"<td>{_esc(created)}</td>"
                f"<td>{link_cell}</td></tr>"
            )
        buf.append("</tbody></table>")

    # ── Data exposure ────────────────────────────────────────────────
    exposed = [t for t in r.data_types if t.get("data_api_open") is True]
    if exposed:
        exposed.sort(key=lambda t: -(t.get("sample_records_count") or 0))
        buf.append("<h2>Data exposure</h2>")
        buf.append(
            f"<p>{len(exposed)} type(s) reachable via the Data API anonymously.</p>"
        )
        buf.append(
            "<table><thead><tr><th>Type</th>"
            '<th style="text-align:right">Fields</th>'
            '<th style="text-align:right">Sample records</th>'
            "</tr></thead><tbody>"
        )
        for t in exposed[:_MAX_TYPES_TABLE]:
            buf.append(
                f"<tr><td><code>{_esc(t['raw'])}</code></td>"
                f'<td style="text-align:right">{t["fields_count"]}</td>'
                f'<td style="text-align:right">{t.get("sample_records_count", 0)}</td></tr>'
            )
        buf.append("</tbody></table>")
        if len(exposed) > _MAX_TYPES_TABLE:
            buf.append(
                f'<p class="muted">&hellip; {len(exposed) - _MAX_TYPES_TABLE} '
                "more exposed type(s) omitted.</p>"
            )

    # ── Findings ─────────────────────────────────────────────────────
    buf.append("<h2>Findings</h2>")
    by_sev: dict[str, list[dict[str, Any]]] = {}
    for f in r.findings:
        by_sev.setdefault(f["severity"], []).append(f)

    counter = 0
    for sev in _SEVERITIES:
        items = by_sev.get(sev) or []
        buf.append(f"<h3>{sev.capitalize()} ({len(items)})</h3>")
        if not items:
            buf.append('<p class="muted">None.</p>')
            continue
        if sev == "info":
            buf.append("<ul>")
            for f in items:
                counter += 1
                buf.append(
                    f'<li><code>F-{counter:03d}</code> &middot; '
                    f'<span class="fmod">{_esc(f["module"])}</span> &mdash; '
                    f"{_esc(f['title'])}</li>"
                )
            buf.append("</ul>")
            continue
        for f in items:
            counter += 1
            buf.append(f'<div class="finding {sev}">')
            buf.append('<div class="finding-head">')
            buf.append(f'<span class="fid">F-{counter:03d}</span>')
            buf.append(f"<h4>{_esc(f['title'])}</h4>")
            buf.append(f'<span class="fsev {sev}">{sev}</span>')
            buf.append(f'<span class="fmod">{_esc(f["module"])}</span>')
            buf.append("</div>")
            if f.get("detail"):
                buf.append(f"<p>{_esc(f['detail'])}</p>")
            if sev in ("critical", "high") and f.get("data"):
                payload = json.dumps(
                    f["data"], indent=2, ensure_ascii=False, default=str
                )
                buf.append(f"<pre>{_esc(_truncate(payload, _MAX_FINDING_DATA_CHARS))}</pre>")
            buf.append("</div>")

    buf.append(
        f"<footer>bubblepwn {_esc(r.toolkit_version)} &middot; by @Siin0pe &middot; "
        f"{_esc(r.generated_at)}</footer>"
    )
    buf.append("</body></html>")
    return "\n".join(buf)
