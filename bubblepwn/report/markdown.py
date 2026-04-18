"""Render a Report as GitHub-flavoured Markdown. Concise, factual."""
from __future__ import annotations

import json
from typing import Any

from bubblepwn.report.generator import Report

_SEVERITIES = ("critical", "high", "medium", "low", "info")
_MAX_TYPES_TABLE = 20
_MAX_FINDING_DATA_CHARS = 1500


def _fmt(v: Any) -> str:
    if v is None or v == "":
        return "—"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, (list, tuple)):
        if not v:
            return "—"
        return ", ".join(f"`{x}`" for x in v)
    return f"`{v}`"


def _truncate(s: str, n: int) -> str:
    if len(s) <= n:
        return s
    return s[:n] + "\n... (truncated)"


def render_markdown(r: Report) -> str:
    out: list[str] = []

    # ── Header ───────────────────────────────────────────────────────
    out.append(f"# {r.title}")
    out.append("")
    out.append(
        f"Target `{r.target_url}` · generated {r.generated_at} · "
        f"bubblepwn {r.toolkit_version}"
    )

    # ── Summary ──────────────────────────────────────────────────────
    total = sum(r.summary.values())
    sev_line = " · ".join(
        f"{s} **{r.summary.get(s, 0)}**" for s in _SEVERITIES
    )
    out.append("")
    out.append("## Summary")
    out.append("")
    out.append(f"{total} finding(s) — {sev_line}")

    # ── Target ───────────────────────────────────────────────────────
    fp = r.fingerprint
    verdict = fp.get("verdict") or "unknown"
    score = fp.get("score")
    app = fp.get("app") or {}
    flags = app.get("flags") or {}
    flag_summary = (
        ", ".join(k for k, v in flags.items() if v) if flags else "—"
    )

    plugin_by_cat: dict[str, int] = {}
    for p in r.plugins:
        plugin_by_cat[p["category"]] = plugin_by_cat.get(p["category"], 0) + 1
    plugin_summary = ", ".join(
        f"{n} {c}" for c, n in sorted(plugin_by_cat.items(), key=lambda x: -x[1])
    ) or "—"

    out.append("")
    out.append("## Target")
    out.append("")
    out.append("| Property | Value |")
    out.append("| --- | --- |")
    out.append(
        f"| Framework | Bubble.io ({verdict}"
        + (f", {score}/100" if score is not None else "")
        + ") |"
    )
    out.append(f"| App ID | {_fmt(fp.get('app_id'))} |")
    out.append(f"| Environment | {_fmt(fp.get('env_name'))} |")
    out.append(f"| Version | {_fmt(fp.get('app_version'))} |")
    out.append(f"| Locale | {_fmt(fp.get('locale'))} |")
    out.append(f"| Current page | {_fmt(fp.get('page_name_current'))} |")
    out.append(f"| App flags | {flag_summary} |")
    out.append(f"| Data types | {r.schema_stats.get('types', 0)} |")
    out.append(f"| Pages | {r.schema_stats.get('pages', 0)} |")
    out.append(f"| Plugins | {len(r.plugins)} ({plugin_summary}) |")
    out.append(f"| UI elements | {r.schema_stats.get('elements', 0)} |")

    session = fp.get("session") or {}
    if session:
        out.append("")
        out.append("### Session tokens")
        out.append("")
        for k, v in sorted(session.items()):
            out.append(f"- `{k}`: `{v}`")

    keys = fp.get("keys") or {}
    if keys:
        out.append("")
        out.append("### Public keys")
        out.append("")
        for k, v in sorted(keys.items()):
            if isinstance(v, list):
                out.append(f"- {k}: " + ", ".join(f"`{x}`" for x in v))
            else:
                out.append(f"- {k}: `{v}`")

    infra = fp.get("infra") or {}
    if infra:
        out.append("")
        out.append("### Infrastructure")
        out.append("")
        for k, v in infra.items():
            if isinstance(v, list):
                if not v:
                    continue
                out.append(f"- {k}: " + ", ".join(f"`{x}`" for x in v))
            elif isinstance(v, dict):
                parts = ", ".join(f"{kk}={vv}" for kk, vv in v.items())
                out.append(f"- {k}: {parts}")
            else:
                out.append(f"- {k}: {_fmt(v)}")

    # ── Data exposure ────────────────────────────────────────────────
    exposed = [t for t in r.data_types if t.get("data_api_open") is True]
    if exposed:
        exposed.sort(key=lambda t: -(t.get("sample_records_count") or 0))
        out.append("")
        out.append("## Data exposure")
        out.append("")
        out.append(f"{len(exposed)} type(s) reachable via the Data API anonymously.")
        out.append("")
        out.append("| Type | Fields | Sample records |")
        out.append("| --- | ---: | ---: |")
        for t in exposed[:_MAX_TYPES_TABLE]:
            out.append(
                f"| `{t['raw']}` | {t['fields_count']} | "
                f"{t.get('sample_records_count', 0)} |"
            )
        if len(exposed) > _MAX_TYPES_TABLE:
            out.append(
                f"| _… {len(exposed) - _MAX_TYPES_TABLE} more exposed type(s)_ | | |"
            )

    # ── Findings ─────────────────────────────────────────────────────
    out.append("")
    out.append("## Findings")

    by_sev: dict[str, list[dict[str, Any]]] = {}
    for f in r.findings:
        by_sev.setdefault(f["severity"], []).append(f)

    counter = 0
    for sev in _SEVERITIES:
        items = by_sev.get(sev) or []
        out.append("")
        out.append(f"### {sev.capitalize()} ({len(items)})")
        out.append("")
        if not items:
            out.append("_None._")
            continue
        if sev == "info":
            for f in items:
                counter += 1
                out.append(f"- **F-{counter:03d}** · `{f['module']}` — {f['title']}")
            continue
        for f in items:
            counter += 1
            out.append(f"#### F-{counter:03d} · {f['title']}")
            out.append("")
            out.append(
                f"_Module_: `{f['module']}` · _Severity_: **{sev}** · "
                f"_Recorded_: {f['ts']}"
            )
            if f.get("detail"):
                out.append("")
                out.append(f["detail"])
            if sev in ("critical", "high") and f.get("data"):
                out.append("")
                payload = json.dumps(
                    f["data"], indent=2, ensure_ascii=False, default=str
                )
                out.append("```json")
                out.append(_truncate(payload, _MAX_FINDING_DATA_CHARS))
                out.append("```")
            out.append("")

    out.append("")
    out.append("---")
    out.append("")
    out.append(
        f"_bubblepwn {r.toolkit_version} · by @Siin0pe · {r.generated_at}_"
    )
    return "\n".join(out)
