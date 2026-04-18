"""Write a Report to disk — format picked by file extension."""
from __future__ import annotations

from pathlib import Path

from bubblepwn.context import Context
from bubblepwn.report.generator import build_report
from bubblepwn.report.html_render import render_html
from bubblepwn.report.json_render import render_json
from bubblepwn.report.markdown import render_markdown


def write_report(ctx: Context, path: str | Path, *, title: str | None = None) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    report = build_report(ctx, title=title)
    ext = p.suffix.lower()
    if ext in (".md", ".markdown"):
        content = render_markdown(report)
    elif ext in (".html", ".htm"):
        content = render_html(report)
    elif ext == ".json":
        content = render_json(report)
    else:
        raise ValueError(f"unsupported extension `{ext}` — use .md, .html, or .json")
    p.write_text(content, encoding="utf-8")
    return p
