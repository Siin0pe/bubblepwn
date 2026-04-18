"""Report generation — structured export of the current Context.

Public API:
  - ``build_report(ctx)``  → ``Report`` dataclass
  - ``render_markdown(r)`` → str (GitHub-flavoured Markdown)
  - ``render_html(r)``     → str (self-contained HTML + CSS)
  - ``render_json(r)``     → str (pretty JSON)
  - ``write_report(ctx, path)`` → picks format by extension
"""
from bubblepwn.report.generator import Report, build_report
from bubblepwn.report.markdown import render_markdown
from bubblepwn.report.html_render import render_html
from bubblepwn.report.json_render import render_json
from bubblepwn.report.writer import write_report

__all__ = [
    "Report",
    "build_report",
    "render_markdown",
    "render_html",
    "render_json",
    "write_report",
]
