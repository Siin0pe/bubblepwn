"""Render a Report as pretty JSON."""
from __future__ import annotations

import dataclasses
import json

from bubblepwn.report.generator import Report


def render_json(r: Report) -> str:
    return json.dumps(
        dataclasses.asdict(r),
        indent=2,
        ensure_ascii=False,
        default=str,
    )
