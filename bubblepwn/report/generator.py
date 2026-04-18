"""Collect the current Context into a structured Report dataclass."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from bubblepwn import __version__
from bubblepwn.context import Context


@dataclass
class Report:
    title: str
    target_url: str
    target_host: str
    generated_at: str
    toolkit_version: str
    summary: dict[str, int]
    fingerprint: dict[str, Any]
    schema_stats: dict[str, int]
    data_types: list[dict[str, Any]]
    pages: list[dict[str, Any]]
    plugins: list[dict[str, Any]]
    elements_total: int
    findings: list[dict[str, Any]]


_SEVERITIES = ("critical", "high", "medium", "low", "info")


def build_report(ctx: Context, *, title: Optional[str] = None) -> Report:
    if ctx.target is None:
        raise ValueError("no target set")

    summary = {s: 0 for s in _SEVERITIES}
    for f in ctx.findings:
        summary[f.severity] = summary.get(f.severity, 0) + 1

    fp_raw = ctx.target.fingerprint or {}
    fingerprint = {
        "verdict": fp_raw.get("verdict"),
        "score": fp_raw.get("score"),
        "app_id": ctx.schema.app_id,
        "app_version": ctx.schema.app_version,
        "env_name": ctx.schema.env_name,
        "page_name_current": ctx.schema.page_name_current,
        "locale": ctx.schema.locale,
        "available_locales": ctx.schema.available_locales,
        "app": fp_raw.get("app", {}),
        "session": fp_raw.get("session", {}),
        "keys": fp_raw.get("keys", {}),
        "meta": fp_raw.get("meta", {}),
        "infra": fp_raw.get("infra", {}),
    }

    data_types = [
        {
            "name": t.name,
            "raw": t.raw,
            "namespace": t.namespace,
            "fields_count": len(t.fields),
            "fields": sorted(t.fields.keys()),
            "data_api_open": t.data_api_open,
            "sources": list(t.sources),
            "sample_records_count": len(t.sample_records),
        }
        for t in ctx.schema.types.values()
    ]

    pages = [
        {
            "name": p.name,
            "id": p.id,
            "title": p.title,
            "url": p.url,
            "status": p.status,
            "language": p.language,
            "accessible_without_auth": p.accessible_without_auth,
        }
        for p in ctx.schema.pages.values()
    ]

    plugins = [
        {
            "id": p.id,
            "name": p.name,
            "category": p.category,
            "sources": list(p.sources),
            "translations_loaded": list(p.translations_loaded),
            "display_name": p.display_name,
            "vendor": p.vendor,
            "marketplace_url": p.marketplace_url,
            "docs_url": p.docs_url,
            "description": p.description,
            "icon_url": p.icon_url,
            "created_at": p.created_at.isoformat() if p.created_at else None,
        }
        for p in ctx.schema.plugins.values()
    ]

    findings = [
        {
            "module": f.module,
            "severity": f.severity,
            "title": f.title,
            "detail": f.detail,
            "data": f.data,
            "ts": f.ts.isoformat(),
        }
        for f in ctx.findings
    ]

    return Report(
        title=title or f"Security Assessment — {ctx.target.host}",
        target_url=ctx.target.url,
        target_host=ctx.target.host,
        generated_at=datetime.now(timezone.utc).isoformat(),
        toolkit_version=__version__,
        summary=summary,
        fingerprint=fingerprint,
        schema_stats={
            "types": len(ctx.schema.types),
            "pages": len(ctx.schema.pages),
            "plugins": len(ctx.schema.plugins),
            "elements": len(ctx.schema.elements),
        },
        data_types=data_types,
        pages=pages,
        plugins=plugins,
        elements_total=len(ctx.schema.elements),
        findings=findings,
    )
