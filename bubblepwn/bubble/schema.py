"""Pydantic models describing what we know about a target Bubble app."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class BubbleField(BaseModel):
    """A field on a Bubble data type."""
    name: str
    type: str          # text, number, boolean, date, image, file, option, list, geographic_address, user, custom.xxx
    raw: str           # e.g. "name___text", "is_admin___boolean"
    source: str        # static_js | init_data | meta | es
    display: Optional[str] = None  # human name from /meta, e.g. "Profile Bio"


class BubbleType(BaseModel):
    """A Bubble data type (table)."""
    name: str                           # "langue"
    raw: str                            # "custom.langue" (or "user")
    namespace: str = "custom"           # custom | system
    fields: dict[str, BubbleField] = Field(default_factory=dict)
    sources: list[str] = Field(default_factory=list)
    data_api_open: Optional[bool] = None
    sample_records: list[dict] = Field(default_factory=list)

    def add_field(self, f: BubbleField) -> None:
        existing = self.fields.get(f.name)
        if existing is None or (existing.type in ("unknown", "text") and f.type != "unknown"):
            self.fields[f.name] = f
        if f.source not in self.sources:
            self.sources.append(f.source)


class BubblePage(BaseModel):
    """A page of the app."""
    name: str                                   # "index", "login"
    id: Optional[str] = None                    # Bubble internal short id, e.g. "bTNCR"
    title: Optional[str] = None
    url: Optional[str] = None
    status: Optional[int] = None
    static_js_url: Optional[str] = None
    dynamic_js_url: Optional[str] = None
    language: Optional[str] = None
    accessible_without_auth: Optional[bool] = None


class BubbleElement(BaseModel):
    """A UI element on a page."""
    id: str
    name: Optional[str] = None
    element_type: Optional[str] = None          # Button, Text, Input, Group, RepeatingGroup...
    path: Optional[str] = None                  # %p3.bTNDC.%el.bTcoz0
    parent_id: Optional[str] = None
    page_name: Optional[str] = None
    plugin_id: Optional[str] = None


class BubblePlugin(BaseModel):
    """A Bubble plugin."""
    id: str                                     # "chartjs" or timestamp ID "1497473108162x748..."
    name: Optional[str] = None                  # Human-readable name if different from id
    category: str = "unknown"                   # first_party | third_party | custom | unknown
    sources: list[str] = Field(default_factory=list)   # where detected: html | static_js | dynamic_js
    translations_loaded: list[str] = Field(default_factory=list)
    headers_source_range: Optional[tuple[int, int]] = None

    # ── Enrichment (catalog + live marketplace lookup) ──────────────────
    display_name: Optional[str] = None          # "Chart.js", "Stripe", vendor-provided title
    vendor: Optional[str] = None                # author / company
    marketplace_url: Optional[str] = None       # https://bubble.io/plugin/<slug>-<id>
    docs_url: Optional[str] = None              # vendor docs / GitHub
    description: Optional[str] = None           # one-line summary
    icon_url: Optional[str] = None              # plugin logo (og:image)
    created_at: Optional[datetime] = None       # derived from timestamp ID when applicable


class BubbleSchema(BaseModel):
    """Everything we've learned about the target, cumulated across modules."""
    app_id: Optional[str] = None
    app_version: Optional[str] = None
    env_name: Optional[str] = None
    page_name_current: Optional[str] = None
    locale: Optional[str] = None
    available_locales: list[str] = Field(default_factory=list)

    types: dict[str, BubbleType] = Field(default_factory=dict)
    pages: dict[str, BubblePage] = Field(default_factory=dict)
    elements: dict[str, BubbleElement] = Field(default_factory=dict)
    plugins: dict[str, BubblePlugin] = Field(default_factory=dict)

    def upsert_type(self, raw: str, source: str) -> BubbleType:
        t = self.types.get(raw)
        if t is None:
            if raw == "user":
                ns, name = "system", "user"
            elif "." in raw:
                ns, name = raw.split(".", 1)
            else:
                ns, name = "custom", raw
            t = BubbleType(name=name, raw=raw, namespace=ns)
            self.types[raw] = t
        if source not in t.sources:
            t.sources.append(source)
        return t

    def upsert_page(self, name: str, **kwargs) -> BubblePage:
        p = self.pages.get(name)
        if p is None:
            p = BubblePage(name=name, **kwargs)
            self.pages[name] = p
        else:
            for k, v in kwargs.items():
                if v is not None and getattr(p, k, None) in (None, [], {}, ""):
                    setattr(p, k, v)
        return p

    def upsert_plugin(self, id_: str, *, source: str, **kwargs) -> BubblePlugin:
        p = self.plugins.get(id_)
        if p is None:
            p = BubblePlugin(id=id_, **kwargs)
            self.plugins[id_] = p
        else:
            for k, v in kwargs.items():
                if v is not None and getattr(p, k, None) in (None, [], {}, "", "unknown"):
                    setattr(p, k, v)
        if source not in p.sources:
            p.sources.append(source)
        return p

    def upsert_element(self, id_: str, **kwargs) -> BubbleElement:
        e = self.elements.get(id_)
        if e is None:
            e = BubbleElement(id=id_, **kwargs)
            self.elements[id_] = e
        else:
            for k, v in kwargs.items():
                if v is not None and getattr(e, k, None) in (None, [], {}, ""):
                    setattr(e, k, v)
        return e
