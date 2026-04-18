from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from bubblepwn.bubble.schema import BubbleSchema


class Finding(BaseModel):
    module: str
    severity: str = "info"
    title: str
    detail: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    ts: datetime = Field(default_factory=datetime.utcnow)


class Target(BaseModel):
    url: str
    host: str
    scheme: str
    fingerprint: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_url(cls, raw: str) -> "Target":
        raw = raw.strip().rstrip("/")
        if "://" not in raw:
            raw = "https://" + raw
        p = urlparse(raw)
        if not p.netloc:
            raise ValueError(f"Invalid URL: {raw}")
        return cls(url=f"{p.scheme}://{p.netloc}", host=p.netloc, scheme=p.scheme)


class Session(BaseModel):
    path: Optional[str] = None
    cookies: dict[str, str] = Field(default_factory=dict)
    storage: dict[str, Any] = Field(default_factory=dict)
    loaded_at: Optional[datetime] = Field(default_factory=datetime.utcnow)


class Context:
    _instance: Optional["Context"] = None

    def __init__(self) -> None:
        self.target: Optional[Target] = None
        self.session: Optional[Session] = None
        self.findings: list[Finding] = []
        self.settings: dict[str, Any] = {}
        self.schema: BubbleSchema = BubbleSchema()

    @classmethod
    def get(cls) -> "Context":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def set_target(self, raw: str) -> Target:
        new = Target.from_url(raw)
        if self.target is None or self.target.host != new.host:
            # Reset cumulative schema when switching targets.
            self.schema = BubbleSchema()
        self.target = new
        return self.target

    def clear_target(self) -> None:
        self.target = None
        self.schema = BubbleSchema()

    def add_finding(self, f: Finding) -> None:
        self.findings.append(f)
