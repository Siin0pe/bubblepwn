from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="BUBBLEPWN_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    user_agent: str = "bubblepwn/0.1.0"
    proxy: Optional[str] = None
    timeout_s: float = 30.0
    rate_limit_rps: float = 5.0
    verify_tls: bool = True
    output_dir: Path = Field(default_factory=lambda: Path.cwd() / "out")


settings = Settings()
