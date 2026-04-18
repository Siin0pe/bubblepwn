from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path

from bubblepwn.modules.base import Module, Registry, register, registry

_SKIP = {"base"}
_pkg_path = Path(__file__).parent
for _info in pkgutil.iter_modules([str(_pkg_path)]):
    if _info.name in _SKIP or _info.name.startswith("_"):
        continue
    importlib.import_module(f"bubblepwn.modules.{_info.name}")

__all__ = ["Module", "Registry", "register", "registry"]
