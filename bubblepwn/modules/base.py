from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Iterable, Optional, Union

from bubblepwn.context import Context

#: A single help entry — either the raw syntax (``str``) or a
#: ``(syntax, description)`` tuple. Modules should prefer the tuple form so the
#: ``help <module>`` renderer can show what each flag/subcommand actually does.
HelpEntry = Union[str, tuple[str, str]]


def help_rows(entries: Iterable[HelpEntry]) -> list[tuple[str, str]]:
    """Normalize a mix of ``str`` / ``(syntax, desc)`` entries into rows.

    Plain strings get an empty description. This keeps the rendering code
    simple while allowing legacy modules (no description yet) to coexist.
    """
    rows: list[tuple[str, str]] = []
    for e in entries:
        if isinstance(e, tuple):
            syntax, desc = e
            rows.append((str(syntax), str(desc)))
        else:
            rows.append((str(e), ""))
    return rows


def parse_flags(argv: list[str]) -> tuple[dict[str, Any], list[str]]:
    """Minimal flag parser for module args.

    Accepts `--key value`, `--key=value`, and `--flag` (→ True).
    Everything else is positional. Dashes in keys become underscores.
    """
    flags: dict[str, Any] = {}
    positional: list[str] = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok.startswith("--"):
            k = tok[2:]
            if "=" in k:
                key, val = k.split("=", 1)
                flags[key.replace("-", "_")] = val
                i += 1
                continue
            key = k.replace("-", "_")
            if i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                flags[key] = argv[i + 1]
                i += 2
            else:
                flags[key] = True
                i += 1
        else:
            positional.append(tok)
            i += 1
    return flags, positional


class Module(ABC):
    """Base class for pentest modules.

    Subclasses set ``name``, ``description``, ``category``, and implement
    :meth:`run`. The ``run`` method receives the raw ``argv`` list under the
    kwarg of the same name.

    ``category`` drives shell grouping and the ``flow`` presets:
      - ``recon``   : passive — no state changes, minimal request volume
      - ``audit``   : active probing — GET/OPTIONS only, no writes
      - ``exploit`` : can exfiltrate data or trigger actions (mutating)

    ``subcommands``, ``flags`` and ``example`` feed the ``help <module>``
    command — keep them one-liners, close to copy-paste usage.
    """

    name: str = "unnamed"
    description: str = ""
    needs_auth: bool = False
    category: str = "recon"
    # Each entry is either a raw syntax string or a ``(syntax, description)``
    # tuple. Tuple form is strongly preferred so ``help <module>`` can explain
    # what the subcommand / flag actually does.
    subcommands: tuple[HelpEntry, ...] = ()
    flags: tuple[HelpEntry, ...] = ()
    example: str = ""
    #: Longer free-form help rendered as a block at the bottom of
    #: ``help <module>``. Optional — short modules can leave it empty.
    long_help: str = ""

    @abstractmethod
    async def run(self, ctx: Context, **kwargs) -> None: ...


_CATEGORY_ORDER = {"recon": 0, "audit": 1, "exploit": 2}


class Registry:
    def __init__(self) -> None:
        self._mods: dict[str, Module] = {}

    def register(self, mod: Module) -> None:
        self._mods[mod.name] = mod

    def get(self, name: str) -> Optional[Module]:
        return self._mods.get(name)

    def all(self) -> Iterable[Module]:
        return sorted(
            self._mods.values(),
            key=lambda m: (_CATEGORY_ORDER.get(m.category, 9), m.name),
        )

    def by_category(self, category: str) -> list[Module]:
        return [m for m in self.all() if m.category == category]

    def names(self) -> list[str]:
        return sorted(self._mods.keys())


registry = Registry()


def register(cls: type[Module]) -> type[Module]:
    registry.register(cls())
    return cls
