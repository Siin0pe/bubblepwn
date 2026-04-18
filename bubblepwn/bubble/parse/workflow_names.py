"""Extract Bubble API workflow name candidates from JS bundles.

Bundles rarely contain full ``/api/1.1/wf/<name>`` URLs — most workflows are
triggered internally via the runtime. We therefore fall back on filtered
string extraction: candidate names are snake_case identifiers matching
attack-surface keywords (auth, password, reset, token, admin, email, etc.).
"""
from __future__ import annotations

import re

_RE_WF_URL = re.compile(r"/api/1\.1/wf/([a-zA-Z_][a-zA-Z0-9_\-]*)")

# Snake_case identifier 4–60 chars.
_RE_SNAKE = re.compile(r'["\']([a-z][a-z0-9_]{3,59})["\']')

_INTEREST_KEYWORDS = (
    "password", "passwd", "reset", "forgot", "temp", "temporary",
    "token", "2fa", "magic", "login", "logout", "signin", "sign_in",
    "signup", "sign_up", "register", "auth", "oauth",
    "admin", "impersonate", "privilege",
    "user", "email", "verify", "confirm", "activate",
    "webhook", "callback",
    "upload", "import", "export",
    "api_key",
)


def extract_workflow_url_names(text: str) -> set[str]:
    """Names appearing explicitly in ``/api/1.1/wf/<name>`` strings."""
    return set(_RE_WF_URL.findall(text))


def extract_interesting_snake_names(text: str) -> set[str]:
    """Snake-case identifiers that contain an attack-surface keyword.

    Heuristic, lossy — every hit is a *candidate*, not a confirmed workflow.
    """
    hits: set[str] = set()
    for m in _RE_SNAKE.finditer(text):
        name = m.group(1)
        low = name.lower()
        if any(k in low for k in _INTEREST_KEYWORDS):
            hits.add(name)
    return hits
