from __future__ import annotations

import logging

import structlog
from rich.logging import RichHandler


def setup_logging(debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="%H:%M:%S",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False, markup=True)],
    )
    # Silence transport libraries unless explicitly in debug mode. httpx
    # emits one INFO line per request, which quickly drowns a long scan.
    if not debug:
        for name in ("httpx", "httpcore", "hpack", "h11", "urllib3", "asyncio"):
            logging.getLogger(name).setLevel(logging.WARNING)
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(level),
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(colors=False),
        ],
    )


def get_logger(name: str) -> structlog.BoundLogger:
    return structlog.get_logger(name)
