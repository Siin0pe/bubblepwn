import sys

__version__ = "0.2.21"

# Windows console defaults to cp1252, which can't encode the box-drawing and
# arrow characters Rich emits — without this, piping output (> file.txt) or
# running under non-UTF-8 code pages crashes with UnicodeEncodeError. Python
# 3.7+ exposes reconfigure() on TextIOWrapper; older interpreters or detached
# streams silently no-op.
if sys.platform == "win32":
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8")
        except Exception:
            pass
