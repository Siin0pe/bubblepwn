"""Built-in wordlists for Bubble pentest modules."""
from pathlib import Path


def load(name: str) -> list[str]:
    """Load a wordlist by name (without extension). Returns list of non-empty,
    non-comment lines."""
    p = Path(__file__).parent / f"{name}.txt"
    if not p.exists():
        return []
    out: list[str] = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out
