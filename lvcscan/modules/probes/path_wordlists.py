"""Repo-root path wordlists for operator recon and post-upload readback sweeps."""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

ROOT = Path(__file__).resolve().parents[2]
WORDLISTS = ROOT / "wordlists"

_NAMES = {
    "general": "general_laravel.txt",
    "webshell": "laravel_webshell_paths.txt",
}


def wordlist_path(name: str) -> Path:
    key = name.lower().strip()
    if key not in _NAMES:
        raise ValueError(f"unknown wordlist {name!r}; choose: {', '.join(_NAMES)}")
    path = WORDLISTS / _NAMES[key]
    if not path.is_file():
        raise FileNotFoundError(f"missing wordlist: {path}")
    return path


def iter_paths(name: str) -> Iterator[str]:
    """Yield URL path suffixes (leading slash) from a wordlist, skipping comments/blanks."""
    with wordlist_path(name).open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if not line.startswith("/"):
                line = "/" + line
            yield line


def list_wordlist_names() -> list[str]:
    return sorted(_NAMES)
