"""Parse CantStopMe unified blacklist pool."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from cantstopme.paths import POOL_DIR, PROJECT_ROOT

DEFAULT_POOL_FILE = POOL_DIR / "pool.yaml"


@dataclass
class Blacklist:
    chars: set[str] = field(default_factory=set)
    keywords: set[str] = field(default_factory=set)
    tokens: set[str] = field(default_factory=set)  # space, tab, newline

    def merge(self, other: Blacklist) -> None:
        self.chars |= other.chars
        self.keywords |= other.keywords
        self.tokens |= other.tokens

    def blocks_char(self, ch: str) -> bool:
        return ch in self.chars

    def blocks_keyword(self, word: str) -> bool:
        return word.lower() in self.keywords

    def blocks_space(self) -> bool:
        return "space" in self.tokens

    def summary(self) -> dict:
        return {
            "chars": sorted(self.chars),
            "keywords": sorted(self.keywords),
            "tokens": sorted(self.tokens),
        }


def _add_char(bl: Blacklist, value: str) -> None:
    value = value.strip()
    if value.lower() in ("newline", "lf"):
        bl.tokens.add("newline")
    elif value.lower() == "tab":
        bl.tokens.add("tab")
    elif value in ("\\", "\\\\", "backslash"):
        bl.chars.add("\\")
    else:
        bl.chars.add(value)


def _parse_line(line: str, bl: Blacklist) -> None:
    line = line.strip()
    if not line or line.startswith("#"):
        return
    if line.startswith("char:"):
        _add_char(bl, line[5:])
        return
    if line.startswith("keyword:"):
        bl.keywords.add(line[8:].strip().lower())
        return
    if line in ("space", "tab", "newline"):
        bl.tokens.add(line)
        return
    if len(line) == 1:
        bl.chars.add(line)
    elif line.lower() == "space":
        bl.tokens.add("space")
    else:
        bl.keywords.add(line.lower())


def _load_yaml_pool(path: Path) -> Blacklist:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    bl = Blacklist()
    for item in data.get("characters") or []:
        _add_char(bl, str(item))
    for item in data.get("keywords") or []:
        bl.keywords.add(str(item).strip().lower())
    for item in data.get("whitespace") or []:
        token = str(item).strip().lower()
        if token in ("space", "tab", "newline"):
            bl.tokens.add(token)
    return bl


def load_blacklist_file(path: Path) -> Blacklist:
    """Plain-text overlay (char:/keyword:/space lines)."""
    bl = Blacklist()
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        _parse_line(line, bl)
    return bl


def load_default_pool(pool_path: Path | None = None) -> Blacklist:
    path = pool_path or DEFAULT_POOL_FILE
    if not path.is_file():
        raise FileNotFoundError(f"Pool file not found: {path}")
    return _load_yaml_pool(path)


def resolve_blacklist(
    overlay_path: Path | None = None,
    *,
    use_pool: bool = True,
    pool_path: Path | None = None,
) -> Blacklist:
    bl = Blacklist()
    if use_pool:
        bl.merge(load_default_pool(pool_path))
    if overlay_path:
        bl.merge(load_blacklist_file(overlay_path))
    if not bl.chars and not bl.keywords and not bl.tokens:
        raise ValueError(
            "Empty blacklist: enable default pool or pass -b overlay file"
        )
    return bl


def list_pool_entries(pool_path: Path | None = None) -> dict:
    path = pool_path or DEFAULT_POOL_FILE
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {
        "file": str(path.relative_to(PROJECT_ROOT)),
        "version": data.get("version"),
        "characters": list(data.get("characters") or []),
        "keywords": list(data.get("keywords") or []),
        "whitespace": list(data.get("whitespace") or []),
        "counts": {
            "characters": len(data.get("characters") or []),
            "keywords": len(data.get("keywords") or []),
            "whitespace": len(data.get("whitespace") or []),
        },
    }
