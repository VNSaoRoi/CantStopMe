"""Resolve project root (repo root with rules/ and blacklist_pool/)."""

from __future__ import annotations

from pathlib import Path


def project_root() -> Path:
    start = Path(__file__).resolve().parent
    for candidate in (start, *start.parents):
        if (candidate / "rules").is_dir() and (candidate / "blacklist_pool").is_dir():
            return candidate
    return start.parent


PROJECT_ROOT = project_root()
RULES_DIR = PROJECT_ROOT / "rules"
POOL_DIR = PROJECT_ROOT / "blacklist_pool"
