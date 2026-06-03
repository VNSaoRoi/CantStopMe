"""Load and match bypass rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from cantstopme.engine.blacklist import Blacklist
from cantstopme.paths import RULES_DIR


@dataclass
class Rule:
    id: str
    name: str
    priority: int
    transform: str
    target: str
    triggers: dict[str, Any] = field(default_factory=dict)
    requires_not_blocked: list[str] = field(default_factory=list)
    requires_blocked: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    notes: str = ""
    defense: list[str] = field(default_factory=list)
    exclusive_group: str | None = None
    category: str = ""
    contexts: list[str] = field(default_factory=lambda: ["general"])
    reference_only: bool = False

    def applies(self, bl: Blacklist, command: str) -> bool:
        for ch in self.requires_not_blocked:
            if bl.blocks_char(ch):
                return False
        for ch in self.requires_blocked:
            if ch == "space":
                if not bl.blocks_space():
                    return False
            elif not bl.blocks_char(ch):
                return False

        blocked_chars = self.triggers.get("blocked_chars") or []
        if blocked_chars:
            if blocked_chars != ["*"] and not any(
                bl.blocks_char(c) for c in blocked_chars
            ):
                return False
            if blocked_chars == ["*"] and not bl.chars:
                return False

        blocked_tokens = self.triggers.get("blocked_tokens") or []
        if blocked_tokens:
            ok = False
            for t in blocked_tokens:
                if t == "space" and bl.blocks_space():
                    ok = True
                elif t in bl.tokens:
                    ok = True
            if not ok:
                return False

        blocked_keywords = self.triggers.get("blocked_keywords") or []
        if blocked_keywords:
            tokens = _command_tokens(command)
            if blocked_keywords == ["*"]:
                if not bl.keywords:
                    return False
                token_hit = any(bl.blocks_keyword(t) for t in tokens)
                cmd_lower = command.lower()
                substr_hit = any(kw in cmd_lower for kw in bl.keywords)
                if self.triggers.get("keyword_match_substring"):
                    if not (token_hit or substr_hit):
                        return False
                elif not token_hit:
                    return False
            else:
                if not any(
                    bl.blocks_keyword(kw) and kw in tokens for kw in blocked_keywords
                ):
                    return False
        return True


def _command_tokens(command: str) -> list[str]:
    import shlex

    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        parts = command.split()
    tokens = []
    for p in parts:
        tokens.append(p.split("/")[0].lower())
    return tokens


def _rule_from_dict(data: dict, category: str = "") -> Rule:
    return Rule(
        id=data["id"],
        name=data.get("name", data["id"]),
        priority=int(data.get("priority", 100)),
        transform=data["transform"],
        target=data.get("target", "whole_command"),
        triggers=data.get("triggers", {}),
        requires_not_blocked=list(data.get("requires_not_blocked") or []),
        requires_blocked=list(data.get("requires_blocked") or []),
        references=list(data.get("references") or []),
        notes=data.get("notes", "") or "",
        defense=list(data.get("defense") or []),
        exclusive_group=data.get("exclusive_group"),
        category=category or data.get("category", ""),
        contexts=list(data.get("contexts") or ["general"]),
        reference_only=bool(data.get("reference_only", False)),
    )


def load_rules() -> list[Rule]:
    rules: list[Rule] = []
    for path in sorted(RULES_DIR.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not data:
            continue
        category = data.get("category", path.stem)
        if "rules" in data:
            for entry in data["rules"]:
                if entry and entry.get("id"):
                    rules.append(_rule_from_dict(entry, category))
        elif data.get("id"):
            rules.append(_rule_from_dict(data, category))
    rules.sort(key=lambda r: r.priority)
    return rules


def select_rules(
    bl: Blacklist,
    command: str,
    *,
    include_reference_only: bool = False,
) -> list[Rule]:
    out = [r for r in load_rules() if r.applies(bl, command)]
    if not include_reference_only:
        out = [r for r in out if not r.reference_only]
    return out


KEYWORD_STYLE_TO_TRANSFORM = {
    "single_quotes": "keyword_single_quotes",
    "double_quotes": "keyword_double_quotes",
    "backticks": "keyword_backticks",
    "dollar_at": "keyword_dollar_at",
    "backslash": "keyword_backslash",
    "uninit_var": "keyword_uninit_var",
    "reverse": "command_reverse",
}
