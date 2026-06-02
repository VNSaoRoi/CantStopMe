"""Orchestrate rules + transforms."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from cantstopme.engine.blacklist import resolve_blacklist
from cantstopme.engine.rules import KEYWORD_STYLE_TO_TRANSFORM, Rule, select_rules
from cantstopme.engine.constants import DEFAULT_CMD_INJECT_PREFIX
from cantstopme.engine.transforms import TransformResult, apply_transform

CMD_INJECT_TRANSFORMS = {"newline_prefix", "newline_cr_prefix"}


@dataclass
class ObfuscationReport:
    original: str
    payload: str
    blacklist_summary: dict
    rules_applied: list[str] = field(default_factory=list)
    transforms_applied: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    defense: list[str] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)
    alternatives: list[str] = field(default_factory=list)

def _skip_rule(
    rule: Rule,
    *,
    prefix_ping: bool,
    prefer_keyword: str,
    applied_groups: set[str],
    keyword_chosen: bool,
    force_transforms: dict[str, str] | None = None,
) -> bool:
    if rule.transform in CMD_INJECT_TRANSFORMS and not prefix_ping:
        return True
    if force_transforms and rule.exclusive_group:
        forced = force_transforms.get(rule.exclusive_group)
        if forced is not None:
            if rule.exclusive_group == "cmd_substitute":
                if rule.transform != "command_substitute":
                    return True
            elif rule.transform != forced:
                return True
    if rule.exclusive_group and rule.exclusive_group in applied_groups:
        return True
    if rule.exclusive_group == "keyword_obf" and not force_transforms:
        preferred = KEYWORD_STYLE_TO_TRANSFORM.get(prefer_keyword)
        if preferred and rule.transform != preferred:
            return True
        if keyword_chosen and rule.transform != preferred:
            return True
    return False


def obfuscate(
    command: str,
    *,
    blacklist_path: Path | None = None,
    use_pool: bool = True,
    pool_path: Path | None = None,
    url_encode: bool = False,
    prefer_keyword: str = "single_quotes",
    list_alternatives: bool = False,
    prefix_ping: bool = False,
    force_transforms: dict[str, str] | None = None,
) -> ObfuscationReport:
    bl = resolve_blacklist(
        blacklist_path,
        use_pool=use_pool,
        pool_path=pool_path,
    )
    include_ref = bool(
        force_transforms and "encoding_deep" in force_transforms
    )
    all_rules = select_rules(
        bl,
        command,
        include_reference_only=include_ref,
    )

    payload = command
    transforms_applied: list[str] = []
    hints: list[str] = []
    references: list[str] = []
    defense: list[str] = []
    rules_applied: list[str] = []
    applied_groups: set[str] = set()
    keyword_chosen = False
    alternatives: list[str] = []

    preferred_transform = KEYWORD_STYLE_TO_TRANSFORM.get(prefer_keyword)

    for rule in all_rules:
        if _skip_rule(
            rule,
            prefix_ping=prefix_ping,
            prefer_keyword=prefer_keyword,
            applied_groups=applied_groups,
            keyword_chosen=keyword_chosen,
            force_transforms=force_transforms,
        ):
            if list_alternatives and rule.exclusive_group == "keyword_obf":
                alt = apply_transform(
                    rule.transform,
                    command,
                    bl,
                    injection_prefix=DEFAULT_CMD_INJECT_PREFIX,
                    url_encode=url_encode,
                )
                if alt.applied and alt.payload != command:
                    alternatives.append(alt.payload)
            continue

        sub_id = None
        if rule.exclusive_group == "cmd_substitute" and force_transforms:
            sub_id = force_transforms.get("cmd_substitute")
        result = apply_transform(
            rule.transform,
            payload,
            bl,
            injection_prefix=DEFAULT_CMD_INJECT_PREFIX,
            url_encode=url_encode,
            force_substitute_id=sub_id,
        )
        if not result.applied:
            continue

        payload = result.payload
        rules_applied.append(rule.id)
        transforms_applied.extend(result.applied)
        hints.extend(result.hints)
        references.extend(rule.references)
        defense.extend(rule.defense)

        if rule.exclusive_group:
            applied_groups.add(rule.exclusive_group)
        if rule.exclusive_group == "keyword_obf":
            keyword_chosen = True

    if list_alternatives and alternatives:
        alternatives = list(dict.fromkeys(alternatives))

    return ObfuscationReport(
        original=command,
        payload=payload,
        blacklist_summary=bl.summary(),
        rules_applied=rules_applied,
        transforms_applied=transforms_applied,
        references=list(dict.fromkeys(references)),
        defense=list(dict.fromkeys(defense)),
        hints=list(dict.fromkeys(hints)),
        alternatives=alternatives,
    )
