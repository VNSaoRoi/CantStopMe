"""Generate ranked obfuscated payload variants (full cross-product per bypass group)."""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from pathlib import Path

from cantstopme.engine.blacklist import resolve_blacklist
from cantstopme.engine.command_alternatives import applicable_substitutes
from cantstopme.engine.constants import DEFAULT_TOP_PAYLOADS
from cantstopme.engine.obfuscator import CMD_INJECT_TRANSFORMS, ObfuscationReport, obfuscate
from cantstopme.engine.rules import KEYWORD_STYLE_TO_TRANSFORM, Rule, select_rules

_MAX_COMBO_ATTEMPTS = 200
_PRODUCT_GROUPS = ("whitespace", "slash", "keyword_obf", "cmd_separator")


@dataclass
class RankedPayload:
    payload: str
    label: str
    rules_applied: list[str] = field(default_factory=list)
    score: int = 0


def _score_payload(payload: str, report: ObfuscationReport, *, original: str) -> int:
    if payload == original:
        return 0
    score = len(report.rules_applied) * 10 + len(report.transforms_applied)
    if "${IFS}" in payload:
        score += 20
    if "%09" in payload or "%0b" in payload:
        score -= 18
    if "%20" in payload:
        score -= 15
    if "+" in payload and " " not in payload and "${IFS}" not in payload:
        score -= 12
    if "%%" in payload:
        score -= 8
    if "${HOME:0:1}" in payload:
        score += 4
    if "bash_binary_c" in report.rules_applied or payload.startswith("${0##"):
        score -= 80
    if "\t" in payload and "${IFS}" not in payload:
        score -= 6
    return score


def _collect_variant(
    *,
    command: str,
    seen: set[str],
    out: list[RankedPayload],
    report: ObfuscationReport,
    label: str,
) -> None:
    if report.payload in seen or report.payload == command:
        return
    seen.add(report.payload)
    out.append(
        RankedPayload(
            payload=report.payload,
            label=label,
            rules_applied=list(report.rules_applied),
            score=_score_payload(report.payload, report, original=command),
        )
    )


def _rules_by_group(matched: list[Rule], *, prefix_ping: bool) -> dict[str, list[Rule]]:
    by_group: dict[str, list[Rule]] = {}
    for rule in matched:
        if not rule.exclusive_group:
            continue
        if rule.transform in CMD_INJECT_TRANSFORMS and not prefix_ping:
            continue
        if rule.exclusive_group == "cmd_substitute":
            continue
        if rule.exclusive_group == "encoding_deep":
            continue
        by_group.setdefault(rule.exclusive_group, []).append(rule)
    return by_group


def _combo_label(force: dict[str, str]) -> str:
    if not force:
        return "primary"
    return "+".join(f"{g}={v}" for g, v in sorted(force.items()))


def _enumerate_force_combos(
    by_group: dict[str, list[Rule]],
    *,
    prefix_ping: bool,
) -> list[dict[str, str]]:
    """
    Full cross-product: one transform per group (whitespace x slash x keyword x …).
    Avoids single-group forces that silently reuse primary picks for other groups.
    """
    active_groups: list[str] = []
    choices_per_group: list[list[tuple[str, str]]] = []

    for group in _PRODUCT_GROUPS:
        if group == "cmd_separator" and not prefix_ping:
            continue
        rules = by_group.get(group)
        if not rules:
            continue
        active_groups.append(group)
        choices_per_group.append([(group, r.transform) for r in rules])

    if not active_groups:
        return []

    combos: list[dict[str, str]] = []
    seen: set[frozenset[tuple[str, str]]] = set()

    for picks in itertools.product(*choices_per_group):
        if len(combos) >= _MAX_COMBO_ATTEMPTS:
            break
        force = {g: transform for g, transform in picks}
        key = frozenset(force.items())
        if key in seen:
            continue
        seen.add(key)
        combos.append(force)

    return combos


def generate_top_payloads(
    command: str,
    *,
    blacklist_path: Path | None = None,
    use_pool: bool = True,
    url_encode: bool = False,
    prefix_ping: bool = False,
    prefer_keyword: str = "single_quotes",
    limit: int = DEFAULT_TOP_PAYLOADS,
) -> list[RankedPayload]:
    """Return up to `limit` unique payloads (cross-product of group-level bypasses)."""
    if limit < 1:
        return []

    bl = resolve_blacklist(blacklist_path, use_pool=use_pool)
    matched = select_rules(bl, command)
    by_group = _rules_by_group(matched, prefix_ping=prefix_ping)

    ranked: list[RankedPayload] = []
    seen: set[str] = {command}

    base_kw = dict(
        blacklist_path=blacklist_path,
        use_pool=use_pool,
        url_encode=url_encode,
        prefer_keyword=prefer_keyword,
        prefix_ping=prefix_ping,
    )

    primary = obfuscate(command, **base_kw)
    _collect_variant(
        command=command,
        seen=seen,
        out=ranked,
        report=primary,
        label="primary",
    )

    for force in _enumerate_force_combos(by_group, prefix_ping=prefix_ping):
        report = obfuscate(command, force_transforms=force, **base_kw)
        _collect_variant(
            command=command,
            seen=seen,
            out=ranked,
            report=report,
            label=_combo_label(force),
        )

    for alt in applicable_substitutes(command, bl):
        if len(ranked) >= limit * 4:
            break
        report = obfuscate(
            command,
            force_transforms={"cmd_substitute": alt.id},
            **base_kw,
        )
        _collect_variant(
            command=command,
            seen=seen,
            out=ranked,
            report=report,
            label=f"cmd_substitute={alt.id}",
        )

    bash_rules = [
        r
        for r in select_rules(bl, command, include_reference_only=True)
        if r.transform == "bash_binary_c"
    ]
    if bash_rules and len(ranked) < limit:
        report = obfuscate(
            command,
            force_transforms={"encoding_deep": "bash_binary_c"},
            **base_kw,
        )
        _collect_variant(
            command=command,
            seen=seen,
            out=ranked,
            report=report,
            label="encoding_deep=bash_binary_c",
        )

    ranked.sort(key=lambda r: r.score, reverse=True)
    primary_entry = next((r for r in ranked if r.label == "primary"), ranked[0])
    rest = [r for r in ranked if r.label != "primary" and r.payload != primary_entry.payload]
    return ([primary_entry] + rest)[:limit]
