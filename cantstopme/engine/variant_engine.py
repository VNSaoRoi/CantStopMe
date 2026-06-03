"""Generate ranked obfuscated payload variants."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from cantstopme.engine.blacklist import resolve_blacklist
from cantstopme.engine.command_alternatives import applicable_substitutes
from cantstopme.engine.constants import DEFAULT_TOP_PAYLOADS
from cantstopme.engine.obfuscator import CMD_INJECT_TRANSFORMS, ObfuscationReport, obfuscate
from cantstopme.engine.rules import KEYWORD_STYLE_TO_TRANSFORM, select_rules


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
    """Return up to `limit` unique payloads, best first."""
    if limit < 1:
        return []

    primary = obfuscate(
        command,
        blacklist_path=blacklist_path,
        use_pool=use_pool,
        url_encode=url_encode,
        prefer_keyword=prefer_keyword,
        prefix_ping=prefix_ping,
    )

    ranked: list[RankedPayload] = [
        RankedPayload(
            payload=primary.payload,
            label="primary",
            rules_applied=list(primary.rules_applied),
            score=_score_payload(primary.payload, primary, original=command),
        )
    ]
    seen: set[str] = {primary.payload, command}

    bl = resolve_blacklist(blacklist_path, use_pool=use_pool)
    matched = select_rules(bl, command)

    by_group: dict[str, list] = {}
    for rule in matched:
        if rule.exclusive_group:
            by_group.setdefault(rule.exclusive_group, []).append(rule)

    for alt in applicable_substitutes(command, bl):
        if len(ranked) >= limit * 3:
            break
        report = obfuscate(
            command,
            blacklist_path=blacklist_path,
            use_pool=use_pool,
            url_encode=url_encode,
            prefer_keyword=prefer_keyword,
            prefix_ping=prefix_ping,
            force_transforms={"cmd_substitute": alt.id},
        )
        _collect_variant(
            command=command,
            seen=seen,
            out=ranked,
            report=report,
            label=f"cmd_substitute={alt.id}",
        )

    for group, rules in sorted(by_group.items()):
        for rule in rules:
            if len(ranked) >= limit * 3:
                break
            if rule.transform in CMD_INJECT_TRANSFORMS and not prefix_ping:
                continue
            if group in ("keyword_obf", "cmd_substitute"):
                continue
            report = obfuscate(
                command,
                blacklist_path=blacklist_path,
                use_pool=use_pool,
                url_encode=url_encode,
                prefer_keyword=prefer_keyword,
                prefix_ping=prefix_ping,
                force_transforms={group: rule.transform},
            )
            _collect_variant(
                command=command,
                seen=seen,
                out=ranked,
                report=report,
                label=f"{group}={rule.id}",
            )

    if any(r.exclusive_group == "keyword_obf" for r in matched):
        for style, transform in KEYWORD_STYLE_TO_TRANSFORM.items():
            if len(ranked) >= limit * 3:
                break
            if style == prefer_keyword:
                continue
            report = obfuscate(
                command,
                blacklist_path=blacklist_path,
                use_pool=use_pool,
                url_encode=url_encode,
                prefer_keyword=style,
                prefix_ping=prefix_ping,
                force_transforms={"keyword_obf": transform},
            )
            _collect_variant(
                command=command,
                seen=seen,
                out=ranked,
                report=report,
                label=f"keyword_obf={style}",
            )

    bash_rules = [
        r
        for r in select_rules(bl, command, include_reference_only=True)
        if r.transform == "bash_binary_c"
    ]
    if bash_rules:
        report = obfuscate(
            command,
            blacklist_path=blacklist_path,
            use_pool=use_pool,
            url_encode=url_encode,
            prefer_keyword=prefer_keyword,
            prefix_ping=prefix_ping,
            force_transforms={"encoding_deep": "bash_binary_c"},
        )
        _collect_variant(
            command=command,
            seen=seen,
            out=ranked,
            report=report,
            label="encoding_deep=bash_binary_c",
        )

    ranked.sort(key=lambda r: r.score, reverse=True)
    # Keep stable order for ties: primary first among equal scores
    prim = ranked[0]
    rest = [r for r in ranked[1:] if r.payload != prim.payload]
    ordered = [prim] + rest
    return ordered[:limit]
