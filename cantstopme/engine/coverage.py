"""Rule coverage gaps and bypass-variant statistics."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import yaml

from cantstopme.paths import POOL_DIR
from cantstopme.engine.blacklist import (
    Blacklist,
    load_blacklist_file,
    load_default_pool,
)
from cantstopme.engine.rules import _command_tokens, load_rules, select_rules

PENDING_FILE = POOL_DIR / "pending_coverage.yaml"
PROBE_COMMAND = "cat .passwd"


def _bl_char(ch: str) -> Blacklist:
    bl = Blacklist()
    bl.chars.add(ch)
    return bl


def _bl_token(token: str) -> Blacklist:
    bl = Blacklist()
    bl.tokens.add(token)
    return bl


def _bl_keyword(kw: str) -> Blacklist:
    bl = Blacklist()
    bl.keywords.add(kw.lower())
    return bl


def _rule_count(bl: Blacklist, command: str = PROBE_COMMAND) -> int:
    return len(select_rules(bl, command))


def filter_key(kind: str, value: str) -> str:
    return f"{kind}:{value}"


def _keyword_probe(kw: str, command: str) -> str:
    """Use the user command only when kw is its own token, not a substring (e.g. cp in TCP)."""
    tokens = [t.lower() for t in _command_tokens(command)]
    if kw.lower() in tokens:
        return command
    return f"{kw} .passwd"


def find_uncovered(bl: Blacklist, command: str = PROBE_COMMAND) -> list[dict]:
    """Filters in bl with zero matching rules."""
    gaps: list[dict] = []

    for ch in sorted(bl.chars):
        if _rule_count(_bl_char(ch), command) == 0:
            gaps.append({"kind": "char", "value": ch})

    for tok in sorted(bl.tokens):
        if _rule_count(_bl_token(tok), command) == 0:
            gaps.append({"kind": "token", "value": tok})

    for kw in sorted(bl.keywords):
        probe = _keyword_probe(kw, command)
        if _rule_count(_bl_keyword(kw), probe) == 0:
            # Substring filters (PHP strpos lists): also check user command
            if probe != command and _rule_count(_bl_keyword(kw), command) > 0:
                continue
            gaps.append({"kind": "keyword", "value": kw})

    return gaps


def prune_resolved_pending(command: str = PROBE_COMMAND) -> int:
    """Drop pending_coverage entries that now have matching rules."""
    data = _load_pending()
    entries = data.get("entries") or []
    kept: list[dict] = []
    removed = 0
    for entry in entries:
        kind, value = entry["kind"], entry["value"]
        if kind == "char":
            bl = _bl_char(value)
        elif kind == "token":
            bl = _bl_token(value)
        elif kind == "keyword":
            bl = _bl_keyword(value)
        else:
            kept.append(entry)
            continue
        if find_uncovered(bl, command):
            kept.append(entry)
        else:
            removed += 1
    if removed:
        data["entries"] = kept
        _save_pending(data)
    return removed


def _load_pending() -> dict:
    if not PENDING_FILE.is_file():
        return {"version": 1, "entries": []}
    data = yaml.safe_load(PENDING_FILE.read_text(encoding="utf-8")) or {}
    if "entries" not in data:
        data["entries"] = []
    return data


def _save_pending(data: dict) -> None:
    PENDING_FILE.parent.mkdir(parents=True, exist_ok=True)
    PENDING_FILE.write_text(
        yaml.dump(data, allow_unicode=True, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )


def record_pending_gaps(
    gaps: list[dict],
    *,
    source: str,
) -> list[dict]:
    """Append new gaps to pending_coverage.yaml; return newly added."""
    if not gaps:
        return []
    data = _load_pending()
    known = {filter_key(e["kind"], e["value"]) for e in data["entries"]}
    added: list[dict] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for g in gaps:
        key = filter_key(g["kind"], g["value"])
        if key in known:
            continue
        entry = {
            "kind": g["kind"],
            "value": g["value"],
            "first_seen": now,
            "source": source,
        }
        data["entries"].append(entry)
        known.add(key)
        added.append(entry)
    if added:
        _save_pending(data)
    return added


def overlay_only_blacklist(overlay_path: Path) -> Blacklist:
    return load_blacklist_file(overlay_path)


def overlay_novel_vs_pool(overlay_path: Path) -> Blacklist:
    """Items present in -b but not in default pool.yaml."""
    overlay = load_blacklist_file(overlay_path)
    pool = load_default_pool()
    novel = Blacklist()
    novel.chars = overlay.chars - pool.chars
    novel.keywords = overlay.keywords - pool.keywords
    novel.tokens = overlay.tokens - pool.tokens
    return novel


def process_blacklist_file_overlay(overlay_path: Path, command: str) -> tuple[list[dict], list[dict]]:
    """
    When -b is set: find uncovered filters and novel pool entries.
    Returns (all_gaps_for_alert, newly_recorded).
    """
    bl_overlay = overlay_only_blacklist(overlay_path)
    gaps = find_uncovered(bl_overlay, command)
    novel = overlay_novel_vs_pool(overlay_path)
    for g in find_uncovered(novel, command):
        key = filter_key(g["kind"], g["value"])
        if not any(filter_key(x["kind"], x["value"]) == key for x in gaps):
            gaps.append(g)
    added = record_pending_gaps(gaps, source=str(overlay_path))
    prune_resolved_pending(command)
    return gaps, added


def pending_summary() -> tuple[int, list[dict]]:
    data = _load_pending()
    entries = data.get("entries") or []
    return len(entries), entries


def variant_count_for_bl(bl: Blacklist, command: str = PROBE_COMMAND) -> int:
    """Distinct applicable rules (bypass variants) for this filter set."""
    return len(select_rules(bl, command))


def variant_count_exclusive_groups(bl: Blacklist, command: str = PROBE_COMMAND) -> int:
    """
    Practical bypass slots: one per exclusive_group (engine picks one rule/group),
    plus each rule without a group counts separately.
    """
    rules = select_rules(bl, command)
    groups: set[str] = set()
    solo = 0
    for r in rules:
        if r.exclusive_group:
            groups.add(r.exclusive_group)
        else:
            solo += 1
    return len(groups) + solo


def per_filter_variant_distribution(
    bl: Blacklist | None = None,
    command: str = PROBE_COMMAND,
) -> dict[int, int]:
    """
    For each atomic filter in pool (or bl), count how many rules apply.
    Returns histogram: {1: n_filters_with_1_rule, 2: n_with_2, ...}
    """
    base = bl or load_default_pool()
    counts: list[int] = []

    for ch in base.chars:
        counts.append(variant_count_for_bl(_bl_char(ch), command))

    for tok in base.tokens:
        counts.append(variant_count_for_bl(_bl_token(tok), command))

    for kw in base.keywords:
        counts.append(variant_count_for_bl(_bl_keyword(kw), f"{kw} .passwd"))

    hist: dict[int, int] = Counter(counts)
    return dict(sorted(hist.items()))


def per_filter_exclusive_distribution(
    bl: Blacklist | None = None,
    command: str = PROBE_COMMAND,
) -> dict[int, int]:
    """Histogram by exclusive_group slots (closer to one obfuscation run)."""
    base = bl or load_default_pool()
    counts: list[int] = []

    for ch in base.chars:
        counts.append(variant_count_exclusive_groups(_bl_char(ch), command))

    for tok in base.tokens:
        counts.append(variant_count_exclusive_groups(_bl_token(tok), command))

    for kw in base.keywords:
        counts.append(
            variant_count_exclusive_groups(_bl_keyword(kw), f"{kw} .passwd")
        )

    return dict(sorted(Counter(counts).items()))


def per_exclusive_group_stats() -> dict[str, int]:
    """How many rule variants exist per exclusive_group (theoretical max)."""
    groups: dict[str, int] = defaultdict(int)
    ungrouped = 0
    for rule in load_rules():
        if rule.exclusive_group:
            groups[rule.exclusive_group] += 1
        else:
            ungrouped += 1
    if ungrouped:
        groups["_none"] = ungrouped
    return dict(groups)


def category_rule_counts() -> dict[str, int]:
    by_cat: dict[str, int] = defaultdict(int)
    for rule in load_rules():
        by_cat[rule.category or "unknown"] += 1
    return dict(by_cat)


def _format_histogram(hist: dict[int, int], *, title: str) -> list[str]:
    lines = [title]
    for n_ways, n_filters in sorted(hist.items()):
        word = "way" if n_ways == 1 else "ways"
        lines.append(f"  {n_filters} pat -> {n_ways} {word}")
    if hist.get(0):
        lines.append(f"  ({hist[0]} pat with no rule — add coverage)")
    return lines


def format_variant_report() -> str:
    hist_rules = per_filter_variant_distribution()
    hist_slots = per_filter_exclusive_distribution()
    groups = per_exclusive_group_stats()
    cats = category_rule_counts()
    base = load_default_pool()
    n_pat = len(base.chars) + len(base.tokens) + len(base.keywords)
    total_rules = len(load_rules())
    lines = [
        f"Total patterns in pool.yaml: {n_pat} "
        f"({len(base.chars)} char, {len(base.tokens)} token, {len(base.keywords)} keyword)",
        f"Total rules in engine: {total_rules}",
        "",
        "Rules per YAML file:",
    ]
    for cat, n in sorted(cats.items()):
        lines.append(f"  {cat}: {n}")
    lines.append("")
    lines.append("Max rules per exclusive_group (one picked per run):")
    for g, n in sorted(groups.items()):
        lines.append(f"  {g}: {n} rule")
    lines.extend(
        _format_histogram(
            hist_slots,
            title=(
                "\nPatterns by bypass group slots (exclusive_group) — "
                "closest to one run / --keyword-style:"
            ),
        )
    )
    lines.extend(
        _format_histogram(
            hist_rules,
            title=(
                "\nPatterns by matching rule count (all YAML rules; "
                "keyword * counts ~7-8 rules):"
            ),
        )
    )
    return "\n".join(lines)
