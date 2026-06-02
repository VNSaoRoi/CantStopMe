"""ANSI terminal styling (stdout)."""

from __future__ import annotations

import sys

from cantstopme.engine.constants import DEFAULT_CMD_INJECT_PREFIX

# Prefix highlight: decoy IP only (1.1.1.1). %0a/newline = payload (green).
PREFIX_FG = "\033[96m"  # bright cyan
CMD_BODY_FG = "\033[92m"  # bright green
RESET = "\033[0m"

# Alert: white on red
ALERT_BG = "\033[41m"
ALERT_FG = "\033[97m"
ALERT_BOLD = "\033[1m"


def enable_windows_ansi() -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_ulong()
        kernel32.GetConsoleMode(handle, ctypes.byref(mode))
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def _is_tty(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty()


def payload_for_terminal(payload: str, *, url_encoded: bool = False) -> str:
    """
    Optional readable view for stderr variants.
    Never use for stdout — bash cannot execute literal %09 / %0b strings.
    """
    if not payload:
        return payload
    out = payload
    if url_encoded:
        for raw, visible in (("\v", "%0b"), ("\t", "%09"), ("\r", "%0d"), ("\n", "%0a")):
            out = out.replace(raw, visible)
    else:
        # Windows console: vertical tab only; keep real TAB for shell copy
        out = out.replace("\v", "\\v")
    return out


def split_cmd_inject_payload(payload: str, *, url_encode: bool) -> tuple[str, str]:
    """
    Return (decoy_ip_only, payload_body).
    %0a / newline are part of the real injection payload, not the decoy prefix.
    """
    if not payload.startswith(DEFAULT_CMD_INJECT_PREFIX):
        return "", payload
    ip = DEFAULT_CMD_INJECT_PREFIX
    rest = payload[len(ip) :]
    return ip, rest


def format_payload_output(
    payload: str,
    *,
    highlight_decoy: bool,
    url_encode: bool,
    use_color: bool | None = None,
) -> str:
    if use_color is None:
        use_color = _is_tty(sys.stdout)
    if not highlight_decoy or not use_color:
        return payload
    enable_windows_ansi()
    prefix, body = split_cmd_inject_payload(payload, url_encode=url_encode)
    if not prefix:
        return payload
    return f"{PREFIX_FG}{prefix}{RESET}{CMD_BODY_FG}{body}{RESET}"


def print_coverage_alert(message: str, *, stream=None) -> None:
    stream = stream or sys.stderr
    if not _is_tty(stream):
        print(message, file=stream)
        return
    enable_windows_ansi()
    print(f"{ALERT_BG}{ALERT_FG}{ALERT_BOLD} {message} {RESET}", file=stream)
