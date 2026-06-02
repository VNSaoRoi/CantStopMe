# Blue team — detection & hardening

When CantStopMe reports `defense` on a rule, treat it as a starting point:

1. **Allowlist** input (e.g. `FILTER_VALIDATE_IP` for ping parameters).
2. **Avoid shells** — use `escapeshellarg()` + fixed binary, or no shell at all.
3. **Reject** `%0a`, `%0d`, `${IFS}`, and nested `${...}` in untrusted fields.
4. **Log** full command lines (auditd / SIEM) — obfuscation often leaves recognizable patterns.
5. **Do not rely** on keyword blacklists alone (`cat`, `whoami`, …).

See matching rule YAML under `rules/` for per-technique notes.
