# Bypass rules

Grouped YAML files; each file contains **many** `rules:` entries.

| File | Topic |
|------|--------|
| `separators.yaml` | `%0a`, `%0d`, backslash-newline, `&&` |
| `whitespace.yaml` | IFS, tab, `+`, brace, redirection, ANSI-C |
| `slashes.yaml` | `${HOME:0:1}`, `${PATH%%u*}`, wildcards, hex path |
| `keywords.yaml` | quotes, `$@`, `\`, `${VAR}`, rev, globs |
| `alternatives.yaml` | swap blocked binary (`ls`→`echo *`, `cat`→`tac`, …) |
| `encoding.yaml` | `$(echo ...)`, hex paths, RodricBr bash_binary |
| `advanced.yaml` | tr/xxd slash, `$()`, `%0b`, base64 pipe, `&&` |

`exclusive_group`: only one rule per group applies per run.

`contexts` in YAML is documentation only (CLI does not filter by it).

`reference_only`: listed only as variants (e.g. `bash_binary_c`, `base64_wrap_command`).

References: [blacklist_pool/SOURCES.md](../blacklist_pool/SOURCES.md).
