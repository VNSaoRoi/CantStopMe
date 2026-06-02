# CantStopMe

**Educational** bash command obfuscation for **authorized labs** (Kali Linux).  
A single **filter pool** plus **bypass rules** helps red and blue teams study command-injection filters.

> Use only on systems you own or have **written permission** to test.

## Inspiration

Ideas and filter shapes are informed by public material (we do not ship their code):

- [PayloadsAllTheThings — Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
- [Commix — Filters Bypasses](https://github.com/commixproject/commix/wiki/Filters-Bypasses)
- Root-Me / community write-ups on ping-style filter bypass (e.g. newline `%0a`)

Local clones for study may live in `_reference/` (gitignored).

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

**Quick guide:** [USAGE.md](USAGE.md)

## Quick start

Run from project root via **`cantstopme.py`** (no install required if dependencies are installed):

```bash
python cantstopme.py -c "cat /etc/passwd" -b examples/php_ping_filter.txt --ping --url-encode -n 10
python cantstopme.py --explain -c "cat .passwd"
python cantstopme.py -c "cat .passwd" -b examples/lab_subset.txt --use-pool
```

Or after `pip install -e .`:

```bash
cantstopme -c "cat /etc/passwd" -b examples/php_ping_filter.txt --ping --url-encode
cantstopme -c "cat .passwd" -b examples/lab_subset.txt -v
cantstopme -c "whoami" -b examples/lab_subset.txt
```

## Layout

```text
cantstopme.py            # Main entry — python cantstopme.py ...
blacklist_pool/pool.yaml # One unified filter pool
rules/                   # YAML bypass rules + defense notes
cantstopme/              # Engine package
examples/                # Lab overlays (-b) + PHP_PING_LAB.md
docs/blue/               # Blue-team hardening notes
```

## Overlay format (`-b`)

```text
char:;
keyword:cat
space
```

With `-b` only: uses that file. Add `--use-pool` to merge with `pool.yaml`. Without `-b`: uses `pool.yaml` only.

## Publish to GitHub

From the project root (first time):

```bash
git init
git add .
git status   # confirm .venv/ and _reference/ are not listed
git commit -m "Initial release: CantStopMe obfuscation engine"
git branch -M main
git remote add origin https://github.com/VNSaoRoi/CantStopMe.git
git push -u origin main
```

Shipped in the repo: `cantstopme/`, `rules/`, `blacklist_pool/`, `examples/`, `USAGE.md`, `LICENSE`, `SECURITY.md`.  
Not shipped (`.gitignore`): `.venv/`, `_reference/`, `*.egg-info/`.

## License

MIT — see [LICENSE](LICENSE).
