# Blacklist pool

Single source of truth: **`pool.yaml`** (v3 — chars, keywords, whitespace; see **`SOURCES.md`**)

Rules live in **`rules/*.yaml`** — each file lists **multiple** bypass variants.

It aggregates common command-injection filters seen in public write-ups and tools.  
**Inspiration** (PayloadsAllTheThings, Commix, Root-Me, …) is documented in the [main README](../README.md#inspiration), not in this file.

## CLI

```bash
python cantstopme.py -c "cat .passwd" -b examples/php_ping_filter.txt --ping --url-encode -n 10
python cantstopme.py -c "cat .passwd" -b examples/lab_subset.txt
python cantstopme.py --pool
```

## Custom overlay format (`-b`)

Same line syntax as before:

```text
char:;
keyword:cat
space
```

Use `-b file` alone for that file only; add `--use-pool` to merge with `pool.yaml`.
