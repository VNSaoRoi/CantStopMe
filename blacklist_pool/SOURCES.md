# Reference sources for `pool.yaml` and `rules/`

| Source | URL | Used for |
|--------|-----|----------|
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection | Metachar, IFS, `%0a`, quote/slash bypass |
| HackTricks | https://book.hacktricks.xyz/pentesting-web/command-injection | Command substitution, `/dev/tcp`, blind |
| Commix | https://github.com/commixproject/commix | Tamper scripts (space2ifs, slash2env, rev, base64) |
| PortSwigger | https://portswigger.net/web-security/os-command-injection | Chaining `&&` `\|\|`, lab patterns |
| Awesome-WAF | https://github.com/0xInfection/Awesome-WAF | Blacklist / WAF fingerprint mindset |
| GTFOBins | https://gtfobins.github.io/ | Alternative binaries for `cat` / `ls` |
| RodricBr | https://github.com/RodricBr/Bash-Command-Injection | Bash `$((2#...))` obfuscation |
| dnsbin / Interactsh | PAT README | DNS exfil (`blind_dns` context) |
| exploit4040 ch53 | `_reference/exploit4040-Command-Injection` | Ping `%0a`, PHP filters |

Bump `version` in `pool.yaml` when adding new pool entries.
