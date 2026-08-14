# Payload Catalog

H4ACKBAR ships **80+ curated seed payloads** across 9 SQLi families.

| Category      | Purpose                                            | Count |
|---------------|----------------------------------------------------|------:|
| `auth`        | Auth-bypass tautologies                            | 13    |
| `union`       | Column-count + data-extract via UNION SELECT       | ~50   |
| `blind_bool`  | Boolean inference (TRUE/FALSE differential)        | 7     |
| `blind_time`  | Time-based inference (SLEEP, WAITFOR, pg_sleep)    | 8     |
| `error`       | Force data into error strings (extractvalue, etc.) | 6     |
| `stacked`     | Multi-statement (`;` chained)                      | 4     |
| `oob`         | Out-of-band exfil (DNS, SMB, HTTP)                 | 4     |
| `self_ref`    | Recursive / self-joining constructs                | 5     |
| `waf`         | Case/comment/encoding obfuscation seeds            | 9     |

## DBMS Coverage

Every `blind_time` and most `union` payloads carry a DBMS tag:

- **MySQL / MariaDB** — SLEEP, BENCHMARK, information_schema, `0x` literals, CHAR()
- **PostgreSQL**       — pg_sleep, CHR||, version(), current_database()
- **MSSQL**            — WAITFOR DELAY, sysobjects, @@version, xp_cmdshell
- **Oracle**           — DBMS_LOCK.SLEEP, all_tables, v$version, UTL_HTTP
- **SQLite**           — sqlite_master, sqlite_version, heavy-LIKE stall

## Provenance

All payloads are **public-domain SQLi patterns** documented across:
- OWASP Testing Guide
- PortSwigger Web Security Academy
- SQLi cheat sheets (pentestmonkey, netsparker archives)

No zero-days. No vendor-specific bypasses.

## Payload Struct

```python
@dataclass
class Payload:
    category: str        # family key
    label:    str        # short human label
    payload:  str        # raw seed string
    notes:    str = ""   # 1-line context
    tags:     list = []  # optional filters
```
