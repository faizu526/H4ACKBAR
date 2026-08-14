# Encoders

All encoders are pure `str → str` functions. Chainable in any order.

| Name                | Effect                                         | Reversible |
|---------------------|------------------------------------------------|-----------:|
| `url`               | `urllib.parse.quote(s, safe="")`               | ✅         |
| `url_double`        | url-encode twice                               | ✅         |
| `url_all`           | %-encode every byte                            | ✅         |
| `hex_0x`            | `0x` + hex (MySQL/PG literal)                  | ✅         |
| `hex_raw`           | plain hex string                               | ✅         |
| `hex_escaped`       | `\xAB\xCD...`                                  | ✅         |
| `unicode_\u`        | `\uXXXX` per char                              | ✅         |
| `utf16_%u`          | IIS-style `%uXXXX`                             | ✅         |
| `base64`            | standard base64                                | ✅         |
| `html_entities`     | `&#NNN;`                                       | ✅         |
| `html_hex`          | `&#xNN;`                                       | ✅         |
| `mysql_CHAR()`      | `CHAR(65,66,...)`                              | ✅         |
| `pg_CHR\|\|`         | `CHR(65)\|\|CHR(66)...`                          | ✅         |
| `mssql_CHAR+`       | `CHAR(65)+CHAR(66)...`                         | ✅         |
| `case_toggle`       | alternating upper/lower                        | ❌         |
| `case_random`       | random upper/lower                             | ❌         |
| `comment_inline`    | space → `/**/`                                 | ❌         |
| `comment_versioned` | space → `/*!50000*/`                           | ❌         |
| `null_byte`         | append `%00`                                   | ❌         |
| `reverse`           | reverse string                                 | ✅         |
| `strip_spaces`      | remove all spaces                              | ❌         |

## Adding an encoder

```python
def enc_myenc(s: str) -> str:
    return "..."

ENCODERS["myenc"] = enc_myenc
```

Then add a test in `tests/test_encoders.py`.

## Chain semantics

`apply_chain(seed, ["a","b","c"])` computes `c(b(a(seed)))`.

## Hex grid

`hex_grid(s, cols=16)` produces classic hexdump:

```
00000000  27 20 4f 52 20 31 3d 31  2d 2d 20 2d              |' OR 1=1-- -|
```
