"""
H4ACKBAR encoder pipeline.
Chainable. Every encoder is a pure function str→str.
"""

import urllib.parse
import base64
import random
from typing import Callable, List, Dict


# ── primitive encoders ──────────────────────────────────────

def enc_url(s: str) -> str:
    return urllib.parse.quote(s, safe="")

def enc_url_double(s: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")

def enc_url_all(s: str) -> str:
    return "".join(f"%{b:02X}" for b in s.encode("utf-8"))

def enc_hex_prefix(s: str) -> str:
    return "0x" + s.encode("utf-8").hex()

def enc_hex_raw(s: str) -> str:
    return s.encode("utf-8").hex()

def enc_hex_escaped(s: str) -> str:
    return "".join(f"\\x{b:02x}" for b in s.encode("utf-8"))

def enc_unicode(s: str) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in s)

def enc_base64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")

def enc_html_entities(s: str) -> str:
    return "".join(f"&#{ord(c)};" for c in s)

def enc_html_hex(s: str) -> str:
    return "".join(f"&#x{ord(c):x};" for c in s)

def enc_char_mysql(s: str) -> str:
    return "CHAR(" + ",".join(str(b) for b in s.encode("utf-8")) + ")"

def enc_chr_pg(s: str) -> str:
    return "||".join(f"CHR({b})" for b in s.encode("utf-8"))

def enc_concat_mssql(s: str) -> str:
    return "+".join(f"CHAR({b})" for b in s.encode("utf-8"))

def enc_case_toggle(s: str) -> str:
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s))

def enc_case_random(s: str) -> str:
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)

def enc_comment_inline(s: str) -> str:
    return s.replace(" ", "/**/")

def enc_comment_versioned(s: str) -> str:
    return s.replace(" ", "/*!50000*/")

def enc_null_byte(s: str) -> str:
    return s + "%00"

def enc_reverse(s: str) -> str:
    return s[::-1]

def enc_strip_spaces(s: str) -> str:
    return s.replace(" ", "")

def enc_utf16(s: str) -> str:
    return "".join(f"%u{ord(c):04x}" for c in s)


# ── registry ───────────────────────────────────────────────

ENCODERS: Dict[str, Callable[[str], str]] = {
    "url":               enc_url,
    "url_double":        enc_url_double,
    "url_all":           enc_url_all,
    "hex_0x":            enc_hex_prefix,
    "hex_raw":           enc_hex_raw,
    "hex_escaped":       enc_hex_escaped,
    "unicode_\\u":       enc_unicode,
    "utf16_%u":          enc_utf16,
    "base64":            enc_base64,
    "html_entities":     enc_html_entities,
    "html_hex":          enc_html_hex,
    "mysql_CHAR()":      enc_char_mysql,
    "pg_CHR||":          enc_chr_pg,
    "mssql_CHAR+":       enc_concat_mssql,
    "case_toggle":       enc_case_toggle,
    "case_random":       enc_case_random,
    "comment_inline":    enc_comment_inline,
    "comment_versioned": enc_comment_versioned,
    "null_byte":         enc_null_byte,
    "reverse":           enc_reverse,
    "strip_spaces":      enc_strip_spaces,
}


def apply_chain(payload: str, chain: List[str]) -> str:
    """
    Apply encoders left→right.
    chain=['hex_0x','url']  →  url( hex_0x( payload ) )
    """
    out = payload
    for name in chain:
        fn = ENCODERS.get(name)
        if fn is None:
            raise KeyError(f"unknown encoder: {name}")
        out = fn(out)
    return out


# ── hex grid ────────────────────────────────────────────────

def hex_grid(s: str, cols: int = 16) -> str:
    """Hexdump-style: offset | hex bytes | ascii sidebar."""
    data = s.encode("utf-8", errors="replace")
    lines = []
    for off in range(0, len(data), cols):
        chunk = data[off:off + cols]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(cols * 3 - 1)
        ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hexpart}  |{ascii_}|")
    return "\n".join(lines)
