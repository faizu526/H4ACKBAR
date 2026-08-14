"""
H4ACKBAR fingerprinter.
Passive detection of web framework + backing DBMS from:
  - response headers (Server, X-Powered-By, X-AspNet-Version, ...)
  - cookie names (PHPSESSID, JSESSIONID, ASPSESSIONID, laravel_session, ...)
  - HTML markers (meta generator, WordPress paths, Django debug, ...)
  - error string signatures (per-DBMS regex library)
"""

import re
from dataclasses import dataclass, field

# ── DBMS error signatures ───────────────────────────────────
# Regex → DBMS. Multi-hit weighting done by caller.
DBMS_ERROR_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # MySQL / MariaDB
    (re.compile(r"You have an error in your SQL syntax.*?MySQL", re.I),          "mysql",      "syntax error banner"),
    (re.compile(r"Warning.*?mysqli?_(?:query|fetch|num_rows|connect)", re.I),    "mysql",      "mysqli warning"),
    (re.compile(r"MySQLSyntaxErrorException", re.I),                             "mysql",      "JDBC MySQL"),
    (re.compile(r"MariaDB server version", re.I),                                "mariadb",    "MariaDB banner"),
    (re.compile(r"valid MySQL result", re.I),                                    "mysql",      ""),
    (re.compile(r"check the manual that corresponds to your (?:MySQL|MariaDB)", re.I), "mysql", ""),

    # PostgreSQL
    (re.compile(r"PostgreSQL.*?ERROR", re.I | re.S),                             "postgresql", "PG error"),
    (re.compile(r"pg_query\(\)|pg_exec\(\)", re.I),                              "postgresql", "PHP pg_ call"),
    (re.compile(r"PSQLException", re.I),                                         "postgresql", "JDBC PG"),
    (re.compile(r"invalid input syntax for.*?integer", re.I),                    "postgresql", "PG cast err"),

    # MSSQL
    (re.compile(r"Microsoft SQL Server", re.I),                                  "mssql",      "MSSQL banner"),
    (re.compile(r"SQLServer JDBC Driver", re.I),                                 "mssql",      ""),
    (re.compile(r"System\.Data\.SqlClient\.SqlException", re.I),                 "mssql",      ".NET SqlClient"),
    (re.compile(r"Unclosed quotation mark after the character string", re.I),    "mssql",      "MSSQL quote"),
    (re.compile(r"OLE DB.*?SQL Server", re.I),                                   "mssql",      ""),

    # Oracle
    (re.compile(r"ORA-\d{5}"),                                                   "oracle",     "ORA-nnnnn"),
    (re.compile(r"Oracle error", re.I),                                          "oracle",     ""),
    (re.compile(r"oci_(?:parse|execute|fetch)", re.I),                           "oracle",     "PHP OCI"),
    (re.compile(r"OracleDriver", re.I),                                          "oracle",     "JDBC Oracle"),

    # SQLite
    (re.compile(r"SQLite/JDBCDriver", re.I),                                     "sqlite",     ""),
    (re.compile(r"SQLite\.Exception", re.I),                                     "sqlite",     ""),
    (re.compile(r"sqlite3\.OperationalError", re.I),                             "sqlite",     "Python sqlite3"),
    (re.compile(r"near \".+?\": syntax error", re.I),                            "sqlite",     "SQLite parser"),

    # Generic
    (re.compile(r"ODBC.*?error", re.I),                                          "odbc",       ""),
    (re.compile(r"JDBC.*?SQLException", re.I),                                   "jdbc",       ""),
]


# ── framework signatures ────────────────────────────────────
FRAMEWORK_HEADER_HINTS: dict[str, list[tuple[str, str]]] = {
    "server":         [("nginx","nginx"),("apache","apache"),("iis","iis"),
                       ("cloudflare","cloudflare"),("gunicorn","gunicorn"),
                       ("werkzeug","werkzeug/flask"),("uvicorn","uvicorn/asgi"),
                       ("caddy","caddy"),("litespeed","litespeed")],
    "x-powered-by":   [("php","php"),("asp.net","asp.net"),("express","express/node"),
                       ("next.js","nextjs"),("rails","rails")],
    "x-aspnet-version":[("","asp.net")],
    "x-drupal-cache": [("","drupal")],
    "x-generator":    [("drupal","drupal"),("wordpress","wordpress")],
}

FRAMEWORK_COOKIE_HINTS: dict[str, str] = {
    "PHPSESSID":       "php",
    "JSESSIONID":      "java",
    "ASP.NET_SessionId":"asp.net",
    "ASPSESSIONID":    "asp",
    "laravel_session": "laravel/php",
    "ci_session":      "codeigniter/php",
    "symfony":         "symfony/php",
    "connect.sid":     "express/node",
    "sessionid":       "django/python",
    "csrftoken":       "django/python",
    "_rails_session":  "rails",
    "cake":            "cakephp",
    "wordpress_logged_in": "wordpress",
    "wp-settings":     "wordpress",
    "next-auth.session-token":"nextjs",
}

FRAMEWORK_HTML_HINTS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"<meta[^>]+generator[^>]+WordPress",       re.I), "wordpress"),
    (re.compile(r"<meta[^>]+generator[^>]+Drupal",          re.I), "drupal"),
    (re.compile(r"<meta[^>]+generator[^>]+Joomla",          re.I), "joomla"),
    (re.compile(r"/wp-content/|/wp-includes/",              re.I), "wordpress"),
    (re.compile(r"Powered by <a[^>]*>Laravel",              re.I), "laravel"),
    (re.compile(r"csrfmiddlewaretoken",                     re.I), "django"),
    (re.compile(r"__NEXT_DATA__",                           re.I), "nextjs"),
    (re.compile(r"ng-version=",                             re.I), "angular"),
    (re.compile(r"data-reactroot|__NEXT_DATA__|_reactRootContainer", re.I), "react"),
    (re.compile(r"__NUXT__",                                re.I), "nuxt"),
    (re.compile(r"window\.__vue_app__",                     re.I), "vue"),
    (re.compile(r"content=\"Ruby on Rails",                 re.I), "rails"),
    (re.compile(r"X-Runtime.*?Rails",                       re.I), "rails"),
]


@dataclass
class Fingerprint:
    frameworks: list[str] = field(default_factory=list)
    dbms:       list[str] = field(default_factory=list)
    server:     str | None = None
    evidence:   list[str] = field(default_factory=list)

    def add_fw(self, name: str, why: str):
        if name and name not in self.frameworks:
            self.frameworks.append(name)
            self.evidence.append(f"framework={name}  ← {why}")

    def add_dbms(self, name: str, why: str):
        if name and name not in self.dbms:
            self.dbms.append(name)
            self.evidence.append(f"dbms={name}  ← {why}")

    def summary(self) -> str:
        fw = ", ".join(self.frameworks) or "unknown"
        db = ", ".join(self.dbms)       or "unknown"
        sv = self.server               or "unknown"
        return f"server={sv} | framework={fw} | dbms={db}"


def fingerprint_headers(headers: dict[str, str], fp: Fingerprint) -> None:
    lower = {k.lower(): v for k, v in headers.items()}
    fp.server = lower.get("server")
    for hdr, hints in FRAMEWORK_HEADER_HINTS.items():
        val = lower.get(hdr, "")
        vl = val.lower()
        for needle, name in hints:
            if needle == "" and hdr in lower:
                fp.add_fw(name, f"header {hdr} present")
            elif needle and needle in vl:
                fp.add_fw(name, f"header {hdr}={val}")


def fingerprint_cookies(cookies: dict[str, str], fp: Fingerprint) -> None:
    for name in cookies:
        # exact + prefix match
        for pattern, fw in FRAMEWORK_COOKIE_HINTS.items():
            if name == pattern or name.lower().startswith(pattern.lower()):
                fp.add_fw(fw, f"cookie {name}")
                break


def fingerprint_html(html: str, fp: Fingerprint) -> None:
    if not html:
        return
    for pat, name in FRAMEWORK_HTML_HINTS:
        if pat.search(html):
            fp.add_fw(name, f"html pattern /{pat.pattern[:40]}/")


def fingerprint_dbms_errors(body: str, fp: Fingerprint) -> list[tuple[str, str]]:
    """Return list of (dbms, matched_snippet_short)."""
    hits: list[tuple[str, str]] = []
    if not body:
        return hits
    for pat, dbms, note in DBMS_ERROR_PATTERNS:
        m = pat.search(body)
        if m:
            snippet = m.group(0)[:120]
            fp.add_dbms(dbms, note or snippet)
            hits.append((dbms, snippet))
    return hits


def fingerprint_response(headers: dict[str, str],
                         cookies: dict[str, str],
                         body: str) -> Fingerprint:
    fp = Fingerprint()
    fingerprint_headers(headers, fp)
    fingerprint_cookies(cookies, fp)
    fingerprint_html(body, fp)
    fingerprint_dbms_errors(body, fp)
    return fp
