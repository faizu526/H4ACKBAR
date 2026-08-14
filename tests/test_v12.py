"""
H4ACKBAR v1.2.0 — regression tests.

Offline. No network. Uses monkeypatched sender + fake responses.
Run with:  python -m pytest tests/test_v12.py -v
    or:    python tests/test_v12.py
"""

import pathlib
import sys
import traceback
import types

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

# Provide a stub PyQt6 module tree BEFORE any h4ackbar import happens,
# because analyzer_v12 imports QtCore.QThread even if we don't touch the UI.
if "PyQt6" not in sys.modules:
    q = types.ModuleType("PyQt6")
    qcore = types.ModuleType("PyQt6.QtCore")
    class _Sig:
        def __init__(self, *a, **kw): pass
        def connect(self, *a, **kw): pass
        def emit(self, *a, **kw): pass
    qcore.pyqtSignal = lambda *a, **kw: _Sig()
    class _QThread:
        def __init__(self, *a, **kw): pass
        def start(self): self.run()
        def run(self): pass
    qcore.QThread = _QThread
    qcore.Qt = types.SimpleNamespace()
    q.QtCore = qcore
    sys.modules["PyQt6"] = q
    sys.modules["PyQt6.QtCore"] = qcore

from h4ackbar import detector_deep, extractor, sender
from h4ackbar.detector_deep import DeepFinding, analyze_param_deep
from h4ackbar.extractor import (
    ExtractionRefused,
    _assert_readonly,
    _expected_token,
    _quote,
    deep_extract,
)
from h4ackbar.sender import SendResult
from h4ackbar.strength import compute_strength
from h4ackbar.waf import detect as waf_detect


# ── fake sender scenarios ───────────────────────────────────
class FakeServer:
    """
    A programmable fake HTTP server.
    Attach a handler(url, method, param, payload, inject_in, headers) → SendResult.
    """
    def __init__(self):
        self.handler = None
        self.calls = []

    def __call__(self, url, method, payload, param,
                 inject_in="query", headers=None, timeout=15.0, verify_tls=True):
        self.calls.append(dict(url=url, method=method, payload=payload,
                               param=param, inject_in=inject_in,
                               headers=dict(headers) if headers else None))
        if self.handler is None:
            return SendResult(200, 100, 100, {}, "ok baseline")
        return self.handler(url, method, param, payload, inject_in, headers)


# ── helpers ────────────────────────────────────────────────
def install_fake(fake: FakeServer):
    # Patch sender.send in every module that imported it directly.
    sender.send = fake
    detector_deep.send = fake
    extractor.send = fake


PASS = 0
FAIL = 0
def check(cond, name):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  \033[32m✓\033[0m {name}")
    else:
        FAIL += 1
        print(f"  \033[31m✗\033[0m {name}")


# ── T01: baseline-only, no signals ─────────────────────────
def test_baseline_no_signals():
    print("\n[T01] baseline only → no signals")
    fake = FakeServer()
    fake.handler = lambda *a, **kw: SendResult(200, 100, 500, {}, "static content")
    install_fake(fake)
    f = analyze_param_deep("http://x.local/", "GET", "id",
                           rate_limit_ms=0, max_requests=30)
    compute_strength(f)
    check(f.signals == [], "no signals fired")
    check(f.strength == 0.0, f"strength=0 (got {f.strength})")
    check(f.strength_grade == "none", f"grade=none (got {f.strength_grade})")


# ── T02: error-based DBMS leak ─────────────────────────────
def test_error_signal():
    print("\n[T02] error probe → E signal + DBMS guess")
    fake = FakeServer()
    def h(url, method, param, payload, inject_in, headers):
        if "'" in payload or "\"" in payload:
            return SendResult(500, 100, 800, {},
                "You have an error in your SQL syntax; check the manual "
                "that corresponds to your MySQL server version for the right syntax")
        return SendResult(200, 100, 500, {}, "ok")
    fake.handler = h
    install_fake(fake)
    f = analyze_param_deep("http://x.local/", "GET", "id",
                           rate_limit_ms=0, max_requests=30)
    compute_strength(f)
    check("E" in f.signals, "E signal present")
    check("mysql" in f.dbms_guess, "mysql detected")
    check(f.strength > 0.30, f"strength>0.30 (got {f.strength})")
    check(f.strength_grade in ("weak", "moderate", "strong"),
          f"grade weak+ (got {f.strength_grade})")


# ── T03: time-blind confirmed ──────────────────────────────
def test_time_signal():
    print("\n[T03] time probe (with jitter defeat) → T signal")
    fake = FakeServer()
    def h(url, method, param, payload, inject_in, headers):
        # simulate: SLEEP(4) causes 4200ms; else 100ms
        if "SLEEP(4)" in payload.upper() or "PG_SLEEP(4)" in payload.upper():
            return SendResult(200, 4200, 500, {}, "ok")
        return SendResult(200, 100, 500, {}, "ok")
    fake.handler = h
    install_fake(fake)
    f = analyze_param_deep("http://x.local/", "GET", "id",
                           rate_limit_ms=0, max_requests=30)
    compute_strength(f)
    check("T" in f.signals, "T signal present")
    check(f.signal_meta["T"]["delay_s"] > 3.0, "delay > threshold")
    check(f.strength_grade in ("weak", "moderate", "strong", "critical"),
          f"time yields >=weak grade (got {f.strength_grade})")


# ── T04: boolean-blind differential ────────────────────────
def test_boolean_signal():
    print("\n[T04] true≈baseline, false differs → B signal")
    fake = FakeServer()
    base_body = "welcome " * 80
    def h(url, method, param, payload, inject_in, headers):
        if "1'='2" in payload:      # FALSE
            return SendResult(200, 100, 200, {}, "no results here found empty")
        # TRUE and baseline both return the welcome body
        return SendResult(200, 100, len(base_body), {}, base_body)
    fake.handler = h
    install_fake(fake)
    f = analyze_param_deep("http://x.local/", "GET", "id",
                           rate_limit_ms=0, max_requests=30)
    compute_strength(f)
    check("B" in f.signals, "B signal present")
    check(f.strength > 0.20, f"strength>0.20 (got {f.strength})")


# ── T05: multi-signal → strength combines ──────────────────
def test_strength_combines():
    print("\n[T05] E+T+B present → moderate/strong grade")
    fake = FakeServer()
    base = "welcome " * 100
    def h(url, method, param, payload, inject_in, headers):
        if "SLEEP(4)" in payload.upper():
            return SendResult(200, 4300, 500, {}, "ok")
        if "1'='2" in payload:
            return SendResult(200, 100, 200, {}, "empty results")
        if payload in ("'", "\"", "')", "\";", "' AND CAST('x' AS INT)-- -"):
            return SendResult(500, 100, 400, {},
                "You have an error in your SQL syntax; check the manual "
                "that corresponds to your MySQL server version")
        return SendResult(200, 100, len(base), {}, base)
    fake.handler = h
    install_fake(fake)
    f = analyze_param_deep("http://x.local/", "GET", "id",
                           rate_limit_ms=0, max_requests=60)
    compute_strength(f)
    check(set(["E","T","B"]).issubset(set(f.signals)),
          f"E,T,B all present (got {f.signals})")
    check(f.strength >= 0.55,
          f"strength>=0.55 (got {f.strength})")
    check(f.strength_grade in ("moderate", "strong", "critical"),
          f"grade moderate+ (got {f.strength_grade})")


# ── T06: WAF penalty applies ───────────────────────────────
def test_waf_penalty():
    print("\n[T06] cloudflare header → WAF flagged, E penalized")
    fake = FakeServer()
    def h(url, method, param, payload, inject_in, headers):
        h_cf = {"server": "cloudflare", "cf-ray": "abcd1234ef567890-SJC"}
        if payload in ("'", "\"", "')", "\";", "' AND CAST('x' AS INT)-- -"):
            # WAF forges a fake mysql error
            return SendResult(200, 100, 400, h_cf,
                "attention required cloudflare "
                "You have an error in your SQL syntax MySQL")
        return SendResult(200, 100, 500, h_cf, "ok")
    fake.handler = h
    install_fake(fake)
    f = analyze_param_deep("http://x.local/", "GET", "id",
                           rate_limit_ms=0, max_requests=30)
    compute_strength(f)
    check(f.waf == "cloudflare", f"waf=cloudflare (got {f.waf})")
    check("E" in f.signals, "E still recorded")
    # E only, penalized: 0.40 * 1.0 * 0.6 = 0.24; strength = 0.24
    # unpenalized would be 0.40 → clear differential
    # Compare against the un-penalized T02 which yielded ~0.40
    check(f.strength < 0.30,
          f"WAF-penalized E gives lower strength (got {f.strength})")


# ── T07: auth-token gate ───────────────────────────────────
def test_auth_gate():
    print("\n[T07] extractor refuses without correct auth token")
    fake = FakeServer()
    install_fake(fake)
    f = DeepFinding(url="http://x.local/vuln", param="id",
                    method="GET", inject_in="query",
                    dbms_guess=["mysql"], techniques=["error"])
    f.signals = ["E"]; f.strength_grade = "strong"
    try:
        deep_extract(f, auth_token="wrong-token", targets=["banner"],
                     rate_limit_ms=0, max_total_requests=50)
        check(False, "should have refused (didn't)")
    except ExtractionRefused as e:
        check("expected token" in str(e), f"correct refusal msg (got: {e})")
    # correct token succeeds (extraction proceeds even if server returns junk)
    tok = _expected_token(f.url)
    try:
        deep_extract(f, auth_token=tok, targets=["banner"],
                     rate_limit_ms=0, max_total_requests=50)
        check(True, "correct token accepted")
    except ExtractionRefused as e:
        # allowed to fail for other reasons (no data), but not on auth
        check("expected token" not in str(e),
              f"wrong refusal (got: {e})")


# ── T08: write-op guard ────────────────────────────────────
def test_write_guard():
    print("\n[T08] write/exec SQL tokens are blocked")
    for bad in ["DROP TABLE users", "INSERT INTO x VALUES(1)",
                "UPDATE u SET p=1", "DELETE FROM x",
                "EXEC master.dbo.xp_cmdshell 'whoami'",
                "SELECT LOAD_FILE('/etc/passwd')",
                "SELECT * INTO OUTFILE '/tmp/x'"]:
        try:
            _assert_readonly(bad)
            check(False, f"failed to block: {bad!r}")
        except ExtractionRefused:
            check(True, f"blocked: {bad[:40]!r}")


# ── T09: extraction happy path (error technique) ──────────
def test_extract_error_happy():
    print("\n[T09] error-based extraction returns leaked value")
    fake = FakeServer()
    def h(url, method, param, payload, inject_in, headers):
        # EXTRACTVALUE pattern → return an XPATH error containing the value
        if "EXTRACTVALUE" in payload:
            return SendResult(500, 100, 400, {},
                "XPATH syntax error: '~5.7.42-log~' at line 1")
        return SendResult(200, 100, 500, {}, "ok")
    fake.handler = h
    install_fake(fake)
    f = DeepFinding(url="http://x.local/vuln", param="id",
                    method="GET", inject_in="query",
                    dbms_guess=["mysql"], techniques=["error"])
    f.signals = ["E"]; f.strength_grade = "strong"
    tok = _expected_token(f.url)
    rep = deep_extract(f, auth_token=tok, targets=["banner"],
                       rate_limit_ms=0, max_total_requests=50)
    check(rep.banner is not None and rep.banner.value == "5.7.42-log",
          f"banner extracted (got {rep.banner and rep.banner.value!r})")
    check(rep.technique_used == "error", "used error technique")


# ── T10: extraction boolean binary search ──────────────────
def test_extract_boolean_binary_search():
    print("\n[T10] boolean-blind binary search extracts a short string")
    fake = FakeServer()
    secret = "root"          # target value
    base_body = "welcome " * 100
    def h(url, method, param, payload, inject_in, headers):
        import re
        # LENGTH probe:  AND LENGTH((expr))>N
        mlen = re.search(r"LENGTH\(.*?\)>(\d+)", payload)
        if mlen and "SUBSTRING" not in payload and "SUBSTR" not in payload:
            n = int(mlen.group(1))
            if len(secret) > n:
                return SendResult(200, 100, len(base_body), {}, base_body)
            return SendResult(200, 100, 200, {}, "empty")
        # per-char ASCII probe
        m = re.search(r"SUBSTRING\(.*?,(\d+),1\)\)>(\d+)", payload)
        if not m:
            return SendResult(200, 100, len(base_body), {}, base_body)
        pos = int(m.group(1)); mid = int(m.group(2))
        if pos > len(secret):
            return SendResult(200, 100, 200, {}, "empty")
        c = ord(secret[pos - 1])
        if c > mid:
            return SendResult(200, 100, len(base_body), {}, base_body)
        return SendResult(200, 100, 200, {}, "empty")
    fake.handler = h
    install_fake(fake)
    f = DeepFinding(url="http://x.local/vuln", param="id",
                    method="GET", inject_in="query",
                    dbms_guess=["mysql"], techniques=["boolean"])
    f.signals = ["B"]; f.strength_grade = "strong"
    tok = _expected_token(f.url)
    rep = deep_extract(f, auth_token=tok, targets=["user"],
                       rate_limit_ms=0, max_total_requests=500,
                       max_len_per_field=8)
    check(rep.current_user is not None,
          "current_user cell created")
    check(rep.current_user.value == "root",
          f"boolean extracted 'root' (got {rep.current_user and rep.current_user.value!r})")


# ── T11: WAF detector ──────────────────────────────────────
def test_waf_detector():
    print("\n[T11] WAF passive detection")
    r = waf_detect({"Server": "cloudflare", "CF-Ray": "abc-SJC"},
                   "attention required cloudflare", 403)
    check("cloudflare" in r.detected, "cloudflare detected")
    check("url_encode_all" in r.tampers, "tampers proposed")
    r2 = waf_detect({"Server": "nginx"}, "ok", 200)
    check(r2.detected == [], "clean nginx → no waf")


# ── T12: strength grade thresholds ─────────────────────────
def test_strength_thresholds():
    print("\n[T12] strength grade thresholds")
    f = DeepFinding(url="http://x", param="id", method="GET", inject_in="query")
    f.signals = []; compute_strength(f)
    check(f.strength_grade == "none", "empty → none")

    f.signals = ["E"]
    f.signal_meta = {"E": {}}
    compute_strength(f)
    check(f.strength_grade in ("weak", "moderate"), f"E alone weak/moderate (got {f.strength_grade})")

    f.signals = ["E", "T", "B", "U"]
    f.signal_meta = {
        "E": {"probe":"'","dbms":["mysql"]},
        "T": {"delay_s": 6.0, "confirm_delay_s": 6.0, "baseline_ms":100, "probe_ms":6100, "confirm_ms":6100},
        "B": {"sim_true_base":0.99,"sim_false_base":0.30,"sim_true_false":0.30,"len_delta":300},
        "U": {"column_hints":[3,4],"trigger_count":2},
    }
    compute_strength(f)
    check(f.strength_grade in ("strong", "critical"),
          f"E+T+B+U → strong/critical (got {f.strength_grade}, s={f.strength})")


# ── T13: DBMS-safe quoting ─────────────────────────────────
def test_quote():
    print("\n[T13] DBMS-safe literal quoting")
    check(_quote("mysql", "test") == "0x74657374", "mysql hex quote")
    check(_quote("mssql", "abc") == "0x616263", "mssql hex quote")
    check(_quote("postgresql", "a'b") == "'a''b'", "postgres escapes '")
    check("CHR(97)" in _quote("oracle", "a"), "oracle uses CHR()")


# ── run ────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("H4ACKBAR v1.2.0 — regression suite")
    print("=" * 60)
    tests = [
        test_baseline_no_signals, test_error_signal, test_time_signal,
        test_boolean_signal, test_strength_combines, test_waf_penalty,
        test_auth_gate, test_write_guard, test_extract_error_happy,
        test_extract_boolean_binary_search, test_waf_detector,
        test_strength_thresholds, test_quote,
    ]
    for t in tests:
        try:
            t()
        except Exception as e:
            FAIL += 1
            print(f"  \033[31m✗ EXCEPTION in {t.__name__}: {type(e).__name__}: {e}\033[0m")
            traceback.print_exc()
    print("=" * 60)
    print(f"PASS: {PASS}   FAIL: {FAIL}")
    print("=" * 60)
    sys.exit(0 if FAIL == 0 else 1)
