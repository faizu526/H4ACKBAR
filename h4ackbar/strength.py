"""
H4ACKBAR v1.2.0 — STRENGTH SCORING.

Replaces "count the signals" with quality-anchored, weighted scoring.

Rationale
─────────
v1.1's confidence tier was just `len(signals)`. That treats:
  - a 4.2s time delay (strong)     == a 20-byte len diff (weak)
  - a DBMS-error banner (strong)   == a union column hint (weak)

v1.2 grades each signal by its own metadata and combines weighted evidence
into a 0..1 strength score, then buckets into 5 tiers.

Signal weight table (BASE, without quality mods):
    E  0.35   direct DBMS oracle
    T  0.30   physical evidence (time cannot be faked by WAF stub)
    S  0.25   silent execution = server-side eval
    2  0.25   second-order = persistent + confirmed
    B  0.20   differential, but jitter-prone
    U  0.15   heuristic only
    H  0.15   header path, often noisier
    O  0.20   OOB — capped unless verified
    W  0.10   WAF bypass is a modifier, not an oracle

Quality modifiers (multiplicative, 0.4 .. 1.15):
    - T: quality ∝ delay/threshold, cap at 1.15 if >2× threshold
    - B: quality ∝ |sim(t,b)-sim(f,b)| and len_delta magnitude
    - E: 1.0 always (banner is banner)
    - U: quality ∝ trigger_count / 2
    - S: 1.0 if sim_base > 0.95 else 0.75
    - O: 1.15 if verified_listener else 0.50
    - 2: 1.15 if marker_visible else 0.85
    - H: 1.0 if reflected AND dbms else 0.7
    - W: 1.0

WAF penalty:
    if waf detected and "W" signal absent → E,O × 0.6
    (WAF may be forging the "error" response)

Combining:
    strength = 1 - Π(1 - wᵢ · qᵢ)     over all present signals
    (independence assumption — pessimistic. Bounded [0,1].)

Grade thresholds:
    0.90+  critical      exploitation almost certain
    0.75+  strong        confirm + safe extract
    0.55+  moderate      confirm before extract
    0.30+  weak          more probes needed
    <0.30  none/noise
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .detector_deep import DeepFinding


BASE_WEIGHTS: dict[str, float] = {
    "E": 0.40, "T": 0.30, "S": 0.25, "2": 0.25, "B": 0.20,
    "U": 0.15, "H": 0.15, "O": 0.20, "W": 0.10,
}

GRADE_THRESHOLDS = [
    (0.90, "critical"),
    (0.75, "strong"),
    (0.55, "moderate"),
    (0.30, "weak"),
    (0.00, "none"),
]


def _quality(sig: str, meta: dict) -> float:
    """Per-signal quality multiplier in [0.4, 1.15]."""
    # E is binary: DBMS banner appeared, or it didn't. No quality gradient.
    if sig == "E":
        return 1.0
    if not meta:
        return 0.6                 # signal fired but no metadata → discount
    m = meta

    if sig == "T":
        delay = float(m.get("delay_s", 0))
        confirm = float(m.get("confirm_delay_s", delay))
        avg = (delay + confirm) / 2.0
        # threshold ~ 3s. quality scales with headroom.
        q = min(1.15, max(0.4, avg / 3.0))
        return q

    if sig == "B":
        sim_tb = float(m.get("sim_true_base", 0))
        sim_fb = float(m.get("sim_false_base", 1))
        gap = abs(sim_tb - sim_fb)          # ideal ~0.3
        len_delta = int(m.get("len_delta", 0))
        len_bonus = min(0.15, len_delta / 500.0)
        q = 0.5 + gap + len_bonus           # can exceed 1.0
        return min(1.15, max(0.4, q))

    if sig == "U":
        n = int(m.get("trigger_count", 1))
        return min(1.0, 0.5 + n * 0.15)     # 2 hits = 0.8, 3+ = 0.95+

    if sig == "S":
        sim = float(m.get("sim_base", 0))
        return 1.0 if sim > 0.95 else 0.75

    if sig == "O":
        return 1.15 if m.get("verified_listener") else 0.5

    if sig == "2":
        return 1.15 if m.get("marker_visible") else 0.85

    if sig == "H":
        return 1.0 if (m.get("reflected") and m.get("dbms")) else 0.7

    if sig == "W":
        return 1.0

    return 0.7


def compute_strength(finding: DeepFinding) -> None:
    """
    Populate finding.strength (0..1) and finding.strength_grade.
    Mutates the object. Idempotent — safe to call multiple times.
    """
    if not finding.signals:
        finding.strength = 0.0
        finding.strength_grade = "none"
        return

    # per-signal weighted contributions
    survival = 1.0
    contribs = []
    waf_penalty = (finding.waf and "W" not in finding.signals)

    for sig in finding.signals:
        base = BASE_WEIGHTS.get(sig, 0.15)
        q = _quality(sig, finding.signal_meta.get(sig, {}))
        # WAF penalty on error/oob if WAF wasn't bypassed
        if waf_penalty and sig in ("E", "O"):
            q *= 0.6
        effective = min(0.95, base * q)     # cap single-signal contribution
        survival *= (1.0 - effective)
        contribs.append((sig, round(base, 2), round(q, 2), round(effective, 3)))

    strength = 1.0 - survival
    # weak signals add tiny nudge (max +0.03 total)
    strength = min(1.0, strength + min(0.03, 0.01 * len(finding.weak_signals)))
    # signal-synergy bonus — corroborating evidence gets rewarded
    # (Bayesian: 4 independent oracles is stronger than the product of two)
    # +0.02 per signal beyond the 2nd, capped at +0.10 (5 extra signals)
    n = len(finding.signals)
    if n > 2:
        strength = min(1.0, strength + min(0.10, 0.02 * (n - 2)))
    finding.strength = round(strength, 3)

    for thresh, grade in GRADE_THRESHOLDS:
        if strength >= thresh:
            finding.strength_grade = grade
            break

    # attach breakdown to evidence for auditability
    breakdown = " · ".join(f"{s}(w{w}×q{q}={e})" for s, w, q, e in contribs)
    finding.evidence.append(
        f"STRENGTH={strength:.3f} grade={finding.strength_grade} | {breakdown}"
        + (f" | WAF-penalty=on ({finding.waf})" if waf_penalty else "")
    )


def strength_color(grade: str) -> str:
    """Hex color for UI tiers. Matches theme.py palette."""
    return {
        "critical": "#7a0f1a",
        "strong":   "#a11d2b",
        "moderate": "#c9782f",
        "weak":     "#8b7a4a",
        "none":     "#999999",
    }.get(grade, "#999999")


def strength_bar(strength: float, width: int = 20) -> str:
    """ASCII bar for text views. width=20 → 5% per block."""
    filled = int(round(strength * width))
    return "█" * filled + "░" * (width - filled)
