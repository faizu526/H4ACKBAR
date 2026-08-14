<h1 align="center">H4ACKBAR</h1>

<p align="center">
  <b>SQLi payload workbench + automated analyzer — desktop, PyQt6.</b><br>
  Cream-themed UI · SVG banner · chain encoder · fingerprint · same-origin crawler · 3-signal detector.<br>
  <sub>Authorized security testing / CTF / lab use only.</sub>
</p>

<p align="center">
  <img alt="python" src="https://img.shields.io/badge/python-3.11%2B-blue">
  <img alt="pyqt6"  src="https://img.shields.io/badge/UI-PyQt6-41cd52">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="version" src="https://img.shields.io/badge/version-1.2.0-orange">
</p>

---

## Why

Burp Suite Repeater is heavy. `sqlmap` is loud. When you need to hand-craft a
SQLi payload, chain it through 3 encoders, hex-dump the wire form, then click
one button to have H4ACKBAR **crawl → fingerprint → 3-signal detect** and
drop the confirmed findings into a fresh tab — that is the workflow this tool
was built for.

## Feature Matrix

| Feature                                                            | Status |
|--------------------------------------------------------------------|:------:|
| Offline payload catalog (107 seeds, 9 SQLi families)               | ✅     |
| 21 encoders (url · hex · CHAR() · CHR|| · base64 · unicode · …)    | ✅     |
| 14 preset chains (seed → mutators → encoders → wire)               | ✅     |
| Hexdump-style wire preview                                          | ✅     |
| Command launcher (Ctrl+K)                                           | ✅     |
| **Framework fingerprinter** (php · django · rails · laravel · wp · nextjs · vue · react · …) | ✅ |
| **DBMS fingerprinter** (mysql · mariadb · postgres · mssql · oracle · sqlite) | ✅ |
| **Same-origin crawler** with robots.txt + rate-limit               | ✅     |
| **Form + query-param harvester**                                    | ✅     |
| **3-signal detector** (Error + Boolean + Time + Union confirmation) — v1.1 | ✅ |
| **9-signal DEEP detector** (E · B · T · U · S · O · H · 2 · W) — v1.2 | ✅ |
| **Weighted strength scoring** (5-tier: none/weak/moderate/strong/critical) — v1.2 | ✅ |
| **WAF fingerprint** (11 vendors + tamper suggestions) — v1.2       | ✅     |
| **Deep extraction** (union · error · boolean-binary · time-bitwise) — v1.2 | ✅ |
| **Auth-token gate** (read-only, host-locked, write-op guard) — v1.2 | ✅   |
| **Dynamic result tabs** (Deep Findings · Extract · WAF · Stack · Crawl · Log) | ✅ |
| Manual HTTP fire (query · body · header · path)                     | ✅     |
| Session + extraction export (JSON)                                  | ✅     |
| Cream/light theme + SVG banner                                      | ✅     |
| Regression test suite (offline, 41 assertions)                      | ✅     |
| Automated write-mode SQL (INSERT/UPDATE/DELETE/DROP/exec)            | ❌ *(hard-blocked)* |

## Detector Model — v1.2 "9-signal deep"

```
Level 0 (traditional):  fire one payload, grep for known errors
Level 1:                differential — true-vs-false response comparison
Level 2 (v1.1):         baseline + true + false + time + union
                        confirm only when ≥ 2 orthogonal signals agree
Level 3 (v1.2 DEEP):    Level 2 + stacked + OOB + header-inject +
                        second-order + WAF-aware retry + weighted
                        strength scoring (Bayesian corroboration bonus)
```

### Signal families (v1.2)

| Sig | Family              | Base weight | What it proves                                        |
|-----|---------------------|:-----------:|-------------------------------------------------------|
| `E` | error-based         | 0.40        | DBMS banner in response — highest-signal oracle       |
| `T` | time-blind          | 0.30        | physical delay confirmed with 2nd shot                |
| `S` | stacked queries     | 0.25        | server accepted extra statement silently              |
| `2` | second-order        | 0.25        | write in POST → marker/error surfaces in later GET    |
| `B` | boolean-blind       | 0.20        | TRUE≈baseline, FALSE differs (median-anchored)        |
| `O` | out-of-band         | 0.20        | DNS/HTTP callback (verified via listener or inferred) |
| `U` | union column-count  | 0.15        | ≥2 NULL-column probes altered response length         |
| `H` | header injection    | 0.15        | UA/Referer/XFF/Cookie yields DBMS error or reflection |
| `W` | WAF-bypass          | 0.10        | tamper chain gets past detected WAF                   |

### Strength grades

```
0.90+  critical     exploitation almost certain — extraction safe
0.75+  strong       confirm + safe to extract
0.55+  moderate     confirm before extract
0.30+  weak         more probes needed
<0.30  none/noise   likely false positive
```

## Deep Extraction — v1.2

Multi-technique data extraction gated behind `I-OWN-<host>` auth token:

- **UNION-based** — one-shot per field, fastest. Needs column count.
- **Error-based** — CAST/EXTRACTVALUE tricks. 1 request per field.
- **Boolean-blind** — binary search per char (7 req/char) + length pre-probe.
- **Time-blind** — bitwise (8 req/byte). Fallback when body identical.

Hard rules:
1. Refuses to run without `I-OWN-<host>` token.
2. All INSERT/UPDATE/DELETE/DROP/EXEC/LOAD_FILE/OUTFILE tokens **blocked pre-fire**.
3. Rate-limited + request-budgeted. Never unbounded loops.
4. Length-capped per field (default 64 chars, max 512).
5. Cooperative abort via UI button.
6. Read-only. No file writes on target. Ever.



Each DeepFinding carries:
- signals (`E`rror / `B`oolean / `T`ime / `U`nion / `S`tacked / `O`ob / `H`eader / `2`nd-order / `W`af-bypass)
- weak signals (fired but below quality threshold — never counted)
- per-signal metadata (delay ms, similarity ratios, error snippets, WAF vendor, …)
- DBMS guess (with per-signal cross-confirmation)
- WAF detection + suggested tampers
- strength score (0.000 – 1.000) with grade tier
- available extraction techniques
- full evidence trail

## UI Tabs

```
┌ Banner ────────────────────────────────────────────────────────────────────┐
│                                                                            │
├ 🧪 Workbench │ 🔎 Analyze (v1.1) │ 🧠 Deep Analyze │ dynamic result tabs → │
│                                                                            │
│   (permanent)    (permanent)         (permanent)                           │
│                                                                            │
│   dynamic:  🎯 Deep Findings │ 💧 Extract │ 🛡 WAF │ 🧬 Stack │ 🕸 Crawl │ 📜 Log │
└────────────────────────────────────────────────────────────────────────────┘
```

Result tabs are **closable** and **stackable** — run multiple analyses;
each set of findings lives in its own tab group.

## Install

```bash
git clone https://github.com/faizu526/H4ACKBAR.git
cd H4ACKBAR
python3 -m venv .venv
source .venv/bin/activate         # Windows: .venv\Scripts\activate
pip install -e .
```

Or from requirements only:

```bash
pip install -r requirements.txt
```

## Run

```bash
h4ackbar
# or
python -m h4ackbar
```

## Regression tests

```bash
python tests/test_v12.py
# → PASS: 41   FAIL: 0
```

Fully offline. No network. No PyQt6 install needed (stub is injected).

## Keyboard

| Key             | Action                        |
|-----------------|-------------------------------|
| `Ctrl+K`        | Command launcher              |
| `Ctrl+F`        | Focus payload filter          |
| `Ctrl+Return`   | Fire current payload          |
| `Ctrl+Shift+A`  | Jump to Analyze (v1.1) tab    |
| `Ctrl+Shift+D`  | Jump to Deep Analyze tab      |
| `Ctrl+Shift+W`  | Jump to Workbench tab         |

## v1.1 Analyze workflow (legacy)

1. Open the **🔎 Analyze (v1.1)** tab.
2. Enter target URL (must be authorized).
3. Tune max pages / depth / delay / robots / detector.
4. Click **▶ RUN ANALYSIS**.
5. Live log streams during fingerprint → crawl → detect.
6. When done, 4 result tabs auto-open, focus lands on **🎯 Findings**.

## v1.2 Deep workflow

1. Open the **🧠 Deep Analyze** tab.
2. Enter target URL (must be authorized).
3. Tune crawler (pages/depth/delay/robots) + deep detector (rate/budget/signals).
4. Optionally add OOB callback host + second-order read URL.
5. Click **▶ RUN DEEP ANALYSIS**.
6. Fingerprint → WAF → crawl → 9-signal deep detect → weighted strength scoring.
7. Result tabs auto-open: **🎯 Deep Findings** · **🧬 Stack** · **🛡 WAF** · **🕸 Crawl** · **📜 Log**.
8. In **Deep Findings**, select a moderate/strong/critical row → **💧 DEEP EXTRACT**.
9. Extraction tab spawns. Paste the `I-OWN-<host>` auth token.
10. Pick targets (banner/version/user/db/databases/tables/columns) + technique.
11. Click **▶ RUN EXTRACTION** → live tree fills with leaked values.
12. Export to JSON.

## Chain Model (Workbench)

```
SEED  →  mutator*  →  encoder*  →  WIRE
```

Every stage is inspectable in the preview + hex grid.

## Tests

```bash
python tests/test_v12.py                     # offline, 41/41 pass
pip install -r requirements-dev.txt          # (optional) full lint/test env
QT_QPA_PLATFORM=offscreen pytest -v
ruff check .
```

## Legal

Use only on systems you own or where you have **explicit written authorization**.
See `LICENSE` and `SECURITY.md`. Unauthorized use is illegal.

## Contributing

See `CONTRIBUTING.md`.
