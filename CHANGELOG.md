# Changelog

All notable changes to this project will be documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html)

## [1.2.0] — 2026-08-13

### Added — Deep Detector · Weighted Strength · Deep Extraction

- **`detector_deep.py`** — 9-signal deep detector (adds S/O/H/2/W to E/B/T/U).
  - Median-anchored baseline (defeats single-request jitter).
  - Confirmation shot on `T` (2nd sleep to reject network noise).
  - Weak-signal channel — signals that fired but below quality threshold.
  - Per-signal metadata dict (delay ms, similarity ratios, snippets, WAF vendor).
  - Cooperative abort + hard request budget per target (default 60).
  - Rate limit between probes.
  - `set_oob_verifier()` hook for real DNSlog/Interactsh listener.
  - Stacked `S` requires prior DBMS narrowing (kills "server ignored" FPs).
- **`strength.py`** — Weighted probabilistic strength scoring (replaces
  `len(signals)` heuristic from v1.1).
  - Base weights per signal (E=0.40 highest, W=0.10 lowest).
  - Quality multipliers (T scales with delay, B scales with sim gap, …).
  - WAF penalty (0.6×) on `E` and `O` when WAF present and not bypassed.
  - Signal-synergy bonus (+0.02 per corroborating signal beyond the 2nd).
  - 5-tier grade: `none / weak / moderate / strong / critical`.
- **`extractor.py`** — Deep extraction engine.
  - Techniques: `union` · `error` · `boolean` (binary-search) · `time` (bitwise).
  - Per-DBMS query book (mysql/mariadb/postgres/mssql/sqlite/oracle).
  - DBMS-safe literal quoting (hex on mysql/mssql, `CHR||` on oracle, escape on pg/sqlite).
  - **AUTH GATE** — refuses without `I-OWN-<hostname>` token.
  - **Read-only guard** — blocks INSERT/UPDATE/DELETE/DROP/EXEC/LOAD_FILE/OUTFILE pre-fire.
  - Length pre-probe on boolean extraction (stops at true end vs converging on space).
  - Bounded request budget + rate limit + cooperative cancel.
- **`waf.py`** — Full WAF catalog + tamper suggestions (11 vendors:
  cloudflare · akamai · aws_waf · imperva · modsecurity · sucuri · f5 ·
  barracuda · wordfence · naxsi · comodo).
- **`analyzer_v12.py`** — `DeepAnalyzerThread` + `ExtractionThread`.
- **`analyzer_panel_v12.py`** — Deep analyzer UI with signal toggles + OOB/2nd-order inputs.
- **`result_tabs_v12.py`** — `DeepFindingsTab` (with 💧 Extract button + I-OWN token copier)
  · `ExtractionTab` (auth gate + tree view + JSON export) · `WAFTab`.
- **`tests/test_v12.py`** — 41-assertion offline regression suite covering
  every new module (no network, PyQt6 stub-injected).

### Changed
- `app.py` — new **🧠 Deep Analyze** tab (Ctrl+Shift+D shortcut).
- `app.py` — extraction spawn on demand from Deep Findings tab (💧 button).
- `app.py` — extraction threads collected in `self._extract_threads` to prevent GC.
- `__init__.py` — version 1.1.0 → 1.2.0.
- README — new detector-level ladder, extraction section, tab diagram, workflow docs.
- CHANGELOG — this entry.

### Preserved (backwards compat)
- v1.1 modules (`detector.py`, `analyzer.py`, `analyzer_panel.py`, `result_tabs.py`)
  untouched and still exposed via the **🔎 Analyze (v1.1)** tab.
- Zero new runtime dependencies — same `requirements.txt`.
- Same cream theme, same SVG banner, same command launcher, same workbench.

### Safety
- Extraction is opt-in and hard-gated by `I-OWN-<host>` token per finding.
- Read-only enforced by pre-fire regex on every extraction payload.
- Request budgets on all extraction loops.
- WAF-aware — flags forged errors and discounts strength accordingly.

## [1.1.0] — 2026-08-13

### Added
- **Cream/light UI theme** with red-oxide accents (`h4ackbar/theme.py`)
- **SVG banner header** with SQLi typography vibe (`assets/banner.svg`,
  `h4ackbar/banner.py`)
- **Main window redesigned around QTabWidget** — Workbench + Analyze tabs
  are permanent; result tabs spawn per analysis run
- **Fingerprinter module** (`h4ackbar/fingerprint.py`) — passive detection of
  framework (php · django · rails · laravel · wordpress · nextjs · nuxt ·
  vue · angular · react · nginx · apache · iis · gunicorn · uvicorn · …)
  and DBMS (mysql · mariadb · postgresql · mssql · oracle · sqlite · odbc ·
  jdbc) from headers, cookies, HTML markers, and error-string regex library
- **Crawler module** (`h4ackbar/crawler.py`) — bounded, same-origin,
  robots.txt-respecting, rate-limited. Harvests query-param links + form
  inputs into injection targets
- **3-signal detector engine** (`h4ackbar/detector.py`) — combines
  Error / Boolean / Time / Union signals; requires ≥2 signals to confirm
  (2 levels above single-shot payload firing). Each Finding carries
  confidence (none/low/medium/high) + evidence trail
- **Analyzer orchestrator** (`h4ackbar/analyzer.py`) + QThread worker —
  runs fingerprint → crawl → detect off the UI thread; emits progress
  signals to keep the window live
- **Analyzer panel widget** (`h4ackbar/analyzer_panel.py`) — target URL,
  max pages / depth / delay / robots / detector toggles, live log,
  progress bar, RUN / ABORT controls
- **Dynamic result tabs** (`h4ackbar/result_tabs.py`) — on successful
  analysis, spawns Findings + Stack (fingerprint) + Crawl + Log tabs and
  smoothly focuses the Findings tab
- **Tests**: `test_fingerprint.py` (11 new), `test_crawler.py` (5 new),
  `test_detector.py` (3 new). Total 40 tests, all green
- New dependencies: `beautifulsoup4`, `lxml`

### Changed
- `app.py` fully rewritten for the tabbed architecture
- Status bar constructed before tabs to fix init-order bug
- README updated with new features and screenshots section

## [1.0.0] — 2026-08-13

### Added
- Initial public release
- 9 payload families, 107 seeds
- 21 encoders, 14 preset chains
- PyQt6 desktop UI, Ctrl+K launcher, hex-grid preview
- Manual HTTP sender (query · body · header · path)
- Session export (JSON), 21 tests, GitHub Actions CI
