# H4ACKBAR Architecture (v1.1.0)

## Layered View

```
┌──────────────────────────────────────────────────────────────┐
│  UI            h4ackbar/app.py                               │
│                banner.py · theme.py · analyzer_panel.py      │
│                result_tabs.py                                │
│  (QMainWindow  →  Banner + QTabWidget)                       │
└─────────────────┬─────────────────┬──────────────────────────┘
                  │                 │
     ┌────────────┴───┐   ┌─────────┴─────────┐
     │ Workbench tab  │   │  Analyze tab      │
     │ (payloads +    │   │  (analyzer_panel) │
     │  chain + fire) │   │       │            │
     └───┬────┬───┬───┘   └───────┼────────────┘
         │    │   │               │
         ▼    ▼   ▼               ▼
    payloads encoders chain   analyzer.py (QThread)
        │       │      │       │  │  │
        └───────┴──────┴───────┘  │  │
                                  ▼  ▼
                        fingerprint  crawler
                              │        │
                              └───┬────┘
                                  ▼
                              detector.py
                                  │
                                  ▼
                              sender.py  (only network boundary)
```

## Modules

| File                        | Role                                                   |
|-----------------------------|--------------------------------------------------------|
| `theme.py`                  | Cream palette + Qt stylesheet                          |
| `banner.py`                 | SVG banner widget (fallback to text if asset missing)  |
| `payloads.py`               | Payload catalog (107 seeds, 9 families)                |
| `encoders.py`               | 21 str→str encoders + hex_grid                         |
| `chain.py`                  | Chain composer + preset chains                         |
| `sender.py`                 | Single HTTP boundary — validated, manual fire only     |
| `fingerprint.py`            | Framework + DBMS passive detection (headers/cookies/HTML/error regex) |
| `crawler.py`                | Bounded same-origin BFS; harvests links + form params  |
| `detector.py`               | 3-signal SQLi detector (E / B / T / U)                 |
| `analyzer.py`               | Orchestrates fingerprint → crawl → detect (QThread)    |
| `analyzer_panel.py`         | UI panel that owns the analyzer thread                 |
| `result_tabs.py`            | FindingsTab · FingerprintTab · CrawlTab · LogTab       |
| `app.py`                    | Main window, tab management, command launcher, wiring  |

## Threading

- Main thread: Qt event loop only.
- Analyzer runs in a `QThread` (`AnalyzerThread`); communicates via signals.
- Workbench sender is still synchronous (single click = single request).

## Detector Signal Semantics

| Signal | Meaning                                                        |
|--------|----------------------------------------------------------------|
| E      | DBMS error string appeared in probe response                   |
| B      | true probe ~= baseline, false probe differs significantly      |
| T      | DBMS-specific sleep payload delayed response ≥ 3 s over baseline |
| U      | ≥ 2 UNION column-probes altered body length without erroring   |

Confidence = signal count → `low / medium / high`.
A finding is "confirmed" iff `len(signals) >= 2`.

## Security Boundaries

| Boundary                     | Control                              |
|------------------------------|--------------------------------------|
| Analyzer URL                 | Scheme validated (http/https only)   |
| Crawler scope                | Same-origin enforced                 |
| Crawler robots.txt           | Respected by default                 |
| Crawler rate                 | Configurable delay (default 250 ms)  |
| Sender method                | Whitelist                            |
| Sender inject_in             | Enum                                 |
| Detector payloads            | Only probes (never destructive)      |
| TLS                          | verify=True default                  |
| Redirects                    | disabled in sender                   |
| Response size                | truncated 20 KB in UI                |

## Extension Points

| Add                 | Where                                                    |
|---------------------|----------------------------------------------------------|
| Payload family      | `payloads.py` → new list, register in `all_payloads()`   |
| Encoder             | `encoders.py` → function + `ENCODERS` dict               |
| Preset chain        | `chain.py` → append to `preset_chains()`                 |
| DBMS error pattern  | `fingerprint.py` → `DBMS_ERROR_PATTERNS`                 |
| Framework hint      | `fingerprint.py` → header / cookie / html tables         |
| Detector signal     | `detector.py` → new probe block in `analyze_param`       |
| Result tab type     | `result_tabs.py` → new QWidget, wire in `app._on_report` |
