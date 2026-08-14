"""
H4ACKBAR v1.2.0 — deep analyzer thread + extraction thread.

Keeps analyzer.py intact for backward compat; this module is what the
v1.2 UI actually uses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from PyQt6.QtCore import QThread, pyqtSignal

from .fingerprint import fingerprint_response, Fingerprint
from .crawler import crawl, CrawlReport
from .detector_deep import DeepFinding, analyze_targets_deep, set_oob_verifier
from .strength import compute_strength
from .sender import send
from .waf import detect as waf_detect, WAFResult
from .extractor import deep_extract, ExtractionReport, ExtractionRefused


@dataclass
class DeepAnalysisReport:
    seed_url: str
    fingerprint: Optional[Fingerprint] = None
    crawl_report: Optional[CrawlReport] = None
    findings: List[DeepFinding] = field(default_factory=list)
    waf: Optional[WAFResult] = None
    log: List[str] = field(default_factory=list)


class DeepAnalyzerThread(QThread):
    progress = pyqtSignal(str)
    step = pyqtSignal(str, int, int)
    finished_report = pyqtSignal(object)         # DeepAnalysisReport
    failed = pyqtSignal(str)

    def __init__(self, seed_url: str,
                 max_pages: int = 20, max_depth: int = 2,
                 delay_ms: int = 250, respect_robots: bool = True,
                 run_detector: bool = True,
                 enable_stacked: bool = True,
                 enable_header: bool = True,
                 enable_second_order: bool = False,
                 second_order_read_url: Optional[str] = None,
                 oob_callback_host: Optional[str] = None,
                 rate_limit_ms: int = 150,
                 max_requests_per_target: int = 60):
        super().__init__()
        self.seed_url = seed_url
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.delay_ms = delay_ms
        self.respect_robots = respect_robots
        self.run_detector = run_detector
        self.enable_stacked = enable_stacked
        self.enable_header = enable_header
        self.enable_second_order = enable_second_order
        self.second_order_read_url = second_order_read_url
        self.oob_callback_host = oob_callback_host
        self.rate_limit_ms = rate_limit_ms
        self.max_requests_per_target = max_requests_per_target
        self._abort = False

    def request_abort(self):
        self._abort = True

    def _log(self, report: DeepAnalysisReport, msg: str):
        report.log.append(msg)
        self.progress.emit(msg)

    def run(self):
        report = DeepAnalysisReport(seed_url=self.seed_url)
        try:
            # ── phase 1: fingerprint + waf ──
            self.step.emit("fingerprint", 0, 4)
            self._log(report, f"[fp] GET {self.seed_url}")
            r = send(self.seed_url, "GET", "", "id", inject_in="query")
            if r.error:
                self._log(report, f"[fp] baseline error: {r.error}")
                report.fingerprint = Fingerprint()
                report.waf = WAFResult()
            else:
                report.fingerprint = fingerprint_response(r.headers, {}, r.body)
                report.waf = waf_detect(r.headers, r.body, r.status)
                self._log(report, f"[fp] {report.fingerprint.summary()}")
                self._log(report, f"[waf] {report.waf.summary()}")
            self.step.emit("fingerprint", 1, 4)
            if self._abort:
                self.finished_report.emit(report); return

            # ── phase 2: crawl ──
            self.step.emit("crawl", 1, 4)
            self._log(report, f"[crawl] seed={self.seed_url} pages={self.max_pages} depth={self.max_depth}")
            report.crawl_report = crawl(
                self.seed_url, max_pages=self.max_pages, max_depth=self.max_depth,
                delay_ms=self.delay_ms, respect_robots=self.respect_robots,
                progress=lambda m: self._log(report, m),
            )
            self._log(report,
                f"[crawl] done: {len(report.crawl_report.pages_visited)} pages, "
                f"{len(report.crawl_report.targets)} targets, "
                f"{report.crawl_report.duration_s}s")
            self.step.emit("crawl", 2, 4)
            if self._abort:
                self.finished_report.emit(report); return

            # ── phase 3: deep detect ──
            if not self.run_detector:
                self._log(report, "[deep] skipped (disabled)")
                self.step.emit("done", 4, 4)
                self.finished_report.emit(report); return
            targets = report.crawl_report.targets
            if not targets:
                self._log(report, "[deep] no targets discovered")
                self.step.emit("done", 4, 4)
                self.finished_report.emit(report); return

            self._log(report, f"[deep] {len(targets)} targets — 9-signal engine")
            target_dicts = [
                dict(url=t.url, method=t.method, param=t.param, inject_in=t.inject_in)
                for t in targets
            ]
            report.findings = analyze_targets_deep(
                target_dicts,
                progress=lambda m: self._log(report, m),
                abort=lambda: self._abort,
                enable_stacked=self.enable_stacked,
                enable_header=self.enable_header,
                enable_second_order=self.enable_second_order,
                second_order_read_url=self.second_order_read_url,
                oob_callback_host=self.oob_callback_host,
                rate_limit_ms=self.rate_limit_ms,
                max_requests=self.max_requests_per_target,
            )
            self.step.emit("deep", 3, 4)

            # ── phase 4: score ──
            self._log(report, "[score] computing weighted strength for all findings")
            for f in report.findings:
                compute_strength(f)
            crit = sum(1 for f in report.findings if f.strength_grade == "critical")
            strong = sum(1 for f in report.findings if f.strength_grade == "strong")
            self._log(report,
                f"[score] critical={crit} strong={strong} "
                f"confirmed={sum(1 for f in report.findings if f.confirmed())} "
                f"total={len(report.findings)}")

            self.step.emit("done", 4, 4)
            self.finished_report.emit(report)

        except Exception as e:
            self.failed.emit(f"{type(e).__name__}: {e}")


class ExtractionThread(QThread):
    progress = pyqtSignal(str)
    finished_report = pyqtSignal(object)      # ExtractionReport
    refused = pyqtSignal(str)
    failed = pyqtSignal(str)

    def __init__(self, finding: DeepFinding,
                 auth_token: str,
                 targets: List[str],
                 rate_limit_ms: int = 200,
                 max_len_per_field: int = 64,
                 max_total_requests: int = 800,
                 technique_override: str = "auto (from finding)"):
        super().__init__()
        self.finding = finding
        self.auth_token = auth_token
        self.targets = targets
        self.rate_limit_ms = rate_limit_ms
        self.max_len_per_field = max_len_per_field
        self.max_total_requests = max_total_requests
        self.technique_override = technique_override
        self._abort = False

    def request_abort(self):
        self._abort = True

    def run(self):
        try:
            # optional technique pin: monkey-patch the finding's technique order
            if self.technique_override and self.technique_override != "auto (from finding)":
                # move chosen technique to front (only if it's already available)
                if self.technique_override in self.finding.techniques:
                    self.finding.techniques = [self.technique_override] + [
                        t for t in self.finding.techniques
                        if t != self.technique_override
                    ]
                else:
                    self.progress.emit(
                        f"[extract] technique '{self.technique_override}' not available "
                        f"on this finding; using auto"
                    )

            report = deep_extract(
                self.finding,
                auth_token=self.auth_token,
                targets=self.targets,
                max_len_per_field=self.max_len_per_field,
                rate_limit_ms=self.rate_limit_ms,
                max_total_requests=self.max_total_requests,
                abort=lambda: self._abort,
                progress=self.progress.emit,
            )
            self.finished_report.emit(report)
        except ExtractionRefused as e:
            self.refused.emit(str(e))
        except Exception as e:
            self.failed.emit(f"{type(e).__name__}: {e}")
