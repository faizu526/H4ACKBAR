"""
H4ACKBAR analyzer.
Orchestrates: fingerprint → crawl → detect.
Runs inside a QThread so the UI stays live.
Emits signals on progress and completion.
"""

from dataclasses import dataclass, field
from typing import List, Optional

from PyQt6.QtCore import QThread, pyqtSignal

from .fingerprint import fingerprint_response, Fingerprint
from .crawler import crawl, CrawlReport, Target
from .detector import analyze_targets, Finding
from .sender import send


@dataclass
class AnalysisReport:
    seed_url: str
    fingerprint: Optional[Fingerprint] = None
    crawl_report: Optional[CrawlReport] = None
    findings: List[Finding] = field(default_factory=list)
    log: List[str] = field(default_factory=list)


class AnalyzerThread(QThread):
    """
    Signals:
        progress(str)             — status text
        step(str, int, int)       — phase name, current, total
        finished_report(object)   — AnalysisReport
        failed(str)               — fatal error
    """
    progress = pyqtSignal(str)
    step = pyqtSignal(str, int, int)
    finished_report = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, seed_url: str,
                 max_pages: int = 20,
                 max_depth: int = 2,
                 delay_ms: int = 250,
                 respect_robots: bool = True,
                 run_detector: bool = True):
        super().__init__()
        self.seed_url = seed_url
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.delay_ms = delay_ms
        self.respect_robots = respect_robots
        self.run_detector = run_detector
        self._abort = False

    def request_abort(self):
        self._abort = True

    def _log(self, report: AnalysisReport, msg: str):
        report.log.append(msg)
        self.progress.emit(msg)

    def run(self):
        report = AnalysisReport(seed_url=self.seed_url)
        try:
            # ── phase 1: fingerprint ──
            self.step.emit("fingerprint", 0, 3)
            self._log(report, f"[fingerprint] fetch {self.seed_url}")
            r = send(self.seed_url, "GET", "", "id", inject_in="query")
            if r.error:
                self._log(report, f"[fingerprint] baseline fetch error: {r.error}")
                # continue anyway with empty fp
                report.fingerprint = Fingerprint()
            else:
                report.fingerprint = fingerprint_response(r.headers, {}, r.body)
                self._log(report, f"[fingerprint] {report.fingerprint.summary()}")
            self.step.emit("fingerprint", 1, 3)

            if self._abort:
                self.finished_report.emit(report); return

            # ── phase 2: crawl ──
            self.step.emit("crawl", 1, 3)
            self._log(report, f"[crawl] seed={self.seed_url} "
                              f"max_pages={self.max_pages} depth={self.max_depth}")
            report.crawl_report = crawl(
                self.seed_url,
                max_pages=self.max_pages,
                max_depth=self.max_depth,
                delay_ms=self.delay_ms,
                respect_robots=self.respect_robots,
                progress=lambda m: self._log(report, m),
            )
            self._log(report,
                f"[crawl] done: {len(report.crawl_report.pages_visited)} pages, "
                f"{len(report.crawl_report.targets)} targets, "
                f"{report.crawl_report.duration_s}s")
            self.step.emit("crawl", 2, 3)

            if self._abort:
                self.finished_report.emit(report); return

            # ── phase 3: detect ──
            if not self.run_detector:
                self._log(report, "[detect] skipped (disabled)")
                self.step.emit("detect", 3, 3)
                self.finished_report.emit(report); return

            self.step.emit("detect", 2, 3)
            targets = report.crawl_report.targets
            if not targets:
                self._log(report, "[detect] no targets discovered")
                self.step.emit("detect", 3, 3)
                self.finished_report.emit(report); return

            self._log(report, f"[detect] analyzing {len(targets)} target(s)")
            target_dicts = [
                dict(url=t.url, method=t.method, param=t.param, inject_in=t.inject_in)
                for t in targets
            ]

            def _progress(msg):
                if self._abort:
                    return
                self._log(report, msg)

            report.findings = analyze_targets(target_dicts, progress=_progress)
            confirmed = sum(1 for f in report.findings if f.confirmed())
            self._log(report,
                f"[detect] done: {len(report.findings)} tested, "
                f"{confirmed} confirmed (≥2 signals)")
            self.step.emit("detect", 3, 3)
            self.finished_report.emit(report)

        except Exception as e:
            self.failed.emit(f"{type(e).__name__}: {e}")
