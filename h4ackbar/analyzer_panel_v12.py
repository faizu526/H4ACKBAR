"""
H4ACKBAR v1.2.0 — deep analyzer panel.

Adds:
  - deep signal toggles (S/O/H/2/W)
  - optional OOB callback host
  - optional second-order read-back URL
  - per-target rate limit + request budget
"""

from __future__ import annotations

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QSpinBox,
    QCheckBox, QPushButton, QPlainTextEdit, QProgressBar, QGroupBox,
)
from PyQt6.QtCore import pyqtSignal, Qt

from .analyzer_v12 import DeepAnalyzerThread, DeepAnalysisReport
from .theme import ACCENT, INK_SOFT, HEX_INK, BAD


class DeepAnalyzerPanel(QWidget):
    report_ready = pyqtSignal(object)   # DeepAnalysisReport

    def __init__(self, parent=None):
        super().__init__(parent)
        self.thread: DeepAnalyzerThread | None = None
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)

        header = QLabel(
            "DEEP ANALYSIS  —  fingerprint · WAF · crawl · 9-signal detect · weighted strength"
        )
        header.setProperty("section", True)
        lay.addWidget(header)

        # target row
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Target URL"))
        self.url = QLineEdit()
        self.url.setPlaceholderText("https://your-lab.local/")
        row1.addWidget(self.url, 5)
        lay.addLayout(row1)

        # crawler tuning
        crawl_box = QGroupBox("Crawler")
        cr = QHBoxLayout(crawl_box)
        cr.addWidget(QLabel("Max pages"))
        self.max_pages = QSpinBox(); self.max_pages.setRange(1, 500); self.max_pages.setValue(20)
        cr.addWidget(self.max_pages)
        cr.addWidget(QLabel("Depth"))
        self.max_depth = QSpinBox(); self.max_depth.setRange(0, 6); self.max_depth.setValue(2)
        cr.addWidget(self.max_depth)
        cr.addWidget(QLabel("Delay (ms)"))
        self.delay = QSpinBox(); self.delay.setRange(0, 5000); self.delay.setSingleStep(50); self.delay.setValue(250)
        cr.addWidget(self.delay)
        self.robots = QCheckBox("Respect robots.txt"); self.robots.setChecked(True)
        cr.addWidget(self.robots)
        cr.addStretch(1)
        lay.addWidget(crawl_box)

        # detector tuning
        det_box = QGroupBox("Deep Detector")
        dr = QVBoxLayout(det_box)
        r_top = QHBoxLayout()
        r_top.addWidget(QLabel("Rate/probe (ms)"))
        self.rate = QSpinBox(); self.rate.setRange(0, 5000); self.rate.setValue(150); self.rate.setSingleStep(50)
        r_top.addWidget(self.rate)
        r_top.addWidget(QLabel("Max reqs/target"))
        self.req_budget = QSpinBox(); self.req_budget.setRange(10, 400); self.req_budget.setValue(60)
        r_top.addWidget(self.req_budget)
        r_top.addStretch(1)
        dr.addLayout(r_top)

        r_sig = QHBoxLayout()
        self.sig_stacked = QCheckBox("S  stacked"); self.sig_stacked.setChecked(True)
        self.sig_header  = QCheckBox("H  header inject"); self.sig_header.setChecked(True)
        self.sig_second  = QCheckBox("2  second-order")
        self.sig_oob     = QCheckBox("O  OOB (needs callback)")
        for w in (self.sig_stacked, self.sig_header, self.sig_second, self.sig_oob):
            r_sig.addWidget(w)
        r_sig.addStretch(1)
        dr.addLayout(r_sig)

        r_ext = QHBoxLayout()
        r_ext.addWidget(QLabel("2nd-order read URL"))
        self.second_url = QLineEdit(); self.second_url.setPlaceholderText("https://target.local/profile")
        r_ext.addWidget(self.second_url, 3)
        r_ext.addWidget(QLabel("OOB callback host"))
        self.oob_host = QLineEdit(); self.oob_host.setPlaceholderText("collab.example.com")
        r_ext.addWidget(self.oob_host, 2)
        dr.addLayout(r_ext)

        lay.addWidget(det_box)

        # controls
        ctl = QHBoxLayout()
        self.btn_run = QPushButton("▶  RUN DEEP ANALYSIS")
        self.btn_run.setProperty("danger", True)
        self.btn_run.clicked.connect(self._on_run)
        self.btn_stop = QPushButton("■ ABORT")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._on_stop)
        ctl.addWidget(self.btn_run, 3)
        ctl.addWidget(self.btn_stop, 1)
        lay.addLayout(ctl)

        # progress
        self.progress = QProgressBar()
        self.progress.setRange(0, 4)
        self.progress.setValue(0)
        self.progress.setFormat("idle")
        lay.addWidget(self.progress)

        # log
        lay.addWidget(QLabel("Live log"))
        self.log = QPlainTextEdit(); self.log.setReadOnly(True)
        self.log.setStyleSheet(f"font-family:monospace; color:{HEX_INK};")
        lay.addWidget(self.log, 1)

        foot = QLabel(
            "⚠  Authorized targets only. Deep detector fires up to ~60 probes/target. "
            "Rate limit + budget are hard caps. OOB and 2nd-order are opt-in."
        )
        foot.setStyleSheet(f"color:{INK_SOFT}; padding:6px; font-style:italic;")
        foot.setWordWrap(True)
        lay.addWidget(foot)

    def _append(self, msg: str):
        self.log.appendPlainText(msg)

    def _on_run(self):
        url = self.url.text().strip()
        if not (url.startswith("http://") or url.startswith("https://")):
            self._append("[error] URL must start with http(s)://")
            return
        self.log.clear()
        self._append(f"[start] deep analysis on {url}")
        self.btn_run.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.progress.setValue(0)
        self.progress.setFormat("starting…")

        self.thread = DeepAnalyzerThread(
            seed_url=url,
            max_pages=self.max_pages.value(),
            max_depth=self.max_depth.value(),
            delay_ms=self.delay.value(),
            respect_robots=self.robots.isChecked(),
            run_detector=True,
            enable_stacked=self.sig_stacked.isChecked(),
            enable_header=self.sig_header.isChecked(),
            enable_second_order=self.sig_second.isChecked(),
            second_order_read_url=(self.second_url.text().strip() or None),
            oob_callback_host=(self.oob_host.text().strip() or None),
            rate_limit_ms=self.rate.value(),
            max_requests_per_target=self.req_budget.value(),
        )
        self.thread.progress.connect(self._append)
        self.thread.step.connect(self._on_step)
        self.thread.finished_report.connect(self._on_done)
        self.thread.failed.connect(self._on_failed)
        self.thread.start()

    def _on_stop(self):
        if self.thread:
            self.thread.request_abort()
            self._append("[abort] requested")

    def _on_step(self, name: str, cur: int, total: int):
        self.progress.setRange(0, total)
        self.progress.setValue(cur)
        self.progress.setFormat(f"{name}  {cur}/{total}")

    def _on_done(self, report: DeepAnalysisReport):
        self._append("[done] deep analysis complete")
        self.progress.setFormat("done")
        self.btn_run.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.report_ready.emit(report)

    def _on_failed(self, err: str):
        self._append(f"[fatal] {err}")
        self.progress.setFormat("failed")
        self.btn_run.setEnabled(True)
        self.btn_stop.setEnabled(False)
