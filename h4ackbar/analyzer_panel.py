"""
H4ACKBAR analyzer panel widget.
Sits inside the 'Analyze' tab in the main window.
Fires AnalyzerThread and emits when a report is ready so the parent
can create result tabs.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QSpinBox,
    QCheckBox, QPushButton, QPlainTextEdit, QProgressBar,
)
from PyQt6.QtCore import pyqtSignal, Qt

from .analyzer import AnalyzerThread, AnalysisReport
from .theme import ACCENT, INK_SOFT, HEX_INK


class AnalyzerPanel(QWidget):
    report_ready = pyqtSignal(object)   # AnalysisReport

    def __init__(self, parent=None):
        super().__init__(parent)
        self.thread: AnalyzerThread | None = None
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)

        header = QLabel("AUTOMATED ANALYSIS  —  fingerprint · crawl · detect")
        header.setProperty("section", True)
        lay.addWidget(header)

        # target row
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Target URL"))
        self.url = QLineEdit()
        self.url.setPlaceholderText("https://your-lab.local/")
        row1.addWidget(self.url, 5)
        lay.addLayout(row1)

        # options row
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Max pages"))
        self.max_pages = QSpinBox(); self.max_pages.setRange(1, 200); self.max_pages.setValue(20)
        row2.addWidget(self.max_pages)

        row2.addSpacing(12)
        row2.addWidget(QLabel("Depth"))
        self.max_depth = QSpinBox(); self.max_depth.setRange(0, 5); self.max_depth.setValue(2)
        row2.addWidget(self.max_depth)

        row2.addSpacing(12)
        row2.addWidget(QLabel("Delay (ms)"))
        self.delay = QSpinBox(); self.delay.setRange(0, 5000); self.delay.setSingleStep(50); self.delay.setValue(250)
        row2.addWidget(self.delay)

        row2.addSpacing(12)
        self.robots = QCheckBox("Respect robots.txt"); self.robots.setChecked(True)
        row2.addWidget(self.robots)

        self.detect = QCheckBox("Run detector (3-signal)"); self.detect.setChecked(True)
        row2.addWidget(self.detect)

        row2.addStretch(1)
        lay.addLayout(row2)

        # controls
        row3 = QHBoxLayout()
        self.btn_run = QPushButton("▶  RUN ANALYSIS")
        self.btn_run.setProperty("danger", True)
        self.btn_run.clicked.connect(self._on_run)
        self.btn_stop = QPushButton("■ ABORT"); self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._on_stop)
        row3.addWidget(self.btn_run, 3)
        row3.addWidget(self.btn_stop, 1)
        lay.addLayout(row3)

        # progress
        self.progress = QProgressBar()
        self.progress.setRange(0, 3)
        self.progress.setValue(0)
        self.progress.setFormat("idle")
        lay.addWidget(self.progress)

        # live log
        lay.addWidget(QLabel("Live log"))
        self.log = QPlainTextEdit(); self.log.setReadOnly(True)
        self.log.setStyleSheet(f"font-family:monospace; color:{HEX_INK};")
        lay.addWidget(self.log, 1)

        footer = QLabel(
            "⚠  Authorized targets only. Crawler respects robots.txt "
            "and stays same-origin. Detector fires only probe payloads."
        )
        footer.setStyleSheet(f"color:{INK_SOFT}; padding:6px; font-style:italic;")
        footer.setWordWrap(True)
        lay.addWidget(footer)

    def _append(self, msg: str):
        self.log.appendPlainText(msg)

    def _on_run(self):
        url = self.url.text().strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            self._append("[error] URL must start with http(s)://")
            return
        self.log.clear()
        self._append(f"[start] {url}")
        self.btn_run.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.progress.setValue(0)
        self.progress.setFormat("starting…")

        self.thread = AnalyzerThread(
            seed_url=url,
            max_pages=self.max_pages.value(),
            max_depth=self.max_depth.value(),
            delay_ms=self.delay.value(),
            respect_robots=self.robots.isChecked(),
            run_detector=self.detect.isChecked(),
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

    def _on_done(self, report: AnalysisReport):
        self._append("[done] analysis complete")
        self.progress.setFormat("done")
        self.btn_run.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.report_ready.emit(report)

    def _on_failed(self, err: str):
        self._append(f"[fatal] {err}")
        self.progress.setFormat("failed")
        self.btn_run.setEnabled(True)
        self.btn_stop.setEnabled(False)
