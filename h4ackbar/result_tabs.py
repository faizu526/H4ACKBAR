"""
H4ACKBAR result-tab widgets.
Each analysis emits a set of tabs added to the main QTabWidget.
"""


from PyQt6.QtCore import Qt
from PyQt6.QtGui import QBrush, QColor, QFont
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .crawler import CrawlReport
from .detector import Finding
from .fingerprint import Fingerprint
from .theme import ACCENT, BAD, CREAM_INPUT, HEX_INK, INK, INK_SOFT, WARN


def _confidence_color(conf: str) -> QColor:
    return {
        "high":   QColor(BAD),
        "medium": QColor(WARN),
        "low":    QColor(INK_SOFT),
        "none":   QColor("#999999"),
    }.get(conf, QColor(INK_SOFT))


# ── Findings tab ────────────────────────────────────────────
class FindingsTab(QWidget):
    def __init__(self, findings: list[Finding], parent=None):
        super().__init__(parent)
        self.findings = findings
        lay = QVBoxLayout(self)

        confirmed = [f for f in findings if f.confirmed()]
        summary = QLabel(
            f"<b>{len(confirmed)}</b> confirmed &nbsp;·&nbsp; "
            f"<b>{len(findings)}</b> tested &nbsp;·&nbsp; "
            f"signals: E=error B=bool T=time U=union"
        )
        summary.setStyleSheet(f"color:{ACCENT}; padding:6px;")
        lay.addWidget(summary)

        split = QSplitter(Qt.Orientation.Vertical)
        lay.addWidget(split, 1)

        # table
        cols = ["Conf", "Signals", "DBMS", "Method", "Param", "Inject", "Payloads", "URL"]
        self.table = QTableWidget(0, len(cols))
        self.table.setHorizontalHeaderLabels(cols)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSortingEnabled(True)
        self.table.itemSelectionChanged.connect(self._show_detail)

        for f in findings:
            r = self.table.rowCount(); self.table.insertRow(r)
            items = [
                QTableWidgetItem(f.confidence),
                QTableWidgetItem("".join(f.signals) or "-"),
                QTableWidgetItem(",".join(f.dbms_guess) or "-"),
                QTableWidgetItem(f.method),
                QTableWidgetItem(f.param),
                QTableWidgetItem(f.inject_in),
                QTableWidgetItem(str(f.payloads_tried)),
                QTableWidgetItem(f.url),
            ]
            color = _confidence_color(f.confidence)
            brush = QBrush(color)
            for c, it in enumerate(items):
                if c == 0:
                    it.setForeground(brush)
                    font = QFont(); font.setBold(True); it.setFont(font)
                self.table.setItem(r, c, it)

        self.table.resizeColumnsToContents()
        split.addWidget(self.table)

        # detail pane
        self.detail = QPlainTextEdit(); self.detail.setReadOnly(True)
        self.detail.setPlaceholderText("select a row to see evidence")
        split.addWidget(self.detail)
        split.setSizes([300, 200])

    def _show_detail(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        i = rows[0].row()
        if i >= len(self.findings):
            return
        f = self.findings[i]
        lines = [
            f"URL       : {f.url}",
            f"Method    : {f.method}",
            f"Param     : {f.param}",
            f"Inject in : {f.inject_in}",
            f"Signals   : {''.join(f.signals) or '-'}",
            f"DBMS guess: {','.join(f.dbms_guess) or '-'}",
            f"Confidence: {f.confidence.upper()}",
            f"Baseline  : status={f.baseline_status} len={f.baseline_length}",
            f"Payloads  : {f.payloads_tried} requests fired",
            "",
            "─── EVIDENCE ─────────────────────────────",
        ]
        lines.extend(f.evidence or ["(none)"])
        self.detail.setPlainText("\n".join(lines))


# ── Fingerprint tab ────────────────────────────────────────
class FingerprintTab(QWidget):
    def __init__(self, fp: Fingerprint, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)

        head = QLabel(f"<h3 style='color:{ACCENT};margin:0'>Target Stack</h3>")
        lay.addWidget(head)
        summary = QLabel(fp.summary())
        summary.setStyleSheet(f"color:{INK}; padding:4px; font-family:monospace;")
        lay.addWidget(summary)

        # k/v panels
        panels = QHBoxLayout()
        panels.addWidget(self._panel("Frameworks", fp.frameworks or ["—"]))
        panels.addWidget(self._panel("DBMS",       fp.dbms       or ["—"]))
        panels.addWidget(self._panel("Server",     [fp.server]   if fp.server else ["—"]))
        lay.addLayout(panels)

        lay.addWidget(QLabel("Evidence:"))
        ev = QPlainTextEdit(); ev.setReadOnly(True)
        ev.setPlainText("\n".join(fp.evidence) if fp.evidence else "(no signals)")
        lay.addWidget(ev, 1)

    def _panel(self, title: str, items: list[str]) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w); v.setContentsMargins(4,4,4,4)
        t = QLabel(f"<b>{title}</b>"); t.setStyleSheet(f"color:{ACCENT};")
        v.addWidget(t)
        body = QLabel("\n".join(f"• {x}" for x in items))
        body.setStyleSheet(f"background:{CREAM_INPUT}; padding:8px; font-family:monospace;")
        body.setWordWrap(True)
        v.addWidget(body, 1)
        return w


# ── Crawl tab ──────────────────────────────────────────────
class CrawlTab(QWidget):
    def __init__(self, report: CrawlReport, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)

        summary = QLabel(
            f"<b>{len(report.pages_visited)}</b> pages &nbsp;·&nbsp; "
            f"<b>{len(report.targets)}</b> targets &nbsp;·&nbsp; "
            f"<b>{report.duration_s}</b> s"
        )
        summary.setStyleSheet(f"color:{ACCENT}; padding:6px;")
        lay.addWidget(summary)

        split = QSplitter(Qt.Orientation.Horizontal)
        lay.addWidget(split, 1)

        # visited
        left = QWidget(); lv = QVBoxLayout(left); lv.setContentsMargins(0,0,0,0)
        lv.addWidget(QLabel("Pages visited"))
        pages = QPlainTextEdit(); pages.setReadOnly(True)
        pages.setPlainText("\n".join(report.pages_visited) or "(none)")
        lv.addWidget(pages)
        split.addWidget(left)

        # targets
        right = QWidget(); rv = QVBoxLayout(right); rv.setContentsMargins(0,0,0,0)
        rv.addWidget(QLabel("Injection targets discovered"))
        table = QTableWidget(0, 5)
        table.setHorizontalHeaderLabels(["Method","Param","Inject","URL","Source"])
        table.horizontalHeader().setStretchLastSection(True)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        for t in report.targets:
            r = table.rowCount(); table.insertRow(r)
            table.setItem(r,0,QTableWidgetItem(t.method))
            table.setItem(r,1,QTableWidgetItem(t.param))
            table.setItem(r,2,QTableWidgetItem(t.inject_in))
            table.setItem(r,3,QTableWidgetItem(t.url))
            table.setItem(r,4,QTableWidgetItem(t.source))
        table.resizeColumnsToContents()
        rv.addWidget(table)
        split.addWidget(right)
        split.setSizes([400, 700])

        if report.errors:
            errs = QPlainTextEdit(); errs.setReadOnly(True); errs.setMaximumHeight(90)
            errs.setPlainText("\n".join(report.errors))
            lay.addWidget(QLabel("Errors / skipped:"))
            lay.addWidget(errs)


# ── Log tab ────────────────────────────────────────────────
class LogTab(QWidget):
    def __init__(self, log: list[str], parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("Full run log"))
        te = QPlainTextEdit(); te.setReadOnly(True)
        te.setPlainText("\n".join(log))
        te.setStyleSheet(f"font-family:monospace; color:{HEX_INK};")
        lay.addWidget(te, 1)
