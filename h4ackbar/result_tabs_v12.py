"""
H4ACKBAR v1.2.0 — result-tab widgets (deep findings, extraction tree, WAF).

Kept in a separate module so v1.1 result_tabs.py stays untouched and importable
by anything expecting the old surface.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QFont
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .detector_deep import DeepFinding
from .extractor import ExtractionReport
from .strength import strength_bar, strength_color
from .theme import ACCENT, BAD, HEX_INK, INK, INK_SOFT
from .waf import WAFResult


# ── DEEP Findings tab ───────────────────────────────────────
class DeepFindingsTab(QWidget):
    """Findings table with strength bars + per-signal metadata expander."""

    extract_requested = pyqtSignal(object)  # emits DeepFinding

    def __init__(self, findings: list[DeepFinding], parent=None):
        super().__init__(parent)
        self.findings = findings
        lay = QVBoxLayout(self)

        confirmed = [f for f in findings if f.confirmed()]
        critical = [f for f in findings if f.strength_grade == "critical"]
        strong   = [f for f in findings if f.strength_grade == "strong"]
        summary = QLabel(
            f"<b>{len(critical)}</b> critical &nbsp;·&nbsp; "
            f"<b>{len(strong)}</b> strong &nbsp;·&nbsp; "
            f"<b>{len(confirmed)}</b> confirmed &nbsp;·&nbsp; "
            f"<b>{len(findings)}</b> tested &nbsp;·&nbsp; "
            f"signals: E B T U S O H 2 W"
        )
        summary.setStyleSheet(f"color:{ACCENT}; padding:6px;")
        lay.addWidget(summary)

        split = QSplitter(Qt.Orientation.Vertical)
        lay.addWidget(split, 1)

        cols = ["Grade", "Strength", "Signals", "DBMS", "WAF", "Method",
                "Param", "Inject", "Reqs", "Tech", "URL"]
        self.table = QTableWidget(0, len(cols))
        self.table.setHorizontalHeaderLabels(cols)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSortingEnabled(True)
        self.table.itemSelectionChanged.connect(self._show_detail)

        # sort by strength desc initially
        sorted_findings = sorted(findings, key=lambda f: -f.strength)
        self.findings = sorted_findings

        for f in sorted_findings:
            r = self.table.rowCount(); self.table.insertRow(r)
            items = [
                QTableWidgetItem(f.strength_grade),
                QTableWidgetItem(f"{f.strength:.2f} {strength_bar(f.strength, 10)}"),
                QTableWidgetItem("".join(f.signals) or "-"),
                QTableWidgetItem(",".join(f.dbms_guess) or "-"),
                QTableWidgetItem(f.waf or "-"),
                QTableWidgetItem(f.method),
                QTableWidgetItem(f.param),
                QTableWidgetItem(f.inject_in),
                QTableWidgetItem(str(f.payloads_tried)),
                QTableWidgetItem(",".join(f.techniques) or "-"),
                QTableWidgetItem(f.url),
            ]
            grade_color = QColor(strength_color(f.strength_grade))
            for c, it in enumerate(items):
                if c in (0, 1):
                    it.setForeground(QBrush(grade_color))
                    font = QFont(); font.setBold(True); it.setFont(font)
                self.table.setItem(r, c, it)

        self.table.resizeColumnsToContents()
        split.addWidget(self.table)

        # bottom panel: details + action buttons
        bottom = QWidget(); bl = QVBoxLayout(bottom); bl.setContentsMargins(0,0,0,0)

        row = QHBoxLayout()
        self.btn_extract = QPushButton("💧  DEEP EXTRACT selected finding")
        self.btn_extract.setProperty("danger", True)
        self.btn_extract.setEnabled(False)
        self.btn_extract.clicked.connect(self._on_extract)
        row.addWidget(self.btn_extract, 3)

        self.btn_copy_cmd = QPushButton("📋  Copy auth-token")
        self.btn_copy_cmd.setEnabled(False)
        self.btn_copy_cmd.clicked.connect(self._on_copy_token)
        row.addWidget(self.btn_copy_cmd, 1)
        bl.addLayout(row)

        self.detail = QPlainTextEdit(); self.detail.setReadOnly(True)
        self.detail.setPlaceholderText("select a row to see signal metadata + strength breakdown")
        self.detail.setStyleSheet(f"font-family:monospace; color:{HEX_INK};")
        bl.addWidget(self.detail)

        split.addWidget(bottom)
        split.setSizes([320, 320])

    def _selected_finding(self) -> DeepFinding | None:
        rows = self.table.selectionModel().selectedRows()
        if not rows: return None
        i = rows[0].row()
        if i >= len(self.findings): return None
        return self.findings[i]

    def _show_detail(self):
        f = self._selected_finding()
        if not f:
            self.btn_extract.setEnabled(False)
            self.btn_copy_cmd.setEnabled(False)
            return
        # only allow extract on moderate+ AND at least one usable technique
        can_extract = f.strength_grade in ("moderate", "strong", "critical") and f.techniques
        self.btn_extract.setEnabled(can_extract)
        self.btn_copy_cmd.setEnabled(True)

        lines = [
            f"URL          : {f.url}",
            f"Method       : {f.method}   Param: {f.param}   Inject: {f.inject_in}",
            f"Signals      : {''.join(f.signals) or '-'}"
            + (f"   weak: {''.join(f.weak_signals)}" if f.weak_signals else ""),
            f"DBMS guess   : {','.join(f.dbms_guess) or '-'}",
            f"WAF          : {f.waf or '-'}",
            f"Techniques   : {', '.join(f.techniques) or '-'}",
            f"Strength     : {f.strength:.3f}  [{strength_bar(f.strength, 20)}]  "
            f"grade={f.strength_grade.upper()}",
            f"Baseline     : status={f.baseline_status}  len={f.baseline_length}",
            f"Requests     : {f.payloads_tried}",
            "",
            "─── PER-SIGNAL METADATA ─────────────────────",
        ]
        if f.signal_meta:
            for sig, meta in f.signal_meta.items():
                lines.append(f"[{sig}]")
                for k, v in meta.items():
                    lines.append(f"    {k}: {v}")
        else:
            lines.append("(no signals with metadata)")
        lines.append("")
        lines.append("─── EVIDENCE TRAIL ──────────────────────────")
        lines.extend(f.evidence or ["(none)"])
        if f.anomalies:
            lines.append("")
            lines.append("─── ANOMALIES ───────────────────────────────")
            lines.extend(f.anomalies)
        self.detail.setPlainText("\n".join(lines))

    def _on_extract(self):
        f = self._selected_finding()
        if not f: return
        self.extract_requested.emit(f)

    def _on_copy_token(self):
        from urllib.parse import urlparse

        from PyQt6.QtWidgets import QApplication
        f = self._selected_finding()
        if not f: return
        host = urlparse(f.url).hostname or "unknown"
        token = f"I-OWN-{host}"
        QApplication.clipboard().setText(token)


# ── Extraction tab (input + tree of results) ───────────────
class ExtractionTab(QWidget):
    """
    Extraction control + live results. Shown after user requests deep extract
    on a DeepFinding.
    """
    run_extraction = pyqtSignal(dict)   # payload dict for parent to spawn thread

    def __init__(self, finding: DeepFinding, parent=None):
        super().__init__(parent)
        self.finding = finding
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)

        head = QLabel(
            f"<h3 style='color:{ACCENT};margin:0'>Deep Extraction</h3>"
            f"<span style='color:{INK_SOFT}'>target: <b>{self.finding.url}</b>  "
            f"param=<b>{self.finding.param}</b>  dbms=<b>"
            f"{','.join(self.finding.dbms_guess) or 'unknown'}</b>  "
            f"strength=<b>{self.finding.strength:.2f}</b> ({self.finding.strength_grade})</span>"
        )
        head.setWordWrap(True)
        lay.addWidget(head)

        # auth gate
        gate = QGroupBox("AUTHORIZATION GATE  (mandatory)")
        gate.setStyleSheet(f"QGroupBox {{ color:{BAD}; font-weight:bold; }}")
        gl = QVBoxLayout(gate)

        from urllib.parse import urlparse
        host = urlparse(self.finding.url).hostname or "unknown"
        expected = f"I-OWN-{host}"

        msg = QLabel(
            f"To run deep extraction on <b>{host}</b>, paste the exact token below:<br>"
            f"<code style='color:{ACCENT}; font-size:12pt'>{expected}</code><br>"
            f"<i style='color:{INK_SOFT}'>Extraction READS live data from the target. "
            f"Only proceed on systems you own or are explicitly authorized to test. "
            f"H4ACKBAR blocks all write/exec SQL tokens (INSERT/UPDATE/DELETE/DROP/exec/…) "
            f"but the responsibility for scope is yours.</i>"
        )
        msg.setWordWrap(True); msg.setTextFormat(Qt.TextFormat.RichText)
        gl.addWidget(msg)

        row = QHBoxLayout()
        self.token = QLineEdit(); self.token.setPlaceholderText(expected)
        row.addWidget(self.token, 5)
        gl.addLayout(row)
        lay.addWidget(gate)

        # target selection
        pick = QGroupBox("Extraction targets")
        pl = QHBoxLayout(pick)
        self.cb_banner  = QCheckBox("banner");       self.cb_banner.setChecked(True)
        self.cb_version = QCheckBox("version");      self.cb_version.setChecked(True)
        self.cb_user    = QCheckBox("current_user"); self.cb_user.setChecked(True)
        self.cb_db      = QCheckBox("current_db");   self.cb_db.setChecked(True)
        self.cb_dbs     = QCheckBox("databases")
        self.cb_tables  = QCheckBox("tables")
        self.cb_cols    = QCheckBox("columns (expensive)")
        for w in (self.cb_banner, self.cb_version, self.cb_user, self.cb_db,
                  self.cb_dbs, self.cb_tables, self.cb_cols):
            pl.addWidget(w)
        pl.addStretch(1)
        lay.addWidget(pick)

        # tuning
        tune = QGroupBox("Tuning")
        tl = QHBoxLayout(tune)
        tl.addWidget(QLabel("Rate (ms)"))
        self.rate = QLineEdit("200"); self.rate.setMaximumWidth(70); tl.addWidget(self.rate)
        tl.addWidget(QLabel("Max chars/field"))
        self.max_len = QLineEdit("64"); self.max_len.setMaximumWidth(70); tl.addWidget(self.max_len)
        tl.addWidget(QLabel("Request budget"))
        self.budget = QLineEdit("800"); self.budget.setMaximumWidth(80); tl.addWidget(self.budget)
        tl.addWidget(QLabel("Technique"))
        self.tech = QComboBox()
        self.tech.addItem("auto (from finding)")
        for t in ("union", "error", "boolean", "time"):
            self.tech.addItem(t)
        tl.addWidget(self.tech)
        tl.addStretch(1)
        lay.addWidget(tune)

        # controls
        ctl = QHBoxLayout()
        self.btn_run = QPushButton("▶  RUN EXTRACTION")
        self.btn_run.setProperty("danger", True)
        self.btn_run.clicked.connect(self._on_run)
        self.btn_stop = QPushButton("■ ABORT")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._on_stop)
        self.btn_export = QPushButton("💾 Export JSON")
        self.btn_export.setEnabled(False)
        self.btn_export.clicked.connect(self._on_export)
        ctl.addWidget(self.btn_run, 3)
        ctl.addWidget(self.btn_stop, 1)
        ctl.addWidget(self.btn_export, 1)
        lay.addLayout(ctl)

        self.bar = QProgressBar(); self.bar.setRange(0, 0); self.bar.setVisible(False)
        lay.addWidget(self.bar)

        # results split: tree | log
        split = QSplitter(Qt.Orientation.Horizontal)
        lay.addWidget(split, 1)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Item", "Value", "Technique", "Reqs", "Time (s)"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        split.addWidget(self.tree)

        self.log = QPlainTextEdit(); self.log.setReadOnly(True)
        self.log.setStyleSheet(f"font-family:monospace; color:{HEX_INK};")
        split.addWidget(self.log)
        split.setSizes([500, 500])

        # store latest report for export
        self._last_report: ExtractionReport | None = None

    def _on_run(self):
        targets = []
        if self.cb_banner.isChecked():  targets.append("banner")
        if self.cb_version.isChecked(): targets.append("version")
        if self.cb_user.isChecked():    targets.append("user")
        if self.cb_db.isChecked():      targets.append("db")
        if self.cb_dbs.isChecked():     targets.append("databases")
        if self.cb_tables.isChecked():  targets.append("tables")
        if self.cb_cols.isChecked():    targets.append("columns")

        try:
            payload = {
                "finding": self.finding,
                "auth_token": self.token.text().strip(),
                "targets": targets,
                "rate_limit_ms": int(self.rate.text() or "200"),
                "max_len_per_field": int(self.max_len.text() or "64"),
                "max_total_requests": int(self.budget.text() or "800"),
                "technique_override": self.tech.currentText(),
            }
        except ValueError as e:
            QMessageBox.warning(self, "H4ACKBAR", f"bad tuning value: {e}")
            return
        self.btn_run.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.bar.setVisible(True)
        self.log.clear()
        self.tree.clear()
        self.run_extraction.emit(payload)

    def _on_stop(self):
        # parent wires this — we just re-enable
        self.btn_stop.setEnabled(False)
        self.btn_run.setEnabled(True)
        self.bar.setVisible(False)
        self.log.appendPlainText("[abort] requested")

    def append_log(self, msg: str):
        self.log.appendPlainText(msg)

    def refused(self, err: str):
        self.btn_run.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.bar.setVisible(False)
        QMessageBox.critical(self, "EXTRACTION REFUSED", err)

    def render_report(self, report: ExtractionReport):
        self._last_report = report
        self.btn_run.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.btn_export.setEnabled(True)
        self.bar.setVisible(False)
        self.tree.clear()

        head = QTreeWidgetItem([
            f"Target ({report.dbms})", report.target_url,
            report.technique_used, str(report.total_requests),
            str(report.duration_s),
        ])
        head.setForeground(0, QBrush(QColor(ACCENT)))
        self.tree.addTopLevelItem(head)

        def add(parent: QTreeWidgetItem, label: str, cell):
            v = cell.value if cell and cell.value else "(none)"
            t = cell.technique if cell else ""
            r = str(cell.requests) if cell else ""
            d = str(cell.duration_s) if cell else ""
            it = QTreeWidgetItem([label, v, t, r, d])
            if cell and cell.error:
                it.setForeground(1, QBrush(QColor(BAD)))
                it.setToolTip(1, cell.error)
            parent.addChild(it)

        add(head, "banner",       report.banner)
        add(head, "version",      report.version)
        add(head, "current_user", report.current_user)
        add(head, "current_db",   report.current_db)

        if report.databases:
            dbs = QTreeWidgetItem(["databases", f"({len(report.databases)})", "", "", ""])
            head.addChild(dbs)
            for db in report.databases:
                dbs.addChild(QTreeWidgetItem([db, "", "", "", ""]))

        for db, tbls in report.tables.items():
            tnode = QTreeWidgetItem([f"tables[{db}]", f"({len(tbls)})", "", "", ""])
            head.addChild(tnode)
            for t in tbls:
                titem = QTreeWidgetItem([t, "", "", "", ""])
                tnode.addChild(titem)
                cols = report.columns.get(f"{db}.{t}", [])
                for c in cols:
                    titem.addChild(QTreeWidgetItem([f"  · {c}", "", "", "", ""]))

        head.setExpanded(True)
        for i in range(head.childCount()):
            head.child(i).setExpanded(True)

        if report.errors:
            self.log.appendPlainText("── errors ──")
            for e in report.errors: self.log.appendPlainText(f"  {e}")

    def _on_export(self):
        import json
        if not self._last_report:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export extraction", "h4ackbar_extraction.json", "JSON (*.json)"
        )
        if not path: return
        def cell_dict(c):
            if not c: return None
            return {
                "label": c.label, "value": c.value, "technique": c.technique,
                "requests": c.requests, "duration_s": c.duration_s,
                "error": c.error, "confidence": c.confidence,
            }
        r = self._last_report
        data = {
            "target_url": r.target_url, "param": r.param, "method": r.method,
            "inject_in": r.inject_in, "dbms": r.dbms,
            "technique_used": r.technique_used,
            "banner":       cell_dict(r.banner),
            "version":      cell_dict(r.version),
            "current_user": cell_dict(r.current_user),
            "current_db":   cell_dict(r.current_db),
            "databases":    r.databases,
            "tables":       r.tables,
            "columns":      r.columns,
            "total_requests": r.total_requests,
            "duration_s":     r.duration_s,
            "errors":         r.errors,
            "log":            r.log,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        self.log.appendPlainText(f"[export] wrote {path}")


# ── WAF tab ─────────────────────────────────────────────────
class WAFTab(QWidget):
    def __init__(self, waf: WAFResult, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        head = QLabel(f"<h3 style='color:{ACCENT};margin:0'>WAF Analysis</h3>")
        lay.addWidget(head)
        summary = QLabel(waf.summary())
        summary.setStyleSheet(f"color:{INK}; padding:6px; font-family:monospace;")
        lay.addWidget(summary)

        lay.addWidget(QLabel("Detected"))
        det = QPlainTextEdit(); det.setReadOnly(True); det.setMaximumHeight(80)
        det.setPlainText("\n".join(waf.detected) or "(none)")
        lay.addWidget(det)

        lay.addWidget(QLabel("Evidence"))
        ev = QPlainTextEdit(); ev.setReadOnly(True); ev.setMaximumHeight(150)
        ev.setPlainText("\n".join(waf.evidence) or "(none)")
        lay.addWidget(ev)

        lay.addWidget(QLabel("Suggested tampers (use encoders.py chain names)"))
        tm = QPlainTextEdit(); tm.setReadOnly(True)
        tm.setPlainText("\n".join(f"• {t}" for t in waf.tampers) or "(none)")
        lay.addWidget(tm, 1)
