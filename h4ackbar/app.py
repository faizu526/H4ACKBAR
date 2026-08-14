#!/usr/bin/env python3
"""
H4ACKBAR — SQLi payload workbench (desktop, PyQt6).
Enhanced UI:
  - cream/light theme with red-oxide accents
  - SVG banner header
  - main QTabWidget: Workbench | Analyze | (dynamic result tabs per run)
  - automated analyzer: fingerprint → crawl → detect → new tab with findings

Authorized security testing only.
"""

import json
import sys
from datetime import datetime

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QFont, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from . import __version__
from .analyzer import AnalysisReport
from .analyzer_panel import AnalyzerPanel

# v1.2.0 additions
from .analyzer_panel_v12 import DeepAnalyzerPanel
from .analyzer_v12 import DeepAnalysisReport, ExtractionThread
from .banner import Banner
from .chain import Chain, preset_chains
from .detector_deep import DeepFinding
from .encoders import ENCODERS, hex_grid
from .payloads import Payload, all_payloads, categories
from .result_tabs import CrawlTab, FindingsTab, FingerprintTab, LogTab
from .result_tabs_v12 import DeepFindingsTab, ExtractionTab, WAFTab
from .sender import send
from .theme import ACCENT, stylesheet


# ─────────────────────────────────────────────────────────────
#  COMMAND LAUNCHER  (Ctrl+K)
# ─────────────────────────────────────────────────────────────
class CommandLauncher(QDialog):
    def __init__(self, parent, actions: dict):
        super().__init__(parent)
        self.setWindowTitle("H4ACKBAR :: Command Launcher")
        self.resize(620, 420)
        self.actions_map = actions
        self.setModal(True)

        lay = QVBoxLayout(self)
        self.input = QLineEdit(self)
        self.input.setPlaceholderText("type command...  (esc to close)")
        self.input.textChanged.connect(self.filter_list)
        self.list = QListWidget(self)
        self.list.itemActivated.connect(self.trigger)
        lay.addWidget(self.input)
        lay.addWidget(self.list)

        for name in sorted(actions.keys()):
            self.list.addItem(QListWidgetItem(name))

        self.input.setFocus()
        self.input.returnPressed.connect(self.trigger_first)
        QShortcut(QKeySequence("Esc"), self, self.reject)

    def filter_list(self, text: str):
        text = text.lower()
        for i in range(self.list.count()):
            it = self.list.item(i)
            it.setHidden(text not in it.text().lower())

    def trigger_first(self):
        for i in range(self.list.count()):
            it = self.list.item(i)
            if not it.isHidden():
                self.trigger(it)
                return

    def trigger(self, item: QListWidgetItem):
        name = item.text()
        self.accept()
        cb = self.actions_map.get(name)
        if cb:
            cb()


# ─────────────────────────────────────────────────────────────
#  WORKBENCH TAB — original payload/chain/sender surface
# ─────────────────────────────────────────────────────────────
class WorkbenchTab(QWidget):
    def __init__(self, main, parent=None):
        super().__init__(parent)
        self.main = main
        self._build()
        self.chain = Chain(seed="")
        self._all_payloads: list[Payload] = []
        self._reload_payloads()

    # ── UI ─────────────────────────────────────────────────
    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        # top bar: search + cat
        top = QHBoxLayout()
        lbl = QLabel("SEARCH"); lbl.setProperty("section", True); top.addWidget(lbl)
        self.search = QLineEdit()
        self.search.setPlaceholderText("filter payloads...  (Ctrl+F)")
        self.search.textChanged.connect(self._filter_table)
        top.addWidget(self.search, 3)
        lbl2 = QLabel("CATEGORY"); lbl2.setProperty("section", True); top.addWidget(lbl2)
        self.cat_combo = QComboBox()
        self.cat_combo.addItem("ALL", None)
        for k, v in categories().items():
            self.cat_combo.addItem(v, k)
        self.cat_combo.currentIndexChanged.connect(self._filter_table)
        top.addWidget(self.cat_combo, 1)
        root.addLayout(top)

        split_main = QSplitter(Qt.Orientation.Horizontal)
        root.addWidget(split_main, 1)

        # left: tree
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Category"])
        self.tree.itemClicked.connect(self._tree_clicked)
        split_main.addWidget(self.tree)

        # center: table
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Cat", "Label", "Payload", "Notes"])
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hh.setStretchLastSection(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self._row_selected)
        self.table.setSortingEnabled(True)
        split_main.addWidget(self.table)

        # right: chain / preview / hex / send
        right = QWidget()
        rlay = QVBoxLayout(right); rlay.setContentsMargins(0, 0, 0, 0)

        lab = QLabel("CHAIN  [seed → mutators → encoders → wire]")
        lab.setProperty("section", True); rlay.addWidget(lab)

        chain_row = QHBoxLayout()
        self.mut_combo = QComboBox(); self.mut_combo.addItems(sorted(ENCODERS.keys()))
        self.enc_combo = QComboBox(); self.enc_combo.addItems(sorted(ENCODERS.keys()))
        btn_add_mut = QPushButton("+ Mutator"); btn_add_mut.clicked.connect(self._add_mutator)
        btn_add_enc = QPushButton("+ Encoder"); btn_add_enc.clicked.connect(self._add_encoder)
        btn_clear   = QPushButton("Clear");     btn_clear.clicked.connect(self._clear_chain)
        chain_row.addWidget(self.mut_combo); chain_row.addWidget(btn_add_mut)
        chain_row.addWidget(self.enc_combo); chain_row.addWidget(btn_add_enc)
        chain_row.addWidget(btn_clear)
        rlay.addLayout(chain_row)

        self.chain_label = QLabel("SEED → WIRE")
        self.chain_label.setStyleSheet(
            f"color:{ACCENT}; padding:6px; background:#efe4c9; "
            f"border:1px solid #c8b98a; border-radius:3px; font-family:monospace;"
        )
        rlay.addWidget(self.chain_label)

        lp = QLabel("PREVIEW"); lp.setProperty("section", True); rlay.addWidget(lp)
        self.preview = QPlainTextEdit(); self.preview.setMaximumHeight(120)
        rlay.addWidget(self.preview)

        lh = QLabel("HEX GRID"); lh.setProperty("section", True); rlay.addWidget(lh)
        self.hex_view = QPlainTextEdit(); self.hex_view.setReadOnly(True)
        self.hex_view.setFont(QFont("JetBrains Mono", 10))
        rlay.addWidget(self.hex_view, 1)

        lpr = QLabel("PRESET CHAINS"); lpr.setProperty("section", True); rlay.addWidget(lpr)
        self.preset_list = QListWidget(); self.preset_list.setMaximumHeight(160)
        self.preset_list.itemActivated.connect(self._apply_preset)
        rlay.addWidget(self.preset_list)

        ls = QLabel("SEND  [authorized only]"); ls.setProperty("section", True); rlay.addWidget(ls)

        send_row1 = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://your-lab.local/vuln.php")
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST", "PUT", "DELETE"])
        send_row1.addWidget(self.url_input, 4)
        send_row1.addWidget(self.method_combo, 1)
        rlay.addLayout(send_row1)

        send_row2 = QHBoxLayout()
        self.param_input = QLineEdit()
        self.param_input.setPlaceholderText("param name (e.g. id)")
        self.inject_combo = QComboBox()
        self.inject_combo.addItems(["query", "body", "header", "path"])
        btn_send = QPushButton("FIRE")
        btn_send.setProperty("danger", True)
        btn_send.clicked.connect(self._fire)
        send_row2.addWidget(self.param_input, 2)
        send_row2.addWidget(self.inject_combo, 1)
        send_row2.addWidget(btn_send, 1)
        rlay.addLayout(send_row2)

        lr = QLabel("RESPONSE"); lr.setProperty("section", True); rlay.addWidget(lr)
        self.response_view = QPlainTextEdit(); self.response_view.setReadOnly(True)
        rlay.addWidget(self.response_view, 1)

        split_main.addWidget(right)
        split_main.setSizes([200, 550, 750])

    # ── data ───────────────────────────────────────────────
    def _reload_payloads(self):
        self._all_payloads = all_payloads()
        self.tree.clear()
        root = QTreeWidgetItem(["ALL"])
        self.tree.addTopLevelItem(root)
        for k, v in categories().items():
            n = sum(1 for p in self._all_payloads if p.category == k)
            it = QTreeWidgetItem([f"{v}  ({n})"])
            it.setData(0, Qt.ItemDataRole.UserRole, k)
            root.addChild(it)
        root.setExpanded(True)
        self._fill_table(self._all_payloads)
        self.main.status.showMessage(f"{len(self._all_payloads)} payloads loaded")

    def _fill_table(self, plist: list[Payload]):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for p in plist:
            r = self.table.rowCount(); self.table.insertRow(r)
            self.table.setItem(r, 0, QTableWidgetItem(p.category))
            self.table.setItem(r, 1, QTableWidgetItem(p.label))
            self.table.setItem(r, 2, QTableWidgetItem(p.payload))
            self.table.setItem(r, 3, QTableWidgetItem(p.notes))
        self.table.resizeColumnsToContents()
        self.table.setSortingEnabled(True)

    def _tree_clicked(self, item, _col):
        key = item.data(0, Qt.ItemDataRole.UserRole)
        if key is None:
            self._fill_table(self._all_payloads)
        else:
            self._fill_table([p for p in self._all_payloads if p.category == key])

    def _filter_table(self):
        q = self.search.text().lower()
        cat_key = self.cat_combo.currentData()
        out = []
        for p in self._all_payloads:
            if cat_key and p.category != cat_key:
                continue
            hay = f"{p.category} {p.label} {p.payload} {p.notes}".lower()
            if q and q not in hay:
                continue
            out.append(p)
        self._fill_table(out)

    def _row_selected(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        r = rows[0].row()
        p = Payload(
            category=self.table.item(r, 0).text(),
            label=self.table.item(r, 1).text(),
            payload=self.table.item(r, 2).text(),
            notes=self.table.item(r, 3).text(),
        )
        self.chain.seed = p.payload
        self._refresh_preview()
        self._refresh_presets()

    # ── chain ──────────────────────────────────────────────
    def _add_mutator(self):
        self.chain.mutators.append(self.mut_combo.currentText()); self._refresh_preview()
    def _add_encoder(self):
        self.chain.encoders.append(self.enc_combo.currentText()); self._refresh_preview()
    def _clear_chain(self):
        self.chain.mutators.clear(); self.chain.encoders.clear(); self._refresh_preview()

    def _refresh_preview(self):
        try:
            wire = self.chain.render() if self.chain.seed else ""
        except Exception as e:
            wire = f"[chain error] {e}"
        self.preview.setPlainText(wire)
        self.chain_label.setText(self.chain.describe())
        self.hex_view.setPlainText(hex_grid(wire) if wire else "")

    def _refresh_presets(self):
        self.preset_list.clear()
        if not self.chain.seed:
            return
        for c in preset_chains(self.chain.seed):
            it = QListWidgetItem(f"{c.describe()}   →   {c.render()[:80]}")
            it.setData(Qt.ItemDataRole.UserRole, (c.mutators, c.encoders))
            self.preset_list.addItem(it)

    def _apply_preset(self, item: QListWidgetItem):
        muts, encs = item.data(Qt.ItemDataRole.UserRole)
        self.chain.mutators = list(muts); self.chain.encoders = list(encs)
        self._refresh_preview()

    # ── fire ───────────────────────────────────────────────
    def _fire(self):
        url = self.url_input.text().strip()
        param = self.param_input.text().strip()
        payload = self.preview.toPlainText()
        inject = self.inject_combo.currentText()

        if not url or not payload:
            self.response_view.setPlainText("[error] URL or payload empty"); return
        if not param and inject != "path":
            self.response_view.setPlainText("[error] param name required"); return
        if not (url.startswith("http://") or url.startswith("https://")):
            self.response_view.setPlainText("[error] URL must start with http(s)://"); return

        r = send(url, self.method_combo.currentText(),
                 payload, param, inject_in=inject)
        if r.error:
            body = f"[send error] {r.error}"
        else:
            hdr = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body = (f"HTTP {r.status}   {r.elapsed_ms} ms   {r.length} bytes\n"
                    f"{'─'*60}\n{hdr}\n{'─'*60}\n{r.body}")
        self.response_view.setPlainText(body)
        self.main.status.showMessage(
            f"status={r.status}  elapsed={r.elapsed_ms}ms  len={r.length}", 5000
        )

    # public helpers used by command launcher
    def copy_preview(self):
        QApplication.clipboard().setText(self.preview.toPlainText())
        self.main.status.showMessage("preview copied", 2000)


# ─────────────────────────────────────────────────────────────
#  MAIN WINDOW
# ─────────────────────────────────────────────────────────────
class H4ackBar(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"H4ACKBAR v{__version__} :: SQLi Workbench")
        self.resize(1600, 980)
        self.setStyleSheet(stylesheet())
        self._build()
        self._register_commands()
        self._bind_shortcuts()

    def _build(self):
        # menu
        mb = self.menuBar()
        m_file = mb.addMenu("&File")
        m_file.addAction(QAction("Export session (JSON)", self, triggered=self._export_session))
        m_file.addSeparator()
        m_file.addAction(QAction("Exit", self, triggered=self.close))
        m_run = mb.addMenu("&Run")
        m_run.addAction(QAction("Command launcher (Ctrl+K)", self, triggered=self._open_launcher))
        m_help = mb.addMenu("&Help")
        m_help.addAction(QAction(f"About H4ACKBAR v{__version__}", self, triggered=self._about))

        # central
        central = QWidget(self)
        self.setCentralWidget(central)
        outer = QVBoxLayout(central); outer.setContentsMargins(0, 0, 0, 0); outer.setSpacing(0)

        outer.addWidget(Banner())

        # status FIRST — child widgets reference self.status during init
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage(
            f"H4ACKBAR v{__version__}  •  authorized testing only  •  Ctrl+K launcher"
        )

        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self._close_tab)
        outer.addWidget(self.tabs, 1)

        # workbench tab (not closable)
        self.workbench = WorkbenchTab(self)
        idx = self.tabs.addTab(self.workbench, "🧪  Workbench")
        self.tabs.tabBar().setTabButton(idx, self.tabs.tabBar().ButtonPosition.RightSide, None)

        # analyzer tab (not closable) — v1.1 legacy
        self.analyzer_panel = AnalyzerPanel()
        self.analyzer_panel.report_ready.connect(self._on_report)
        idx2 = self.tabs.addTab(self.analyzer_panel, "🔎  Analyze (v1.1)")
        self.tabs.tabBar().setTabButton(idx2, self.tabs.tabBar().ButtonPosition.RightSide, None)

        # deep analyzer tab (not closable) — v1.2
        self.deep_panel = DeepAnalyzerPanel()
        self.deep_panel.report_ready.connect(self._on_deep_report)
        idx3 = self.tabs.addTab(self.deep_panel, "🧠  Deep Analyze")
        self.tabs.tabBar().setTabButton(idx3, self.tabs.tabBar().ButtonPosition.RightSide, None)

        # extraction threads container (keep refs alive)
        self._extract_threads: list = []

    # ── commands / shortcuts ────────────────────────────────
    def _register_commands(self):
        self.commands = {
            "Reload payloads":              self.workbench._reload_payloads,
            "Clear chain":                  self.workbench._clear_chain,
            "Copy preview to clipboard":    self.workbench.copy_preview,
            "Focus search":                 lambda: self.workbench.search.setFocus(),
            "Focus URL (Workbench)":        lambda: self.workbench.url_input.setFocus(),
            "Fire request":                 self.workbench._fire,
            "Open Workbench tab":           lambda: self.tabs.setCurrentWidget(self.workbench),
            "Open Analyze tab (v1.1)":      lambda: self.tabs.setCurrentWidget(self.analyzer_panel),
            "Open Deep Analyze tab":        lambda: self.tabs.setCurrentWidget(self.deep_panel),
            "Close current result tab":     self._close_current_tab,
            "Export session (JSON)":        self._export_session,
            "About":                        self._about,
        }

    def _bind_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+K"), self, self._open_launcher)
        QShortcut(QKeySequence("Ctrl+F"), self, lambda: self.workbench.search.setFocus())
        QShortcut(QKeySequence("Ctrl+Return"), self, self.workbench._fire)
        QShortcut(QKeySequence("Ctrl+Shift+A"), self, lambda: self.tabs.setCurrentWidget(self.analyzer_panel))
        QShortcut(QKeySequence("Ctrl+Shift+W"), self, lambda: self.tabs.setCurrentWidget(self.workbench))
        QShortcut(QKeySequence("Ctrl+Shift+D"), self, lambda: self.tabs.setCurrentWidget(self.deep_panel))

    def _open_launcher(self):
        CommandLauncher(self, self.commands).exec()

    def _about(self):
        QMessageBox.information(
            self, "H4ACKBAR",
            f"<h2 style='color:{ACCENT}'>H4ACKBAR v{__version__}</h2>"
            "<p>SQLi payload workbench with automated fingerprint / crawl / detect.</p>"
            "<p style='color:#5a3a1a'>Authorized security testing only.</p>"
        )

    # ── tabs ────────────────────────────────────────────────
    def _close_tab(self, idx: int):
        w = self.tabs.widget(idx)
        if w in (self.workbench, self.analyzer_panel, self.deep_panel):
            return  # never close core tabs
        self.tabs.removeTab(idx)
        w.deleteLater()

    def _close_current_tab(self):
        self._close_tab(self.tabs.currentIndex())

    # ── analyzer done → spawn result tabs ──────────────────
    def _on_report(self, report: AnalysisReport):
        ts = datetime.now().strftime("%H:%M:%S")
        confirmed = sum(1 for f in report.findings if f.confirmed())

        # findings tab (main result, focus)
        f_tab = FindingsTab(report.findings)
        f_idx = self.tabs.addTab(
            f_tab, f"🎯  Findings [{confirmed}/{len(report.findings)}] {ts}"
        )
        # fingerprint tab
        if report.fingerprint:
            fp_tab = FingerprintTab(report.fingerprint)
            self.tabs.addTab(fp_tab, f"🧬  Stack {ts}")
        # crawl tab
        if report.crawl_report:
            c_tab = CrawlTab(report.crawl_report)
            self.tabs.addTab(c_tab, f"🕸  Crawl {ts}")
        # log tab
        l_tab = LogTab(report.log)
        self.tabs.addTab(l_tab, f"📜  Log {ts}")

        # smoothly focus the findings tab
        self.tabs.setCurrentIndex(f_idx)
        self.status.showMessage(
            f"analysis complete  •  {confirmed} confirmed / {len(report.findings)} tested  •  {ts}",
            8000,
        )

    # ── v1.2 deep analyzer → spawn deep result tabs ────────
    def _on_deep_report(self, report: DeepAnalysisReport):
        ts = datetime.now().strftime("%H:%M:%S")
        critical = sum(1 for f in report.findings if f.strength_grade == "critical")
        strong   = sum(1 for f in report.findings if f.strength_grade == "strong")

        f_tab = DeepFindingsTab(report.findings)
        f_tab.extract_requested.connect(self._on_extract_requested)
        label = f"🎯  Deep [{critical}!+{strong}★/{len(report.findings)}] {ts}"
        f_idx = self.tabs.addTab(f_tab, label)

        if report.fingerprint:
            self.tabs.addTab(FingerprintTab(report.fingerprint), f"🧬  Stack {ts}")
        if report.waf and (report.waf.detected or report.waf.evidence):
            self.tabs.addTab(WAFTab(report.waf), f"🛡  WAF {ts}")
        if report.crawl_report:
            self.tabs.addTab(CrawlTab(report.crawl_report), f"🕸  Crawl {ts}")
        self.tabs.addTab(LogTab(report.log), f"📜  Log {ts}")

        self.tabs.setCurrentIndex(f_idx)
        self.status.showMessage(
            f"deep analysis complete  •  {critical} critical / {strong} strong / "
            f"{len(report.findings)} tested  •  {ts}",
            8000,
        )

    def _on_extract_requested(self, finding: DeepFinding):
        """DeepFindingsTab requested extraction on a finding — spawn ExtractionTab."""
        ts = datetime.now().strftime("%H:%M:%S")
        tab = ExtractionTab(finding)
        tab.run_extraction.connect(self._on_run_extraction)
        idx = self.tabs.addTab(tab, f"💧  Extract [{finding.param}] {ts}")
        self.tabs.setCurrentIndex(idx)

    def _on_run_extraction(self, payload: dict):
        """ExtractionTab clicked RUN — start a thread."""
        # find the tab that emitted (currentWidget is safe here)
        tab = self.tabs.currentWidget()
        if not isinstance(tab, ExtractionTab):
            return
        th = ExtractionThread(
            finding=payload["finding"],
            auth_token=payload["auth_token"],
            targets=payload["targets"],
            rate_limit_ms=payload["rate_limit_ms"],
            max_len_per_field=payload["max_len_per_field"],
            max_total_requests=payload["max_total_requests"],
            technique_override=payload["technique_override"],
        )
        th.progress.connect(tab.append_log)
        th.finished_report.connect(tab.render_report)
        th.refused.connect(tab.refused)
        th.failed.connect(lambda e: tab.refused(f"[fatal] {e}"))
        # Route tab abort → thread
        tab.btn_stop.clicked.connect(th.request_abort)
        self._extract_threads.append(th)
        th.start()

    # ── export ──────────────────────────────────────────────
    def _export_session(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export session", "h4ackbar_session.json", "JSON (*.json)"
        )
        if not path:
            return
        wb = self.workbench
        data = {
            "seed":      wb.chain.seed,
            "mutators":  wb.chain.mutators,
            "encoders":  wb.chain.encoders,
            "wire":      wb.preview.toPlainText(),
            "url":       wb.url_input.text(),
            "method":    wb.method_combo.currentText(),
            "param":     wb.param_input.text(),
            "inject_in": wb.inject_combo.currentText(),
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        self.status.showMessage(f"exported → {path}", 3000)


# ─────────────────────────────────────────────────────────────
def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    w = H4ackBar()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
