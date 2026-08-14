"""
H4ACKBAR theme — cream/light aesthetic with red-oxide accents.
Centralized Qt stylesheet for consistent look across widgets.
"""

# ── palette ────────────────────────────────────────────────
CREAM_BG        = "#f6efd8"   # base
CREAM_PANEL     = "#f0e6c6"   # panels
CREAM_INPUT     = "#fbf6e4"   # inputs
BORDER          = "#c8b98a"
BORDER_STRONG   = "#8b7a4a"
INK             = "#2b1a1a"   # primary text
INK_SOFT        = "#5a3a1a"
ACCENT          = "#8b1a1a"   # red-oxide
ACCENT_HOT      = "#c0392b"
OK              = "#2e7d32"
WARN            = "#c9782f"
BAD             = "#a11d2b"
HEX_INK         = "#3a5a1a"

FONT_MONO       = "'JetBrains Mono','Fira Code','Consolas','Courier New',monospace"
FONT_UI         = "'Segoe UI','Helvetica Neue','Arial',sans-serif"


def stylesheet() -> str:
    return f"""
    QMainWindow, QDialog {{
        background: {CREAM_BG};
        color: {INK};
    }}
    QWidget {{
        background: {CREAM_BG};
        color: {INK};
        font-family: {FONT_UI};
        font-size: 10pt;
    }}
    QLabel {{ background: transparent; color: {INK_SOFT}; }}
    QLabel[section="true"] {{
        color: {ACCENT};
        font-weight: bold;
        font-size: 9pt;
        letter-spacing: 1.5px;
        padding: 4px 2px 2px 2px;
    }}
    QLineEdit, QPlainTextEdit, QTextEdit, QComboBox,
    QTreeWidget, QTableWidget, QListWidget, QSpinBox {{
        background: {CREAM_INPUT};
        color: {INK};
        border: 1px solid {BORDER};
        border-radius: 3px;
        selection-background-color: {ACCENT};
        selection-color: {CREAM_BG};
        padding: 3px;
    }}
    QPlainTextEdit, QTextEdit {{
        font-family: {FONT_MONO};
        font-size: 10pt;
    }}
    QPushButton {{
        background: {CREAM_PANEL};
        color: {INK};
        border: 1px solid {BORDER_STRONG};
        border-radius: 3px;
        padding: 6px 14px;
        font-weight: 600;
    }}
    QPushButton:hover {{
        background: {ACCENT};
        color: {CREAM_BG};
        border-color: {ACCENT};
    }}
    QPushButton:pressed {{
        background: {ACCENT_HOT};
    }}
    QPushButton[danger="true"] {{
        background: {ACCENT};
        color: {CREAM_BG};
        border-color: {ACCENT};
    }}
    QPushButton[danger="true"]:hover {{
        background: {ACCENT_HOT};
    }}
    QHeaderView::section {{
        background: {CREAM_PANEL};
        color: {ACCENT};
        border: 1px solid {BORDER};
        padding: 5px;
        font-weight: bold;
    }}
    QTabWidget::pane {{
        border: 1px solid {BORDER_STRONG};
        background: {CREAM_INPUT};
        top: -1px;
    }}
    QTabBar::tab {{
        background: {CREAM_PANEL};
        color: {INK_SOFT};
        border: 1px solid {BORDER};
        border-bottom: none;
        padding: 6px 14px;
        margin-right: 2px;
        border-top-left-radius: 4px;
        border-top-right-radius: 4px;
    }}
    QTabBar::tab:selected {{
        background: {CREAM_INPUT};
        color: {ACCENT};
        font-weight: bold;
        border-color: {BORDER_STRONG};
    }}
    QTabBar::tab:hover:!selected {{
        background: {CREAM_INPUT};
    }}
    QTabBar::close-button {{
        subcontrol-position: right;
    }}
    QMenuBar {{
        background: {CREAM_PANEL};
        color: {INK};
        border-bottom: 1px solid {BORDER};
    }}
    QMenuBar::item:selected {{ background: {ACCENT}; color: {CREAM_BG}; }}
    QMenu {{ background: {CREAM_INPUT}; border: 1px solid {BORDER_STRONG}; }}
    QMenu::item:selected {{ background: {ACCENT}; color: {CREAM_BG}; }}
    QStatusBar {{
        background: {CREAM_PANEL};
        color: {INK_SOFT};
        border-top: 1px solid {BORDER};
    }}
    QStatusBar QLabel {{ color: {INK_SOFT}; }}
    QSplitter::handle {{ background: {BORDER}; }}
    QSplitter::handle:horizontal {{ width: 3px; }}
    QSplitter::handle:vertical {{ height: 3px; }}
    QProgressBar {{
        border: 1px solid {BORDER_STRONG};
        border-radius: 3px;
        background: {CREAM_INPUT};
        color: {INK};
        text-align: center;
        height: 16px;
    }}
    QProgressBar::chunk {{
        background: {ACCENT};
        border-radius: 2px;
    }}
    QCheckBox {{ color: {INK}; spacing: 6px; }}
    QCheckBox::indicator {{
        width: 14px; height: 14px;
        border: 1px solid {BORDER_STRONG};
        background: {CREAM_INPUT};
    }}
    QCheckBox::indicator:checked {{ background: {ACCENT}; }}
    QScrollBar:vertical {{
        background: {CREAM_PANEL};
        width: 12px;
        border: none;
    }}
    QScrollBar::handle:vertical {{
        background: {BORDER_STRONG};
        border-radius: 3px;
        min-height: 20px;
    }}
    QScrollBar::handle:vertical:hover {{ background: {ACCENT}; }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
    QScrollBar:horizontal {{
        background: {CREAM_PANEL};
        height: 12px;
        border: none;
    }}
    QScrollBar::handle:horizontal {{
        background: {BORDER_STRONG};
        border-radius: 3px;
        min-width: 20px;
    }}
    QScrollBar::handle:horizontal:hover {{ background: {ACCENT}; }}
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
    """
