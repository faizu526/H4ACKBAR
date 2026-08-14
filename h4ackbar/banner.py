"""
H4ACKBAR banner widget — renders the SVG asset at the top of the window.
Falls back to a text banner if SVG asset is missing.
"""

from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtSvgWidgets import QSvgWidget
from PyQt6.QtWidgets import QLabel, QSizePolicy, QVBoxLayout, QWidget

from .theme import ACCENT, CREAM_PANEL, INK_SOFT

BANNER_PATH = Path(__file__).parent.parent / "assets" / "banner.svg"


class Banner(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(110)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setStyleSheet(f"background: {CREAM_PANEL}; border-bottom: 2px solid {ACCENT};")

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        if BANNER_PATH.exists():
            self.svg = QSvgWidget(str(BANNER_PATH))
            self.svg.setFixedHeight(110)
            lay.addWidget(self.svg)
        else:
            fallback = QLabel("H4ACKBAR :: SQLi Workbench")
            fallback.setAlignment(Qt.AlignmentFlag.AlignCenter)
            fallback.setStyleSheet(
                f"color: {ACCENT}; font-size: 32px; font-weight: 900;"
                f"letter-spacing: 6px; font-family: Impact,'Arial Black',sans-serif;"
            )
            sub = QLabel("chain · detect · crawl")
            sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
            sub.setStyleSheet(f"color: {INK_SOFT}; font-family: monospace; letter-spacing: 3px;")
            lay.addWidget(fallback)
            lay.addWidget(sub)
