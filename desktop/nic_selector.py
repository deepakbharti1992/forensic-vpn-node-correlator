"""
NIC selector dialog shown on first run / calibration.
"""
from __future__ import annotations

from PyQt6.QtWidgets import (
    QDialog, QDialogButtonBox, QFormLayout,
    QComboBox, QLineEdit, QLabel,
)

from capture_engine import list_hotspot_interfaces


class NicSelectorDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Select Hotspot NIC")
        self.setMinimumWidth(400)
        self.selected_iface = ""
        self.mobile_ip = ""
        self._build()

    def _build(self) -> None:
        layout = QFormLayout(self)

        self._combo = QComboBox()
        ifaces = list_hotspot_interfaces()
        if ifaces:
            self._combo.addItems(ifaces)
        else:
            # Fallback: show all scapy interfaces
            try:
                from scapy.arch.windows import get_windows_if_list
                for i in get_windows_if_list():
                    self._combo.addItem(i.get("description", i.get("name", "")))
            except Exception:
                self._combo.addItem("(no interfaces found)")

        self._ip_edit = QLineEdit("192.168.137.")
        self._ip_edit.setPlaceholderText("e.g. 192.168.137.45 (leave blank for auto)")

        layout.addRow(QLabel("Hotspot NIC:"), self._combo)
        layout.addRow(QLabel("Mobile IP (optional):"), self._ip_edit)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self._accept)
        btns.rejected.connect(self.reject)
        layout.addRow(btns)

    def _accept(self) -> None:
        self.selected_iface = self._combo.currentText()
        self.mobile_ip = self._ip_edit.text().strip()
        self.accept()
