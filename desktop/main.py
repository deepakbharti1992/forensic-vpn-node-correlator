"""
Forensic VPN Node Correlator — desktop entry point.
Run as administrator for packet capture.
"""
from __future__ import annotations

import logging
import sys

from PyQt6.QtWidgets import QApplication

from app_controller import AppController
from gui_dashboard import MainWindow
from nic_selector import NicSelectorDialog

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)


def main() -> None:
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    controller = AppController()

    # First-run NIC selection
    dlg = NicSelectorDialog()
    if dlg.exec():
        controller.set_iface(dlg.selected_iface, dlg.mobile_ip)

    window = MainWindow(controller)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
