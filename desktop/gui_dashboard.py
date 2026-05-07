"""
PyQt6 live monitoring dashboard for the VPN Node Correlator.
"""
from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from typing import List, Optional

from PyQt6.QtCore import QTimer, Qt, pyqtSignal, QObject
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QApplication, QGroupBox, QHBoxLayout, QHeaderView,
    QLabel, QMainWindow, QProgressBar, QPushButton,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
    QComboBox, QLineEdit, QFormLayout, QMessageBox,
)

from pairing_engine import CorrelatedPair


class _Signals(QObject):
    pair_added = pyqtSignal(object)       # CorrelatedPair
    status_changed = pyqtSignal(bool, str)  # (connected, ip)
    packet_count_changed = pyqtSignal(int)


# Module-level singleton so capture threads can emit without importing Qt
signals = _Signals()


class MainWindow(QMainWindow):
    MAX_TABLE_ROWS = 50

    def __init__(self, app_controller) -> None:
        super().__init__()
        self._ctrl = app_controller
        self._session_start: Optional[float] = None
        self._pairs: List[CorrelatedPair] = []

        self.setWindowTitle("Forensic VPN Node Correlator v1.0")
        self.setMinimumSize(900, 650)
        self._build_ui()

        # Connect signals
        signals.pair_added.connect(self._on_pair)
        signals.status_changed.connect(self._on_mobile_status)
        signals.packet_count_changed.connect(self._on_packet_count)

        # Refresh timer for session clock
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(1000)

    # ---------------------------------------------------------------- UI build

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setSpacing(8)
        root.setContentsMargins(10, 10, 10, 10)

        root.addWidget(self._build_header())
        root.addWidget(self._build_status_bar())
        root.addWidget(self._build_last_pair_box())
        root.addWidget(self._build_controls())
        root.addWidget(self._build_table())

    def _build_header(self) -> QWidget:
        w = QWidget()
        h = QHBoxLayout(w)
        title = QLabel("VPN NODE CORRELATOR v1.0")
        title.setFont(QFont("Consolas", 14, QFont.Weight.Bold))
        h.addWidget(title)
        h.addStretch()
        self._lbl_status_dot = QLabel("●")
        self._lbl_status_dot.setStyleSheet("color: gray; font-size: 18px;")
        h.addWidget(self._lbl_status_dot)
        self._lbl_status_text = QLabel("Idle")
        h.addWidget(self._lbl_status_text)
        return w

    def _build_status_bar(self) -> QGroupBox:
        box = QGroupBox("Session")
        h = QHBoxLayout(box)

        self._lbl_duration = QLabel("Session: 00:00:00")
        self._lbl_packets = QLabel("Packets: 0")
        self._lbl_pairs = QLabel("Pairs: 0")
        self._lbl_mobile = QLabel("Mobile: Disconnected")
        self._lbl_mobile.setStyleSheet("color: red;")

        for w in [self._lbl_duration, self._lbl_packets, self._lbl_pairs, self._lbl_mobile]:
            h.addWidget(w)
            h.addStretch()
        return box

    def _build_last_pair_box(self) -> QGroupBox:
        box = QGroupBox("Last Correlated Pair")
        form = QFormLayout(box)

        self._lbl_last_pair = QLabel("—")
        self._lbl_last_pair.setFont(QFont("Consolas", 11))
        self._lbl_confidence = QLabel("—")
        self._pb_confidence = QProgressBar()
        self._pb_confidence.setRange(0, 100)
        self._pb_confidence.setValue(0)
        self._lbl_subnet = QLabel("—")

        form.addRow("Entry ↔ Exit:", self._lbl_last_pair)
        h = QHBoxLayout()
        h.addWidget(self._pb_confidence)
        h.addWidget(self._lbl_confidence)
        form.addRow("Confidence:", h)
        form.addRow("Subnet match:", self._lbl_subnet)
        return box

    def _build_controls(self) -> QGroupBox:
        box = QGroupBox("Controls")
        h = QHBoxLayout(box)

        self._btn_start = QPushButton("START SESSION")
        self._btn_start.setStyleSheet("background-color: #27ae60; color: white; font-weight: bold;")
        self._btn_stop = QPushButton("STOP")
        self._btn_stop.setStyleSheet("background-color: #c0392b; color: white;")
        self._btn_stop.setEnabled(False)
        self._btn_reconnect = QPushButton("TRIGGER RECONNECT")
        self._btn_export = QPushButton("EXPORT CSV/XLSX")
        self._btn_calibrate = QPushButton("CALIBRATE NIC")

        self._btn_start.clicked.connect(self._on_start)
        self._btn_stop.clicked.connect(self._on_stop)
        self._btn_reconnect.clicked.connect(self._on_reconnect)
        self._btn_export.clicked.connect(self._on_export)
        self._btn_calibrate.clicked.connect(self._on_calibrate)

        for btn in [self._btn_start, self._btn_stop, self._btn_reconnect,
                    self._btn_export, self._btn_calibrate]:
            h.addWidget(btn)
        return box

    def _build_table(self) -> QGroupBox:
        box = QGroupBox(f"Live Pairs (last {self.MAX_TABLE_ROWS})")
        v = QVBoxLayout(box)
        cols = ["Time", "Entry Node", "Exit Node", "Subnet", "Conf%", "Provider", "Port", "Location"]
        self._table = QTableWidget(0, len(cols))
        self._table.setHorizontalHeaderLabels(cols)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        v.addWidget(self._table)
        return box

    # --------------------------------------------------------------- callbacks

    def _on_start(self) -> None:
        self._ctrl.start_session()
        self._session_start = time.time()
        self._btn_start.setEnabled(False)
        self._btn_stop.setEnabled(True)
        self._lbl_status_dot.setStyleSheet("color: #27ae60; font-size: 18px;")
        self._lbl_status_text.setText("Running")

    def _on_stop(self) -> None:
        self._ctrl.stop_session()
        self._btn_start.setEnabled(True)
        self._btn_stop.setEnabled(False)
        self._session_start = None
        self._lbl_status_dot.setStyleSheet("color: gray; font-size: 18px;")
        self._lbl_status_text.setText("Stopped")

    def _on_reconnect(self) -> None:
        self._ctrl.trigger_reconnect()

    def _on_export(self) -> None:
        xlsx = self._ctrl.export()
        if xlsx:
            QMessageBox.information(self, "Export", f"Saved:\n{xlsx}")

    def _on_calibrate(self) -> None:
        from nic_selector import NicSelectorDialog
        dlg = NicSelectorDialog(self)
        if dlg.exec():
            self._ctrl.set_iface(dlg.selected_iface, dlg.mobile_ip)

    def _on_pair(self, pair: CorrelatedPair) -> None:
        self._pairs.append(pair)
        self._lbl_pairs.setText(f"Pairs: {len(self._pairs)}")
        self._lbl_last_pair.setText(f"{pair.entry_node}  ↔  {pair.exit_node}")
        conf = pair.correlation_confidence
        self._pb_confidence.setValue(conf)
        self._lbl_confidence.setText(f"{conf}%")
        color = "#27ae60" if conf >= 85 else "#f39c12" if conf >= 70 else "#c0392b"
        self._pb_confidence.setStyleSheet(f"QProgressBar::chunk {{ background: {color}; }}")
        self._lbl_subnet.setText("MATCH" if pair.subnet_match else "CROSS-SUBNET")
        self._lbl_subnet.setStyleSheet(f"color: {'#27ae60' if pair.subnet_match else '#e67e22'};")
        self._insert_table_row(pair)

    def _on_mobile_status(self, connected: bool, ip: str) -> None:
        if connected:
            self._lbl_mobile.setText(f"Mobile: Connected ({ip})")
            self._lbl_mobile.setStyleSheet("color: #27ae60;")
        else:
            self._lbl_mobile.setText("Mobile: Disconnected")
            self._lbl_mobile.setStyleSheet("color: red;")

    def _on_packet_count(self, count: int) -> None:
        self._lbl_packets.setText(f"Packets: {count:,}")

    def _tick(self) -> None:
        if self._session_start:
            elapsed = int(time.time() - self._session_start)
            h, rem = divmod(elapsed, 3600)
            m, s = divmod(rem, 60)
            self._lbl_duration.setText(f"Session: {h:02d}:{m:02d}:{s:02d}")

    def _insert_table_row(self, pair: CorrelatedPair) -> None:
        row = 0
        self._table.insertRow(row)
        values = [
            pair.timestamp.strftime("%H:%M:%S"),
            pair.entry_node,
            pair.exit_node,
            "YES" if pair.subnet_match else "NO",
            str(pair.correlation_confidence),
            pair.vpn_provider,
            str(pair.port),
            pair.server_location,
        ]
        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if col == 4:  # confidence
                c = int(pair.correlation_confidence)
                color = QColor("#27ae60") if c >= 85 else QColor("#f39c12") if c >= 70 else QColor("#c0392b")
                item.setForeground(color)
            self._table.setItem(row, col, item)
        while self._table.rowCount() > self.MAX_TABLE_ROWS:
            self._table.removeRow(self._table.rowCount() - 1)
