"""
Demo / sample-data test mode.
Replays sample_output.csv pairs into the live dashboard at 2-second intervals.
No Npcap or mobile device required.

Usage:
    python demo_runner.py
"""
from __future__ import annotations

import csv
import sys
import time
import threading
from datetime import datetime, timezone
from pathlib import Path

from PyQt6.QtWidgets import QApplication

from pairing_engine import CorrelatedPair
from csv_exporter import CsvExporter
from gui_dashboard import MainWindow, signals


SAMPLE_CSV = Path(__file__).parent / "sample_output.csv"
REPLAY_INTERVAL = 2.0   # seconds between injected pairs


class DemoController:
    """Minimal controller stub for demo mode — no capture engine, no bridge."""

    def __init__(self) -> None:
        self._exporter = CsvExporter("vnc_output_demo")
        self._running = False

    def start_session(self) -> None:
        self._running = True
        threading.Thread(target=self._replay_loop, daemon=True).start()

    def stop_session(self) -> None:
        self._running = False

    def trigger_reconnect(self) -> None:
        print("[DEMO] Reconnect command sent (no-op in demo mode)")

    def export(self):
        return self._exporter.export_excel()

    def set_iface(self, iface: str, mobile_ip: str) -> None:
        pass   # no-op in demo mode

    def _replay_loop(self) -> None:
        pairs = list(self._load_sample_pairs())
        if not pairs:
            print("[DEMO] No sample data found in", SAMPLE_CSV)
            return

        # Simulate mobile connected
        signals.status_changed.emit(True, "192.168.137.45")

        idx = 0
        pkt_count = 0
        while self._running:
            pair = pairs[idx % len(pairs)]
            # Re-stamp with current time so the GUI clock makes sense
            pair = CorrelatedPair(
                timestamp=datetime.now(tz=timezone.utc),
                entry_node=pair.entry_node,
                exit_node=pair.exit_node,
                mobile_local_ip=pair.mobile_local_ip,
                vpn_provider=pair.vpn_provider,
                protocol=pair.protocol,
                port=pair.port,
                server_location=pair.server_location,
                subnet_match=pair.subnet_match,
                correlation_confidence=pair.correlation_confidence,
                entry_method=pair.entry_method,
            )
            self._exporter.append(pair)
            signals.pair_added.emit(pair)
            idx += 1
            pkt_count += 150 + idx * 23   # simulated packet count
            signals.packet_count_changed.emit(pkt_count)
            print(
                f"[DEMO] Pair {idx}: {pair.entry_node} <-> {pair.exit_node} "
                f"conf={pair.correlation_confidence}% subnet={pair.subnet_match}"
            )
            time.sleep(REPLAY_INTERVAL)

    @staticmethod
    def _load_sample_pairs():
        if not SAMPLE_CSV.exists():
            return
        with open(SAMPLE_CSV, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                try:
                    yield CorrelatedPair(
                        timestamp=datetime.fromisoformat(row["timestamp"]),
                        entry_node=row["entry_node"],
                        exit_node=row["exit_node"],
                        mobile_local_ip=row["mobile_local_ip"],
                        vpn_provider=row["vpn_provider"],
                        protocol=row["protocol"],
                        port=int(row["port"]),
                        server_location=row["server_location"],
                        subnet_match=row["subnet_match"].strip().upper() == "TRUE",
                        correlation_confidence=int(row["correlation_confidence"]),
                        entry_method=row["entry_method"],
                    )
                except (KeyError, ValueError) as e:
                    print(f"[DEMO] Skipping row: {e}")


def main() -> None:
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    ctrl = DemoController()
    window = MainWindow(ctrl)
    window.setWindowTitle("VPN Node Correlator v1.0  [DEMO MODE]")
    window.show()

    # Auto-start the replay after the window appears
    from PyQt6.QtCore import QTimer
    QTimer.singleShot(500, ctrl.start_session)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
