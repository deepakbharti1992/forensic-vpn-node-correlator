"""
Application controller — wires capture, detection, pairing, bridge, and export together.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from capture_engine import CaptureEngine
from vpn_detector import VpnDetector
from pairing_engine import PairingEngine
from mobile_bridge import MobileBridge
from csv_exporter import CsvExporter
from gui_dashboard import signals

log = logging.getLogger(__name__)

OUTPUT_DIR = Path("vnc_output")


class AppController:
    def __init__(self) -> None:
        self._capture = CaptureEngine()
        self._detector = VpnDetector()
        self._pairing = PairingEngine(self._capture, self._detector)
        self._bridge = MobileBridge(self._on_entry_event)
        self._exporter: Optional[CsvExporter] = None
        self._running = False

        self._capture.set_packet_callback(self._on_packet)
        self._bridge.set_status_callback(self._on_mobile_status)

    # ------------------------------------------------------------------ public

    def start_session(self) -> None:
        if self._running:
            return
        self._running = True
        self._exporter = CsvExporter(str(OUTPUT_DIR))
        self._capture.start()
        self._bridge.start()
        self._exporter.write_log_event("SESSION_START")
        log.info("Session started")

    def stop_session(self) -> None:
        if not self._running:
            return
        self._running = False
        self._capture.stop()
        self._bridge.stop()
        if self._exporter:
            self._exporter.write_log_event("SESSION_STOP")
        log.info("Session stopped")

    def trigger_reconnect(self) -> None:
        self._bridge.send_reconnect()

    def export(self) -> Optional[Path]:
        if self._exporter:
            return self._exporter.export_excel()
        return None

    def set_iface(self, iface: str, mobile_ip: str) -> None:
        was_running = self._running
        if was_running:
            self.stop_session()
        self._capture.iface = iface
        self._capture.mobile_ip = mobile_ip
        if was_running:
            self.start_session()

    # ----------------------------------------------------------------- private

    def _on_entry_event(self, msg: dict) -> None:
        entry_node = msg.get("entry_node", "")
        ts_raw = msg.get("timestamp", "")
        method = msg.get("entry_method", "AccessibilityService")
        mobile_ip = msg.get("mobile_local_ip", self._capture.mobile_ip)
        location = msg.get("location", "")

        try:
            event_time = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            event_time = datetime.now(tz=timezone.utc)

        if not entry_node:
            log.warning("Entry event missing entry_node field")
            return

        pair = self._pairing.correlate(
            entry_node=entry_node,
            event_time=event_time,
            mobile_ip=mobile_ip,
            entry_method=method,
            location=location,
        )
        if pair:
            if self._exporter:
                self._exporter.append(pair)
            signals.pair_added.emit(pair)
            log.info(
                "Pair: %s <-> %s conf=%d%%",
                pair.entry_node, pair.exit_node, pair.correlation_confidence
            )
        else:
            log.warning("Correlation failed for entry_node=%s", entry_node)
            if self._exporter:
                self._exporter.write_log_event(f"CORRELATION_FAILED entry={entry_node}")

    def _on_packet(self, pkt) -> None:
        signals.packet_count_changed.emit(self._capture.packet_count)

    def _on_mobile_status(self, connected: bool, ip: str) -> None:
        signals.status_changed.emit(connected, ip)
        if self._exporter:
            status = f"MOBILE_{'CONNECTED' if connected else 'DISCONNECTED'} ip={ip}"
            self._exporter.write_log_event(status)
