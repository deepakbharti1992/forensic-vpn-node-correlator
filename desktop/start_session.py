"""Start live capture + bridge session from command line."""
from __future__ import annotations
import sys, time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from capture_engine import CaptureEngine
from vpn_detector import VpnDetector
from pairing_engine import PairingEngine
from mobile_bridge import MobileBridge
from csv_exporter import CsvExporter

PHONE_IP    = "192.168.137.184"
HOTSPOT_NIC = "Local Area Connection* 4"

capture  = CaptureEngine(mobile_ip=PHONE_IP, iface=HOTSPOT_NIC)
detector = VpnDetector()
pairing  = PairingEngine(capture, detector)
exporter = CsvExporter("vnc_live_output")

def on_entry(msg: dict) -> None:
    entry  = msg.get("entry_node", "")
    ts_raw = msg.get("timestamp", "")
    mobile = msg.get("mobile_local_ip", PHONE_IP)
    loc    = msg.get("location", "")
    method = msg.get("entry_method", "")
    try:
        event_time = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
    except Exception:
        event_time = datetime.now(tz=timezone.utc)
    pair = pairing.correlate(entry, event_time, mobile, method, location=loc)
    if pair:
        exporter.append(pair)
        print(f"\n  PAIR CAPTURED: {pair.entry_node} <-> {pair.exit_node}  "
              f"conf={pair.correlation_confidence}%  subnet={'YES' if pair.subnet_match else 'NO'}")
        print(f"  Saved to: {exporter.csv_path}")
    else:
        print("  WARN: Entry event received but no correlation found")

capture.start()
bridge = MobileBridge(on_entry_event=on_entry)
bridge.start()

print("=" * 50)
print("  VNC SESSION STARTED")
print(f"  Capturing : {PHONE_IP} on '{HOTSPOT_NIC}'")
print(f"  Bridge    : listening on 0.0.0.0:5000")
print("  Press Ctrl+C to stop")
print("=" * 50)

try:
    while True:
        time.sleep(5)
        status = "CONNECTED" if bridge.is_connected else "waiting..."
        print(f"  Packets: {capture.packet_count}  Mobile: {status}")
except KeyboardInterrupt:
    pass

print("\nStopping...")
capture.stop()
bridge.stop()
xlsx = exporter.export_excel()
print(f"  CSV  : {exporter.csv_path}")
print(f"  Excel: {xlsx}")
