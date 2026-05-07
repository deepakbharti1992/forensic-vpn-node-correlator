"""
Continuous VPN IP monitor:
- Merges all existing session CSVs into one master file
- Every 60s: force-stops active VPN → relaunches → captures new IP → appends to master CSV
- Supports: NordVPN, ExpressVPN, ProtonVPN, PIA, Surfshark, Windscribe,
            IPVanish, Hotspot Shield, TunnelBear, CyberGhost, Mullvad, OpenVPN
"""
from __future__ import annotations

import csv
import json
import re
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from capture_engine import CaptureEngine
from vpn_detector import VpnDetector
from pairing_engine import PairingEngine, CorrelatedPair
from mobile_bridge import MobileBridge
from csv_exporter import CsvExporter
from vpn_apps import detect_active_vpn, SUPPORTED_VPNS

ADB         = r"C:\AndroidSDK\platform-tools\adb.exe"
HOTSPOT_NIC = "Local Area Connection* 4"
PHONE_IP    = "192.168.137.184"
PORT    = 5000
IP_RE   = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")
MASTER_CSV  = Path(__file__).parent / "vnc_master_log.csv"
INTERVAL    = 60   # seconds between reconnects

FIELDNAMES = [
    "timestamp", "entry_node", "exit_node", "mobile_local_ip",
    "vpn_provider", "protocol", "port", "server_location",
    "subnet_match", "correlation_confidence", "entry_method",
    "exit_method", "file_hash"
]

def adb(*args, timeout=20) -> str:
    r = subprocess.run([ADB, *args], capture_output=True, text=True, timeout=timeout)
    return (r.stdout + r.stderr).strip()

def is_private(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4: return True
    p = [int(x) for x in parts]
    return (p[0]==10 or p[0]==127 or (p[0]==172 and 16<=p[1]<=31) or
            (p[0]==192 and p[1]==168) or (p[0]==169 and p[1]==254))

def extract_ip(xml_text: str) -> str | None:
    for candidate in IP_RE.findall(xml_text):
        if not is_private(candidate):
            return candidate
    return None

def read_nordvpn_ip() -> str | None:
    dump = adb("shell",
               "uiautomator dump /data/local/tmp/ui.xml 2>/dev/null && "
               "cat /data/local/tmp/ui.xml", timeout=15)
    return extract_ip(dump)

# ── Step 1: merge all existing CSVs into master ──────────────────────────────

def merge_existing():
    existing_files = sorted(Path(__file__).parent.rglob("vnc_session_*.csv"))
    rows = []
    seen_hashes = set()
    for f in existing_files:
        try:
            with open(f, newline="", encoding="utf-8") as fh:
                for row in csv.DictReader(fh):
                    h = row.get("file_hash", "")
                    if h and h not in seen_hashes and row.get("entry_node"):
                        seen_hashes.add(h)
                        rows.append(row)
        except Exception:
            pass

    rows.sort(key=lambda r: r.get("timestamp", ""))

    with open(MASTER_CSV, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDNAMES, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    print(f"  Master CSV: {MASTER_CSV}  ({len(rows)} existing rows merged)")
    return len(rows)

def append_to_master(pair: CorrelatedPair):
    row = pair.to_dict()
    exists = MASTER_CSV.exists()
    with open(MASTER_CSV, "a", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDNAMES, extrasaction="ignore")
        if not exists:
            w.writeheader()
        w.writerow(row)

# ── Step 2: start capture + bridge ──────────────────────────────────────────

print("\n" + "="*60)
print("  VNC CONTINUOUS MONITOR")
print("="*60)
print("\nMerging existing data...")
total = merge_existing()

print("\nStarting capture engine and bridge...")
capture  = CaptureEngine(mobile_ip=PHONE_IP, iface=HOTSPOT_NIC)
detector = VpnDetector()
pairing  = PairingEngine(capture, detector)
capture.start()
time.sleep(2)

pair_result: list[CorrelatedPair] = []
pair_event  = threading.Event()

def on_entry(msg: dict) -> None:
    entry  = msg.get("entry_node", "")
    ts_raw = msg.get("timestamp", "")
    mobile = msg.get("mobile_local_ip", PHONE_IP)
    loc    = msg.get("location", "")
    method = msg.get("entry_method", "ADB_UIAutomator")
    try:
        event_time = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
    except Exception:
        event_time = datetime.now(tz=timezone.utc)
    pair = pairing.correlate(entry, event_time, mobile, method, location=loc)
    if pair:
        pair_result.clear()
        pair_result.append(pair)
        append_to_master(pair)
        print(f"\n  [CAPTURED] {pair.entry_node} <-> {pair.exit_node}  "
              f"conf={pair.correlation_confidence}%  subnet={'YES' if pair.subnet_match else 'NO'}")
        print(f"  [SAVED]    {MASTER_CSV.name}  (total rows: {sum(1 for _ in open(MASTER_CSV))-1})")
    else:
        print(f"  [MISS]  {entry} — no match in ±3s window")
    pair_event.set()

bridge = MobileBridge(on_entry_event=on_entry)
bridge.start()
print("  Bridge listening on :5000")
print(f"  Interval : {INTERVAL}s per reconnect")
print(f"  Master   : {MASTER_CSV}")
print("\nPress Ctrl+C to stop.\n")

# ── Step 3: detect active VPN app ───────────────────────────────────────────

print("\nDetecting active VPN app on phone...")
active_vpn = detect_active_vpn(adb)
if active_vpn:
    print(f"  Detected: {active_vpn.name}  ({active_vpn.package})")
else:
    print("  No known VPN detected — defaulting to NordVPN")
    from vpn_apps import PACKAGE_MAP
    active_vpn = PACKAGE_MAP.get("com.nordvpn.android")

VPN_PKG  = active_vpn.package
VPN_NAME = active_vpn.name

# ── Step 4: reconnect loop ───────────────────────────────────────────────────

reconnect_count = 0
try:
    while True:
        reconnect_count += 1
        print(f"\n{'─'*50}")
        print(f"  RECONNECT #{reconnect_count}  |  {datetime.now().strftime('%H:%M:%S')}  |  "
              f"VPN={VPN_NAME}  packets={capture.packet_count}")

        # Read pre-reconnect IP
        pre_ip = read_nordvpn_ip()

        # Force-stop VPN app → disconnect
        adb("shell", f"am force-stop {VPN_PKG}")
        reconnect_time = datetime.now(tz=timezone.utc)
        print(f"  Stopped {VPN_NAME}  (was: {pre_ip or 'unknown'})")
        time.sleep(2)

        # Relaunch VPN app → auto-reconnects
        adb("shell", f"monkey -p {VPN_PKG} -c android.intent.category.LAUNCHER 1")
        print(f"  Relaunched {VPN_NAME} — waiting for new IP...")

        # Poll for new IP (up to 30s)
        new_ip = None
        deadline = time.time() + 30
        while time.time() < deadline:
            time.sleep(3)
            candidate = read_nordvpn_ip()
            if candidate and candidate != pre_ip:
                new_ip = candidate
                print(f"  New IP: {new_ip}")
                break
            elif candidate:
                print(f"  Still: {candidate} — waiting...")

        if not new_ip:
            new_ip = read_nordvpn_ip()
            if new_ip:
                print(f"  IP (same/fallback): {new_ip}")

        # Inject event into bridge
        if new_ip:
            event = {
                "event":           "VPN_RECONNECT",
                "timestamp":       reconnect_time.isoformat(),
                "entry_node":      new_ip,
                "mobile_local_ip": PHONE_IP,
                "location":        "India",
                "protocol":        "Auto",
                "confidence":      100,
                "entry_method":    "ADB_UIAutomator",
                "vpn_app":         VPN_NAME,
            }
            pair_event.clear()
            try:
                with socket.create_connection(("127.0.0.1", PORT), timeout=5) as s:
                    s.sendall((json.dumps(event) + "\n").encode())
            except Exception as e:
                on_entry(event)
            pair_event.wait(timeout=6)
        else:
            print("  Could not read new IP — skipping")

        # Wait remainder of interval
        elapsed = time.time() - (reconnect_time.timestamp() + 2)
        wait = max(5, INTERVAL - elapsed)
        print(f"  Next reconnect in {int(wait)}s...")
        time.sleep(wait)

except KeyboardInterrupt:
    print("\n\nStopping...")

capture.stop()
bridge.stop()
print(f"\nTotal reconnects : {reconnect_count}")
print(f"Total pairs saved: {sum(1 for _ in open(MASTER_CSV))-1}")
print(f"Master CSV       : {MASTER_CSV}")
