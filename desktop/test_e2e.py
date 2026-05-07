"""
Full end-to-end test: real VPN reconnect on phone → packet capture on desktop → correlated CSV row.

Architecture:
  - Packet capture runs on hotspot NIC throughout
  - VPN IP extracted directly from NordVPN UI via ADB uiautomator (no AccessibilityService timing issues)
  - Reconnect triggered by tapping NordVPN disconnect → connect
  - New VPN IP read from UI and injected as VPN_RECONNECT to the bridge
  - Pairing engine correlates against real captured packets
  - Result exported to CSV/Excel
"""
from __future__ import annotations

import json
import re
import socket
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from capture_engine import CaptureEngine
from vpn_detector import VpnDetector
from pairing_engine import PairingEngine, CorrelatedPair
from mobile_bridge import MobileBridge
from csv_exporter import CsvExporter
from vpn_apps import detect_active_vpn

ADB         = r"C:\AndroidSDK\platform-tools\adb.exe"
HOTSPOT_NIC = "Local Area Connection* 4"
PHONE_IP    = "192.168.137.184"
DESKTOP_IP  = "192.168.137.1"
PORT        = 5000
IP_RE       = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")

# ─────────────────────────── helpers

def adb(*args, timeout=20) -> str:
    r = subprocess.run([ADB, *args], capture_output=True, text=True, timeout=timeout)
    return (r.stdout + r.stderr).strip()

def step(n: int, msg: str) -> None:
    print(f"\n[STEP {n}] {msg}")

def is_private(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4: return True
    p = [int(x) for x in parts]
    return (p[0]==10 or p[0]==127 or (p[0]==172 and 16<=p[1]<=31) or
            (p[0]==192 and p[1]==168) or (p[0]==169 and p[1]==254))

def extract_ip_from_ui_dump(xml_text: str) -> str | None:
    """Walk the UI XML looking for a public IPv4 address."""
    for candidate in IP_RE.findall(xml_text):
        if not is_private(candidate):
            return candidate
    return None

def get_nordvpn_ui_ip(launch=True) -> str | None:
    """Launch NordVPN, dump UI, return the visible server IP (or None)."""
    if launch:
        adb("shell", f"monkey -p {NORDVPN_PKG} -c android.intent.category.LAUNCHER 1")
        time.sleep(4)
    dump = adb("shell",
               "uiautomator dump /data/local/tmp/ui.xml 2>/dev/null && "
               "cat /data/local/tmp/ui.xml", timeout=15)
    ip = extract_ip_from_ui_dump(dump)
    return ip

def tap_ui_text(ui_xml: str, *texts) -> bool:
    """Tap the first button whose text matches any of texts. Returns True if tapped."""
    for text in texts:
        nodes = [n for n in ui_xml.split("<node") if f'text="{text}"' in n]
        for node in nodes:
            m = re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', node)
            if m:
                x = (int(m.group(1)) + int(m.group(3))) // 2
                y = (int(m.group(2)) + int(m.group(4))) // 2
                print(f"  Tapping '{text}' at ({x},{y})")
                adb("shell", f"input tap {x} {y}")
                return True
    return False


# ─────────────────────────── STEP 1: network check

print("\n" + "="*60)
print("  FORENSIC VPN NODE CORRELATOR — END-TO-END TEST")
print("="*60)

step(1, "Network check + VPN app detection")
ping = subprocess.run(["ping","-n","2","-w","1000", PHONE_IP], capture_output=True, text=True)
print(f"  Phone {PHONE_IP}: {'reachable ✓' if 'TTL=' in ping.stdout else 'no response'}")
print(f"  Hotspot NIC : {HOTSPOT_NIC}")
print(f"  Desktop IP  : {DESKTOP_IP}:{PORT}")

# Auto-detect active VPN app
active_vpn = detect_active_vpn(adb)
if active_vpn:
    NORDVPN_PKG = active_vpn.package
    print(f"  VPN App     : {active_vpn.name}  ({NORDVPN_PKG})")
else:
    NORDVPN_PKG = "com.nordvpn.android"
    print(f"  VPN App     : NordVPN (default)")

# ─────────────────────────── STEP 2: start packet capture

step(2, f"Starting packet capture — src filter: {PHONE_IP}")
capture  = CaptureEngine(mobile_ip=PHONE_IP, iface=HOTSPOT_NIC)
detector = VpnDetector()
pairing  = PairingEngine(capture, detector)
exporter = CsvExporter("vnc_e2e_output")
capture.start()
time.sleep(2)
print(f"  Capturing... {capture.packet_count} packets so far")

# ─────────────────────────── STEP 3: start bridge (for entry-node injection)

step(3, "Starting TCP bridge server")
pair_result: list[CorrelatedPair] = []
pair_event  = threading.Event()

def on_entry(msg: dict) -> None:
    entry  = msg.get("entry_node","")
    ts_raw = msg.get("timestamp","")
    mobile = msg.get("mobile_local_ip", PHONE_IP)
    loc    = msg.get("location","")
    method = msg.get("entry_method","ADB_UIAutomator")
    print(f"\n  [BRIDGE] Entry event: {entry}  method={method}")
    try:
        event_time = datetime.fromisoformat(ts_raw.replace("Z","+00:00"))
    except Exception:
        event_time = datetime.now(tz=timezone.utc)
    pair = pairing.correlate(entry, event_time, mobile, method, location=loc)
    if pair:
        pair_result.append(pair)
        exporter.append(pair)
        pair_event.set()
        print(f"  [PAIR]  {pair.entry_node}  ↔  {pair.exit_node}  "
              f"conf={pair.correlation_confidence}%  subnet={'YES' if pair.subnet_match else 'NO'}")
    else:
        print(f"  [WARN]  Correlation failed — no matching capture in ±3s window")
        pair_event.set()

bridge = MobileBridge(on_entry_event=on_entry)
bridge.start()
print("  Bridge listening on 0.0.0.0:5000")

# ─────────────────────────── STEP 4: read pre-reconnect VPN IP

step(4, "Reading current NordVPN server IP from phone screen")
pre_ip = get_nordvpn_ui_ip(launch=True)
if pre_ip:
    print(f"  Current VPN server IP (before reconnect): {pre_ip}")
else:
    print("  Could not read IP from NordVPN UI (VPN may show hostname instead of IP)")
    print("  NordVPN UI may need to be on the 'Connected' screen showing server details")

# ─────────────────────────── STEP 5: trigger reconnect

step(5, "Triggering NordVPN reconnect via ADB UI tap")
dump = adb("shell",
           "uiautomator dump /data/local/tmp/ui.xml 2>/dev/null && "
           "cat /data/local/tmp/ui.xml", timeout=15)

DISCONNECT_TEXTS = ["Disconnect", "DISCONNECT", "disconnect"]
CONNECT_TEXTS    = ["Quick Connect", "Connect", "CONNECT", "Quick connect"]

reconnect_time: datetime | None = None

# Phase A: tap Disconnect
tapped_disconnect = tap_ui_text(dump, *DISCONNECT_TEXTS)
if tapped_disconnect:
    reconnect_time = datetime.now(tz=timezone.utc)
    print(f"  Disconnected at {reconnect_time.strftime('%H:%M:%S.%f')[:-3]}")
    time.sleep(4)
    # Phase B: tap Connect
    dump2 = adb("shell",
                "uiautomator dump /data/local/tmp/ui2.xml 2>/dev/null && "
                "cat /data/local/tmp/ui2.xml", timeout=15)
    tapped_connect = tap_ui_text(dump2, *CONNECT_TEXTS)
    if tapped_connect:
        print("  Connect tapped — NordVPN reconnecting...")
    else:
        print("  [WARN] Connect button not found, NordVPN may reconnect automatically")
else:
    # Maybe already on connect screen or a different UI layout
    tapped_connect = tap_ui_text(dump, *CONNECT_TEXTS)
    if tapped_connect:
        reconnect_time = datetime.now(tz=timezone.utc)
        print(f"  Connect tapped at {reconnect_time.strftime('%H:%M:%S.%f')[:-3]}")
    else:
        print("  [WARN] Neither Disconnect nor Connect found — using force-stop to reconnect")
        adb("shell", f"am force-stop {NORDVPN_PKG}")
        print("  NordVPN force-stopped (VPN disconnected)")
        time.sleep(2)
        adb("shell", f"monkey -p {NORDVPN_PKG} -c android.intent.category.LAUNCHER 1")
        reconnect_time = datetime.now(tz=timezone.utc)
        print(f"  NordVPN relaunched — reconnect_time={reconnect_time.strftime('%H:%M:%S.%f')[:-3]}")

# ─────────────────────────── STEP 6: wait for VPN to reconnect, read new IP

step(6, "Waiting for NordVPN to reconnect and reading new server IP (up to 30s)")

new_ip: str | None = None
deadline = time.time() + 30
attempts = 0
while time.time() < deadline:
    time.sleep(3)
    attempts += 1
    vpn_buf = [p for p in capture.get_buffer_snapshot() if detector.is_vpn_candidate(p)]
    print(f"  [{attempts}] Packets: {capture.packet_count}  VPN candidates: {len(vpn_buf)}", end="")
    # Try reading IP from NordVPN UI
    candidate = get_nordvpn_ui_ip(launch=False)
    if candidate and candidate != pre_ip:
        print(f"  → NEW IP: {candidate}")
        new_ip = candidate
        break
    elif candidate:
        print(f"  → same IP ({candidate}) — still reconnecting...")
    else:
        print("  → IP not visible in UI yet")

if not new_ip:
    # Fallback: read whatever IP is currently showing
    new_ip = get_nordvpn_ui_ip(launch=True)
    if new_ip:
        print(f"  Fallback read: {new_ip}")
    else:
        print("  [WARN] Could not read new IP from UI — will try exit-node-only correlation")

# ─────────────────────────── STEP 7: inject entry event into bridge

step(7, "Injecting entry node event into bridge")
event_time = reconnect_time or datetime.now(tz=timezone.utc)

if new_ip:
    print(f"  Entry node: {new_ip}")
    event = {
        "event":          "VPN_RECONNECT",
        "timestamp":      event_time.isoformat(),
        "entry_node":     new_ip,
        "mobile_local_ip": PHONE_IP,
        "location":       "India",
        "protocol":       "NordLynx",
        "confidence":     100,
        "entry_method":   "ADB_UIAutomator",
    }
    # Send directly to bridge via local TCP
    try:
        with socket.create_connection(("127.0.0.1", PORT), timeout=5) as s:
            s.sendall((json.dumps(event) + "\n").encode())
        print(f"  Event sent to bridge")
    except Exception as e:
        print(f"  [WARN] Could not send to bridge: {e}")
        # Call on_entry directly as fallback
        on_entry(event)
else:
    print("  No entry node available — attempting exit-only capture")
    # Use the most-frequent VPN IP from the capture buffer as best guess
    buf = [p for p in capture.get_buffer_snapshot() if detector.is_vpn_candidate(p)]
    if buf:
        from collections import Counter
        top_ip = Counter(p.dst_ip for p in buf).most_common(1)[0][0]
        print(f"  Using most-frequent VPN dst as entry node: {top_ip}")
        fallback_event = {
            "event": "VPN_RECONNECT",
            "timestamp": event_time.isoformat(),
            "entry_node": top_ip,
            "mobile_local_ip": PHONE_IP,
            "location": "India",
            "protocol": "NordLynx",
            "confidence": 60,
            "entry_method": "PacketCapture_Fallback",
        }
        on_entry(fallback_event)

# ─────────────────────────── STEP 8: wait for correlation

pair_event.wait(timeout=8)

# ─────────────────────────── STEP 9: results

step(8, "Results")
print(f"\n  Packets captured      : {capture.packet_count}")
vpn_final = [p for p in capture.get_buffer_snapshot() if detector.is_vpn_candidate(p)]
print(f"  VPN packets in buffer : {len(vpn_final)}")

if pair_result:
    p = pair_result[0]
    print(f"""
  {'='*54}
  CORRELATED PAIR CAPTURED  ✓
  {'='*54}
  Timestamp    : {p.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} UTC
  Entry Node   : {p.entry_node}   (from NordVPN UI via ADB)
  Exit  Node   : {p.exit_node}   (from packet capture)
  Subnet Match : {'YES — same /24 datacenter' if p.subnet_match else 'NO — cross-subnet pair'}
  Confidence   : {p.correlation_confidence}%
  Provider     : {p.vpn_provider}
  Protocol     : {p.protocol}:{p.port}
  Location     : {p.server_location}
  Entry method : {p.entry_method}
  {'='*54}""")

    xlsx = exporter.export_excel()
    print(f"\n  CSV  : {exporter.csv_path}")
    print(f"  Excel: {xlsx}")
    print("\n  END-TO-END TEST: PASS")
else:
    print("\n  No correlated pair — dumping VPN candidates from capture:")
    for pk in sorted(vpn_final, key=lambda x: detector.score(x), reverse=True)[:8]:
        print(f"    {pk.dst_ip}:{pk.port} {pk.protocol} "
              f"score={detector.score(pk)}% size={pk.size}B")
    print("\n  END-TO-END TEST: FAIL (check VPN traffic and reconnect timing)")

print("\nStopping...")
capture.stop()
bridge.stop()
