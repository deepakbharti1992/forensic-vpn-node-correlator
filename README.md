# Forensic VPN Node Correlator (VNC) v1.0

A two-component forensic system that correlates VPN **entry nodes** (from the mobile VPN app UI) with **exit nodes** (from real-time packet capture on a Windows hotspot), producing tamper-evident CSV/Excel reports with SHA-256 row hashing.

## Architecture

```
┌─────────────────────────────┐        TCP :5000        ┌─────────────────────────┐
│   Android Phone (NordVPN)   │ ◄──────────────────────► │   Windows Desktop       │
│                             │                          │                         │
│  ForensicAccessibilityService│                         │  CaptureEngine (Scapy)  │
│  → reads VPN server IP      │                         │  VpnDetector            │
│  → sends VPN_RECONNECT JSON │                         │  PairingEngine          │
│                             │                         │  MobileBridge (TCP srv) │
│  TcpClientService           │                         │  CsvExporter (SHA-256)  │
│  → persistent TCP client    │                         │  PyQt6 GUI Dashboard    │
└─────────────────────────────┘                          └─────────────────────────┘
```

**How it works:**
1. Phone connects to the desktop hotspot (`192.168.137.x`)
2. Desktop captures all packets from the phone on the hotspot NIC
3. When NordVPN reconnects, the phone reads the new server IP from the NordVPN UI and sends it to the desktop over TCP
4. The pairing engine correlates the entry node (reported by phone) with the exit node (seen in captured traffic) within a ±3 s time window
5. Matched pairs are written to a forensic CSV with a SHA-256 integrity hash per row

## Results

Live end-to-end test output:

```
Entry Node   : 81.17.122.220   (from NordVPN UI via ADB)
Exit  Node   : 81.17.122.210   (from packet capture)
Subnet Match : YES — same /24 datacenter
Confidence   : 95%
Provider     : NordVPN/WireGuard
Protocol     : UDP:51820
Location     : India
```

## Repository Structure

```
├── desktop/                  # Python desktop application
│   ├── capture_engine.py     # Scapy AsyncSniffer, 12s rolling buffer
│   ├── vpn_detector.py       # Port/range heuristics, VPN scoring
│   ├── pairing_engine.py     # 3-tier correlation algorithm
│   ├── mobile_bridge.py      # TCP server, JSON framing, PING/PONG
│   ├── csv_exporter.py       # SHA-256 row hashing, Excel export
│   ├── gui_dashboard.py      # PyQt6 live dashboard
│   ├── main.py               # Application entry point
│   ├── test_connection.py    # TCP bridge unit tests (14 checks)
│   ├── test_e2e.py           # Full end-to-end test with real VPN
│   └── requirements.txt
├── android/                  # Kotlin Android app (source)
│   └── app/src/main/kotlin/com/forensic/vpncorrelator/
│       ├── TcpClientService.kt           # Persistent TCP client
│       ├── ForensicAccessibilityService.kt # VPN UI reader
│       ├── IpExtractor.kt                # IPv4 tree walker
│       └── MainActivity.kt
├── VNCForensic-debug.apk     # Pre-built Android APK (ready to install)
└── VPN_Node_Correlator_Complete_Prompt.txt
```

## Desktop Setup

**Requirements:** Windows 10/11, Python 3.10+, [Npcap](https://npcap.com) (for packet capture)

```bash
cd desktop
pip install -r requirements.txt
python main.py
```

Run tests:
```bash
python test_connection.py   # TCP bridge tests
python test_e2e.py          # Full end-to-end (requires phone + NordVPN)
```

## Android Setup

**Option A — install pre-built APK:**
```bash
adb install VNCForensic-debug.apk
```

**Option B — build from source** (requires Android SDK, JDK 11+):
```bash
cd android
./gradlew.bat assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
```

**Enable the AccessibilityService on the phone:**
```bash
adb shell settings put secure enabled_accessibility_services \
  com.forensic.vpncorrelator/com.forensic.vpncorrelator.ForensicAccessibilityService
```

**Start the TCP client service (point to desktop IP):**
```bash
adb shell am start-foreground-service \
  -n com.forensic.vpncorrelator/.TcpClientService \
  --es host 192.168.137.1 --ei port 5000
```

## Correlation Algorithm

| Priority | Condition | Confidence |
|----------|-----------|------------|
| 1 | Entry and exit in same /24 subnet | 95% |
| 2 | Exit IP in known VPN provider range | 85% |
| 3 | Exit matches any VPN heuristic | 70% |

Time window: ±3 seconds around the VPN reconnect event.

## Forensic Integrity

Each CSV row includes a SHA-256 hash of `timestamp + entry_node + exit_node + mobile_local_ip`, making any post-capture tampering detectable.

## Supported VPN Apps

NordVPN, ExpressVPN, ProtonVPN, Private Internet Access, Surfshark
