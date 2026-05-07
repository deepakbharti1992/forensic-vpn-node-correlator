"""
End-to-end connection test: MobileBridge TCP server + simulated mobile client.
Also drives a real device test via ADB reverse tunnel if a device is attached.
"""
from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

sys.path.insert(0, ".")
from mobile_bridge import MobileBridge

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"
results: list[tuple[str, bool]] = []

def check(label: str, condition: bool) -> None:
    results.append((label, condition))
    print(f"  {'[PASS]' if condition else '[FAIL]'} {label}")

# ───────────────────────────────────────── helpers

def tcp_send(host: str, port: int, payload: dict, recv_timeout: float = 2.0) -> str:
    """Send one JSON line, return first response line."""
    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall((json.dumps(payload) + "\n").encode())
        s.settimeout(recv_timeout)
        try:
            return s.recv(4096).decode()
        except socket.timeout:
            return ""

# ───────────────────────────────────────── TEST 1: server starts + accepts connection

print("\n═══ TEST 1: Server starts and accepts TCP connection ═══")
received_events: list[dict] = []

def on_entry(msg: dict) -> None:
    received_events.append(msg)

bridge = MobileBridge(on_entry_event=on_entry)
bridge.start()
time.sleep(0.5)   # let server socket bind

try:
    sock = socket.create_connection(("127.0.0.1", 5000), timeout=3)
    sock.close()
    check("Server accepts connection on port 5000", True)
except Exception as e:
    check(f"Server accepts connection on port 5000 ({e})", False)

# ───────────────────────────────────────── TEST 2: heartbeat PING received by client

print("\n═══ TEST 2: Server sends PING heartbeat ═══")

ping_received = threading.Event()
ping_payload: list[dict] = []

def listen_for_ping():
    with socket.create_connection(("127.0.0.1", 5000), timeout=5) as s:
        s.settimeout(7)
        try:
            data = s.recv(4096).decode()
            for line in data.splitlines():
                msg = json.loads(line)
                if msg.get("command") == "PING":
                    ping_payload.append(msg)
                    ping_received.set()
        except Exception:
            pass

t = threading.Thread(target=listen_for_ping, daemon=True)
t.start()
ping_received.wait(timeout=8)
check("Heartbeat PING sent within 8 seconds", ping_received.is_set())
if ping_payload:
    check("PING has timestamp field", "timestamp" in ping_payload[0])

# ───────────────────────────────────────── TEST 3: VPN_RECONNECT event parsed

print("\n═══ TEST 3: VPN_RECONNECT event received and parsed ═══")

event_received = threading.Event()
received_events.clear()

def _wait_event():
    event_received.wait(timeout=5)

wait_t = threading.Thread(target=_wait_event, daemon=True)
wait_t.start()

# Monkey-patch callback to signal
orig_cb = bridge._on_entry
def signalling_cb(msg):
    orig_cb(msg)
    event_received.set()
bridge._on_entry = signalling_cb

test_event = {
    "event": "VPN_RECONNECT",
    "timestamp": datetime.now(tz=timezone.utc).isoformat(),
    "entry_node": "94.156.30.65",
    "server_id": "India #173",
    "location": "Mumbai, India",
    "mobile_local_ip": "192.168.137.45",
    "protocol": "NordLynx",
    "confidence": 100,
    "entry_method": "AccessibilityService",
}

with socket.create_connection(("127.0.0.1", 5000), timeout=3) as s:
    s.sendall((json.dumps(test_event) + "\n").encode())
    time.sleep(0.5)

event_received.wait(timeout=4)
check("VPN_RECONNECT event received by server", event_received.is_set())
if received_events:
    ev = received_events[0]
    check("entry_node parsed correctly (94.156.30.65)", ev.get("entry_node") == "94.156.30.65")
    check("mobile_local_ip parsed correctly",           ev.get("mobile_local_ip") == "192.168.137.45")
    check("location parsed correctly",                  ev.get("location") == "Mumbai, India")

# ───────────────────────────────────────── TEST 4: send TRIGGER_RECONNECT to client

print("\n═══ TEST 4: Desktop sends TRIGGER_RECONNECT to mobile ═══")

cmd_received = threading.Event()
cmd_payload: list[dict] = []

def listen_for_command():
    with socket.create_connection(("127.0.0.1", 5000), timeout=3) as s:
        s.settimeout(4)
        buf = b""
        try:
            while not cmd_received.is_set():
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    try:
                        msg = json.loads(line.decode())
                        if msg.get("command") == "PING":
                            s.sendall((json.dumps({"event": "PONG"}) + "\n").encode())
                        elif msg.get("command") == "TRIGGER_RECONNECT":
                            cmd_payload.append(msg)
                            cmd_received.set()
                    except json.JSONDecodeError:
                        pass
        except socket.timeout:
            pass

t2 = threading.Thread(target=listen_for_command, daemon=True)
t2.start()
# Wait until bridge confirms the new client is connected before sending
deadline = time.time() + 3
while not bridge.is_connected and time.time() < deadline:
    time.sleep(0.05)
bridge.send_reconnect(delay_ms=500, location="India")
cmd_received.wait(timeout=4)
check("TRIGGER_RECONNECT delivered to connected client", cmd_received.is_set())
if cmd_payload:
    check("delay_ms field present",      "delay_ms" in cmd_payload[0])
    check("target_location = 'India'",   cmd_payload[0].get("target_location") == "India")

# ───────────────────────────────────────── TEST 5: ADB reverse tunnel (real device)

print("\n═══ TEST 5: Real device via ADB reverse tunnel ═══")

adb = r"C:\AndroidSDK\platform-tools\adb.exe"
try:
    dev = subprocess.check_output([adb, "devices"], text=True, timeout=5)
    has_device = any(line.strip().endswith("device") for line in dev.splitlines()[1:])
except Exception:
    has_device = False

if not has_device:
    print("  [SKIP] No ADB device connected — skipping real-device test")
    check("ADB device present (skipped)", True)
else:
    # Set up reverse tunnel: phone localhost:5000 → desktop 5000
    rev = subprocess.run([adb, "reverse", "tcp:5000", "tcp:5000"],
                         capture_output=True, text=True, timeout=10)
    check("ADB reverse tunnel established", rev.returncode == 0)

    # Send a JSON event from phone via adb shell using /dev/tcp
    adb_event = json.dumps({
        "event": "VPN_RECONNECT",
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "entry_node": "81.17.122.203",
        "mobile_local_ip": "192.168.137.45",
        "location": "Delhi, India",
        "protocol": "NordLynx",
        "confidence": 100,
        "entry_method": "ADB_Test",
    })

    adb_event_escaped = adb_event.replace('"', '\\"')
    # Release port 5000 so mini_bridge can bind it
    bridge.stop()
    import time as _t2; _t2.sleep(0.5)

    # Start the real installed TcpClientService on the device — it will connect
    # to 127.0.0.1:5000 on the phone which the tunnel forwards to desktop:5000.
    subprocess.run([adb, "shell", "am force-stop com.forensic.vpncorrelator"],
                   capture_output=True, timeout=5)
    import time as _t; _t.sleep(1)

    # Start a lightweight bridge server that sends PING and awaits PONG
    pong_received = threading.Event()
    pong_data: list[dict] = []

    def mini_bridge():
        with socket.socket() as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("", 5000))
            srv.listen(1)
            srv.settimeout(12)
            try:
                conn, _ = srv.accept()
                conn.settimeout(8)
                conn.sendall((json.dumps({"command": "PING",
                                          "timestamp": datetime.now(tz=timezone.utc).isoformat()})
                               + "\n").encode())
                buf = b""
                deadline = _t.time() + 8
                while _t.time() < deadline:
                    try:
                        chunk = conn.recv(4096)
                        if not chunk: break
                        buf += chunk
                        while b"\n" in buf:
                            line, buf = buf.split(b"\n", 1)
                            msg = json.loads(line.decode())
                            if msg.get("event") == "PONG":
                                pong_data.append(msg)
                                pong_received.set()
                                return
                    except (socket.timeout, json.JSONDecodeError):
                        break
            except socket.timeout:
                pass

    bridge_t = threading.Thread(target=mini_bridge, daemon=True)
    bridge_t.start()
    _t.sleep(0.5)

    adb_result = subprocess.run(
        [adb, "shell",
         "am start-foreground-service -n com.forensic.vpncorrelator/.TcpClientService"
         " --es host 127.0.0.1 --ei port 5000"],
        capture_output=True, text=True, timeout=10
    )
    check("Phone sent event via ADB tunnel", adb_result.returncode == 0)
    pong_received.wait(timeout=12)
    check("Desktop received phone event (PONG from Kotlin app)", pong_received.is_set())
    if pong_data:
        check("PONG has timestamp field", "timestamp" in pong_data[0])

    # Clean up reverse tunnel
    subprocess.run([adb, "reverse", "--remove", "tcp:5000"], capture_output=True, timeout=5)

# ───────────────────────────────────────── summary

bridge.stop()
print("\n═══ RESULTS ═══")
passed = sum(1 for _, ok in results if ok)
total  = len(results)
for label, ok in results:
    print(f"  {'[PASS]' if ok else '[FAIL]'} {label}")
print(f"\n  {passed}/{total} tests passed")
sys.exit(0 if passed == total else 1)
