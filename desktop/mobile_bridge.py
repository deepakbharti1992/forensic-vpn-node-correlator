"""
TCP server that communicates with the Android forensic companion APK.
"""
from __future__ import annotations

import json
import logging
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Optional

log = logging.getLogger(__name__)

PORT = 5000
HEARTBEAT_INTERVAL = 5   # seconds


class MobileBridge:
    def __init__(self, on_entry_event: Callable[[dict], None]) -> None:
        self._on_entry = on_entry_event
        self._client_sock: Optional[socket.socket] = None
        self._client_addr: Optional[tuple] = None
        self._server_sock: Optional[socket.socket] = None
        self._running = False
        self._lock = threading.Lock()
        self._status_cb: Optional[Callable[[bool, str], None]] = None

    def set_status_callback(self, cb: Callable[[bool, str], None]) -> None:
        """Callback: (connected: bool, ip: str)"""
        self._status_cb = cb

    def start(self) -> None:
        self._running = True
        threading.Thread(target=self._serve_loop, daemon=True).start()

    def stop(self) -> None:
        self._running = False
        self._close_client()
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass

    def send_reconnect(self, delay_ms: int = 500, location: str = "India") -> bool:
        return self._send({
            "command": "TRIGGER_RECONNECT",
            "delay_ms": delay_ms,
            "target_location": location,
        })

    @property
    def is_connected(self) -> bool:
        return self._client_sock is not None

    @property
    def client_ip(self) -> str:
        if self._client_addr:
            return self._client_addr[0]
        return ""

    # ----------------------------------------------------------------- private

    def _serve_loop(self) -> None:
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind(("0.0.0.0", PORT))
        self._server_sock.listen(1)
        self._server_sock.settimeout(2.0)
        log.info("MobileBridge listening on port %d", PORT)

        while self._running:
            try:
                conn, addr = self._server_sock.accept()
                self._set_client(conn, addr)
                threading.Thread(target=self._recv_loop, args=(conn,), daemon=True).start()
                threading.Thread(target=self._heartbeat_loop, daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _recv_loop(self, conn: socket.socket) -> None:
        buf = b""
        while self._running:
            try:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    self._handle_message(line.decode("utf-8", errors="replace"))
            except (OSError, ConnectionResetError):
                break
        self._clear_client()

    def _handle_message(self, raw: str) -> None:
        try:
            msg = json.loads(raw.strip())
        except json.JSONDecodeError:
            log.warning("Bad JSON from mobile: %s", raw[:120])
            return

        event = msg.get("event", "")
        if event == "VPN_RECONNECT":
            self._on_entry(msg)
        elif event == "PONG":
            pass  # heartbeat reply
        else:
            log.debug("Mobile message: %s", msg)

    def _heartbeat_loop(self) -> None:
        while self._running and self.is_connected:
            self._send({"command": "PING", "timestamp": datetime.now(tz=timezone.utc).isoformat()})
            time.sleep(HEARTBEAT_INTERVAL)

    def _send(self, payload: dict) -> bool:
        with self._lock:
            if not self._client_sock:
                return False
            try:
                data = (json.dumps(payload) + "\n").encode()
                self._client_sock.sendall(data)
                return True
            except OSError:
                self._clear_client()
                return False

    def _set_client(self, conn: socket.socket, addr: tuple) -> None:
        self._close_client()
        self._client_sock = conn
        self._client_addr = addr
        log.info("Mobile connected from %s", addr[0])
        if self._status_cb:
            self._status_cb(True, addr[0])

    def _clear_client(self) -> None:
        self._client_sock = None
        self._client_addr = None
        log.info("Mobile disconnected")
        if self._status_cb:
            self._status_cb(False, "")

    def _close_client(self) -> None:
        with self._lock:
            if self._client_sock:
                try:
                    self._client_sock.close()
                except OSError:
                    pass
                self._client_sock = None
