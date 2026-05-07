"""
Packet capture engine — sniffs hotspot NIC and buffers VPN-candidate packets.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Deque, List, Optional

from scapy.all import AsyncSniffer, Ether, IP, TCP, UDP, conf


@dataclass
class CapturedPacket:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    protocol: str
    port: int
    size: int
    raw_payload_len: int = 0


class CaptureEngine:
    BUFFER_SECONDS = 12          # Keep 12 s rolling window for correlation
    MOBILE_SUBNET = "192.168.137"  # Windows hotspot default DHCP range

    def __init__(self, mobile_ip: str = "", iface: str = "") -> None:
        self.mobile_ip = mobile_ip
        self.iface = iface
        self._buffer: Deque[CapturedPacket] = deque()
        self._lock = threading.Lock()
        self._sniffer: Optional[AsyncSniffer] = None
        self._running = False
        self._packet_count = 0
        self._on_packet_cb: Optional[Callable[[CapturedPacket], None]] = None

    # ------------------------------------------------------------------ public

    def set_packet_callback(self, cb: Callable[[CapturedPacket], None]) -> None:
        self._on_packet_cb = cb

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        bpf = self._build_bpf()
        self._sniffer = AsyncSniffer(
            iface=self.iface or None,
            filter=bpf,
            prn=self._process_packet,
            store=False,
        )
        self._sniffer.start()
        # Background thread purges stale buffer entries
        threading.Thread(target=self._purge_loop, daemon=True).start()

    def stop(self) -> None:
        self._running = False
        if self._sniffer:
            self._sniffer.stop()

    def get_buffer_snapshot(self) -> List[CapturedPacket]:
        with self._lock:
            return list(self._buffer)

    def get_window(self, center: datetime, half_window: float = 3.0) -> List[CapturedPacket]:
        """Return packets within ±half_window seconds of center."""
        lo = center.timestamp() - half_window
        hi = center.timestamp() + half_window
        with self._lock:
            return [p for p in self._buffer if lo <= p.timestamp.timestamp() <= hi]

    @property
    def packet_count(self) -> int:
        return self._packet_count

    # ----------------------------------------------------------------- private

    def _build_bpf(self) -> str:
        if self.mobile_ip:
            return f"src host {self.mobile_ip}"
        # Broad hotspot subnet filter
        return f"src net {self.MOBILE_SUBNET}.0/24"

    def _process_packet(self, pkt) -> None:
        if not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc)
        proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "OTHER"
        if proto == "OTHER":
            return

        layer = pkt[TCP] if proto == "TCP" else pkt[UDP]
        cp = CapturedPacket(
            timestamp=ts,
            src_ip=ip.src,
            dst_ip=ip.dst,
            protocol=proto,
            port=layer.dport,
            size=len(pkt),
            raw_payload_len=len(bytes(layer.payload)),
        )
        with self._lock:
            self._buffer.append(cp)
        self._packet_count += 1
        if self._on_packet_cb:
            self._on_packet_cb(cp)

    def _purge_loop(self) -> None:
        while self._running:
            cutoff = time.time() - self.BUFFER_SECONDS
            with self._lock:
                while self._buffer and self._buffer[0].timestamp.timestamp() < cutoff:
                    self._buffer.popleft()
            time.sleep(1)


def list_hotspot_interfaces() -> List[str]:
    """Return NIC names that look like a Windows hotspot adapter."""
    from scapy.arch.windows import get_windows_if_list
    results = []
    try:
        for iface in get_windows_if_list():
            name = iface.get("name", "") + iface.get("description", "")
            if any(kw in name.lower() for kw in ("hotspot", "hosted", "wi-fi direct", "virtual")):
                results.append(iface.get("name", ""))
    except Exception:
        pass
    return results
