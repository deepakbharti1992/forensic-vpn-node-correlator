"""
Entry-Exit node pairing engine — correlates mobile VPN entry node with
desktop packet-capture exit node using time-window matching.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from capture_engine import CaptureEngine, CapturedPacket
from vpn_detector import VpnDetector, KNOWN_VPN_RANGES


@dataclass
class CorrelatedPair:
    timestamp: datetime
    entry_node: str
    exit_node: str
    mobile_local_ip: str
    vpn_provider: str
    protocol: str
    port: int
    server_location: str
    subnet_match: bool
    correlation_confidence: int   # 0-100
    entry_method: str
    exit_method: str = "PacketCapture"

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "entry_node": self.entry_node,
            "exit_node": self.exit_node,
            "mobile_local_ip": self.mobile_local_ip,
            "vpn_provider": self.vpn_provider,
            "protocol": self.protocol,
            "port": self.port,
            "server_location": self.server_location,
            "subnet_match": self.subnet_match,
            "correlation_confidence": self.correlation_confidence,
            "entry_method": self.entry_method,
            "exit_method": self.exit_method,
        }


class PairingEngine:
    HALF_WINDOW = 3.0   # seconds either side of entry event

    def __init__(self, capture: CaptureEngine, detector: VpnDetector) -> None:
        self._capture = capture
        self._detector = detector

    def correlate(
        self,
        entry_node: str,
        event_time: datetime,
        mobile_ip: str,
        entry_method: str = "AccessibilityService",
        server_id: str = "",
        location: str = "",
    ) -> Optional[CorrelatedPair]:
        window = self._capture.get_window(event_time, self.HALF_WINDOW)
        candidates = [
            p for p in window
            if self._detector.is_vpn_candidate(p)
        ]

        if not candidates:
            return None

        exit_pkt, confidence = self._pick_best(candidates, entry_node, event_time)
        if exit_pkt is None:
            return None

        subnet_match = VpnDetector.same_slash24(entry_node, exit_pkt.dst_ip)
        provider = self._detector.guess_provider(exit_pkt)
        geo = location or _geoip_lookup(exit_pkt.dst_ip)

        return CorrelatedPair(
            timestamp=event_time,
            entry_node=entry_node,
            exit_node=exit_pkt.dst_ip,
            mobile_local_ip=mobile_ip,
            vpn_provider=provider,
            protocol=exit_pkt.protocol,
            port=exit_pkt.port,
            server_location=geo,
            subnet_match=subnet_match,
            correlation_confidence=confidence,
            entry_method=entry_method,
        )

    # ----------------------------------------------------------------- private

    def _pick_best(
        self,
        candidates: List[CapturedPacket],
        entry_node: str,
        ref_time: datetime,
    ) -> Tuple[Optional[CapturedPacket], int]:
        ref_ts = ref_time.timestamp()

        # Priority 1 — same /24 subnet
        same_net = [p for p in candidates if VpnDetector.same_slash24(p.dst_ip, entry_node)]
        if same_net:
            best = min(same_net, key=lambda p: abs(p.timestamp.timestamp() - ref_ts))
            return best, 95

        # Priority 2 — known VPN range
        known = [p for p in candidates if _in_known_range(p.dst_ip)]
        if known:
            best = min(known, key=lambda p: abs(p.timestamp.timestamp() - ref_ts))
            return best, 85

        # Priority 3 — any VPN-heuristic traffic (closest in time)
        best = min(candidates, key=lambda p: abs(p.timestamp.timestamp() - ref_ts))
        return best, 70


# --------------------------------------------------------------------------- helpers

def _in_known_range(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in KNOWN_VPN_RANGES)
    except ValueError:
        return False


def _geoip_lookup(ip: str) -> str:
    """Best-effort GeoIP via ip-api.com (no key required, rate-limited)."""
    try:
        import requests
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=city,country", timeout=2)
        if resp.ok:
            data = resp.json()
            return f"{data.get('city', '')}, {data.get('country', '')}".strip(", ")
    except Exception:
        pass
    return "Unknown"
