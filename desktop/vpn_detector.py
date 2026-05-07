"""
Generic VPN traffic detector — heuristics for ports, known ranges, and entropy.
"""
from __future__ import annotations

import ipaddress
from typing import List, Optional

from capture_engine import CapturedPacket

# Common VPN tunnel ports (WireGuard, OpenVPN UDP/TCP, IPsec, L2TP, SSTP, etc.)
VPN_PORTS = {51820, 1194, 443, 4500, 500, 1701, 1723, 8443, 4096}

# Known VPN datacenter ranges — extend as intelligence grows
KNOWN_VPN_RANGES: List[ipaddress.IPv4Network] = [
    ipaddress.ip_network("94.156.30.0/24"),
    ipaddress.ip_network("81.17.122.0/24"),
    ipaddress.ip_network("87.17.122.0/24"),
    ipaddress.ip_network("185.159.156.0/24"),   # NordVPN India cluster
    ipaddress.ip_network("103.234.220.0/24"),
    ipaddress.ip_network("45.134.212.0/24"),
]

# Port → provider hints (best-effort)
PROVIDER_HINTS = {
    51820: "NordVPN/WireGuard",
    1194: "OpenVPN",
    443: "SSTP/OpenVPN-TCP/ProtonVPN",
    4500: "IPsec/IKEv2",
    500:  "IPsec/IKEv2",
    1701: "L2TP",
    1723: "PPTP",
}


class VpnDetector:
    MIN_ENTROPY_PAYLOAD = 80   # bytes — encrypted payloads are large & random

    def is_vpn_candidate(self, pkt: CapturedPacket) -> bool:
        return (
            self._port_match(pkt.port)
            or self._range_match(pkt.dst_ip)
            or self._entropy_heuristic(pkt)
        )

    def score(self, pkt: CapturedPacket) -> int:
        """Return 0-100 likelihood that this packet belongs to a VPN tunnel."""
        s = 0
        if self._port_match(pkt.port):
            s += 50
        if self._range_match(pkt.dst_ip):
            s += 40
        if self._entropy_heuristic(pkt):
            s += 20
        return min(s, 100)

    def guess_provider(self, pkt: CapturedPacket) -> str:
        hint = PROVIDER_HINTS.get(pkt.port)
        if hint:
            return hint
        try:
            addr = ipaddress.ip_address(pkt.dst_ip)
            for net in KNOWN_VPN_RANGES:
                if addr in net:
                    return "VPN (known range)"
        except ValueError:
            pass
        return "Unknown VPN"

    # ----------------------------------------------------------------- helpers

    @staticmethod
    def _port_match(port: int) -> bool:
        return port in VPN_PORTS

    @staticmethod
    def _range_match(dst_ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(dst_ip)
            return any(addr in net for net in KNOWN_VPN_RANGES)
        except ValueError:
            return False

    @staticmethod
    def _entropy_heuristic(pkt: CapturedPacket) -> bool:
        return pkt.protocol == "UDP" and pkt.raw_payload_len > VpnDetector.MIN_ENTROPY_PAYLOAD

    @staticmethod
    def same_slash24(ip_a: str, ip_b: str) -> bool:
        try:
            a = ipaddress.ip_address(ip_a)
            b = ipaddress.ip_address(ip_b)
            net_a = ipaddress.ip_network(f"{ip_a}/24", strict=False)
            return b in net_a
        except ValueError:
            return False
