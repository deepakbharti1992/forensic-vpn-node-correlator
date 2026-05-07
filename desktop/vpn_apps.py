"""Registry of supported VPN apps — package names, UI text patterns, deep links."""
from __future__ import annotations
from dataclasses import dataclass, field

@dataclass
class VpnApp:
    name: str
    package: str
    disconnect_texts: list[str] = field(default_factory=list)
    connect_texts: list[str]    = field(default_factory=list)

SUPPORTED_VPNS: list[VpnApp] = [
    VpnApp("NordVPN",
           "com.nordvpn.android",
           disconnect_texts=["Disconnect", "DISCONNECT", "Pause connection"],
           connect_texts=["Quick Connect", "Connect", "CONNECT", "Quick connect"]),

    VpnApp("ExpressVPN",
           "com.expressvpn.vpn",
           disconnect_texts=["Disconnect", "DISCONNECT", "Connected"],
           connect_texts=["Connect", "CONNECT", "Tap to connect"]),

    VpnApp("ProtonVPN",
           "ch.protonvpn.android",
           disconnect_texts=["Disconnect", "DISCONNECT"],
           connect_texts=["Quick Connect", "Connect", "CONNECT"]),

    VpnApp("PIA - Private Internet Access",
           "com.privateinternetaccess.android",
           disconnect_texts=["Disconnect", "DISCONNECT", "ON"],
           connect_texts=["Connect", "CONNECT", "OFF"]),

    VpnApp("Surfshark",
           "com.surfshark.vpnclient.android",
           disconnect_texts=["Disconnect", "DISCONNECT", "Connected"],
           connect_texts=["Connect", "CONNECT", "Quick-connect"]),

    VpnApp("Windscribe",
           "com.windscribe.vpn",
           disconnect_texts=["Disconnect", "DISCONNECT", "ON"],
           connect_texts=["Connect", "CONNECT", "OFF"]),

    VpnApp("IPVanish",
           "com.ipvanish.android",
           disconnect_texts=["Disconnect", "DISCONNECT"],
           connect_texts=["Connect", "CONNECT"]),

    VpnApp("Hotspot Shield",
           "com.anchorfree.vpnclient",
           disconnect_texts=["Disconnect", "DISCONNECT", "Turn Off"],
           connect_texts=["Connect", "Turn On", "CONNECT"]),

    VpnApp("TunnelBear",
           "com.tunnelbear.android",
           disconnect_texts=["Disconnect", "ON"],
           connect_texts=["Connect", "OFF"]),

    VpnApp("CyberGhost",
           "de.cyberghost.vpnclient.android",
           disconnect_texts=["Disconnect", "DISCONNECT"],
           connect_texts=["Connect", "CONNECT", "Power On"]),

    VpnApp("Mullvad",
           "net.mullvad.mullvadvpn",
           disconnect_texts=["Disconnect", "DISCONNECT"],
           connect_texts=["Secure my connection", "Connect", "CONNECT"]),

    VpnApp("OpenVPN Connect",
           "net.openvpn.unified",
           disconnect_texts=["Disconnect", "DISCONNECT"],
           connect_texts=["Connect", "CONNECT"]),
]

PACKAGE_MAP = {app.package: app for app in SUPPORTED_VPNS}


def detect_installed(adb_func) -> VpnApp | None:
    """Return the first installed+running VPN app detected on the device."""
    # Check which VPN packages are installed
    installed = adb_func("shell", "pm list packages")
    for app in SUPPORTED_VPNS:
        if app.package in installed:
            # Check if it's currently running (has a VPN interface active)
            running = adb_func("shell", f"pidof {app.package}")
            if running.strip():
                return app
    # Fallback: just return first installed
    for app in SUPPORTED_VPNS:
        if app.package in installed:
            return app
    return None


def detect_active_vpn(adb_func) -> VpnApp | None:
    """Detect active VPN by checking which package shows a VPN key icon (tun/vpn interface)."""
    # Check Android VPN service via dumpsys
    dump = adb_func("shell", "dumpsys connectivity | grep -i vpn", timeout=10)
    for app in SUPPORTED_VPNS:
        if app.package in dump:
            return app
    # Fallback to detecting installed
    return detect_installed(adb_func)
