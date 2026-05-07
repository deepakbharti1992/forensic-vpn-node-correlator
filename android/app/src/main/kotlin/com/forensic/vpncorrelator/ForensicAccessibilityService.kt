package com.forensic.vpncorrelator

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.ComponentName
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import org.json.JSONObject
import java.time.Instant

private const val TAG = "ForensicA11y"

// Package names of supported VPN apps
private val VPN_PACKAGES = setOf(
    "com.nordvpn.android",
    "com.expressvpn.vpn",
    "com.protonvpn.android",
    "com.privateinternetaccess.android",
    "com.surfshark.vpnclient.android",
    "com.ipvanish.android",
    "com.vyprvpn.android",
)

// Texts found on reconnect/disconnect buttons
private val RECONNECT_TEXTS = setOf(
    "reconnect", "disconnect", "switch location", "change location",
    "quick connect", "connect", "refresh"
)

class ForensicAccessibilityService : AccessibilityService() {

    private var tcpService: TcpClientService? = null
    private var bound = false
    private var lastExtractedIp: String? = null
    private var pendingReconnect = false

    private val conn = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, service: IBinder) {
            val binder = service as TcpClientService.LocalBinder
            tcpService = binder.getService()
            bound = true
            tcpService?.onCommandReceived = ::handleDesktopCommand
            Log.i(TAG, "TcpClientService bound")
        }
        override fun onServiceDisconnected(name: ComponentName) {
            bound = false
            tcpService = null
        }
    }

    override fun onServiceConnected() {
        val info = serviceInfo ?: AccessibilityServiceInfo()
        info.eventTypes = AccessibilityEvent.TYPES_ALL_MASK
        info.feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC
        info.flags = AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS or
                     AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS
        info.notificationTimeout = 100
        serviceInfo = info

        val intent = Intent(this, TcpClientService::class.java)
        bindService(intent, conn, BIND_AUTO_CREATE)
        startService(intent)
        Log.i(TAG, "AccessibilityService connected")
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent) {
        val pkg = event.packageName?.toString() ?: return
        if (pkg !in VPN_PACKAGES) return

        val root = rootInActiveWindow ?: return
        val ip = IpExtractor.findInTree(root)
        root.recycle()

        if (ip != null && ip != lastExtractedIp) {
            lastExtractedIp = ip
            Log.i(TAG, "Detected VPN IP: $ip from $pkg")
            if (pendingReconnect) {
                sendEntryEvent(ip, pkg)
                pendingReconnect = false
            }
        }
    }

    override fun onInterrupt() {
        Log.w(TAG, "Service interrupted")
    }

    override fun onDestroy() {
        if (bound) unbindService(conn)
        super.onDestroy()
    }

    // ----------------------------------------------------------------- private

    private fun handleDesktopCommand(cmd: JSONObject) {
        when (cmd.optString("command")) {
            "TRIGGER_RECONNECT" -> {
                val delayMs = cmd.optLong("delay_ms", 500)
                Log.i(TAG, "Reconnect command received, delay=${delayMs}ms")
                Thread.sleep(delayMs)
                triggerVpnReconnect()
            }
        }
    }

    private fun triggerVpnReconnect() {
        pendingReconnect = true
        val root = rootInActiveWindow

        if (root != null && root.packageName?.toString() in VPN_PACKAGES) {
            val clicked = clickReconnectButton(root)
            root.recycle()
            if (clicked) {
                Log.i(TAG, "Clicked reconnect button via a11y tree")
                return
            }
        }
        root?.recycle()

        // Fallback: launch VPN app main screen so the event fires
        launchFirstAvailableVpnApp()
    }

    private fun clickReconnectButton(root: AccessibilityNodeInfo): Boolean {
        for (text in RECONNECT_TEXTS) {
            val nodes = root.findAccessibilityNodeInfosByText(text)
            for (node in nodes) {
                if (node.isClickable) {
                    val result = node.performAction(AccessibilityNodeInfo.ACTION_CLICK)
                    node.recycle()
                    if (result) return true
                }
                node.recycle()
            }
        }
        return false
    }

    private fun launchFirstAvailableVpnApp() {
        val pm = packageManager
        for (pkg in VPN_PACKAGES) {
            val intent = pm.getLaunchIntentForPackage(pkg) ?: continue
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            startActivity(intent)
            Log.i(TAG, "Launched $pkg")
            return
        }
        Log.w(TAG, "No VPN app found to launch")
    }

    private fun sendEntryEvent(ip: String, sourcePkg: String) {
        val payload = JSONObject().apply {
            put("event", "VPN_RECONNECT")
            put("timestamp", Instant.now().toString())
            put("entry_node", ip)
            put("server_id", "")
            put("location", "")
            put("mobile_local_ip", getMobileHotspotIp())
            put("protocol", guessProtocol(sourcePkg))
            put("confidence", 100)
            put("entry_method", "AccessibilityService")
            put("source_package", sourcePkg)
        }
        tcpService?.sendEvent(payload)
        Log.i(TAG, "Sent entry event: $payload")
    }

    private fun getMobileHotspotIp(): String {
        return try {
            val ifaces = java.net.NetworkInterface.getNetworkInterfaces()
            for (iface in ifaces.toList()) {
                for (addr in iface.inetAddresses.toList()) {
                    val host = addr.hostAddress ?: continue
                    if (host.startsWith("192.168.137.")) return host
                }
            }
            ""
        } catch (e: Exception) { "" }
    }

    private fun guessProtocol(pkg: String): String = when {
        "nordvpn" in pkg -> "NordLynx/WireGuard"
        "proton" in pkg  -> "WireGuard/OpenVPN"
        "express" in pkg -> "Lightway"
        else -> "Unknown"
    }
}
