package com.forensic.vpncorrelator

import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.text.TextUtils
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    private lateinit var tvStatus: TextView
    private lateinit var tvMobileIp: TextView
    private lateinit var etDesktopIp: EditText
    private lateinit var btnConnect: Button
    private lateinit var btnA11y: Button
    private lateinit var btnReconnect: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(buildLayout())
        refresh()
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    private fun refresh() {
        val a11yOn = isAccessibilityEnabled()
        tvStatus.text = if (a11yOn) "AccessibilityService: ENABLED" else "AccessibilityService: DISABLED"
        tvStatus.setTextColor(if (a11yOn) 0xFF27AE60.toInt() else 0xFFE74C3C.toInt())
        tvMobileIp.text = "Mobile IP: ${getMobileIp()}"
    }

    private fun buildLayout(): View {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(40, 80, 40, 40)
        }

        val title = TextView(this).apply {
            text = "VNC Forensic Companion"
            textSize = 20f
            setTextColor(0xFF2C3E50.toInt())
            setPadding(0, 0, 0, 30)
        }

        tvStatus = TextView(this).apply { textSize = 14f }
        tvMobileIp = TextView(this).apply { textSize = 13f; setPadding(0, 8, 0, 8) }

        val ipLabel = TextView(this).apply { text = "Desktop IP (hotspot gateway):"; textSize = 13f }
        etDesktopIp = EditText(this).apply {
            setText("192.168.137.1")
            textSize = 14f
        }

        btnA11y = Button(this).apply {
            text = "Open Accessibility Settings"
            setOnClickListener { startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)) }
        }

        btnConnect = Button(this).apply {
            text = "Start VNC Service"
            setBackgroundColor(0xFF27AE60.toInt())
            setTextColor(0xFFFFFFFF.toInt())
            setOnClickListener { startVncService() }
        }

        btnReconnect = Button(this).apply {
            text = "Manual Reconnect Test"
            setOnClickListener { sendManualReconnect() }
        }

        for (v in listOf(title, tvStatus, tvMobileIp, ipLabel, etDesktopIp,
                         btnA11y, btnConnect, btnReconnect)) {
            root.addView(v)
            (v.layoutParams as? LinearLayout.LayoutParams)?.apply {
                bottomMargin = 12
            }
        }
        return root
    }

    private fun startVncService() {
        val host = etDesktopIp.text.toString().trim().ifEmpty { "192.168.137.1" }
        val intent = Intent(this, TcpClientService::class.java)
        intent.putExtra("host", host)
        intent.putExtra("port", 5000)
        startForegroundService(intent)
        Toast.makeText(this, "VNC service started", Toast.LENGTH_SHORT).show()
    }

    private fun sendManualReconnect() {
        Toast.makeText(this, "Manual reconnect — use via desktop TRIGGER RECONNECT button", Toast.LENGTH_LONG).show()
    }

    private fun isAccessibilityEnabled(): Boolean {
        val expectedService = "${packageName}/${ForensicAccessibilityService::class.java.canonicalName}"
        val enabled = Settings.Secure.getString(contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
            ?: return false
        return TextUtils.SimpleStringSplitter(':').also { it.setString(enabled) }
            .any { it.equals(expectedService, ignoreCase = true) }
    }

    private fun getMobileIp(): String {
        return try {
            val ifaces = java.net.NetworkInterface.getNetworkInterfaces()
            for (iface in ifaces.toList()) {
                for (addr in iface.inetAddresses.toList()) {
                    val host = addr.hostAddress ?: continue
                    if (host.startsWith("192.168.137.")) return host
                }
            }
            "Not on hotspot"
        } catch (e: Exception) { "Unknown" }
    }
}
