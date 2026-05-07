package com.forensic.vpncorrelator

import android.view.accessibility.AccessibilityNodeInfo
import android.util.Log

private const val TAG = "IpExtractor"

private val IP_REGEX = Regex("""\b((?:\d{1,3}\.){3}\d{1,3})\b""")

/**
 * Walks an AccessibilityNodeInfo tree looking for text that matches an IPv4 address.
 * Returns the first valid public IP found, or null.
 */
object IpExtractor {

    fun findInTree(root: AccessibilityNodeInfo?): String? {
        root ?: return null
        return walkNode(root)
    }

    fun extractFromText(text: String): String? {
        val matches = IP_REGEX.findAll(text)
        for (m in matches) {
            val ip = m.groupValues[1]
            if (isValidPublicIp(ip)) {
                Log.d(TAG, "Extracted IP: $ip from text")
                return ip
            }
        }
        return null
    }

    private fun walkNode(node: AccessibilityNodeInfo): String? {
        val text = node.text?.toString() ?: ""
        val desc = node.contentDescription?.toString() ?: ""
        for (candidate in listOf(text, desc)) {
            val ip = extractFromText(candidate)
            if (ip != null) return ip
        }
        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            val result = walkNode(child)
            if (result != null) {
                child.recycle()
                return result
            }
            child.recycle()
        }
        return null
    }

    private fun isValidPublicIp(ip: String): Boolean {
        val parts = ip.split(".").mapNotNull { it.toIntOrNull() }
        if (parts.size != 4 || parts.any { it !in 0..255 }) return false
        // Exclude private/loopback/link-local ranges
        if (parts[0] == 10) return false
        if (parts[0] == 127) return false
        if (parts[0] == 172 && parts[1] in 16..31) return false
        if (parts[0] == 192 && parts[1] == 168) return false
        if (parts[0] == 169 && parts[1] == 254) return false
        return true
    }
}
