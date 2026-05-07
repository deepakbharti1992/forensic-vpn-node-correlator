package com.forensic.vpncorrelator

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.util.Log
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue

private const val TAG = "TcpClientService"
private const val CHANNEL_ID = "vnc_channel"
private const val NOTIF_ID = 1
private const val RECONNECT_DELAY_MS = 3000L
private val POISON = JSONObject()   // sentinel to shut down send queue

class TcpClientService : Service() {

    inner class LocalBinder : Binder() {
        fun getService(): TcpClientService = this@TcpClientService
    }

    private val binder = LocalBinder()

    // Separate executors: connectExecutor drives the connection loop,
    // sendQueue drains outbound messages — never blocks on receiveLoop.
    private val connectExecutor = Executors.newSingleThreadExecutor()
    private val sendQueue = LinkedBlockingQueue<JSONObject>()

    private var socket: Socket? = null
    private var writer: PrintWriter? = null
    private var desktopHost = "192.168.137.1"
    private var desktopPort = 5000
    private var running = false

    var onCommandReceived: ((JSONObject) -> Unit)? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(NOTIF_ID, buildNotification("VNC: Connecting..."))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        intent?.getStringExtra("host")?.let { desktopHost = it }
        intent?.getIntExtra("port", 5000).let { desktopPort = it ?: 5000 }
        startConnection()
        return START_STICKY
    }

    override fun onBind(intent: Intent): IBinder = binder

    /** Enqueue an outbound JSON event — safe to call from any thread. */
    fun sendEvent(event: JSONObject) {
        sendQueue.put(event)
    }

    fun stopService() {
        running = false
        sendQueue.put(POISON)
        socket?.close()
        stopSelf()
    }

    private fun startConnection() {
        running = true
        connectExecutor.submit { connectionLoop() }
    }

    private fun connectionLoop() {
        while (running) {
            try {
                Log.i(TAG, "Connecting to $desktopHost:$desktopPort")
                updateNotification("VNC: Connecting to $desktopHost...")
                val sock = Socket(desktopHost, desktopPort)
                socket = sock
                writer = PrintWriter(sock.getOutputStream(), true)
                val reader = BufferedReader(InputStreamReader(sock.getInputStream()))
                updateNotification("VNC: Connected to $desktopHost")
                Log.i(TAG, "Connected")

                // Drain the send queue on a separate thread so receiveLoop never starves it
                val sendThread = Thread({ sendLoop() }, "vnc-send").also { it.isDaemon = true; it.start() }
                receiveLoop(reader)          // blocks until socket closes
                sendThread.interrupt()
            } catch (e: Exception) {
                Log.w(TAG, "Connection error: ${e.message}")
            }
            if (running) {
                updateNotification("VNC: Reconnecting in ${RECONNECT_DELAY_MS / 1000}s...")
                Thread.sleep(RECONNECT_DELAY_MS)
            }
        }
    }

    /** Drains sendQueue and writes each event to the socket. */
    private fun sendLoop() {
        try {
            while (true) {
                val event = sendQueue.take()
                if (event === POISON) break
                try {
                    writer?.println(event.toString())
                    writer?.flush()
                    Log.d(TAG, "Sent: ${event.optString("event")}")
                } catch (e: Exception) {
                    Log.w(TAG, "Send failed: ${e.message}")
                }
            }
        } catch (_: InterruptedException) { }
    }

    private fun receiveLoop(reader: BufferedReader) {
        try {
            var line = reader.readLine()
            while (line != null && running) {
                try {
                    val json = JSONObject(line.trim())
                    handleCommand(json)
                } catch (e: Exception) {
                    Log.w(TAG, "Bad JSON: $line")
                }
                line = reader.readLine()
            }
        } catch (e: Exception) {
            Log.w(TAG, "Receive error: ${e.message}")
        }
    }

    private fun handleCommand(cmd: JSONObject) {
        when (cmd.optString("command")) {
            "PING" -> sendEvent(
                JSONObject().put("event", "PONG")
                    .put("timestamp", java.time.Instant.now().toString())
            )
            "TRIGGER_RECONNECT" -> onCommandReceived?.invoke(cmd)
            else -> onCommandReceived?.invoke(cmd)
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, "VNC Service", NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("VPN Node Correlator")
                .setContentText(text)
                .setSmallIcon(android.R.drawable.ic_menu_compass)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("VPN Node Correlator")
                .setContentText(text)
                .setSmallIcon(android.R.drawable.ic_menu_compass)
                .build()
        }
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm?.notify(NOTIF_ID, buildNotification(text))
    }
}
