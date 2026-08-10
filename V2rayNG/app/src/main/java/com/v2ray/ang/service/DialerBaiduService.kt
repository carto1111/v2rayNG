package com.v2ray.ang.service

import android.content.Context
import com.v2ray.ang.util.LogUtil
import com.v2ray.ang.handler.NotificationManager as AngNotificationManager
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLSocketFactory

/**
 * Baidu Tunnel SOCKS5 proxy service.
 *
 * Implements a SOCKS5 proxy that tunnels traffic through
 * Baidu's cloud proxy (cloudnproxy.baidu.com:443) using HTTP CONNECT
 * with X-T5-Auth authentication.
 *
 * Matches the reference Go implementation exactly:
 * - X-T5-Auth: 482857715 (fixed token)
 * - Host: sptest.baidu.com
 * - User-Agent: okhttp/3.11.0 Dalvik/2.1.0 ... baiduboxapp/11.0.5.12
 */
class DialerBaiduService : IDialerService {

    companion object {
        private const val TAG = "DialerBaiduService"

        // Baidu proxy entry nodes (from official sing-box config, 4 ISPs + original)
        // 电信 / 联通 / 移动 三网各一个入口，外加 cloudnproxy 原始入口
        private const val BAIDU_HOST_DIANXIN = "180.101.50.249"   // 📍BD-电信
        private const val BAIDU_HOST_LIANTONG = "157.0.146.158"    // 📍BD-联通
        private const val BAIDU_HOST_YIDONG = "36.155.169.188"     // 📍BD-移动
        private const val BAIDU_HOST_ORIGIN = "cloudnproxy.baidu.com" // 📍BD-原始
        private const val BAIDU_PROXY_PORT = 443

        // 当前使用的百度入口（默认原始 cloudnproxy，会在 start 时按运营商自动选择）
        @Volatile
        private var currentBaiduHost: String = BAIDU_HOST_ORIGIN
        private set

        // X-T5-Auth token - fixed value from Go reference implementation
        private const val X_T5_AUTH_TOKEN = "482857715"

        // User-Agent matching baiduboxapp exactly as in Go reference
        private const val USER_AGENT = "okhttp/3.11.0 Dalvik/2.1.0 (Linux; Build/RKQ1.200826.002) baiduboxapp/11.0.5.12 (Baidu; P1 11)"

        // Connection timeout for dialing baidu proxy (10s as in Go)
        private const val BAIDU_CONNECT_TIMEOUT_MS = 10000

        // SOCKS5 constants
        private const val SOCKS_VERSION = 0x05
        private const val AUTH_NONE = 0x00
        private const val AUTH_PASSWORD = 0x02
        private const val AUTH_NO_ACCEPTABLE = 0xFF

        private const val CMD_CONNECT = 0x01

        private const val ATYP_IPV4 = 0x01
        private const val ATYP_DOMAIN = 0x03
        private const val ATYP_IPV6 = 0x04

        private const val REP_SUCCESS = 0x00
        private const val REP_GENERAL_FAILURE = 0x01
        private const val REP_CONNECTION_REFUSED = 0x05
        private const val REP_CMD_NOT_SUPPORTED = 0x07
        private const val REP_ATYP_NOT_SUPPORTED = 0x08

        // Buffer size for relay (same as Go BUFFER_SIZE)
        private const val BUFFER_SIZE = 8192

        @Volatile
        var status: String = "disabled"
            private set

        @Volatile
        var lastError: String = ""
            private set

        @Volatile
        var lastBaiduResponse: String = ""
            private set
    }

    @Volatile
    private var serverSocket: ServerSocket? = null

    @Volatile
    private var executor: ExecutorService? = null

    private val running = AtomicBoolean(false)

    override fun start(context: Context, dialerAddr: String) {
        stop()
        setStatus("starting")

        if (dialerAddr.isEmpty()) {
            LogUtil.e(TAG, "Empty dialer address")
            return
        }

        val parts = dialerAddr.split(":")
        if (parts.size != 2) {
            LogUtil.e(TAG, "Invalid dialer address format: $dialerAddr")
            return
        }

        val host = parts[0]
        val port = parts[1].toIntOrNull() ?: run {
            LogUtil.e(TAG, "Invalid port in dialer address: $dialerAddr")
            return
        }

        // 按当前运营商自动选择百度入口节点（电信/联通/移动/原始）
        currentBaiduHost = selectBaiduHostByCarrier(context)
        LogUtil.e(TAG, "🚀 Baidu Tunnel entry node: $currentBaiduHost")

        try {
            val sock = ServerSocket()
            sock.setReuseAddress(true)
            sock.bind(java.net.InetSocketAddress(InetAddress.getByName(host), port), 128)
            serverSocket = sock
            executor = Executors.newCachedThreadPool { runnable ->
                Thread(runnable, "BaiduTunnel-Worker").apply {
                    isDaemon = true
                }
            }
            running.set(true)

            setStatus("active")
            LogUtil.e(TAG, "🚀 Baidu Tunnel SOCKS5 server started on $dialerAddr")

            // Start acceptor thread
            Thread({ acceptLoop() }, "BaiduTunnel-Acceptor").apply {
                isDaemon = true
                start()
            }
        } catch (e: Exception) {
            lastError = "Start failed: ${e.message}"
            LogUtil.e(TAG, "Failed to start Baidu Tunnel server: ${e.message}")
            stop()
        }
    }

    override fun stop() {
        running.set(false)

        try {
            serverSocket?.close()
        } catch (_: Exception) {
        }
        serverSocket = null

        try {
            executor?.shutdown()
        } catch (_: Exception) {
        }
        executor = null

        setStatus("stopped")
        LogUtil.e(TAG, "🚀 Baidu Tunnel SOCKS5 server stopped")
    }

    /**
     * 根据当前 SIM 卡运营商自动选择百度入口节点：
     * - 中国电信 → BD-电信 (180.101.50.249)
     * - 中国联通 → BD-联通 (157.0.146.158)
     * - 中国移动 → BD-移动 (36.155.169.188)
     * - 其他/无法识别 → BD-原始 (cloudnproxy.baidu.com)
     */
    private fun selectBaiduHostByCarrier(context: Context): String {
        return try {
            val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? android.telephony.TelephonyManager
            if (tm == null) {
                return BAIDU_HOST_ORIGIN
            }

            // 优先看当前注册网络运营商，其次 SIM 卡运营商
            val operator = tm.networkOperatorName.ifBlank { tm.simOperatorName }
            if (operator.isBlank()) {
                return BAIDU_HOST_ORIGIN
            }

            val op = operator.lowercase()
            when {
                op.contains("电信") || op.contains("ct") || op.contains("chinatelecom") ||
                    op.contains("中国电信") -> BAIDU_HOST_DIANXIN
                op.contains("联通") || op.contains("cu") || op.contains("chinaunicom") ||
                    op.contains("中国联通") -> BAIDU_HOST_LIANTONG
                op.contains("移动") || op.contains("cm") || op.contains("chinamobile") ||
                    op.contains("中国移动") -> BAIDU_HOST_YIDONG
                else -> BAIDU_HOST_ORIGIN
            }
        } catch (e: Exception) {
            LogUtil.d(TAG, "Carrier detection failed, fallback to origin: ${e.message}")
            BAIDU_HOST_ORIGIN
        }
    }

    private fun acceptLoop() {
        val server = serverSocket ?: return
        val exec = executor ?: return

        while (running.get()) {
            try {
                val clientSocket = server.accept()
                exec.submit { handleClient(clientSocket) }
            } catch (e: Exception) {
                if (running.get()) {
                    LogUtil.d(TAG, "Accept error: ${e.message}")
                }
            }
        }
    }

    private fun handleClient(clientSocket: Socket) {
        try {
            clientSocket.use { client ->
                val input = client.getInputStream()
                val output = client.getOutputStream()

                // SOCKS5 handshake
                if (!handleSocks5Handshake(input, output)) {
                    return
                }

                // Parse SOCKS5 CONNECT request
                val connectRequest = parseSocks5ConnectRequest(input) ?: run {
                    sendSocks5Error(output, REP_GENERAL_FAILURE)
                    return
                }

                // Connect through Baidu tunnel (exact Go implementation)
                val baiduSocket = dialBaiduTunnel(
                    currentBaiduHost,
                    BAIDU_PROXY_PORT,
                    connectRequest.destinationAddress,
                    connectRequest.destinationPort
                )
                if (baiduSocket == null) {
                    sendSocks5Error(output, REP_CONNECTION_REFUSED)
                    return
                }

                // Send SOCKS5 success response
                sendSocks5Success(output, client.localAddress.address, client.localPort)

                setStatus("tunneling")
                LogUtil.e(TAG, "🚀 Baidu tunnel established for ${connectRequest.destinationAddress}:${connectRequest.destinationPort}")

                // Start bidirectional relay (matching Go relayBidirectional)
                relayBidirectional(client, baiduSocket)
            }
        } catch (e: Exception) {
            LogUtil.d(TAG, "Client handler error: ${e.message}")
        }
    }

    // ------------------------------------------------------------------
    // SOCKS5 handshake
    // ------------------------------------------------------------------

    private fun handleSocks5Handshake(input: InputStream, output: OutputStream): Boolean {
        val version = input.read()
        if (version != SOCKS_VERSION) {
            LogUtil.d(TAG, "Invalid SOCKS version: $version")
            return false
        }

        val nMethods = input.read()
        if (nMethods < 0) {
            return false
        }

        val methods = ByteArray(nMethods)
        var totalRead = 0
        while (totalRead < nMethods) {
            val read = input.read(methods, totalRead, nMethods - totalRead)
            if (read < 0) {
                return false
            }
            totalRead += read
        }

        val selectedMethod = when {
            methods.contains(AUTH_NONE.toByte()) -> AUTH_NONE
            methods.contains(AUTH_PASSWORD.toByte()) -> AUTH_PASSWORD
            else -> AUTH_NO_ACCEPTABLE
        }

        output.write(byteArrayOf(SOCKS_VERSION.toByte(), selectedMethod.toByte()))
        output.flush()

        if (selectedMethod == AUTH_NO_ACCEPTABLE) {
            LogUtil.d(TAG, "No acceptable authentication method")
            return false
        }

        if (selectedMethod == AUTH_PASSWORD) {
            return handleSocks5PasswordAuth(input, output)
        }

        return true
    }

    private fun handleSocks5PasswordAuth(input: InputStream, output: OutputStream): Boolean {
        val authVersion = input.read()
        if (authVersion != 0x01) {
            return false
        }

        val uLen = input.read()
        if (uLen < 0) return false

        val username = ByteArray(uLen)
        var totalRead = 0
        while (totalRead < uLen) {
            val read = input.read(username, totalRead, uLen - totalRead)
            if (read < 0) return false
            totalRead += read
        }

        val pLen = input.read()
        if (pLen < 0) return false

        val password = ByteArray(pLen)
        totalRead = 0
        while (totalRead < pLen) {
            val read = input.read(password, totalRead, pLen - totalRead)
            if (read < 0) return false
            totalRead += read
        }

        output.write(byteArrayOf(0x01, 0x00))
        output.flush()
        return true
    }

    // ------------------------------------------------------------------
    // SOCKS5 request parsing
    // ------------------------------------------------------------------

    private data class ConnectRequest(
        val command: Int,
        val addressType: Int,
        val destinationAddress: String,
        val destinationPort: Int
    )

    private fun parseSocks5ConnectRequest(input: InputStream): ConnectRequest? {
        val version = input.read()
        if (version != SOCKS_VERSION) {
            LogUtil.d(TAG, "Invalid SOCKS version in request: $version")
            return null
        }

        val command = input.read()
        if (command != CMD_CONNECT) {
            LogUtil.d(TAG, "Unsupported command: $command")
            sendSocks5Error(null, REP_CMD_NOT_SUPPORTED)
            return null
        }

        input.read()

        val addressType = input.read()

        val destinationAddress = when (addressType) {
            ATYP_IPV4 -> {
                val addr = ByteArray(4)
                readFully(input, addr)
                String.format("%d.%d.%d.%d",
                    addr[0].toInt() and 0xFF,
                    addr[1].toInt() and 0xFF,
                    addr[2].toInt() and 0xFF,
                    addr[3].toInt() and 0xFF)
            }
            ATYP_DOMAIN -> {
                val domainLen = input.read()
                if (domainLen < 0) return null
                val domain = ByteArray(domainLen)
                readFully(input, domain)
                String(domain, Charsets.UTF_8)
            }
            ATYP_IPV6 -> {
                val addr = ByteArray(16)
                readFully(input, addr)
                val ip = InetAddress.getByAddress(addr).hostAddress
                ip
            }
            else -> {
                LogUtil.d(TAG, "Unknown address type: $addressType")
                return null
            }
        }

        val portBytes = ByteArray(2)
        readFully(input, portBytes)
        val destinationPort = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)

        return ConnectRequest(command, addressType, destinationAddress, destinationPort)
    }

    private fun readFully(input: InputStream, buffer: ByteArray) {
        var totalRead = 0
        while (totalRead < buffer.size) {
            val read = input.read(buffer, totalRead, buffer.size - totalRead)
            if (read < 0) throw java.io.EOFException("Unexpected EOF")
            totalRead += read
        }
    }

    // ------------------------------------------------------------------
    // SOCKS5 reply helpers
    // ------------------------------------------------------------------

    private fun sendSocks5Error(output: OutputStream?, errorCode: Int) {
        if (output == null) return
        try {
            output.write(byteArrayOf(
                SOCKS_VERSION.toByte(),
                errorCode.toByte(),
                0x00,
                ATYP_IPV4.toByte(),
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00
            ))
            output.flush()
        } catch (_: Exception) {
        }
    }

    private fun sendSocks5Success(output: OutputStream, bindAddr: ByteArray?, bindPort: Int) {
        try {
            val addr = bindAddr ?: byteArrayOf(0x00, 0x00, 0x00, 0x00)
            output.write(byteArrayOf(
                SOCKS_VERSION.toByte(),
                REP_SUCCESS.toByte(),
                0x00,
                ATYP_IPV4.toByte(),
                addr[0], addr[1], addr[2], addr[3],
                (bindPort shr 8).toByte(),
                (bindPort and 0xFF).toByte()
            ))
            output.flush()
        } catch (_: Exception) {
        }
    }

    // ------------------------------------------------------------------
    // Baidu tunnel dial: try bare TCP first, fall back to TLS
    // ------------------------------------------------------------------

    private fun dialBaiduTunnel(
        proxyHost: String,
        proxyPort: Int,
        targetHost: String,
        targetPort: Int
    ): Socket? {
        // Try bare TCP first (matching Go reference implementation exactly)
        val socket = tryBareTcpConnect(proxyHost, proxyPort, targetHost, targetPort)
        if (socket != null) return socket

        // Fall back to TLS (some restrictive networks need it)
        return tryTlsConnect(proxyHost, proxyPort, targetHost, targetPort)
    }

    private fun tryBareTcpConnect(
        proxyHost: String, proxyPort: Int,
        targetHost: String, targetPort: Int
    ): Socket? {
        return try {
            val sock = Socket()
            sock.connect(
                java.net.InetSocketAddress(proxyHost, proxyPort),
                BAIDU_CONNECT_TIMEOUT_MS
            )

            if (sendConnectAndCheckResponse(sock, targetHost, targetPort)) {
                LogUtil.e(TAG, "🚀 Baidu tunnel established (bare TCP via $proxyHost)")
                lastError = ""
                sock
            } else {
                sock.close()
                null
            }
        } catch (e: Exception) {
            lastError = "TCP: ${e.message}"
            LogUtil.d(TAG, "Bare TCP connect failed: ${e.message}")
            null
        }
    }

    private fun tryTlsConnect(
        proxyHost: String, proxyPort: Int,
        targetHost: String, targetPort: Int
    ): Socket? {
        return try {
            val sock = Socket()
            sock.connect(
                java.net.InetSocketAddress(proxyHost, proxyPort),
                BAIDU_CONNECT_TIMEOUT_MS
            )
            val sslFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
            val sslSocket = sslFactory.createSocket(sock, proxyHost, proxyPort, true) as javax.net.ssl.SSLSocket
            sslSocket.startHandshake()

            if (sendConnectAndCheckResponse(sslSocket, targetHost, targetPort)) {
                LogUtil.e(TAG, "🚀 Baidu tunnel established (TLS via $proxyHost)")
                lastError = ""
                sslSocket
            } else {
                sslSocket.close()
                null
            }
        } catch (e: Exception) {
            lastError = "TLS: ${e.message}"
            LogUtil.d(TAG, "TLS connect failed: ${e.message}")
            null
        }
    }

    private fun sendConnectAndCheckResponse(
        sock: Socket, targetHost: String, targetPort: Int
    ): Boolean {
        val output = sock.getOutputStream()
        val input = sock.getInputStream()

        val connectRequest = buildString {
            append("CONNECT $targetHost:$targetPort HTTP/1.1\r\n")
            append("Host: sptest.baidu.com\r\n")
            append("X-T5-Auth: $X_T5_AUTH_TOKEN\r\n")
            append("User-Agent: $USER_AGENT\r\n")
            append("Proxy-Connection: keep-alive\r\n")
            append("Connection: keep-alive\r\n")
            append("\r\n")
        }

        output.write(connectRequest.toByteArray(Charsets.UTF_8))
        output.flush()

        val responseStr = readHttpResponse(input)
        lastBaiduResponse = responseStr.take(200)
        LogUtil.e(TAG, "🚀 Baidu CONNECT response: ${responseStr.take(100)}")

        if (!responseStr.startsWith("HTTP/1.1 200") && !responseStr.startsWith("HTTP/1.0 200")) {
            LogUtil.e(TAG, "❌ Baidu proxy CONNECT failed: ${responseStr.take(200)}")
            lastError = "Baidu returned: ${responseStr.take(80)}"
            return false
        }

        return true
    }

    private fun readHttpResponse(input: InputStream): String {
        val response = StringBuilder()
        val buffer = ByteArray(1024)

        while (true) {
            val read = input.read(buffer)
            if (read < 0) break

            response.append(String(buffer, 0, read, Charsets.UTF_8))

            if (response.contains("\r\n\r\n")) {
                break
            }
        }

        return response.toString()
    }

    // ------------------------------------------------------------------
    // Bidirectional relay (matching Go relayBidirectional)
    // ------------------------------------------------------------------

    private fun relayBidirectional(client: Socket, target: Socket) {
        val errc = arrayOfNulls<Throwable>(2)
        val threads = arrayOfNulls<Thread>(2)

        threads[0] = Thread({
            try {
                relayStream(client.getInputStream(), target.getOutputStream())
            } catch (e: Exception) {
                errc[0] = e
            }
        }, "Relay-ClientToBaidu")

        threads[1] = Thread({
            try {
                relayStream(target.getInputStream(), client.getOutputStream())
            } catch (e: Exception) {
                errc[1] = e
            }
        }, "Relay-BaiduToClient")

        threads[0]!!.start()
        threads[1]!!.start()

        try {
            threads[0]!!.join()
        } catch (_: InterruptedException) {
        }

        try {
            client.close()
        } catch (_: Exception) {
        }
        try {
            target.close()
        } catch (_: Exception) {
        }

        try {
            threads[1]!!.join()
        } catch (_: InterruptedException) {
        }
    }

    private fun relayStream(input: InputStream, output: OutputStream) {
        val buffer = ByteArray(BUFFER_SIZE)
        try {
            while (running.get()) {
                val read = input.read(buffer)
                if (read < 0) {
                    break
                }
                if (read > 0) {
                    output.write(buffer, 0, read)
                    output.flush()
                }
            }
        } catch (e: Exception) {
            LogUtil.d(TAG, "Relay stream done: ${e.message}")
        } finally {
            try {
                output.close()
            } catch (_: Exception) {
            }
        }
    }

    // ------------------------------------------------------------------
    // Status helper
    // ------------------------------------------------------------------

    private fun setStatus(newStatus: String) {
        status = newStatus
        AngNotificationManager.refreshBaiduStatus()
    }
}
