package com.v2ray.ang.service

import android.content.Context
import com.v2ray.ang.util.LogUtil
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

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
 *
 * Flow:
 * 1. Xray-core routes traffic to this SOCKS5 server
 * 2. SOCKS5 handshake and CONNECT request are handled
 * 3. For each CONNECT, open a TLS connection to cloudnproxy.baidu.com:443
 * 4. Send HTTP CONNECT with X-T5-Auth + baidu-specific headers
 * 5. Relay data bidirectionally once connection is established
 */
class DialerBaiduService : IDialerService {

    companion object {
        private const val TAG = "DialerBaiduService"

        // Baidu proxy endpoint
        private const val BAIDU_PROXY_HOST = "cloudnproxy.baidu.com"
        private const val BAIDU_PROXY_PORT = 443

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
    }

    @Volatile
    private var serverSocket: ServerSocket? = null

    @Volatile
    private var executor: ExecutorService? = null

    private val running = AtomicBoolean(false)

    override fun start(context: Context, dialerAddr: String) {
        stop()

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

        try {
            serverSocket = ServerSocket(port, 128, InetAddress.getByName(host))
            executor = Executors.newCachedThreadPool { runnable ->
                Thread(runnable, "BaiduTunnel-Worker").apply {
                    isDaemon = true
                }
            }
            running.set(true)

            LogUtil.i(TAG, "Baidu Tunnel SOCKS5 server started on $dialerAddr")

            // Start acceptor thread
            Thread({ acceptLoop() }, "BaiduTunnel-Acceptor").apply {
                isDaemon = true
                start()
            }
        } catch (e: Exception) {
            LogUtil.e(TAG, "Failed to start Baidu Tunnel server", e)
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

        LogUtil.i(TAG, "Baidu Tunnel SOCKS5 server stopped")
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
                    BAIDU_PROXY_HOST,
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

                // Start bidirectional relay (matching Go relayBidirectional)
                relayBidirectional(client, baiduSocket)
            }
        } catch (e: Exception) {
            LogUtil.d(TAG, "Client handler error: ${e.message}")
        }
    }

    // ------------------------------------------------------------------
    // SOCKS5 handshake (matching Go performSOCKSHandshake)
    // ------------------------------------------------------------------

    private fun handleSocks5Handshake(input: InputStream, output: OutputStream): Boolean {
        // Read greeting: VER, NMETHODS, METHODS[]
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

        // Prefer NO AUTH; fall back to USERNAME/PASSWORD if client requires it
        val selectedMethod = when {
            methods.contains(AUTH_NONE.toByte()) -> AUTH_NONE
            methods.contains(AUTH_PASSWORD.toByte()) -> AUTH_PASSWORD
            else -> AUTH_NO_ACCEPTABLE
        }

        // Send greeting response
        output.write(byteArrayOf(SOCKS_VERSION.toByte(), selectedMethod.toByte()))
        output.flush()

        if (selectedMethod == AUTH_NO_ACCEPTABLE) {
            LogUtil.d(TAG, "No acceptable authentication method")
            return false
        }

        // Handle username/password auth if selected
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

        // Accept any credentials (matching Go behavior)
        output.write(byteArrayOf(0x01, 0x00))
        output.flush()
        return true
    }

    // ------------------------------------------------------------------
    // SOCKS5 request parsing (matching Go readSOCKSRequest + readSOCKSAddress)
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

        // Skip reserved byte
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
                // Format IPv6 address with brackets
                val ip = InetAddress.getByAddress(addr).hostAddress
                // Go uses net.IP.String() which may produce a compact form
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
    // SOCKS5 reply helpers (matching Go sendSOCKSReply)
    // ------------------------------------------------------------------

    private fun sendSocks5Error(output: OutputStream?, errorCode: Int) {
        if (output == null) return
        try {
            output.write(byteArrayOf(
                SOCKS_VERSION.toByte(),
                errorCode.toByte(),
                0x00,  // RSV
                ATYP_IPV4.toByte(),
                0x00, 0x00, 0x00, 0x00,  // 0.0.0.0
                0x00, 0x00  // port 0
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
                0x00,  // RSV
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
    // Baidu tunnel dial (matching Go dialBaiduTunnel exactly)
    // ------------------------------------------------------------------

    /**
     * Dials the Baidu tunnel proxy and establishes a CONNECT tunnel.
     *
     * Matches the Go reference implementation:
     * - net.DialTimeout with 10s timeout
     * - HTTP CONNECT with exact headers
     * - http.ReadResponse to parse the CONNECT response
     * - Returns the raw socket on success, null on failure
     */
    private fun dialBaiduTunnel(
        proxyHost: String,
        proxyPort: Int,
        targetHost: String,
        targetPort: Int
    ): Socket? {
        return try {
            // Dial with timeout (matching Go net.DialTimeout)
            // IMPORTANT: Go connects with bare TCP to port 443, NO TLS
            val sock = Socket()
            sock.connect(
                java.net.InetSocketAddress(proxyHost, proxyPort),
                BAIDU_CONNECT_TIMEOUT_MS
            )

            val output = sock.getOutputStream()
            val input = sock.getInputStream()

            // Build CONNECT request matching Go exactly:
            // fmt.Sprintf("CONNECT %s:%s HTTP/1.1\r\nHost: sptest.baidu.com\r\nX-T5-Auth: 482857715\r\nUser-Agent: okhttp/3.11.0 ...\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\n\r\n")
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

            // Read HTTP response (matching Go http.ReadResponse)
            val responseStr = readHttpResponse(input)
            LogUtil.d(TAG, "Baidu CONNECT response: ${responseStr.take(100)}")

            if (!responseStr.startsWith("HTTP/1.1 200") && !responseStr.startsWith("HTTP/1.0 200")) {
                LogUtil.d(TAG, "Baidu proxy CONNECT failed: ${responseStr.take(200)}")
                sock.close()
                return null
            }

            // Success - tunnel established
            sock
        } catch (e: SocketTimeoutException) {
            LogUtil.d(TAG, "Baidu tunnel connect timeout: ${e.message}")
            null
        } catch (e: Exception) {
            LogUtil.d(TAG, "Baidu tunnel connect failed: ${e.message}")
            null
        }
    }

    /**
     * Read the HTTP response headers until \r\n\r\n.
     * Matches Go's http.ReadResponse behavior for the CONNECT response.
     */
    private fun readHttpResponse(input: InputStream): String {
        val response = StringBuilder()
        val buffer = ByteArray(1024)
        var crlfCount = 0

        // Use a read loop that properly detects the end of headers
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break

            response.append(String(buffer, 0, read, Charsets.UTF_8))

            // Check for \r\n\r\n end of headers
            if (response.contains("\r\n\r\n")) {
                break
            }
        }

        return response.toString()
    }

    // ------------------------------------------------------------------
    // Bidirectional relay (matching Go relayBidirectional)
    // ------------------------------------------------------------------

    /**
     * Bidirectional relay between client and target connections.
     * Uses two threads with io.Copy-like behavior, matching Go's relayBidirectional.
     * When one direction finishes, both connections are closed.
     */
    private fun relayBidirectional(client: Socket, target: Socket) {
        val errc = arrayOfNulls<Throwable>(2)
        val threads = arrayOfNulls<Thread>(2)

        // Thread 1: client -> target
        threads[0] = Thread({
            try {
                relayStream(client.getInputStream(), target.getOutputStream())
            } catch (e: Exception) {
                errc[0] = e
            }
        }, "Relay-ClientToBaidu")

        // Thread 2: target -> client
        threads[1] = Thread({
            try {
                relayStream(target.getInputStream(), client.getOutputStream())
            } catch (e: Exception) {
                errc[1] = e
            }
        }, "Relay-BaiduToClient")

        threads[0]!!.start()
        threads[1]!!.start()

        // Wait for both to finish (matching Go's select on errc)
        try {
            threads[0]!!.join()
        } catch (_: InterruptedException) {
        }

        // Close both sockets immediately (matching Go: left.Close(); right.Close())
        try {
            client.close()
        } catch (_: Exception) {
        }
        try {
            target.close()
        } catch (_: Exception) {
        }

        // Wait for the other direction to finish
        try {
            threads[1]!!.join()
        } catch (_: InterruptedException) {
        }
    }

    /**
     * Stream relay matching Go's io.Copy behavior.
     * Reads from input, writes to output until EOF or error.
     */
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
            // Normal for bidirectional relay when one side closes
            LogUtil.d(TAG, "Relay stream done: ${e.message}")
        } finally {
            try {
                output.close()
            } catch (_: Exception) {
            }
        }
    }
}
