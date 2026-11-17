package net.datamancy.platform

import com.sun.net.httpserver.HttpExchange
import com.sun.security.auth.module.UnixSystem
import com.sun.net.httpserver.HttpServer
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URL
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.nio.charset.StandardCharsets.US_ASCII
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.util.concurrent.Executors
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** No upstream key, refresh token or human bearer is serialized into the lane or capture. */
internal data class ManagedLaneGrant(val subject: String, val issuer: String, val generation: String,
    val laneId: String, val session: String, val provider: String, val model: String,
    val expiresAtEpochSeconds: Long, val revisionSha256: String, val tokenHash: String)

internal interface ManagedLaneAuthority {
    /** Must verify signature, issuer, subject, Keycloak introspection active and account enabled, without caching. */
    fun authorizeBearer(bearer: String, expected: ManagedLaneGrant, nowEpochSeconds: Long): Boolean
    fun revisionHead(generation: String): String
    fun generationActive(generation: String): Boolean
}

/** A generation-local loopback endpoint. The only accepted destination is OpenAI's pinned HTTPS host. */
internal data class ManagedBrokerTokenRefresh(val bearer: String, val expiresAtEpochSeconds: Long)
internal fun interface ManagedBrokerTokenRefresher { fun mint(grant: ManagedLaneGrant): ManagedBrokerTokenRefresh }
/** A05's native confidential issuer is the only bearer producer. The parsed exp is UNTRUSTED
 * until ManagedLaneIdentityAuthority verifies RSA signature + fresh native introspection.
 */
internal class NativeManagedBrokerTokenRefresher(private val issuer: NativeManagedAgentTokenIssuer,
    private val authority: ManagedLaneAuthority, private val clock: Clock = Clock.systemUTC()) : ManagedBrokerTokenRefresher {
    override fun mint(grant: ManagedLaneGrant): ManagedBrokerTokenRefresh {
        require(authority.generationActive(grant.generation) &&
            authority.revisionHead(grant.generation) == grant.revisionSha256)
        val bearer = issuer.mint(grant.generation, grant.subject)
        require(bearer.length in 24..8192 && bearer.split('.').size == 3)
        val payload = bearer.split('.')[1]
        require(payload.matches(Regex("[A-Za-z0-9_-]{8,8192}")))
        val claims = Json.parseToJsonElement(java.util.Base64.getUrlDecoder().decode(payload)
            .decodeToString(throwOnInvalidSequence = true)).jsonObject
        val expiry = claims["exp"]?.jsonPrimitive?.content?.toLongOrNull()
        val now = clock.instant().epochSecond
        require(expiry != null && expiry - now in 1..300)
        val proposed = grant.copy(tokenHash = MessageDigest.getInstance("SHA-256").digest(bearer.toByteArray())
            .joinToString("") { "%02x".format(it) }, expiresAtEpochSeconds = expiry)
        require(authority.authorizeBearer(bearer, proposed, now)) {
            "Unverified native agent refresh cannot enter the managed broker"
        }
        return ManagedBrokerTokenRefresh(bearer, expiry)
    }
}
@Serializable internal data class ManagedBrokerDeliveryIntent(val generation: String, val laneId: String,
    val session: String, val operationId: String, val tokenSha256: String,
    val expiresAtEpochSeconds: Long, val identityHeadSha256: String)
@Serializable internal data class ManagedLaneInitialDeliveryReceipt(val generation: String, val laneId: String,
    val session: String, val operationId: String, val tokenHash: String, val expiresAtEpochSeconds: Long,
    val nativeReadbackSha256: String)
internal fun interface ManagedLaneInitialDelivery {
    fun deliver(plan: ManagedLanePlan, token: String, operationId: String): ManagedLaneInitialDeliveryReceipt
}
@Serializable internal data class ManagedBrokerTokenRevision(val generation: String, val laneId: String,
    val identityHeadSha256: String, val previousTokenHash: String, val tokenHash: String,
    val expiresAtEpochSeconds: Long, val observedAtEpochSeconds: Long, val intentSha256: String)
internal class ManagedLaneBroker(private val grant: ManagedLaneGrant, private val authority: ManagedLaneAuthority,
    private val upstreamKey: () -> CharArray, private val clock: Clock = Clock.systemUTC(),
    private val upstream: URL = URL("https://api.openai.com/v1/responses"),
    private val tokenRefresher: ManagedBrokerTokenRefresher? = null,
    private val revisionsRoot: Path? = null,
    private val subscription: ManagedPiSubscriptionBridge? = null) : AutoCloseable {
    @Volatile private var effectiveGrant: ManagedLaneGrant = grant
    @Volatile private var activeLease: ActivationInput? = null
    @Volatile private var laneSuspended: Boolean = false
    private var server: HttpServer? = null
    private var unixServer: ServerSocketChannel? = null
    private var unixThread: Thread? = null
    private var unixPath: Path? = null
    private var unixFileKey: Any? = null
    private val unixWorkers = java.util.concurrent.ThreadPoolExecutor(2, 8, 30,
        java.util.concurrent.TimeUnit.SECONDS, java.util.concurrent.ArrayBlockingQueue(16),
        { runnable -> Thread(runnable, "managed-broker-request").apply { isDaemon = true } },
        java.util.concurrent.ThreadPoolExecutor.AbortPolicy())
    private val authorizationPool = java.util.concurrent.ThreadPoolExecutor(1, 2, 0,
        java.util.concurrent.TimeUnit.MILLISECONDS, java.util.concurrent.ArrayBlockingQueue(4),
        { runnable -> Thread(runnable, "managed-broker-authority").apply { isDaemon = true } },
        java.util.concurrent.ThreadPoolExecutor.AbortPolicy())
    init {
        require(grant.provider == "openai" && grant.model == "gpt-6-sol" &&
            grant.issuer == "https://auth.datamancy.net/realms/p0v3" &&
            grant.subject.matches(Regex("[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}")) &&
            grant.laneId.matches(Regex("[a-f0-9]{8}-[a-f0-9]{4}-[345][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}")) &&
            grant.session.matches(Regex("[a-z][a-z0-9-]{0,40}")) &&
            grant.generation.matches(Regex("q-[a-f0-9]{12}")) &&
            grant.revisionSha256.matches(Regex("[a-f0-9]{64}")) &&
            grant.tokenHash.matches(Regex("[a-f0-9]{64}")) &&
            grant.expiresAtEpochSeconds - clock.instant().epochSecond in 1..300)
        require(upstream.protocol == "https" && upstream.host == "api.openai.com" && upstream.port == -1 &&
            upstream.path == "/v1/responses" && upstream.query == null && upstream.userInfo == null)
    }
    private fun hash(value: String): ByteArray = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(StandardCharsets.UTF_8))
    private fun authorized(bearer: String): Boolean {
        val now = clock.instant().epochSecond
        val current = effectiveGrant
        if (laneSuspended || bearer.length !in 16..8192 || now >= current.expiresAtEpochSeconds ||
            !MessageDigest.isEqual(hash(bearer), current.tokenHash.chunked(2).map { it.toInt(16).toByte() }.toByteArray()))
            return false
        activeLease?.let { pin ->
            if (runCatching { ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(pin.path), 65536)) == pin.sha256 }
                    .getOrDefault(false) != true) return false
        }
        // All native identity/ledger reads have one combined 400ms budget; no stale cache on idle streams.
        val pending = try { authorizationPool.submit<Boolean> {
            authority.generationActive(current.generation) &&
                authority.revisionHead(current.generation) == current.revisionSha256 &&
                authority.authorizeBearer(bearer, current, now)
        } } catch (_: java.util.concurrent.RejectedExecutionException) { return false }
        return try { pending.get(400, java.util.concurrent.TimeUnit.MILLISECONDS) && effectiveGrant == current }
        catch (_: Exception) { pending.cancel(true); false }
    }
    /** Parent-only typed STOP fences the model socket before the native lane stop.
     * The host broker remains alive; STOP never tears down its own supervisor.
     */
    @Synchronized internal fun suspendLane() { laneSuspended = true }

    /** One newly minted native issuer bearer for a specific, already journaled
     * physical lane START. The old grant is never reenabled. The caller owns
     * release controller/generation/member locks and independently verifies the
     * Worklane restart, receipt and Pi/TUIOS native identities before activation.
     */
    @Synchronized internal fun reissueForLaneStart(operationId: String): String {
        require(laneSuspended && operationId.matches(Regex("resume-device-[a-f0-9]{32}")))
        val issuer = requireNotNull(tokenRefresher)
        val root = requireNotNull(revisionsRoot)
        val before = effectiveGrant
        require(root == GenerationRuntime.BASE.resolve(before.generation).resolve("managed/control/leases"))
        ReleasePrivateFiles.directory(root)
        val intent = root.resolve("restart-$operationId.intent.json")
        val result = root.resolve("restart-$operationId.result.json")
        require(!Files.exists(intent, java.nio.file.LinkOption.NOFOLLOW_LINKS) &&
            !Files.exists(result, java.nio.file.LinkOption.NOFOLLOW_LINKS))
        val now = clock.instant().epochSecond
        val bytes = "${before.generation}|${before.laneId}|${before.tokenHash}|$operationId|$now\n".toByteArray()
        ReleasePrivateFiles.save(intent, bytes)
        val minted = issuer.mint(before)
        val next = before.copy(tokenHash = ReleaseLocks.sha256(minted.bearer.toByteArray()),
            expiresAtEpochSeconds = minted.expiresAtEpochSeconds)
        require(next.tokenHash != before.tokenHash && minted.expiresAtEpochSeconds - clock.instant().epochSecond in 1..300 &&
            authority.generationActive(next.generation) && authority.revisionHead(next.generation) == next.revisionSha256 &&
            authority.authorizeBearer(minted.bearer, next, clock.instant().epochSecond))
        val record = ManagedBrokerTokenRevision(next.generation, next.laneId, next.revisionSha256,
            before.tokenHash, next.tokenHash, next.expiresAtEpochSeconds, now, ReleaseLocks.sha256(bytes))
        val resultBytes = Json.encodeToString(record).toByteArray()
        ReleasePrivateFiles.save(result, resultBytes)
        activeLease = ActivationInput(result.toString(), ReleaseLocks.sha256(resultBytes))
        effectiveGrant = next // suspended until all three native components attest.
        return minted.bearer
    }
    @Synchronized internal fun activateLane(operationId: String, receipt: ManagedLaneInitialDeliveryReceipt) {
        val current = effectiveGrant
        require(laneSuspended && operationId.matches(Regex("resume-device-[a-f0-9]{32}")) &&
            receipt.operationId == operationId && receipt.generation == current.generation &&
            receipt.laneId == current.laneId && receipt.session == current.session &&
            receipt.tokenHash == current.tokenHash && receipt.nativeReadbackSha256 == current.tokenHash &&
            receipt.expiresAtEpochSeconds == current.expiresAtEpochSeconds &&
            current.expiresAtEpochSeconds > clock.instant().epochSecond &&
            authority.generationActive(current.generation) && authority.revisionHead(current.generation) == current.revisionSha256)
        laneSuspended = false
    }

    /** Refresh through the native confidential issuer, never a lane-stored client secret.
     * One previously valid bearer can be exchanged once. A lost acknowledgement fences
     * the old bearer; never resend a maybe-delivered token or replay a model request.
     */
    @Synchronized internal fun refresh(bearer: String): String {
        val issuer = requireNotNull(tokenRefresher) { "Native managed agent issuer not registered" }
        val root = requireNotNull(revisionsRoot) { "Immutable token revision custody required" }
        require(authorized(bearer) && root.isAbsolute && root.normalize() == root)
        ReleasePrivateFiles.directory(root)
        val before = effectiveGrant
        val now = clock.instant().epochSecond
        require(before.expiresAtEpochSeconds - now in 1..300 &&
            root == GenerationRuntime.BASE.resolve(before.generation).resolve("managed/control/leases"))
        val intent = root.resolve("refresh-${before.tokenHash}.intent.json")
        require(!Files.exists(intent, java.nio.file.LinkOption.NOFOLLOW_LINKS))
        val intentBytes = "${before.generation}|${before.laneId}|${before.tokenHash}|$now\n".toByteArray()
        ReleasePrivateFiles.save(intent, intentBytes)
        val minted = issuer.mint(before)
        require(minted.bearer.length in 24..8192 && minted.bearer != bearer &&
            minted.expiresAtEpochSeconds - clock.instant().epochSecond in 1..300)
        val next = before.copy(tokenHash = hash(minted.bearer).joinToString("") { "%02x".format(it) },
            expiresAtEpochSeconds = minted.expiresAtEpochSeconds)
        require(authority.generationActive(next.generation) &&
            authority.revisionHead(next.generation) == next.revisionSha256 &&
            authority.authorizeBearer(minted.bearer, next, clock.instant().epochSecond))
        val record = ManagedBrokerTokenRevision(next.generation, next.laneId, next.revisionSha256,
            before.tokenHash, next.tokenHash, next.expiresAtEpochSeconds, now, ReleaseLocks.sha256(intentBytes))
        val result = root.resolve("refresh-${before.tokenHash}.result.json")
        val resultBytes = Json.encodeToString(record).toByteArray()
        ReleasePrivateFiles.save(result, resultBytes)
        activeLease = ActivationInput(result.toString(), ReleaseLocks.sha256(resultBytes))
        effectiveGrant = next
        return minted.bearer
    }
    private fun deny(exchange: HttpExchange, code: Int) {
        exchange.sendResponseHeaders(code, -1)
        exchange.close()
    }
    private fun readBody(input: InputStream): ByteArray {
        val bytes = input.readNBytes(1048577)
        require(bytes.size in 2..1048576) { "Invalid managed model request size" }
        val value = kotlinx.serialization.json.Json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(value["model"]?.jsonPrimitive?.content == grant.model &&
            value["stream"]?.jsonPrimitive?.content in setOf(null, "true", "false")) {
            "Managed requests must use the exact approved model"
        }
        return bytes
    }
    private fun responseCode(connection: HttpURLConnection, bearer: String): Int {
        val pending = java.util.concurrent.CompletableFuture.supplyAsync { connection.responseCode }
        val deadline = System.currentTimeMillis() + 60000
        while (System.currentTimeMillis() < deadline) {
            require(authorized(bearer)) { "Managed grant revoked before upstream headers" }
            try { return pending.get(400, java.util.concurrent.TimeUnit.MILLISECONDS) }
            catch (_: java.util.concurrent.TimeoutException) { /* Poll live revocation even without upstream bytes. */ }
        }
        connection.disconnect()
        error("Upstream response deadline exhausted")
    }
    private fun handle(exchange: HttpExchange) {
        if (subscription != null) { deny(exchange, 403); return }
        var connection: HttpURLConnection? = null
        try {
            if (exchange.remoteAddress.address != InetAddress.getLoopbackAddress() ||
                exchange.requestMethod != "POST" || exchange.requestURI.toString() != "/v1/responses" ||
                exchange.requestHeaders["Authorization"]?.size != 1) { deny(exchange, 403); return }
            val bearer = exchange.requestHeaders.getFirst("Authorization")?.removePrefix("Bearer ") ?: ""
            if (!authorized(bearer)) { deny(exchange, 403); return }
            val body = readBody(exchange.requestBody)
            if (!authorized(bearer)) { deny(exchange, 403); return }
            val key = upstreamKey()
            require(key.size in 8..8192 && key.all { it.code in 33..126 }) { "Broker key unavailable" }
            try {
                connection = upstream.openConnection() as HttpURLConnection
                connection.requestMethod = "POST"
                connection.connectTimeout = 900
                connection.readTimeout = 60000
                connection.doOutput = true
                connection.instanceFollowRedirects = false
                connection.setRequestProperty("Authorization", "Bearer ${String(key)}")
                connection.setRequestProperty("Content-Type", "application/json")
                connection.setRequestProperty("Accept", "text/event-stream, application/json")
                connection.outputStream.use { it.write(body); it.flush() }
            } finally { key.fill('\u0000') }
            if (!authorized(bearer)) { deny(exchange, 403); return }
            val status = responseCode(connection, bearer)
            connection.readTimeout = 450
            require(status in 200..299 && connection.url == upstream) { "Upstream refused or redirected" }
            exchange.responseHeaders.set("Content-Type", connection.contentType?.takeIf {
                it.startsWith("application/json") || it.startsWith("text/event-stream")
            } ?: "application/octet-stream")
            exchange.responseHeaders.set("Cache-Control", "no-store")
            exchange.sendResponseHeaders(status, 0)
            connection.inputStream.use { input ->
                exchange.responseBody.use { output ->
                    val buffer = ByteArray(16384)
                    while (true) {
                        // 500ms upstream socket timeout is a heartbeat, not a reason to authorize an idle stream indefinitely.
                        if (!authorized(bearer)) break
                        val count = try { input.read(buffer) } catch (_: java.net.SocketTimeoutException) { continue }
                        if (count < 0) break
                        if (!authorized(bearer)) break
                        output.write(buffer, 0, count)
                        output.flush()
                    }
                }
            }
        } catch (_: Exception) {
            try { exchange.close() } catch (_: Exception) { /* No error details/keys reach a lane. */ }
        } finally { connection?.disconnect() }
    }
    fun start(): Int {
        check(server == null) { "Managed broker already started" }
        val socket = InetSocketAddress(InetAddress.getLoopbackAddress(), 0)
        val instance = HttpServer.create(socket, 0)
        instance.createContext("/v1/responses", ::handle)
        instance.executor = Executors.newCachedThreadPool { runnable ->
            Thread(runnable, "managed-lane-broker").apply { isDaemon = true }
        }
        instance.start()
        server = instance
        return instance.address.port
    }
    private fun readUnix(channel: SocketChannel, maxBytes: Int, deadline: Long): ByteArray {
        val bytes = java.io.ByteArrayOutputStream()
        val buffer = ByteBuffer.allocate(16384)
        Selector.open().use { selector ->
            channel.register(selector, SelectionKey.OP_READ)
            while (System.currentTimeMillis() < deadline) {
                if (selector.select(400) == 0) continue
                buffer.clear()
                val count = channel.read(buffer)
                require(count >= 0 && bytes.size() + count <= maxBytes) { "Invalid broker request size" }
                if (count > 0) { bytes.write(buffer.array(), 0, count); return bytes.toByteArray() }
            }
        }
        error("Broker request timed out")
    }
    private fun sendUnix(channel: SocketChannel, bytes: ByteArray, bearer: String) {
        val buffer = ByteBuffer.wrap(bytes)
        Selector.open().use { selector ->
            channel.register(selector, SelectionKey.OP_WRITE)
            while (buffer.hasRemaining()) {
                require(authorized(bearer)) { "Managed grant revoked while writing" }
                require(selector.select(400) != 0 || authorized(bearer)) { "Managed grant revoked while idle" }
                channel.write(buffer)
            }
        }
    }
    private fun handleUnix(channel: SocketChannel) {
        var connection: HttpURLConnection? = null
        try {
            channel.configureBlocking(false)
            val deadline = System.currentTimeMillis() + 5000
            val prefix = java.io.ByteArrayOutputStream()
            var split = -1
            while (split < 0) {
                prefix.write(readUnix(channel, 8192, deadline))
                require(prefix.size() <= 8192)
                split = prefix.toByteArray().indexOfSequence(byteArrayOf(13, 10, 13, 10))
            }
            val bytes = prefix.toByteArray()
            val header = bytes.copyOfRange(0, split).toString(US_ASCII)
            val lines = header.split("\r\n")
            require(lines.first() in setOf("POST /v1/responses HTTP/1.1", "POST /v1/refresh HTTP/1.1") &&
                lines.count { it.startsWith("Authorization:", ignoreCase = true) } == 1)
            val bearer = lines.single { it.startsWith("Authorization:", ignoreCase = true) }
                .substringAfter(':').trim().removePrefix("Bearer ")
            require(authorized(bearer))
            val length = lines.single { it.startsWith("Content-Length:", ignoreCase = true) }
                .substringAfter(':').trim().toInt()
            require(length in 2..1048576)
            val body = java.io.ByteArrayOutputStream()
            body.write(bytes, split + 4, bytes.size - split - 4)
            require(body.size() <= length)
            while (body.size() < length) {
                require(authorized(bearer))
                val more = readUnix(channel, length - body.size(), deadline)
                body.write(more)
            }
            if (lines.first() == "POST /v1/refresh HTTP/1.1") {
                require(length == 2 && body.toByteArray().contentEquals("{}".toByteArray(US_ASCII)))
                val replacement = refresh(bearer)
                val payload = "{\"access_token\":\"$replacement\"}".toByteArray(US_ASCII)
                sendUnix(channel, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: ${payload.size}\r\n\r\n".toByteArray(US_ASCII) + payload, replacement)
                return
            }
            val request = readBody(body.toByteArray().inputStream())
            require(authorized(bearer))
            if (subscription != null) {
                val result = subscription.execute(request) { authorized(bearer) }
                require(authorized(bearer))
                val encoded = ManagedPiSubscriptionResponse.sse(result)
                sendUnix(channel, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\nContent-Length: ${encoded.size}\r\n\r\n".toByteArray(US_ASCII), bearer)
                sendUnix(channel, encoded, bearer)
                return
            }
            val key = upstreamKey()
            require(key.size in 8..8192 && key.all { it.code in 33..126 })
            try {
                connection = upstream.openConnection() as HttpURLConnection
                connection.requestMethod = "POST"
                connection.connectTimeout = 900
                connection.readTimeout = 60000
                connection.doOutput = true
                connection.instanceFollowRedirects = false
                connection.setRequestProperty("Authorization", "Bearer ${String(key)}")
                connection.setRequestProperty("Content-Type", "application/json")
                connection.outputStream.use { it.write(request) }
            } finally { key.fill('\u0000') }
            require(responseCode(connection, bearer) in 200..299 && connection.url == upstream)
            connection.readTimeout = 450
            sendUnix(channel, "HTTP/1.1 200 OK\r\nContent-Type: ${connection.contentType?.takeIf {
                it.startsWith("application/json") || it.startsWith("text/event-stream")
            } ?: "application/octet-stream"}\r\nCache-Control: no-store\r\nTransfer-Encoding: chunked\r\n\r\n".toByteArray(US_ASCII), bearer)
            connection.inputStream.use { input ->
                val buffer = ByteArray(16384)
                while (authorized(bearer)) {
                    val count = try { input.read(buffer) } catch (_: java.net.SocketTimeoutException) { continue }
                    if (count < 0) break
                    sendUnix(channel, "${count.toString(16)}\r\n".toByteArray(US_ASCII) +
                        buffer.copyOf(count) + "\r\n".toByteArray(US_ASCII), bearer)
                }
            }
            if (authorized(bearer)) sendUnix(channel, "0\r\n\r\n".toByteArray(US_ASCII), bearer)
        } catch (_: Exception) {
            // Drop incomplete streams without returning secret-bearing diagnostics.
        } finally { connection?.disconnect(); channel.close() }
    }
    /** Fixed Unix socket mounted only into this lane; a bearer still needs live identity introspection. */
    fun startUnix(socket: Path) {
        check(unixServer == null)
        require(socket.isAbsolute && socket.normalize() == socket && !Files.exists(socket) &&
            socket.fileName.toString() == "broker.sock" &&
            socket.parent.fileName.toString() == "run" &&
            socket.parent.parent.fileName.toString() == "control")
        ReleasePrivateFiles.directory(socket.parent)
        ReleasePrivateFiles.directory(socket.parent.parent)
        val bound = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
        bound.bind(UnixDomainSocketAddress.of(socket))
        Files.setPosixFilePermissions(socket, PosixFilePermissions.fromString("rw-------"))
        unixServer = bound; unixPath = socket
        unixFileKey = Files.readAttributes(socket, java.nio.file.attribute.BasicFileAttributes::class.java,
            java.nio.file.LinkOption.NOFOLLOW_LINKS).fileKey()
        unixThread = Thread({
            while (bound.isOpen) {
                try {
                    val incoming = bound.accept()
                    try { unixWorkers.execute { handleUnix(incoming) } }
                    catch (_: java.util.concurrent.RejectedExecutionException) { incoming.close() }
                } catch (_: Exception) { if (!bound.isOpen) break }
            }
        }, "managed-broker-unix").apply { isDaemon = true; start() }
    }
    override fun close() {
        server?.stop(0); server = null
        unixServer?.close(); unixServer = null
        // Remove only our exact socket after closing; do not touch other generation runtime state.
        unixPath?.let {
            require(!Files.isSymbolicLink(it) && Files.readAttributes(it,
                java.nio.file.attribute.BasicFileAttributes::class.java,
                java.nio.file.LinkOption.NOFOLLOW_LINKS).fileKey() == unixFileKey) {
                "Broker socket replaced during shutdown; leave foreign node untouched"
            }
            Files.delete(it)
        }
        unixPath = null; unixFileKey = null
        unixWorkers.shutdownNow()
        authorizationPool.shutdownNow()
    }
}

@Serializable internal data class ManagedBrokerConfiguration(val generation: String, val laneId: String,
    val session: String, val subject: String, val issuer: String,
    val provider: String = "openai", val model: String = "gpt-6-sol")
internal data class ManagedBrokerUnit(val name: String, val text: String, val sha256: String,
    val socket: Path)
internal data class ManagedBrokerObservation(val generation: String, val unit: String,
    val unitSha256: String, val active: Boolean, val mainPid: Long, val socketInode: Any?)

/** Separate supervised host-side broker; never run it inside a short-lived controller invocation. */
internal object ManagedLaneBrokerService {
    /** Long-lived fixed service entry invoked by Main's pinned managed-broker-serve.
     * Host-only Keycloak confidential agent/reader/introspection and OpenAI key inputs
     * are resolved by Main from their own effective custody; never passed in argv,
     * environment, sealed human-bootstrap realm or captured Worklane home.
     */
    fun serve(plan: ManagedLanePlan, generationRoot: Path, authority: ManagedLaneAuthority,
        issuer: NativeManagedAgentTokenIssuer, upstreamKey: () -> CharArray,
        initialDelivery: ManagedLaneInitialDelivery, clock: Clock = Clock.systemUTC()) {
        plan.validate(plan.generation)
        val bundleBytes = ReleasePrivateFiles.read(generationRoot.resolve("bundle.json"), 1048576)
        val bundle = Json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString(throwOnInvalidSequence = true))
        require(bundle.request.id == plan.generation && bundle.request.managedLanes == plan &&
            generationRoot == GenerationRuntime.BASE.resolve(plan.generation))
        SiteOwnerships.checkSealed(bundle)
        val head = NativeManagedIdentityLedger(generationRoot.resolve("managed/identity"))
            .requireBound(plan, ReleaseLocks.sha256(bundleBytes))
        require(authority.generationActive(plan.generation) && authority.revisionHead(plan.generation) == head)
        val lane = plan.lanes.single { it.kind == ManagedLaneKind.PI }
        val resumed = Files.list(generationRoot).use { entries -> entries.filter { entry ->
            entry.fileName.toString().matches(Regex("managed-resume-[a-z0-9-]{1,48}\\.intent\\.json")) &&
                !Files.exists(entry.resolveSibling(entry.fileName.toString().removeSuffix(".intent.json") + ".result.json"),
                    java.nio.file.LinkOption.NOFOLLOW_LINKS)
        }.limit(2).toList() }
        require(resumed.size <= 1)
        val operationId = if (resumed.isEmpty()) "managed-start" else
            resumed.single().fileName.toString().removePrefix("managed-").removeSuffix(".intent.json")
        val nativeIssuer = NativeManagedBrokerTokenRefresher(issuer, authority, clock)
        val now = clock.instant().epochSecond
        val scope = ManagedLaneGrant(lane.subject, ManagedLaneIdentityAuthority.ISSUER,
            plan.generation, lane.laneId, lane.session, plan.provider, plan.model,
            now + 1, head, "0".repeat(64))
        val minted = nativeIssuer.mint(scope)
        val initial = scope.copy(expiresAtEpochSeconds = minted.expiresAtEpochSeconds,
            tokenHash = ReleaseLocks.sha256(minted.bearer.toByteArray()))
        val root = generationRoot.resolve("managed/control")
        val socket = root.resolve("run/broker.sock")
        val leases = root.resolve("leases")
        ReleasePrivateFiles.directory(leases)
        ManagedLaneBroker(initial, authority, upstreamKey, clock,
            tokenRefresher = nativeIssuer, revisionsRoot = leases,
            subscription = if (plan.native.brokerHost?.authenticationMode == "pi-openai-oauth-v2")
                ManagedPiSubscriptionBridge(plan.generation,lane.laneId) else null).use { broker ->
            broker.startUnix(socket)
            // Podman must see broker.sock BEFORE the Worklane container START; the
            // Worklane native delivery CLI needs a RUNNING verified container. Poll
            // only its durable START result; never replay the native START command.
            val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(120)
            while (true) {
                require(System.nanoTime() < deadline && clock.instant().epochSecond < initial.expiresAtEpochSeconds) {
                    "Native Worklane did not become ready within short agent token lifetime"
                }
                val started = runCatching { ManagedLaneRuntime.real(generationRoot, plan).recorded(
                    plan.lanes.single { it.kind == ManagedLaneKind.WORKLANE },
                    ManagedLaneOperation.START, operationId) }.getOrNull()
                if (started != null && !started.isolated) break
                Thread.sleep(200)
            }
            val deliveryIntent = root.resolve("run/delivery-$operationId.intent.json")
            val deliveryResult = root.resolve("run/delivery-$operationId.result.json")
            require(!Files.exists(deliveryIntent, java.nio.file.LinkOption.NOFOLLOW_LINKS) &&
                !Files.exists(deliveryResult, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                "A prior native Pi bearer delivery is uncertain; no replay"
            }
            val intent = ManagedBrokerDeliveryIntent(plan.generation, lane.laneId, lane.session,
                operationId, initial.tokenHash, minted.expiresAtEpochSeconds, head)
            ReleasePrivateFiles.save(deliveryIntent, Json.encodeToString(intent).toByteArray())
            val delivered = initialDelivery.deliver(plan, minted.bearer, operationId)
            require(delivered.generation == plan.generation && delivered.laneId == lane.laneId &&
                delivered.session == lane.session && delivered.operationId == operationId &&
                delivered.tokenHash == initial.tokenHash &&
                delivered.expiresAtEpochSeconds == initial.expiresAtEpochSeconds &&
                delivered.nativeReadbackSha256.matches(Regex("[a-f0-9]{64}")))
            ReleasePrivateFiles.save(deliveryResult, Json.encodeToString(delivered).toByteArray())
            if (plan.ownerSubject == null) {
                while (!Thread.currentThread().isInterrupted) Thread.sleep(400)
            } else FreshManagedControlHttp(plan, generationRoot, authority, head, clock,
                FreshManagedLaneOperator(plan,generationRoot,broker,authority,head)).use { control ->
                control.start()
                while (!Thread.currentThread().isInterrupted) Thread.sleep(400)
            }
        }
    }

    fun unit(plan: ManagedLanePlan, generationRoot: Path, userId: Int): ManagedBrokerUnit {
        plan.validate(plan.generation)
        require(userId == UnixSystem().uid.toInt() && userId in 1..65534 &&
            generationRoot.isAbsolute && generationRoot.normalize() == generationRoot &&
            generationRoot.fileName.toString() == plan.generation)
        val binding = requireNotNull(plan.native.broker)
        val root = generationRoot.resolve("managed")
        val configPath = root.resolve("inputs/broker.json")
        require(Path.of(binding.configuration.path) == configPath)
        val configBytes = ReleasePrivateFiles.read(configPath, 1048576)
        require(ReleaseLocks.sha256(configBytes) == binding.configuration.sha256)
        val config = Json { ignoreUnknownKeys = false }.decodeFromString<ManagedBrokerConfiguration>(
            configBytes.decodeToString(throwOnInvalidSequence = true))
        val lane = plan.lanes.single { it.kind == ManagedLaneKind.PI }
        require(config.generation == plan.generation && config.laneId == lane.laneId &&
            config.session == lane.session && config.subject == lane.subject &&
            config.issuer == "https://auth.datamancy.net/realms/p0v3" &&
            config.provider == plan.provider && config.model == plan.model)
        val controller = "/mnt/media/p0-v3/runtime-supervision/releases/${binding.controllerSha256}/bin/p0-v3-platform"
        val executable = Path.of(controller)
        require(executable.isAbsolute && executable.toRealPath() == executable &&
            Files.isRegularFile(executable, java.nio.file.LinkOption.NOFOLLOW_LINKS))
        val binaryHash = java.security.MessageDigest.getInstance("SHA-256")
        Files.newInputStream(executable, java.nio.file.LinkOption.NOFOLLOW_LINKS).use { input ->
            val buffer = ByteArray(65536)
            while (true) { val count = input.read(buffer); if (count < 0) break; binaryHash.update(buffer, 0, count) }
        }
        require(binaryHash.digest().joinToString("") { "%02x".format(it) } == binding.executableSha256) {
            "Supervised broker executable differs from pinned release"
        }
        val unitName = "p0v3-managed-lanes-${plan.generation}.service"
        val socket = root.resolve("control/run/broker.sock")
        val body = """
            [Unit]
            Description=Fixed managed lane broker for ${plan.generation}
            RequiresMountsFor=${generationRoot}
            After=network-online.target
            Wants=network-online.target
            [Service]
            Type=exec
            UMask=0077
            ExecStart=$controller managed-broker-serve ${plan.generation} ${binding.configuration.sha256}
            WorkingDirectory=${root.resolve("control")}
            Environment=JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
            MemoryMax=256M
            TasksMax=64
            LimitNOFILE=256
            TimeoutStartSec=60
            TimeoutStopSec=30
            KillMode=control-group
            Restart=no
            NoNewPrivileges=yes
            ProtectSystem=strict
            ReadWritePaths=${root.resolve("control/run")} ${root.resolve("control/leases")} ${root.resolve("control/data/worklane")}
            RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
            [Install]
            WantedBy=default.target
        """.trimIndent() + "\n"
        return ManagedBrokerUnit(unitName, body, ReleaseLocks.sha256(body.toByteArray()), socket)
    }

    /** Real native readback, not generic health or an asserted boolean. */
    fun inspect(plan: ManagedLanePlan, generationRoot: Path, userId: Int,
        showUnit: (String) -> String): ManagedBrokerObservation {
        val bound = unit(plan, generationRoot, userId)
        val fields = showUnit(bound.name).lines().filter { it.contains('=') }
            .associate { it.substringBefore('=') to it.substringAfter('=') }
        require(fields["Id"] == bound.name && fields["ActiveState"] in setOf("active", "inactive", "failed") &&
            fields["MainPID"]?.toLongOrNull() != null &&
            fields["FragmentPath"] == Path.of("/home/gerald/.config/systemd/user").resolve(bound.name).toString() &&
            fields["NeedDaemonReload"] == "no")
        val active = fields.getValue("ActiveState") == "active"
        val pid = fields.getValue("MainPID").toLong()
        val inode = if (active) {
            require(pid > 1 && Files.exists(bound.socket, java.nio.file.LinkOption.NOFOLLOW_LINKS) &&
                Files.getPosixFilePermissions(bound.socket) == PosixFilePermissions.fromString("rw-------") &&
                (Files.getAttribute(bound.socket, "unix:uid", java.nio.file.LinkOption.NOFOLLOW_LINKS) as Number).toInt() == userId)
            val identity = Files.readAttributes(bound.socket, java.nio.file.attribute.BasicFileAttributes::class.java,
                java.nio.file.LinkOption.NOFOLLOW_LINKS).fileKey()
            SocketChannel.open(StandardProtocolFamily.UNIX).use { channel ->
                channel.connect(UnixDomainSocketAddress.of(bound.socket))
                channel.write(ByteBuffer.wrap("POST /v1/responses HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}"
                    .toByteArray(US_ASCII)))
                channel.configureBlocking(false)
                val buffer = ByteBuffer.allocate(16)
                val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(1)
                var rejected = false
                while (System.nanoTime() < deadline) {
                    val count = channel.read(buffer)
                    if (count < 0) { rejected = true; break }
                    require(count == 0) { "Unauthenticated broker probe received response data" }
                    Thread.sleep(20)
                }
                require(rejected) { "Broker did not reject unauthorized local connection" }
            }
            identity
        } else {
            require(pid == 0L && !Files.exists(bound.socket, java.nio.file.LinkOption.NOFOLLOW_LINKS))
            null
        }
        return ManagedBrokerObservation(plan.generation, bound.name, bound.sha256, active, pid, inode)
    }
}

/** Controller holds the generation lock. Every start/stop has an irreversible write-ahead intent. */
internal class NativeManagedBrokerSupervisor(private val plan: ManagedLanePlan,
    private val generationRoot: Path, private val userId: Int = UnixSystem().uid.toInt()) {
    private val brokerRoot = generationRoot.resolve("managed/control")
    private fun native(vararg args: String): String {
        val process = ProcessBuilder(listOf("/usr/bin/systemctl", "--user") + args).apply {
            environment().clear()
            environment()["PATH"] = "/usr/bin:/bin"
            environment()["LANG"] = "C.UTF-8"
            environment()["HOME"] = "/home/gerald"
            environment()["XDG_RUNTIME_DIR"] = "/run/user/$userId"
            redirectError(ProcessBuilder.Redirect.DISCARD)
        }.start()
        try {
            val output = java.util.concurrent.CompletableFuture.supplyAsync { process.inputStream.readNBytes(8193) }
            require(process.waitFor(30, java.util.concurrent.TimeUnit.SECONDS)) {
                "Native broker supervisor timed out; retain intent"
            }
            val bytes = output.get(5, java.util.concurrent.TimeUnit.SECONDS)
            require(process.exitValue() == 0 && bytes.size <= 8192) {
                "Native broker supervisor refused or returned oversized response"
            }
            return bytes.decodeToString(throwOnInvalidSequence = true)
        } finally { if (process.isAlive) process.destroyForcibly() }
    }
    private fun boundUnitFile(unit: ManagedBrokerUnit) {
        val path = Path.of("/home/gerald/.config/systemd/user").resolve(unit.name)
        require(path.isAbsolute && path.toRealPath() == path &&
            Files.isRegularFile(path, java.nio.file.LinkOption.NOFOLLOW_LINKS) && Files.size(path) <= 16384 &&
            (Files.getAttribute(path, "unix:uid", java.nio.file.LinkOption.NOFOLLOW_LINKS) as Number).toInt() == userId &&
            (Files.getAttribute(path, "unix:nlink", java.nio.file.LinkOption.NOFOLLOW_LINKS) as Number).toInt() == 1 &&
            Files.getPosixFilePermissions(path).none { it.name == "GROUP_WRITE" || it.name == "OTHERS_WRITE" } &&
            ReleaseLocks.sha256(Files.readAllBytes(path)) == unit.sha256) {
            "Foreign or changed managed broker systemd unit"
        }
    }
    fun inspect(): ManagedBrokerObservation {
        val unit = ManagedLaneBrokerService.unit(plan, generationRoot, userId)
        boundUnitFile(unit)
        return ManagedLaneBrokerService.inspect(plan, generationRoot, userId) {
            native("show", it, "--property=Id,ActiveState,MainPID,FragmentPath,NeedDaemonReload", "--no-pager")
        }
    }
    private fun effect(action: String, operationId: String, expectedUnitSha256: String): ManagedBrokerObservation {
        require(action in setOf("start", "stop") && operationId.matches(Regex("[a-z0-9-]{1,64}")))
        val unit = ManagedLaneBrokerService.unit(plan, generationRoot, userId)
        require(unit.sha256 == expectedUnitSha256)
        boundUnitFile(unit)
        ReleasePrivateFiles.directory(brokerRoot)
        val intent = brokerRoot.resolve("broker-$action-$operationId.intent.json")
        val result = brokerRoot.resolve("broker-$action-$operationId.result.json")
        Files.list(brokerRoot).use { stream -> require(stream.noneMatch { entry ->
            entry.fileName.toString().startsWith("broker-") && entry.fileName.toString().endsWith(".intent.json") &&
                !Files.exists(entry.resolveSibling(entry.fileName.toString().removeSuffix(".intent.json") + ".result.json"),
                    java.nio.file.LinkOption.NOFOLLOW_LINKS)
        }) { "Previous broker operation uncertain; reconcile before effects" } }
        val claim = "${plan.generation}|$action|$operationId|${unit.sha256}\n".toByteArray()
        ReleasePrivateFiles.save(intent, claim)
        if (action == "start") native("daemon-reload")
        native(action, unit.name)
        var observation: ManagedBrokerObservation? = null
        val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(60)
        while (System.nanoTime() < deadline) {
            observation = try { inspect() } catch (_: IllegalArgumentException) { null }
            if (observation?.active == (action == "start")) break
            Thread.sleep(200) // Read-only readiness polling; never repeat the start/stop effect.
        }
        val settled = requireNotNull(observation) { "Broker transition unconfirmed; retain durable intent" }
        require(settled.active == (action == "start") && settled.unitSha256 == unit.sha256)
        ReleasePrivateFiles.save(result, Json.encodeToString(mapOf(
            "generation" to plan.generation, "action" to action, "operationId" to operationId,
            "unitSha256" to unit.sha256, "mainPid" to settled.mainPid.toString(),
            "socketInode" to (settled.socketInode?.toString() ?: "absent"))).toByteArray())
        return settled
    }
    fun start(operationId: String, unitSha256: String): ManagedBrokerObservation =
        effect("start", operationId, unitSha256)
    fun isolate(operationId: String, unitSha256: String): ManagedBrokerObservation =
        effect("stop", operationId, unitSha256)
}

private fun ByteArray.indexOfSequence(sequence: ByteArray): Int {
    for (index in 0..(size - sequence.size)) if (sequence.indices.all { this[index + it] == sequence[it] }) return index
    return -1
}

