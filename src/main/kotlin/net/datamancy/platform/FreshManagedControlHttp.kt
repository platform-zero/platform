package net.datamancy.platform

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import java.security.SecureRandom
import java.security.MessageDigest
import java.util.Base64
import java.time.Clock
import java.io.ByteArrayOutputStream
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.nio.charset.StandardCharsets.US_ASCII
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

@Serializable internal data class FreshManagedDeviceGrant(val generation: String, val subject: String,
    val tokenSha256: String, val issuedAt: Long, val expiresAt: Long, val scope: String = "p0-agent")

/** One-use fresh enrollment: durable intent before issuance, no token in durable
 * state, no retry after an uncertain result. RESTORE to a new generation never
 * copies a usable credential. Revocation is an exclusive monotonic file.
 */
internal class FreshManagedDeviceGrantStore(private val generation: String, private val subject: String,
    private val current: () -> Boolean, private val clock: Clock = Clock.systemUTC(),
    private val generationRoot: Path = GenerationRuntime.BASE.resolve(generation)) {
    private val root = generationRoot.resolve("managed/control/device-grants")
    private val nonce = Regex("[a-f0-9]{32}")
    private val entropy = SecureRandom()
    init { require(generation.matches(Regex("q-[a-f0-9]{12}")) &&
        generationRoot.isAbsolute && generationRoot.normalize() == generationRoot &&
        generationRoot.fileName.toString() == generation &&
        java.util.UUID.fromString(subject).toString() == subject) }
    fun prepare() {
        ReleasePrivateFiles.directory(root.parent)
        if (!Files.exists(root, NOFOLLOW_LINKS))
            Files.createDirectory(root, PosixFilePermissions.asFileAttribute(
                PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.directory(root)
    }
    @Synchronized fun issue(id: String): String {
        require(nonce.matches(id) && current())
        ReleasePrivateFiles.directory(root)
        val intent = root.resolve("$id.intent.json")
        require(!Files.exists(intent, NOFOLLOW_LINKS) && !Files.exists(root.resolve("$id.result.json"), NOFOLLOW_LINKS))
        Files.list(root).use { entries -> require(entries.filter { it.fileName.toString().matches(
            Regex("[a-f0-9]{32}\\.result\\.json")) }.limit(65).count() < 64) }
        val now = clock.instant().epochSecond
        ReleasePrivateFiles.save(intent, "$generation|$subject|$id|$now\n".toByteArray())
        val random = ByteArray(48).also(entropy::nextBytes)
        val token = "p0d_" + Base64.getUrlEncoder().withoutPadding().encodeToString(random)
        random.fill(0)
        val grant = FreshManagedDeviceGrant(generation, subject, ReleaseLocks.sha256(token.toByteArray()), now, now+3600)
        require(current())
        ReleasePrivateFiles.save(root.resolve("$id.result.json"), Json.encodeToString(grant).toByteArray())
        return token // the original response is the ONLY disclosure; never replay it
    }
    @Synchronized fun revoke(id: String) {
        require(nonce.matches(id) && current())
        val grant = Json.decodeFromString<FreshManagedDeviceGrant>(ReleasePrivateFiles.read(root.resolve("$id.result.json"),4096)
            .decodeToString(throwOnInvalidSequence = true))
        require(grant.generation==generation && grant.subject==subject && grant.scope=="p0-agent")
        ReleasePrivateFiles.save(root.resolve("$id.revoked"), "revoked\n".toByteArray())
    }
    fun valid(token: String): Boolean {
      return try {
        if (!current() || !token.matches(Regex("p0d_[A-Za-z0-9_-]{64}"))) return false
        val expected = ReleaseLocks.sha256(token.toByteArray()).toByteArray()
        val now = clock.instant().epochSecond
        Files.list(root).use { files ->
            val results = files.filter { it.fileName.toString().matches(
                Regex("[a-f0-9]{32}\\.result\\.json")) }.limit(65).toList()
            require(results.size <= 64)
            results.any { path ->
            val id = path.fileName.toString().removeSuffix(".result.json")
            if (Files.exists(root.resolve("$id.revoked"), NOFOLLOW_LINKS)) false else {
                val grant = Json.decodeFromString<FreshManagedDeviceGrant>(ReleasePrivateFiles.read(path,4096)
                    .decodeToString(throwOnInvalidSequence = true))
                grant.generation==generation && grant.subject==subject && grant.scope=="p0-agent" &&
                    grant.issuedAt <= now && now < grant.expiresAt && grant.expiresAt-grant.issuedAt==3600L &&
                    MessageDigest.isEqual(expected,grant.tokenSha256.toByteArray())
            }
        } }
      } catch (_: Exception) { false }
    }
}

/** Device chat admits exactly one user turn. History is the owned Pi session,
 * never a caller-supplied assistant/system/tool transcript or a broker shortcut. */
internal object FreshManagedChatContract {
    fun prompt(request: ByteArray): String {
        require(request.size in 16..8192)
        val body = Json.parseToJsonElement(request.decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(body.keys in setOf(setOf("model", "messages"), setOf("model", "messages", "stream")) &&
            body.getValue("model").jsonPrimitive.content == "p0/agent" &&
            body["stream"]?.jsonPrimitive?.content != "true")
        val message = body.getValue("messages").jsonArray.single().jsonObject
        require(message.keys == setOf("role", "content") && message.getValue("role").jsonPrimitive.content == "user")
        return message.getValue("content").jsonPrimitive.content.also {
            require(it.isNotBlank() && it.toByteArray(Charsets.UTF_8).size <= 4096)
        }
    }
}

/** Native broker-supervised HTTP adjunct; never a VM, OLD store or host-command path. */
internal class FreshManagedControlHttp(private val plan: ManagedLanePlan, private val generationRoot: Path,
    private val authority: ManagedLaneAuthority, private val identityHead: String,
    private val clock: java.time.Clock = java.time.Clock.systemUTC(),
    private val laneOperator: FreshManagedLaneOperator? = null) : AutoCloseable {
    private val generation = plan.generation
    private val socket = generationRoot.resolve("managed/control/run/http.sock")
    private val device = plan.ownerSubject?.let { FreshManagedDeviceGrantStore(generation,it,::current,clock,generationRoot) }
    private val workers = ThreadPoolExecutor(1, 4, 10, TimeUnit.SECONDS,
        ArrayBlockingQueue(8), { r -> Thread(r, "fresh-managed-control-http").apply { isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy())
    private var server: ServerSocketChannel? = null
    private var loop: Thread? = null
    private var fileKey: Any? = null

    fun start() {
        require(plan.generation == generation && plan.ownerSubject != null)
        plan.validate(generation)
        require(identityHead.matches(Regex("[a-f0-9]{64}")) &&
            generationRoot == GenerationRuntime.BASE.resolve(generation))
        ReleasePrivateFiles.directory(socket.parent)
        requireNotNull(device).prepare()
        require(!Files.exists(socket, NOFOLLOW_LINKS)) { "Existing HTTP socket cannot be replaced" }
        val channel = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
        try {
            channel.bind(UnixDomainSocketAddress.of(socket))
            Files.setPosixFilePermissions(socket, setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE))
            fileKey = Files.readAttributes(socket, java.nio.file.attribute.BasicFileAttributes::class.java,
                NOFOLLOW_LINKS).fileKey()
            server = channel
            loop = Thread({
                while (channel.isOpen) {
                    val peer = try { channel.accept() } catch (_: Exception) { break }
                    try { workers.execute { peer.use { handle(it) } } }
                    catch (_: java.util.concurrent.RejectedExecutionException) { peer.close() }
                }
            }, "fresh-managed-control-accept").apply { isDaemon = true; start() }
        } catch (e: Exception) {
            channel.close()
            Files.deleteIfExists(socket)
            throw e
        }
    }

    private fun current(): Boolean = try {
        val bundleBytes = ReleasePrivateFiles.read(generationRoot.resolve("bundle.json"), 1048576)
        val bundle = Json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString(throwOnInvalidSequence = true))
        bundle.request.id == generation && bundle.request.managedLanes == plan &&
            NativeManagedIdentityLedger(generationRoot.resolve("managed/identity"))
                .requireBound(plan, ReleaseLocks.sha256(bundleBytes)) == identityHead &&
            authority.generationActive(generation) && authority.revisionHead(generation) == identityHead
    } catch (_: Exception) { false }

    private fun owner(headers: Map<String,String>): Boolean {
        if (!current() || headers["x-webservices-sso-subject"] != plan.ownerSubject) return false
        val groups = headers["remote-groups"]?.split(',', ' ', ';')?.filter { it.isNotEmpty() }?.toSet() ?: emptySet()
        return groups.any { it in setOf("admins", "operators", "users") }
    }

    private fun chat(headers: Map<String, String>, request: ByteArray): String {
        val token = headers["authorization"]?.removePrefix("Bearer ") ?: ""
        val deviceStore = requireNotNull(device)
        require(deviceStore.valid(token))
        requireNotNull(laneOperator).requireChatReady()
        val intent = requireNotNull(headers["x-p0-intent"])
        require(intent.matches(Regex("[a-f0-9]{32}")))
        val prompt = FreshManagedChatContract.prompt(request)
        val result = ManagedLaneRuntime.real(generationRoot, plan).chat(requireNotNull(plan.ownerSubject), intent, prompt)
        // No result may cross a revoked device credential or lost generation authority.
        require(deviceStore.valid(token) && current())
        laneOperator.requireChatReady()
        return "{\"id\":\"p0-$intent\",\"object\":\"chat.completion\",\"model\":\"p0/agent\",\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\",\"content\":" +
            Json.encodeToString(result) + "},\"finish_reason\":\"stop\"}]}"
    }

    private fun response(peer: SocketChannel, status: Int, body: String) {
        val bytes = body.toByteArray(Charsets.UTF_8)
        val reason = when (status) { 200 -> "OK"; 403 -> "Forbidden"; 404 -> "Not Found";
            501 -> "Not Implemented"; else -> "Service Unavailable" }
        val packet = ("HTTP/1.1 $status $reason\r\nContent-Type: application/json\r\n" +
            "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Length: ${bytes.size}\r\nConnection: close\r\n\r\n")
            .toByteArray(US_ASCII) + bytes
        peer.configureBlocking(false)
        java.nio.channels.Selector.open().use { selector ->
            peer.register(selector, java.nio.channels.SelectionKey.OP_WRITE)
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
            val buffer = ByteBuffer.wrap(packet)
            while (buffer.hasRemaining() && System.nanoTime() < deadline) {
                if (selector.select(200) == 0) continue
                peer.write(buffer)
                selector.selectedKeys().clear()
            }
        }
    }

    private fun handle(peer: SocketChannel) {
        try {
            peer.configureBlocking(false)
            val data = ByteArrayOutputStream()
            val buffer = ByteBuffer.allocate(2048)
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
            while (data.size() < 8192 && System.nanoTime() < deadline) {
                val count = peer.read(buffer)
                if (count < 0) break
                if (count == 0) { Thread.sleep(2); continue }
                buffer.flip(); val part = ByteArray(buffer.remaining()); buffer.get(part); data.write(part); buffer.clear()
                if (data.toString(US_ASCII).contains("\r\n\r\n")) break
            }
            val request = data.toString(US_ASCII)
            require(request.length in 8..8192 && "\r\n\r\n" in request)
            val lines = request.substringBefore("\r\n\r\n").split("\r\n")
            val line = lines.first().split(' ')
            require(line.size == 3 && line[2] == "HTTP/1.1" && line[1].startsWith('/') &&
                line[1].length <= 128 && '?' !in line[1])
            val headers = mutableMapOf<String,String>()
            lines.drop(1).forEach { header ->
                val key = header.substringBefore(':').lowercase()
                require(':' in header && key.matches(Regex("[a-z0-9-]{1,64}")) && key !in headers)
                headers[key] = header.substringAfter(':').trim()
            }
            require("transfer-encoding" !in headers)
            val (method,path) = line
            val length = headers["content-length"]?.toIntOrNull() ?: 0
            require(length in 0..65536 && (path == "/v1/chat/completions" && method == "POST" || length == 0))
            val split = request.indexOf("\r\n\r\n") + 4
            val body = ByteArrayOutputStream()
            body.write(data.toByteArray(),split,data.size()-split)
            require(body.size() <= length)
            while (body.size() < length && System.nanoTime() < deadline) {
                val count = peer.read(buffer)
                if (count < 0) break
                if (count == 0) { Thread.sleep(2); continue }
                buffer.flip(); require(body.size()+count <= length)
                val part = ByteArray(count);buffer.get(part);body.write(part);buffer.clear()
            }
            require(body.size()==length)
            when {
                path == "/ops/status" && method == "GET" && owner(headers) ->
                    response(peer,200,"{\"generation\":\"$generation\",\"lane\":\"managed-pi\",\"nativeIdentityBound\":true,\"running\":${requireNotNull(laneOperator).status()}}")
                path.startsWith("/ops") && !owner(headers) -> response(peer,403,"{\"error\":\"owner session required\"}")
                path in setOf("/ops/lane/start","/ops/lane/stop") && method == "POST" &&
                    headers["origin"] == "https://control.datamancy.net" -> {
                    require(length == 0)
                    val kind = if (path.endsWith("/start")) FreshLaneAction.START else FreshLaneAction.STOP
                    val result = requireNotNull(laneOperator).operate(kind,requireNotNull(headers["x-p0-intent"]))
                    response(peer,200,"{\"generation\":\"$generation\",\"lane\":\"managed-pi\",\"running\":${result.nativePhysicalRunning}}")
                }
                path == "/ops/device-tokens" && method == "POST" &&
                    headers["origin"] == "https://control.datamancy.net" -> {
                    val token = requireNotNull(device).issue(requireNotNull(headers["x-p0-intent"]))
                    response(peer,200,"{\"access_token\":\"$token\",\"token_type\":\"Bearer\",\"expires_in\":3600}")
                }
                path.startsWith("/ops/device-tokens/") && method == "DELETE" &&
                    headers["origin"] == "https://control.datamancy.net" -> {
                    requireNotNull(device).revoke(path.removePrefix("/ops/device-tokens/"))
                    response(peer,200,"{\"revoked\":true}")
                }
                path.startsWith("/ops") || path in setOf("/user","/goals","/notifications","/terminal","/ws") ->
                    response(peer,501,"{\"error\":\"no approved typed v3 controller operation\"}")
                path == "/v1/models" && method == "GET" && device?.valid(
                    headers["authorization"]?.removePrefix("Bearer ") ?: "") == true -> {
                    requireNotNull(laneOperator).requireChatReady()
                    require(device.valid(headers["authorization"]?.removePrefix("Bearer ") ?: "") && current())
                    response(peer,200,"{\"object\":\"list\",\"data\":[{\"id\":\"p0/agent\",\"object\":\"model\"}],\"chatReady\":true}")
                }
                path == "/v1/chat/completions" && method == "POST" && device?.valid(
                    headers["authorization"]?.removePrefix("Bearer ") ?: "") == true ->
                    response(peer,200,chat(headers,body.toByteArray()))
                path in setOf("/v1/models", "/v1/chat/completions") ->
                    response(peer,403,"{\"error\":\"fresh device token required\"}")
                else -> response(peer,404,"{\"error\":\"unknown endpoint\"}")
            }
        } catch (_: Exception) { runCatching { response(peer,503,"{\"error\":\"native authority unavailable\"}") } }
    }

    override fun close() {
        server?.close(); loop?.join(1000); workers.shutdownNow()
        if (fileKey != null && Files.exists(socket, NOFOLLOW_LINKS) &&
            Files.readAttributes(socket, java.nio.file.attribute.BasicFileAttributes::class.java,
                NOFOLLOW_LINKS).fileKey() == fileKey) Files.deleteIfExists(socket)
    }
}
