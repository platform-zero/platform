package net.datamancy.platform

import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.nio.charset.StandardCharsets.US_ASCII
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import jdk.net.ExtendedSocketOptions
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

internal enum class NotebookParentAction { START, STOP, STATE }
internal data class NotebookParentReply(val status: Int, val body: String = "")
internal fun interface NotebookParentEffects {
    fun apply(user: String, action: NotebookParentAction, intent: String?): NotebookParentReply
}

/** Owned only for the lifetime of the serving generation's generation+member lock
 * lease. A client may request typed notebook actions, never engine/systemd commands.
 * The sealed Hub input supplies distinct per-user bearer keys, absent from notebook
 * child containers. No HTTP proxy, TCP listener, or rootful Podman socket exists.
 */
internal class NotebookParentControlSocket(private val generationRoot: Path, private val member: String,
    private val expectedInputSha256: String, private val effects: NotebookParentEffects,
    private val runtimeRoot: Path = PrivateDeployment.BASE,
    private val generationBase: Path = GenerationRuntime.BASE,
    private val ownerAuthorized: () -> Boolean = {
        val pid = ProcessHandle.current().pid()
        QuadletNativeLockProof.classifyStable(pid, QuadletNativeLockProof.nativeTicks(pid),
            generationRoot.parent.resolve("generation.lock"), runtimeRoot.resolve(member).resolve("runtime.lock")) ==
            QuadletOwnerProof.VERIFIED
    }) : AutoCloseable {
    private val socket = generationRoot.resolve("notebooks/control.sock")
    private val json = Json { ignoreUnknownKeys = false }
    private var server: ServerSocketChannel? = null
    private var thread: Thread? = null
    private var socketKey: Any? = null
    private var keys: Map<String, ByteArray> = emptyMap()

    fun start() {
        require(generationRoot == generationBase.resolve(generationRoot.fileName.toString()) &&
            generationRoot.fileName.toString().matches(Regex("q-[a-f0-9]{12}")) &&
            member.startsWith("${generationRoot.fileName}-") &&
            expectedInputSha256.matches(Regex("[a-f0-9]{64}")) && ownerAuthorized() && server == null)
        if (generationBase == GenerationRuntime.BASE) {
            val bundle = json.decodeFromString<GenerationBundle>(ReleasePrivateFiles.read(
                generationRoot.resolve("bundle.json"),1048576).decodeToString(throwOnInvalidSequence=true))
            require(bundle.request.id == generationRoot.fileName.toString() &&
                NotebookSelectedGraph.selected(generationRoot,
                    bundle.members.single { it.spec.name == member }.spec))
        }
        val bytes = ReleasePrivateFiles.read(runtimeRoot.resolve(member).resolve("jupyterhub-hub-settings.json"),65536)
        require(ReleaseLocks.sha256(bytes) == expectedInputSha256)
        val settings = json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(settings.getValue("notebookGeneration").jsonPrimitive.content == generationRoot.fileName.toString())
        val entries = settings.getValue("servers").jsonObject
        require(entries.keys == setOf("alice","bob"))
        keys = entries.mapValues { (_, value) ->
            val secret = value.jsonObject.getValue("parentControlKey").jsonPrimitive.content
            require(secret.matches(Regex("[a-f0-9]{64}")))
            secret.toByteArray(US_ASCII)
        }
        require(!MessageDigest.isEqual(keys.getValue("alice"), keys.getValue("bob")))
        val parent = socket.parent
        if (!Files.exists(parent,NOFOLLOW_LINKS)) Files.createDirectory(parent,
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.directory(parent)
        require(!Files.exists(socket,NOFOLLOW_LINKS)) { "Foreign or stale notebook socket; no replacement" }
        val bound = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
        try {
            bound.bind(UnixDomainSocketAddress.of(socket))
            Files.setPosixFilePermissions(socket,PosixFilePermissions.fromString("rw-------"))
            socketKey = Files.readAttributes(socket,java.nio.file.attribute.BasicFileAttributes::class.java,
                NOFOLLOW_LINKS).fileKey()
            bound.configureBlocking(false)
            server = bound
            thread = Thread({
                while (bound.isOpen) {
                    val peer = try { bound.accept() } catch (_: Exception) { break }
                    if (peer == null) { try { Thread.sleep(20) } catch (_: InterruptedException) { break }; continue }
                    peer.use { handle(it) } // Exactly one bounded request; no concurrent effects.
                }
            },"notebook-parent-control").apply { isDaemon = true; start() }
        } catch (failure: Exception) {
            bound.close(); Files.deleteIfExists(socket); throw failure
        }
    }

    private fun handle(channel: SocketChannel) {
        try {
            require(ownerAuthorized() && server?.isOpen == true &&
                Files.readAttributes(socket,java.nio.file.attribute.BasicFileAttributes::class.java,NOFOLLOW_LINKS).fileKey() == socketKey &&
                Files.getPosixFilePermissions(socket) == PosixFilePermissions.fromString("rw-------"))
            val peer = channel.getOption(ExtendedSocketOptions.SO_PEERCRED)
            require(peer.user().name == com.sun.security.auth.module.UnixSystem().username)
            channel.configureBlocking(false)
            val data = ByteBuffer.allocate(4097)
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
            while (System.nanoTime() < deadline && data.position() <= 4096) {
                val count = channel.read(data)
                if (count < 0) break
                if (count == 0) { Thread.sleep(2); continue }
                if (data.array().copyOf(data.position()).toString(US_ASCII).contains("\r\n\r\n")) break
            }
            val request = data.array().copyOf(data.position()).toString(US_ASCII)
            require(request.length in 32..4096 && "\r\n\r\n" in request &&
                request.substringAfter("\r\n\r\n").isEmpty())
            val lines = request.substringBefore("\r\n\r\n").split("\r\n")
            val first = lines.first().split(' ')
            require(first.size == 3 && first[2] == "HTTP/1.1")
            val headers = linkedMapOf<String,String>()
            lines.drop(1).forEach { line ->
                require(':' in line)
                val key = line.substringBefore(':').lowercase()
                require(key.matches(Regex("[a-z0-9-]{1,48}")) && key !in headers)
                headers[key] = line.substringAfter(':').trim()
            }
            require(headers.keys.all { it in setOf("authorization","x-p0-generation","x-p0-notebook-user",
                "x-p0-intent","host","content-length","accept-encoding") } &&
                headers["content-length"] in setOf(null,"0") && "transfer-encoding" !in headers)
            val path = first[1]
            val match = Regex("/v1/notebooks/(alice|bob)/(start|stop|state)").matchEntire(path)
                ?: throw IllegalArgumentException("Unknown notebook endpoint")
            val user = match.groupValues[1]
            val action = when (match.groupValues[2]) {
                "start" -> NotebookParentAction.START
                "stop" -> NotebookParentAction.STOP
                else -> NotebookParentAction.STATE
            }
            require(first[0] == (if (action == NotebookParentAction.STATE) "GET" else "POST") &&
                headers["x-p0-generation"] == generationRoot.fileName.toString() &&
                headers["x-p0-notebook-user"] == user)
            val supplied = headers["authorization"]?.removePrefix("Bearer ")?.toByteArray(US_ASCII) ?: byteArrayOf()
            require(MessageDigest.isEqual(supplied,keys.getValue(user)))
            val intent = headers["x-p0-intent"]
            require(if (action == NotebookParentAction.STATE) intent == null else
                intent?.matches(Regex("[a-f0-9]{32}")) == true)
            require(ownerAuthorized())
            val result = effects.apply(user,action,intent)
            require(result.status in setOf(200,201,204,409,503) && result.body.length <= 1024 &&
                (result.status != 204 || result.body.isEmpty()))
            respond(channel,result)
        } catch (_: Exception) {
            try { respond(channel,NotebookParentReply(503,"{\"error\":\"notebook parent authorization or state unavailable\"}")) }
            catch (_: Exception) { /* peer closed; never retry native effect */ }
        }
    }
    private fun respond(channel: SocketChannel, result: NotebookParentReply) {
        val body = result.body.toByteArray(Charsets.UTF_8)
        val packet = ("HTTP/1.1 ${result.status} ${if (result.status in 200..299) "OK" else "Unavailable"}\r\n" +
            "Content-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: ${body.size}\r\n" +
            "Connection: close\r\n\r\n").toByteArray(US_ASCII) + body
        val buffer = ByteBuffer.wrap(packet)
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        while (buffer.hasRemaining() && System.nanoTime() < deadline) {
            if (channel.write(buffer) == 0) Thread.sleep(2)
        }
    }
    override fun close() {
        server?.close(); thread?.interrupt(); thread?.join(3500)
        if (socketKey != null && Files.exists(socket,NOFOLLOW_LINKS) &&
            Files.readAttributes(socket,java.nio.file.attribute.BasicFileAttributes::class.java,NOFOLLOW_LINKS).fileKey() == socketKey)
            Files.delete(socket)
        server = null
    }
}
