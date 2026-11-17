package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.SecureDirectoryStream
import java.nio.file.attribute.BasicFileAttributeView
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

@Serializable internal data class QualificationSpoolRequest(val schemaVersion: Int,
    val invocationId: String, val sequence: Int, val family: String, val request: JsonObject)
@Serializable internal data class QualificationSpoolResult(val schemaVersion: Int,
    val invocationId: String, val sequence: Int, val family: String,
    val requestSha256: String, val result: JsonObject)

/** Exactly one owner-thread spool per case. Client files are transport, never original
 * effect authority: the protected raw request and typed reply precede effect/ACK. */
internal class QualificationCaseSpool(private val caseDir: Path, private val controlRoot: Path,
    private val invocationId: String, private val owner: Thread = Thread.currentThread()) {
    private val json = Json { encodeDefaults = true; explicitNulls = true; ignoreUnknownKeys = false }
    private val uid = UnixSystem().uid
    private val modeFile = PosixFilePermissions.fromString("rw-------")
    private val modeDir = PosixFilePermissions.fromString("rwx------")
    private val requestDir = caseDir.resolve("control-requests")
    private val resultDir = caseDir.resolve("control-results")
    private val originals = privateControlDirectory(privateControlDirectory(controlRoot.resolve("case-native"))
        .resolve(invocationId))
    private val directoryKeys = listOf(requestDir, resultDir, originals).associateWith { path ->
        directory(path)
        requireNotNull(Files.readAttributes(path, java.nio.file.attribute.BasicFileAttributes::class.java, NOFOLLOW_LINKS).fileKey())
    }
    private var next = 1
    private var poisoned = false
    private val families = setOf("OBSERVABILITY", "OPENSEARCH", "CROWDSEC", "QBITTORRENT",
        "OFFICE_CALLBACK", "RSS", "PROVIDER", "BACKUP", "MANAGED", "IDENTITY", "MASTODON", "MATRIX")
    init {
        require(uid > 0 && invocationId.matches(Regex("case-[a-f0-9-]{36}")) &&
            caseDir.isAbsolute && caseDir.normalize() == caseDir &&
            controlRoot.isAbsolute && controlRoot.normalize() == controlRoot)
        for (directory in listOf(caseDir, requestDir, resultDir)) directory(directory)
    }
    private fun owned() = check(Thread.currentThread() === owner && !poisoned) {
        "Original native spool effect/publication uncertain or left retained owner"
    }
    private fun directory(path: Path): Map<String, Any> {
        require(Files.isDirectory(path, NOFOLLOW_LINKS) && path.toRealPath() == path &&
            Files.getPosixFilePermissions(path, NOFOLLOW_LINKS) == modeDir)
        return Files.readAttributes(path, "unix:dev,ino,uid,mode,nlink", NOFOLLOW_LINKS).also {
            require((it.getValue("uid") as Number).toLong() == uid &&
                (it.getValue("nlink") as Number).toLong() >= 1)
        }
    }
    private fun <T> held(path: Path, action: (SecureDirectoryStream<Path>) -> T): T {
        directory(path)
        val expected = directoryKeys.getValue(path)
        fun current() = Files.readAttributes(path, java.nio.file.attribute.BasicFileAttributes::class.java, NOFOLLOW_LINKS).fileKey()
        require(current() == expected)
        return Files.newDirectoryStream(path).use { opened ->
            val secure = opened as? SecureDirectoryStream<Path> ?: error("Descriptor-relative spool required")
            require(secure.getFileAttributeView(BasicFileAttributeView::class.java).readAttributes().fileKey() == expected)
            val result = action(secure)
            require(current() == expected &&
                secure.getFileAttributeView(BasicFileAttributeView::class.java).readAttributes().fileKey() == expected)
            directory(path)
            result
        }
    }
    private fun sync(held: SecureDirectoryStream<Path>) {
        held.newByteChannel(Path.of("."), setOf(READ, NOFOLLOW_LINKS)).use {
            require(it is FileChannel) { "Durable spool directory channel required" }
            it.force(true)
        }
    }
    /** Transport reads/writes use a held directory, not merely final-component O_NOFOLLOW. */
    private fun bytes(path: Path, maximum: Int): ByteArray = held(path.parent) { held ->
        val parent = directory(path.parent)
        val before = Files.readAttributes(path, "unix:dev,ino,uid,nlink,mode,size", NOFOLLOW_LINKS)
        require(Files.isRegularFile(path, NOFOLLOW_LINKS) &&
            Files.getPosixFilePermissions(path, NOFOLLOW_LINKS) == modeFile &&
            (before.getValue("uid") as Number).toLong() == uid &&
            (before.getValue("nlink") as Number).toLong() == 1L)
        val basic = Files.readAttributes(path, java.nio.file.attribute.BasicFileAttributes::class.java, NOFOLLOW_LINKS)
        val view = held.getFileAttributeView(path.fileName, BasicFileAttributeView::class.java, NOFOLLOW_LINKS)
        require(view.readAttributes().fileKey() == basic.fileKey())
        val result = held.newByteChannel(path.fileName, setOf(READ, NOFOLLOW_LINKS)).use { file ->
            val size = file.size()
            require(size in (if (maximum == 0) 0L..0L else 1L..maximum.toLong()))
            val buffer = ByteBuffer.allocate(size.toInt() + 1)
            while (buffer.hasRemaining()) {
                val count = file.read(buffer)
                if (count < 0) break
                require(count > 0)
            }
            require(buffer.position().toLong() == size && file.size() == size)
            buffer.array().copyOf(size.toInt())
        }
        require(Files.readAttributes(path, "unix:dev,ino,uid,nlink,mode,size", NOFOLLOW_LINKS) == before &&
            view.readAttributes().fileKey() == basic.fileKey() && directory(path.parent) == parent)
        result
    }
    private fun stem(sequence: Int): String {
        require(sequence in 1..1024)
        return sequence.toString().padStart(8, '0')
    }
    private fun offered(): Pair<QualificationSpoolRequest, ByteArray>? {
        owned()
        val name = next.toString().padStart(8, '0')
        val marker = requestDir.resolve("$name.ready")
        if (!Files.exists(marker, NOFOLLOW_LINKS)) return null
        poisoned = true // Includes malformed and foreign ready requests; never resubmit.
        require(next in 1..1024)
        bytes(marker, 0)
        val raw = bytes(requestDir.resolve("$name.json"), 65536)
        val request = json.decodeFromString<QualificationSpoolRequest>(raw.decodeToString(throwOnInvalidSequence = true))
        require(json.encodeToString(request).encodeToByteArray().contentEquals(raw) &&
            request.schemaVersion == 1 && request.invocationId == invocationId &&
            request.sequence == next && request.family in families && request.request.isNotEmpty())
        require(!Files.exists(resultDir.resolve("$name.json"), NOFOLLOW_LINKS) &&
            !Files.exists(resultDir.resolve("$name.ready"), NOFOLLOW_LINKS))
        return request to raw
    }
    /** HOST returns the typed reply for acceptance's original outer publication. QCLIENT
     * publishes its exact result itself. Both use the identical protected actor path. */
    fun service(publish: Boolean, expected: OwnerCaseNative?, beforeEffect: () -> Unit,
        afterEffect: () -> Unit, actor: (QualificationSpoolRequest, String) -> OwnerCaseNativeReply): OwnerCaseNativeReply? {
        owned()
        val (request, raw) = offered() ?: return null
        // No next effect if the previous host ACK/case publication is incomplete.
        census(next - 1, allowNextRequest = true)
        val name = stem(next)
        val digest = ReleaseLocks.sha256(raw)
        if (expected != null) require(expected.family == request.family &&
            expected.caseDirectory == caseDir.toString() &&
            expected.request == ActivationInput(requestDir.resolve("$name.json").toString(), digest))
        beforeEffect()
        ReleasePrivateFiles.save(originals.resolve("$name.intent.json"), raw)
        val reply = actor(request, digest)
        require(reply.invocationId == invocationId && reply.family == request.family &&
            reply.requestSha256 == digest && reply.result.isNotEmpty())
        val originalReply = json.encodeToString(reply).encodeToByteArray()
        require(originalReply.size in 1..65536)
        ReleasePrivateFiles.save(originals.resolve("$name.result.json"), originalReply)
        afterEffect() // A dead tracked client never receives a purported successful result.
        if (publish) {
            val result = QualificationSpoolResult(1, invocationId, next, request.family, digest, reply.result)
            saveResult(resultDir.resolve("$name.json"), json.encodeToString(result).encodeToByteArray())
            // saveResult fsyncs both the file and its held directory before returning.
            saveResult(resultDir.resolve("$name.ready"), byteArrayOf())
        }
        next++
        poisoned = false
        return reply
    }
    private fun saveResult(path: Path, payload: ByteArray) = held(path.parent) { held ->
        require(payload.size in 0..65536)
        val parent = directory(path.parent)
        held.newByteChannel(path.fileName, setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS),
            PosixFilePermissions.asFileAttribute(modeFile)).use { file ->
            require(file is FileChannel) { "Durable spool result channel required" }
            val buffer = ByteBuffer.wrap(payload)
            while (buffer.hasRemaining()) file.write(buffer)
            file.force(true)
        }
        require(directory(path.parent) == parent)
        sync(held)
    }
    private fun names(path: Path): Set<String> = held(path) { held ->
        val before = directory(path)
        val entries = held.asSequence().take(2049).toList()
        require(entries.size <= 2048 && directory(path) == before)
        entries.map { it.fileName.toString() }.toSet().also { require(it.size == entries.size) }
    }
    private fun census(completed: Int, allowNextRequest: Boolean = false) {
        require(completed in 0..1024 && (!allowNextRequest || completed < 1024))
        val numbers = (1..completed).map(::stem)
        val caseNames = numbers.flatMap { listOf("$it.json", "$it.ready") }.toSet()
        val protectedNames = numbers.flatMap { listOf("$it.intent.json", "$it.result.json") }.toSet()
        val pending = if (!allowNextRequest) emptySet() else {
            val nextName = stem(completed + 1)
            val payload = Files.exists(requestDir.resolve("$nextName.json"), NOFOLLOW_LINKS)
            val marker = Files.exists(requestDir.resolve("$nextName.ready"), NOFOLLOW_LINKS)
            require(!marker || payload)
            (if (payload) setOf("$nextName.json") else emptySet()) +
                (if (marker) setOf("$nextName.ready") else emptySet())
        }
        require(names(requestDir) == caseNames + pending && names(resultDir) == caseNames &&
            names(originals) == protectedNames) { "Deleted, extra or pending native spool record" }
        for ((index, number) in numbers.withIndex()) {
            bytes(requestDir.resolve("$number.ready"), 0)
            bytes(resultDir.resolve("$number.ready"), 0)
            val raw = bytes(requestDir.resolve("$number.json"), 65536)
            val original = ReleasePrivateFiles.read(originals.resolve("$number.intent.json"), 65536)
            require(raw.contentEquals(original))
            val request = json.decodeFromString<QualificationSpoolRequest>(raw.decodeToString(throwOnInvalidSequence = true))
            val responseBytes = bytes(resultDir.resolve("$number.json"), 65536)
            val response = json.decodeFromString<QualificationSpoolResult>(responseBytes.decodeToString(throwOnInvalidSequence = true))
            val originalReply = ReleasePrivateFiles.read(originals.resolve("$number.result.json"), 65536)
            val reply = json.decodeFromString<OwnerCaseNativeReply>(originalReply.decodeToString(throwOnInvalidSequence = true))
            require(json.encodeToString(reply).encodeToByteArray().contentEquals(originalReply) &&
                request.schemaVersion == 1 && request.invocationId == invocationId &&
                request.sequence == index + 1 && request.family in families && request.request.isNotEmpty() &&
                json.encodeToString(request).encodeToByteArray().contentEquals(raw) &&
                response.schemaVersion == 1 && response.invocationId == invocationId &&
                response.sequence == index + 1 && response.family == request.family &&
                response.requestSha256 == ReleaseLocks.sha256(raw) && response.result == reply.result &&
                json.encodeToString(response).encodeToByteArray().contentEquals(responseBytes) &&
                reply == OwnerCaseNativeReply(invocationId, request.family, response.requestSha256, response.result) &&
                reply.result.isNotEmpty())
        }
    }
    fun requireDrained() { owned(); census(next - 1) }
}
