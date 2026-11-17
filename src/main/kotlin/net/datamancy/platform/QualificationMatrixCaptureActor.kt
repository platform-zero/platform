package net.datamancy.platform

import java.io.ByteArrayOutputStream
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** One fixed owner-held native LiveKit capture. No QClient native PID, raw pcap or
 * arbitrary capture filter crosses the case spool. A missing END/ACK is a retained fence. */
internal class QualificationMatrixCaptureActor(private val owner: Thread = Thread.currentThread()) {
    private val json = Json { encodeDefaults = true; explicitNulls = true; ignoreUnknownKeys = false }
    private data class Session(val id: String, val cid: String, val client: String, val turn: String,
        val sfu: String, val process: Process, val output: ByteArrayOutputStream,
        val errors: ByteArrayOutputStream, val ready: AtomicBoolean, val overflow: AtomicBoolean,
        val readers: List<Thread>)
    private var session: Session? = null
    private var attempted = false
    private fun owned() = check(Thread.currentThread() === owner)
    private fun stop(process: Process) {
        process.destroy()
        if (!process.waitFor(8, TimeUnit.SECONDS)) {
            process.toHandle().descendants().use { it.toList().asReversed().forEach { child -> child.destroyForcibly() } }
            process.destroyForcibly().waitFor()
            error("Original native tcpdump did not stop; capture fence retained")
        }
    }
    fun begin(action: JsonObject, caseDir: Path, context: JsonObject,
        pin: GenerationPin, client: QualificationClientNative, invocation: String): JsonObject {
        owned()
        require(!attempted && session == null && action.keys == setOf("action", "roomId") &&
            action.getValue("action").jsonPrimitive.content == "CAPTURE_BEGIN")
        val room = action.getValue("roomId").jsonPrimitive.content
        val original = json.parseToJsonElement(ReleasePrivateFiles.read(Path.of(context.getValue(
            "originalMatrixOracleFile").jsonPrimitive.content), 1048576).decodeToString()).jsonObject
        require(room == original.getValue("roomId").jsonPrimitive.content)
        val selected = QualificationMatrixActor.selectedProcess(pin.spec, pin.runtimeFingerprint, "livekit")
        val cid = selected.getValue("containerId").jsonPrimitive.content
        val pid = selected.getValue("pid").jsonPrimitive.int
        val networks = selected.getValue("networks").jsonObject
        val name = "p0v3-live-${pin.spec.name}-"
        val turn = networks.getValue("${name}qualification-web").jsonPrimitive.content
        val sfu = networks.getValue("${name}rtc-data").jsonPrimitive.content
        val policyPath = GenerationRuntime.BASE.resolve(clientCaseGeneration(pin)).resolve(
            "qualification-client/$invocation/turn-policy.json")
        val policy = json.decodeFromString<QualificationTurnPolicy>(ReleasePrivateFiles.read(policyPath, 65536)
            .decodeToString(throwOnInvalidSequence = true))
        require(policy.containerId == client.containerId && policy.containerNetnsInode == client.netnsInode &&
            policy.livekitClientIp == turn && policy.rtcHost == "matrix-rtc.datamancy.net" &&
            client.clientIp != turn && client.clientIp != sfu && turn != sfu)
        val intent = buildJsonObject {
            put("schemaVersion", 1); put("invocationId", invocation); put("roomId", room)
            put("selectedManifestSha256", pin.manifestSha256); put("livekitContainerId", cid)
            put("clientAddress", client.clientIp); put("turnAddress", turn); put("sfuAddress", sfu)
        }
        val intentBytes = json.encodeToString(intent).encodeToByteArray()
        ReleasePrivateFiles.save(caseDir.resolve("owner-proofs/matrix-capture.intent.json"), intentBytes)
        attempted = true // No second capture after a native start or lost owner ACK.
        val id = ReleaseLocks.sha256(intentBytes)
        // All literals except these selected observed private IPs; no shell, caller PID or filter.
        val args = listOf("/usr/bin/sudo", "-n", "/usr/bin/nsenter", "--target=$pid", "--net", "--",
            "/usr/sbin/tcpdump", "-n", "-U", "-s", "512", "-i", "any", "-w", "-",
            "udp and host ${client.clientIp} and host $turn and port 3478")
        val process = ProcessBuilder(args).redirectErrorStream(false).start()
        process.outputStream.close()
        val bytes = ByteArrayOutputStream()
        val stderr = ByteArrayOutputStream()
        val ready = AtomicBoolean(false); val overflow = AtomicBoolean(false)
        fun pump(input: java.io.InputStream, output: ByteArrayOutputStream, limit: Int,
            started: Boolean): Thread = thread(isDaemon = true, name = "matrix-native-capture") {
            input.use { stream ->
                val buffer = ByteArray(4096)
                while (true) {
                    val count = stream.read(buffer)
                    if (count < 0) break
                    if (output.size() + count > limit) {
                        overflow.set(true); process.destroyForcibly(); break
                    }
                    output.write(buffer, 0, count)
                    if (started && output.toString(Charsets.UTF_8).contains("listening on any")) ready.set(true)
                }
            }
        }
        val readers = listOf(pump(process.inputStream, bytes, 32 * 1024 * 1024, false),
            pump(process.errorStream, stderr, 65536, true))
        val started = Session(id, cid, client.clientIp, turn, sfu, process, bytes, stderr, ready, overflow, readers)
        session = started
        try {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8)
            while (!ready.get() && process.isAlive && System.nanoTime() < deadline && !overflow.get()) Thread.sleep(25)
            require(ready.get() && process.isAlive && !overflow.get()) { "Native tcpdump did not begin before Android UI" }
            val receipt = buildJsonObject { put("captureId", id); put("containerId", cid); put("started", true) }
            ReleasePrivateFiles.save(caseDir.resolve("owner-proofs/matrix-capture.started.json"),
                json.encodeToString(receipt).encodeToByteArray())
            return receipt
        } catch (failure: Throwable) {
            stop(process)
            throw failure // intent retained; no replay on another ID or sequence
        }
    }
    private fun clientCaseGeneration(pin: GenerationPin): String = pin.spec.name.removeSuffix("-v2").also {
        require(pin.spec.name == "$it-v2" && it.matches(Regex("q-[a-f0-9]{12}")))
    }
    fun end(action: JsonObject, caseDir: Path): JsonObject {
        owned()
        val captured = requireNotNull(session)
        require(action.keys == setOf("action", "captureId") &&
            action.getValue("action").jsonPrimitive.content == "CAPTURE_END" &&
            action.getValue("captureId").jsonPrimitive.content == captured.id)
        session = null // Failure still retains durable intent, never starts again.
        stop(captured.process)
        captured.readers.forEach { it.join(2000); require(!it.isAlive) }
        require(!captured.overflow.get()) { "Native capture truncated; case remains fenced" }
        val report = captured.errors.toString(Charsets.UTF_8)
        val dropped = Regex("(?m)^([0-9]+) packets dropped by kernel$").findAll(report).toList()
        require(dropped.size == 1 && dropped.single().groupValues[1] == "0") {
            "Native tcpdump kernel drops missing or nonzero"
        }
        val bytes = captured.output.toByteArray()
        val media = QualificationMatrixPcap.parse(bytes, captured.client, captured.turn, captured.sfu)
        val result = buildJsonObject {
            put("captureId", captured.id); put("containerId", captured.cid); put("stopped", true)
            put("kernelPacketsDropped", 0); put("truncated", false)
            put("pcapSha256", ReleaseLocks.sha256(bytes))
            put("media", JsonObject(media + mapOf("captureId" to JsonPrimitive(captured.id),
                "clientAddress" to JsonPrimitive(captured.client),
                "turnAddress" to JsonPrimitive(captured.turn),
                "sfuAddress" to JsonPrimitive(captured.sfu))))
        }
        ReleasePrivateFiles.save(caseDir.resolve("owner-proofs/matrix-capture.result.json"),
            json.encodeToString(result).encodeToByteArray())
        return result
    }
    /** Teardown safety only. A missing END never becomes a success or clears intent. */
    fun abandon(caseDir: Path): Boolean {
        owned()
        val running = session ?: return false
        session = null
        stop(running.process)
        running.readers.forEach { it.join(2000) }
        val uncertain = buildJsonObject {
            put("schemaVersion", 1); put("captureId", running.id)
            put("containerId", running.cid); put("status", "STOPPED_WITHOUT_OWNER_END_ACK")
            put("success", false)
        }
        ReleasePrivateFiles.save(caseDir.resolve("owner-proofs/matrix-capture.uncertain.json"),
            json.encodeToString(uncertain).encodeToByteArray())
        return true
    }
}
