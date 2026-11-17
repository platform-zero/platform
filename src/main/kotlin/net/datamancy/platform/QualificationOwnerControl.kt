package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption.WRITE
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.TimeUnit
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import jdk.net.ExtendedSocketOptions
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.*

/** Identical literal wire layout is mirrored in acceptance; no release V1 DTO changes. */
@Serializable internal data class QualificationControlScope(val schemaVersion: Int = 1,
    val suiteId: String, val generationId: String, val bundleSha256: String, val operation: String,
    val controllerSha256: String, val products: ActivationInput, val manifest: ActivationInput,
    val binding: ActivationInput, val journalFile: String, val journalHeadSha256: String,
    val artifactRoot: String, val contexts: ActivationInput?)
@Serializable internal data class QualificationControlBootstrap(val schemaVersion: Int = 1,
    val suiteId: String, val scopeSha256: String, val scope: QualificationControlScope,
    val socketPath: String, val capabilityBase64: String, val remainingMillis: Long)
@Serializable internal data class QualificationControlRequestBody(val schemaVersion: Int = 1,
    val suiteId: String, val scopeSha256: String, val sequence: Int, val operation: String,
    val payload: JsonElement)
@Serializable internal data class QualificationControlReplyBody(val schemaVersion: Int = 1,
    val suiteId: String, val scopeSha256: String, val sequence: Int, val operation: String,
    val status: String, val payload: JsonElement?, val errorCode: String?)
@Serializable internal data class QualificationControlRequest(val body: QualificationControlRequestBody, val mac: String)
@Serializable internal data class QualificationControlReply(val body: QualificationControlReplyBody, val mac: String)
@Serializable internal data class QualificationControlPhasePin(val request: ActivationInput)
@Serializable internal data class QualificationControlPhaseFinish(val request: ActivationInput,
    val phaseClaimSha256: String, val resultSha256: String)
@Serializable internal data class QualificationControlRssCaseBegin(val caseDirectory: String,
    val phaseClaimSha256: String)
@Serializable internal data class QualificationControlRssCaseFinish(val caseDirectory: String,
    val claimSha256: String, val phaseClaimSha256: String, val resultSha256: String)

/** Pure ordering guard; real effects remain in the original native/RSS publishers. */
internal class QualificationOwnerClaims(private val owner: Thread = Thread.currentThread()) {
    private var phase: String? = null
    private var finished = false
    private val begun = mutableMapOf<Pair<String, String>, String>()
    private val completed = mutableSetOf<Pair<String, String>>()
    private fun owned() = check(Thread.currentThread() === owner) { "Claim left owner thread" }
    fun requireOpen() { owned(); check(!finished) { "Whole phase already completed" } }
    fun beginPhase(claim: String) { requireOpen(); require(phase == null && claim.matches(Regex("[a-f0-9]{64}"))); phase = claim }
    fun phaseClaim(): String { requireOpen(); return requireNotNull(phase) }
    fun beginCase(kind: String, path: String, claim: String) {
        phaseClaim(); require(kind in setOf("NATIVE", "RSS") && claim.matches(Regex("[a-f0-9]{64}")))
        require(begun.putIfAbsent(kind to path, claim) == null) { "Case already attempted" }
    }
    fun requireCase(kind: String, path: String, claim: String) {
        phaseClaim(); require(begun[kind to path] == claim && (kind to path) !in completed)
    }
    fun completeCase(kind: String, path: String, claim: String) {
        requireCase(kind, path, claim); require(completed.add(kind to path))
    }
    fun requireReadyForPhaseCompletion() {
        phaseClaim()
        require(begun.isNotEmpty() && completed.size == begun.size) { "Pending native/RSS case blocks durable phase completion" }
    }
    /** Never call the durable RSS writer until all cases are complete; a failed writer
     * leaves the in-memory phase open, but its one-use intent still forbids replay. */
    fun <T> completePhaseWith(writer: () -> T): T {
        requireReadyForPhaseCompletion()
        val result = writer()
        requireReadyForPhaseCompletion()
        finished = true
        return result
    }
    fun requireFinished() { owned(); check(finished && completed.size == begun.size) { "Unfinished qualification phase" } }
    fun requireNoPendingNativeEffect() {
        owned()
        check(completed.size == begun.size) { "Native/RSS case effect remains uncertain; source stays held" }
    }
}

/** EOF is not an exit acknowledgement; continue to pump under the parent's deadline. */
internal object QualificationOwnerLifecycle {
    /** A zero nonblocking read is not EOF. After observed child exit keep observing the
     * socket under the same budget until real EOF; data from an exited child is never a
     * new handler authorization, and a partial header remains an error at EOF. */
    fun headerRead(read: () -> Int, alive: () -> Boolean, tick: () -> Unit,
        pause: () -> Unit = { Thread.sleep(10) }): Int {
        while (true) {
            tick()
            val count = read()
            if (count == 0) { pause(); continue }
            if (count > 0) check(alive()) { "Qualification child exited during control frame" }
            return count
        }
    }
    fun awaitExit(child: Process, tick: () -> Unit, pause: () -> Unit = { Thread.sleep(10) }) {
        while (child.isAlive) { tick(); pause() }
    }
    fun requireStopped(child: Process, timeoutSeconds: Long) {
        require(timeoutSeconds in 1..5)
        check(child.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
            "Owned qualification child did not stop; retain uncertainty"
        }
    }
    /** Call ONLY after actual child-stop observation. Log fsync is not a prerequisite
     * for the first legitimate client/bridge teardown; retain both failures. */
    fun stoppedCleanup(sync: () -> Unit, cleanup: () -> Unit) {
        var failure: Throwable? = null
        var interrupted = Thread.interrupted()
        fun record(error: Throwable) {
            if (failure == null) failure = error
            else if (failure !== error) requireNotNull(failure).addSuppressed(error)
            interrupted = Thread.interrupted() || interrupted || error is InterruptedException
        }
        try {
            try { sync() } catch (error: Throwable) { record(error) }
            try { cleanup() } catch (error: Throwable) { record(error) }
            failure?.let { throw it }
        } finally { if (Thread.interrupted() || interrupted) Thread.currentThread().interrupt() }
    }
}

/** The original authenticated body, never MAC/capability, is durable before its actor.
 * CREATE_NEW is also the recovery rule after a lost reply or a crashed handler. */
internal class QualificationOwnerRecords(private val root: Path, private val owner: Thread = Thread.currentThread()) {
    private fun path(sequence: Int, kind: String): Path {
        check(Thread.currentThread() === owner && sequence > 1)
        ReleasePrivateFiles.directory(root)
        return root.resolve("$sequence.$kind.json")
    }
    fun intent(sequence: Int, body: ByteArray) {
        require(body.size in 1..65536)
        ReleasePrivateFiles.save(path(sequence, "intent"), body)
    }
    fun result(sequence: Int, body: ByteArray) {
        ReleasePrivateFiles.read(path(sequence, "intent"), 65536)
        require(body.size in 1..65536)
        ReleasePrivateFiles.save(path(sequence, "result"), body)
    }
}

/** Owner-thread bounded pipe capture; stdout and stderr cannot grow past a private cap. */
internal class QualificationOwnerOutput(private val stdout: InputStream, private val stderr: InputStream,
    private val out: FileChannel, private val err: FileChannel, private val limit: Int = 4 * 1024 * 1024,
    private val owner: Thread = Thread.currentThread(),
    private val budget: () -> Unit = { RecoveryDeadline.remainingMillis(); Unit }) {
    private var stdoutBytes = 0
    private var stderrBytes = 0
    private var poisoned = false
    private fun guard() {
        check(Thread.currentThread() === owner && !Thread.currentThread().isInterrupted && !poisoned) {
            "Qualification child output capture unavailable"
        }
        budget()
    }
    fun pump() {
        try {
            guard() // Entry failure poisons capture too; teardown must only fsync prior bytes.
            fun drain(input: InputStream, file: FileChannel, current: () -> Int, commit: (Int) -> Unit) {
                while (true) {
                    guard() // Includes budget even if no new bytes or channel writes are pending.
                    val available = input.available()
                    if (available == 0) break
                    val count = current()
                    check(count < limit) { "Qualification child output exceeded cap" }
                    val size = minOf(8192, available, limit - count)
                    guard()
                    val bytes = input.readNBytes(size)
                    check(bytes.isNotEmpty() && bytes.size <= limit - count) { "Qualification child output exceeded cap" }
                    val buffer = ByteBuffer.wrap(bytes)
                    while (buffer.hasRemaining()) {
                        guard()
                        check(file.write(buffer) > 0) { "Qualification child output write made no progress" }
                    }
                    commit(count + bytes.size) // Commit EACH successful chunk, not at the end of a pump.
                }
            }
            drain(stdout, out, { stdoutBytes }, { stdoutBytes = it })
            drain(stderr, err, { stderrBytes }, { stderrBytes = it })
        } catch (failure: Throwable) {
            poisoned = true // Teardown may fsync existing bytes but MUST NOT drain again.
            throw failure
        }
    }
    fun sync() {
        if (!poisoned) pump()
        out.force(true); err.force(true)
        check(!poisoned) { "Qualification output capture failed; retain uncertainty" }
    }
}

/** Runs exclusively on the thread which entered GenerationRuntime's native lock cohort. */
internal class QualificationOwnerControl(private val scope: QualificationControlScope,
    private val root: Path, private val socket: Path, private val capability: ByteArray,
    private val owner: Thread = Thread.currentThread(),
    private val restored: RestoredOwnerScope? = null) {
    companion object {
        internal val json = Json { encodeDefaults = true; explicitNulls = true; ignoreUnknownKeys = false }
        private val hash = Regex("[a-f0-9]{64}")
        private val mode = PosixFilePermissions.fromString("rwx------")
        private fun digest(bytes: ByteArray) = ReleaseLocks.sha256(bytes)
        fun suiteId(invocation: ReleaseAcceptanceInvocation, operation: String): String = digest(
            "p0v3-qualification-control-v1\n${invocation.controllerSha256}\n${invocation.input.sha256}\n${invocation.expectedHead}\n$operation\n"
                .encodeToByteArray()).take(24)
        fun scope(invocation: ReleaseAcceptanceInvocation, operation: String): QualificationControlScope {
            require(operation in setOf("execute-staged", "execute-qualified"))
            val bytes = ReleasePrivateFiles.read(Path.of(invocation.input.path), 1048576)
            require(digest(bytes) == invocation.input.sha256)
            val binding = json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
            val generation = binding.getValue("generationId").jsonPrimitive.content
            require(generation.matches(Regex("q-[a-f0-9]{12}")) &&
                binding.getValue("phase").jsonPrimitive.content in setOf("INSTALL", "RESTORE") &&
                binding.getValue("trialId").jsonPrimitive.content.matches(Regex("[a-z][a-z0-9-]{0,63}")))
            val bundle = ReleasePrivateFiles.read(GenerationRuntime.BASE.resolve(generation).resolve("bundle.json"))
            val decoded = json.decodeFromString<GenerationBundle>(bundle.decodeToString(throwOnInvalidSequence = true))
            SiteOwnerships.checkSealed(decoded)
            require(decoded.request.id == generation)
            return QualificationControlScope(suiteId = suiteId(invocation, operation), generationId = generation,
                bundleSha256 = digest(bundle), operation = operation, controllerSha256 = invocation.controllerSha256,
                products = invocation.products, manifest = invocation.manifest, binding = invocation.input,
                journalFile = invocation.journal, journalHeadSha256 = invocation.expectedHead,
                artifactRoot = requireNotNull(invocation.artifacts), contexts = invocation.contexts)
        }
        fun real(scope: QualificationControlScope, restored: RestoredOwnerScope? = null): QualificationOwnerControl {
            require(scope.schemaVersion == 1 && scope.suiteId.matches(Regex("[a-f0-9]{24}")))
            val generation = GenerationRuntime.BASE.resolve(scope.generationId)
            val root = generation.resolve("qualification-control/${scope.suiteId}")
            val socket = generation.resolve("qc/${scope.suiteId}/c.sock")
            require(socket.toString().toByteArray(Charsets.UTF_8).size <= 103)
            val secret = ByteArray(32).also(SecureRandom()::nextBytes)
            return QualificationOwnerControl(scope, root, socket, secret, restored = restored)
        }
        /** Stable across differently encoded binding/manifest/context paths for the SAME
         * original generation trial/phase; CREATE_NEW is the non-replay admission point. */
        internal fun admitPhase(generation: Path, scope: QualificationControlScope,
            original: JsonObject): Path {
            ReleasePrivateFiles.directory(generation)
            require(original.getValue("generationId").jsonPrimitive.content == scope.generationId)
            val trial = original.getValue("trialId").jsonPrimitive.content
            val phase = original.getValue("phase").jsonPrimitive.content
            require(trial.matches(Regex("[a-z][a-z0-9-]{0,63}")) && phase in setOf("INSTALL", "RESTORE") &&
                scope.journalHeadSha256.matches(Regex("[a-f0-9]{64}")))
            val marker = ReleaseLocks.sha256("$trial\n$phase\n${scope.operation}\n${scope.journalHeadSha256}\n"
                .encodeToByteArray()).take(24)
            val control = generation.resolve("qualification-control")
            ReleasePrivateFiles.directory(control)
            val path = control.resolve("phase-$marker.intent.json")
            ReleasePrivateFiles.save(path, json.encodeToString(scope).encodeToByteArray())
            return path
        }
        internal fun boundedBootstrap(frameSize: Int) {
            require(frameSize in 5..4096) { "Qualification launch pipe must fit one empty atomic PIPE_BUF" }
        }
        internal fun requirePeer(childPid: Long, peerUser: String, ownerUser: String) {
            require(childPid > 1 && peerUser.isNotBlank() && peerUser == ownerUser) {
                "Foreign qualification control peer"
            }
        }
        fun mac(capability: ByteArray, direction: String, body: ByteArray): String {
            require(capability.size == 32 && direction in setOf("request", "response"))
            val hmac = Mac.getInstance("HmacSHA256")
            hmac.init(SecretKeySpec(capability, "HmacSHA256"))
            return hmac.doFinal(("$direction\n").encodeToByteArray() + body).joinToString("") { "%02x".format(it) }
        }
        fun canonicalRequest(bytes: ByteArray): QualificationControlRequest {
            require(bytes.size in 1..65536)
            val decoded = json.decodeFromString<QualificationControlRequest>(bytes.decodeToString(throwOnInvalidSequence = true))
            require(json.encodeToString(decoded).encodeToByteArray().contentEquals(bytes))
            return decoded
        }
    }
    private val scopeBytes = json.encodeToString(scope).encodeToByteArray()
    private val scopeHash = ReleaseLocks.sha256(scopeBytes)
    private val generation = GenerationRuntime.BASE.resolve(scope.generationId)
    private var childStopObserved = false
    private var sequence = 1
    private var phaseClaim: String? = null
    private val claims = QualificationOwnerClaims(owner)
    private val cases = QualificationCaseController(scope, owner, restored)
    private var output: QualificationOwnerOutput? = null
    private val attempted = mutableSetOf<String>()
    private fun owned() { check(Thread.currentThread() === owner) { "Qualification actor left owner locks" } }
    private fun mkdir(parent: Path, directory: Path) {
        ReleasePrivateFiles.directory(parent)
        Files.createDirectory(directory, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.sync(parent)
        ReleasePrivateFiles.directory(directory)
    }
    private fun heartbeat(process: Process, requireAlive: Boolean = true) {
        owned()
        output?.pump()
        check(!Thread.currentThread().isInterrupted && (!requireAlive || process.isAlive)) {
            "Qualification child exited or owner interrupted"
        }
        RecoveryDeadline.remainingMillis()
    }
    private fun readFully(channel: SocketChannel, buffer: ByteBuffer, process: Process) {
        while (buffer.hasRemaining()) {
            heartbeat(process)
            val read = channel.read(buffer)
            check(read >= 0) { "Qualification control closed mid-frame" }
            if (read == 0) Thread.sleep(10)
        }
    }
    private fun send(channel: SocketChannel, bytes: ByteArray, process: Process) {
        require(bytes.size in 1..65536)
        val buf = ByteBuffer.allocate(bytes.size + 4).putInt(bytes.size).put(bytes).flip() as ByteBuffer
        while (buf.hasRemaining()) {
            heartbeat(process)
            if (channel.write(buf) == 0) Thread.sleep(10)
        }
    }
    private fun binding(): JsonObject {
        val bytes = ReleasePrivateFiles.read(Path.of(scope.binding.path), 1048576)
        require(ReleaseLocks.sha256(bytes) == scope.binding.sha256)
        return json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject.also {
            require(it.getValue("generationId").jsonPrimitive.content == scope.generationId)
        }
    }
    private fun phaseRequest(pin: ActivationInput): RssQualificationPhaseRequest {
        val bytes = ReleasePrivateFiles.read(Path.of(pin.path), 16384)
        require(ReleaseLocks.sha256(bytes) == pin.sha256)
        val r = json.decodeFromString<RssQualificationPhaseRequest>(bytes.decodeToString(throwOnInvalidSequence = true))
        val b = binding()
        val stem = "${if (r.stagedOnly) "staged" else "phase"}-${r.trialId}-${r.phase.lowercase()}"
        val journal = Path.of(scope.journalFile)
        require(r.schemaVersion == 1 && r.trialId == b.getValue("trialId").jsonPrimitive.content &&
            r.phase == b.getValue("phase").jsonPrimitive.content && r.generationId == scope.generationId &&
            r.bundleSha256 == scope.bundleSha256 && r.inventorySha256 == scope.products.sha256 &&
            r.manifestSha256 == scope.manifest.sha256 && r.journalHead == scope.journalHeadSha256 &&
            r.artifactRoot == scope.artifactRoot && r.stagedOnly == (scope.operation == "execute-staged") &&
            Path.of(r.phaseIntentPath) == journal.parent.resolve("$stem.intent.json") &&
            Path.of(r.phaseResultPath) == journal.parent.resolve("$stem.result.json") &&
            Path.of(pin.path).parent == journal.parent)
        return r
    }
    private fun case(path: String): JsonObject {
        val p = Path.of(path)
        require(p.isAbsolute && p.normalize() == p && p.parent == Path.of(scope.artifactRoot))
        ReleasePrivateFiles.directory(p)
        val bytes = ReleasePrivateFiles.read(p.resolve("intent.json"), 65536)
        val intent = json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val b = intent.getValue("binding").jsonObject
        val original = binding()
        require(b == original && intent.getValue("contextSha256").jsonPrimitive.content ==
            ReleaseLocks.sha256(ReleasePrivateFiles.read(p.resolve("context.json"), 4194304)))
        return intent
    }
    private fun handle(body: QualificationControlRequestBody, process: Process): JsonElement {
        claims.requireOpen()
        owned()
        val p = body.payload
        val generationRoot = generation
        return when (body.operation) {
            "CASE_PREPARE" -> {
                val request = json.decodeFromJsonElement<OwnerCasePrepare>(p)
                val rss = request.evidenceKey.startsWith("rss-pack-") ||
                    request.evidenceKey.startsWith("rss-jobs--") ||
                    request.evidenceKey.startsWith("mastodon-rss-publisher--")
                val hub = request.evidenceKey in setOf(
                    "jupyterhub--workflow--web--browser", "jupyterhub--workflow--headless--native",
                    "jupyter-notebook--workflow--web--browser",
                    "jupyter-notebook--workflow--headless--native")
                val ownerReadback = if (hub) {
                    val dir = Path.of(request.caseDirectory)
                    require(dir.parent == Path.of(scope.artifactRoot) &&
                        dir.fileName.toString() == request.evidenceKey)
                    val bytes = ReleasePrivateFiles.read(generation.resolve("bundle.json"),4194304)
                    require(ReleaseLocks.sha256(bytes) == scope.bundleSha256)
                    val selectedBundle = json.decodeFromString<GenerationBundle>(
                        bytes.decodeToString(throwOnInvalidSequence=true))
                    val selected = QualificationCanonicalTopology.require(selectedBundle,
                        binding().getValue("phase").jsonPrimitive.content == "RESTORE")
                    require(selectedBundle.request.id == scope.generationId &&
                        selected.spec.name == "${scope.generationId}-v2")
                    QualificationHubOwnerReadback.observe(dir,selectedBundle,selected)
                } else null
                json.encodeToJsonElement(cases.prepare(request, if (rss) requireNotNull(phaseClaim) else null,
                    hubOwnerReadback=ownerReadback))
            }
            "CASE_START" -> json.encodeToJsonElement(cases.start(json.decodeFromJsonElement<OwnerCaseStart>(p)))
            "CASE_AWAIT" -> {
                require(p.jsonObject.keys == setOf("caseDirectory"))
                json.encodeToJsonElement(cases.await(p.jsonObject.getValue("caseDirectory").jsonPrimitive.content) {
                    heartbeat(process)
                })
            }
            "CASE_NATIVE" -> json.encodeToJsonElement(cases.native(json.decodeFromJsonElement<OwnerCaseNative>(p)))
            "CASE_FENCE" -> {
                require(p.jsonObject.keys == setOf("caseDirectory"))
                json.encodeToJsonElement(cases.fence(p.jsonObject.getValue("caseDirectory").jsonPrimitive.content))
            }
            "NATIVE_CASE_BEGIN" -> {
                val request = json.decodeFromJsonElement<NativeCaseBeginRequest>(p)
                val intent = case(request.caseDirectory)
                require(intent.getValue("surface").jsonPrimitive.content == "HEADLESS" &&
                    intent.getValue("variant").jsonPrimitive.content == "NATIVE" &&
                    request.bundleSha256 == scope.bundleSha256 && request.journalFile == scope.journalFile &&
                    request.journalHeadSha256 == scope.journalHeadSha256)
                val phase = requireNotNull(phaseClaim)
                RssQualificationIntents.requireNativePhase(generationRoot, phase,
                    binding().getValue("trialId").jsonPrimitive.content,
                    binding().getValue("phase").jsonPrimitive.content,
                    Path.of(scope.artifactRoot), request.phaseIntent)
                val receipt = NativeQualificationCasePublisher.begin(request, phase)
                claims.beginCase("NATIVE", request.caseDirectory, receipt.claimSha256)
                json.encodeToJsonElement(receipt)
            }
            "NATIVE_CASE_COMPLETE" -> {
                val request = json.decodeFromJsonElement<NativeCaseCompletionRequest>(p)
                case(request.caseDirectory)
                claims.requireCase("NATIVE", request.caseDirectory, request.claimSha256)
                cases.requireFenced(request.caseDirectory)
                val receipt = NativeQualificationCasePublisher.complete(request)
                require(receipt.claimSha256 == request.claimSha256 && receipt.resultSha256 == request.resultSha256)
                claims.completeCase("NATIVE", request.caseDirectory, request.claimSha256)
                json.encodeToJsonElement(receipt)
            }
            "RSS_PHASE_BEGIN" -> {
                require(phaseClaim == null)
                val request = json.decodeFromJsonElement<QualificationControlPhasePin>(p)
                phaseRequest(request.request)
                val claim = RssQualificationIntents.beginPhase(generationRoot, Path.of(request.request.path))
                claims.beginPhase(claim.phaseClaimSha256)
                phaseClaim = claim.phaseClaimSha256
                json.encodeToJsonElement(claim)
            }
            "RSS_PHASE_COMPLETE" -> {
                val request = json.decodeFromJsonElement<QualificationControlPhaseFinish>(p)
                val phase = phaseRequest(request.request)
                require(request.phaseClaimSha256 == phaseClaim &&
                    ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(phase.phaseResultPath), 1048576)) == request.resultSha256)
                val receipt = claims.completePhaseWith {
                    cases.requireDeclaredClosures()
                    RssQualificationIntents.completePhase(generationRoot,
                        Path.of(request.request.path), request.phaseClaimSha256, request.resultSha256).also {
                        require(it.phaseClaimSha256 == request.phaseClaimSha256 &&
                            it.resultSha256 == request.resultSha256)
                    }
                }
                json.encodeToJsonElement(receipt)
            }
            "RSS_CASE_BEGIN" -> {
                val request = json.decodeFromJsonElement<QualificationControlRssCaseBegin>(p)
                case(request.caseDirectory)
                require(request.phaseClaimSha256 == phaseClaim)
                val receipt = RssQualificationIntents.begin(generationRoot,
                    Path.of(request.caseDirectory), request.phaseClaimSha256)
                claims.beginCase("RSS", request.caseDirectory, receipt.claimSha256)
                json.encodeToJsonElement(receipt)
            }
            "RSS_CASE_COMPLETE" -> {
                val request = json.decodeFromJsonElement<QualificationControlRssCaseFinish>(p)
                case(request.caseDirectory)
                require(request.phaseClaimSha256 == phaseClaim)
                claims.requireCase("RSS", request.caseDirectory, request.claimSha256)
                cases.requireFenced(request.caseDirectory)
                val receipt = RssQualificationIntents.complete(generationRoot,
                    Path.of(request.caseDirectory), request.claimSha256, request.resultSha256,
                    request.phaseClaimSha256)
                require(receipt.claimSha256 == request.claimSha256 && receipt.resultSha256 == request.resultSha256)
                claims.completeCase("RSS", request.caseDirectory, request.claimSha256)
                json.encodeToJsonElement(receipt)
            }
            else -> error("Unknown qualification operation")
        }
    }
    fun completedCaseClosures(): List<ActivationInput> { owned(); return cases.closures() }
    fun safeCaseReceipts(): List<ActivationInput> {
        owned(); check(childStopObserved) { "Acceptance child not observed stopped; no source resume" }
        claims.requireNoPendingNativeEffect(); return cases.safetyReceipts()
    }
    /** Caller holds same-thread RSS/generation/member locks; only the pinned acceptance child
     * receives the in-memory bootstrap, never a runner or a caller-supplied executable. */
    fun run(argv: List<String>, work: Path): RuntimeCommandResult = try {
        runOwned(argv, work)
    } finally {
        capability.fill(0)
    }
    private fun runOwned(argv: List<String>, work: Path): RuntimeCommandResult {
        owned()
        require(scope.operation == argv.getOrNull(1) && scope.products.path == argv.getOrNull(2) &&
            scope.manifest.path == argv.getOrNull(3) && scope.binding.path == argv.getOrNull(4) &&
            scope.journalFile == argv.getOrNull(5) && scope.journalHeadSha256 == argv.getOrNull(6) &&
            scope.artifactRoot == argv.getOrNull(7) && scope.contexts?.path == argv.getOrNull(8) &&
            argv[0] == "/mnt/media/p0-v3/runtime-supervision/acceptance-releases/${scope.controllerSha256}/bin/p0-v3-acceptance" &&
            scope.schemaVersion == 1 && scope.suiteId == suiteId(ReleaseAcceptanceInvocation(scope.controllerSha256,
                scope.products, scope.manifest, scope.binding, scope.journalFile, scope.journalHeadSha256,
                scope.artifactRoot, scope.contexts), scope.operation))
        ReleasePrivateFiles.directory(work)
        require((binding().getValue("phase").jsonPrimitive.content == "RESTORE") == (restored != null)) {
            "RESTORE requires the explicit retained source/target owner scope"
        }
        val parent = generation.resolve("qualification-control")
        if (!Files.exists(parent, NOFOLLOW_LINKS)) mkdir(generation, parent)
        admitPhase(generation, scope, binding())
        mkdir(parent, root) // Intentional CREATE_NEW: no restarts after a lost acknowledgement.
        mkdir(root, root.resolve("requests"))
        val qc = generation.resolve("qc")
        if (!Files.exists(qc, NOFOLLOW_LINKS)) mkdir(generation, qc)
        val socketDir = socket.parent
        mkdir(qc, socketDir)
        val bootstrap = QualificationControlBootstrap(suiteId = scope.suiteId, scopeSha256 = scopeHash,
            scope = scope, socketPath = socket.toString(), capabilityBase64 = Base64.getEncoder().encodeToString(capability),
            remainingMillis = RecoveryDeadline.remainingMillis())
        val bootstrapBytes = json.encodeToString(bootstrap).encodeToByteArray()
        boundedBootstrap(bootstrapBytes.size + 4)
        ReleasePrivateFiles.save(root.resolve("scope.intent.json"), scopeBytes)
        val out = root.resolve("child.stdout")
        val err = root.resolve("child.stderr")
        val fileMode = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))
        Files.createFile(out, fileMode); Files.createFile(err, fileMode)
        FileChannel.open(out, WRITE).use { outFile -> FileChannel.open(err, WRITE).use { errFile ->
        ServerSocketChannel.open(StandardProtocolFamily.UNIX).use { server ->
            server.bind(UnixDomainSocketAddress.of(socket))
            Files.setPosixFilePermissions(socket, PosixFilePermissions.fromString("rw-------"))
            server.configureBlocking(false)
            val builder = ProcessBuilder(argv).directory(work.toFile())
            builder.environment().apply {
                clear(); put("JAVA_HOME", "/usr/lib/jvm/java-21-openjdk-amd64"); put("PATH", "/usr/bin:/bin")
                put("JAVA_OPTS", "-Xms32m -Xmx512m"); put("LANG", "C.UTF-8"); put("HOME", work.toString())
                put("P0V3_QUALIFICATION_CONTROL", "1")
            }
            val child = builder.start()
            output = QualificationOwnerOutput(child.inputStream, child.errorStream, outFile, errFile, owner = owner)
            var connection: SocketChannel? = null
            var executionFailure: Throwable? = null
            var outputSyncAttempted = false
            try {
                // Parent alone knows PID; JDK SO_PEERCRED supplies UID, not PID.
                require(child.pid() > 1)
                check(!Thread.currentThread().isInterrupted && child.isAlive)
                child.outputStream.use { stream ->
                    // One initially empty exclusive Linux pipe; <=PIPE_BUF is nonblocking as a
                    // complete atomic write. No executor, unbounded producer or second frame.
                    stream.write(ByteBuffer.allocate(bootstrapBytes.size + 4).putInt(bootstrapBytes.size)
                        .put(bootstrapBytes).array())
                    stream.flush()
                }
                while (child.isAlive || connection != null) {
                    heartbeat(child, requireAlive = false)
                    if (connection == null) {
                        connection = server.accept()
                        if (connection == null) { Thread.sleep(10); continue }
                        val peer = connection.getOption(ExtendedSocketOptions.SO_PEERCRED)
                        requirePeer(child.pid(), peer.user().name, UnixSystem().username)
                        require(Files.getPosixFilePermissions(socket) == PosixFilePermissions.fromString("rw-------"))
                        connection.configureBlocking(false)
                    }
                    val c = connection
                    if (c != null) {
                        // One persistent child connection, with no reconnect after EOF.
                        val first = ByteBuffer.allocate(4)
                        while (first.hasRemaining()) {
                            val read = QualificationOwnerLifecycle.headerRead(
                                { c.read(first) }, { child.isAlive },
                                { heartbeat(child, requireAlive = false) })
                            if (read < 0) {
                                require(first.position() == 0)
                                c.close(); connection = null
                                QualificationOwnerLifecycle.awaitExit(child, { heartbeat(child, requireAlive = false) })
                                break
                            }
                        }
                        if (connection == null) break
                        first.flip()
                        val size = first.int
                        require(size in 1..65536)
                        val payload = ByteBuffer.allocate(size)
                        readFully(c, payload, child)
                        // Authenticate before saving an intent or executing any effect.
                        exchangeFrame(c, payload.array(), child)
                    }
                }
                outputSyncAttempted = true
                output?.sync()
                claims.requireFinished()
                check(child.exitValue() == 0) { "Pinned acceptance rejected qualification" }
                val result = ReleasePrivateFiles.read(out, 4 * 1024 * 1024).decodeToString(throwOnInvalidSequence = true)
                return RuntimeCommandResult(child.exitValue(), result)
            } catch (failure: Throwable) {
                executionFailure = failure
                if (failure is InterruptedException) Thread.currentThread().interrupt()
                throw failure
            } finally {
                val wasInterrupted = Thread.interrupted()
                try {
                    try { connection?.close() } catch (_: Exception) { /* Retain uncertain intent; still kill owned child. */ }
                    if (child.isAlive) {
                        child.descendants().use { entries -> entries.forEach { it.destroyForcibly() } }
                        child.destroyForcibly()
                        QualificationOwnerLifecycle.requireStopped(child, 5)
                    }
                    check(!child.isAlive) { "Owned qualification child stop unknown; do not teardown as if stopped" }
                    childStopObserved = true
                    QualificationOwnerLifecycle.stoppedCleanup(
                        sync = { if (!outputSyncAttempted) output?.sync() },
                        cleanup = { check(cases.cleanupKnown()) {
                            "Case teardown uncertain; retain source and isolate target"
                        } })
                } catch (teardown: Throwable) {
                    if (teardown is InterruptedException) Thread.currentThread().interrupt()
                    if (executionFailure == null) throw teardown
                    if (executionFailure !== teardown) requireNotNull(executionFailure).addSuppressed(teardown)
                } finally { if (wasInterrupted) Thread.currentThread().interrupt() }
            }
        }
        } }
    }
    private fun exchangeFrame(channel: SocketChannel, bytes: ByteArray, process: Process) {
        // The framing header was already read by the polling parent; re-use the same authenticated handler.
        val decoded = canonicalRequest(bytes)
        val body = decoded.body
        require(body.schemaVersion == 1 && body.sequence == sequence && body.suiteId == scope.suiteId &&
            body.scopeSha256 == scopeHash && decoded.mac.matches(Regex("[a-f0-9]{64}")))
        val expected = mac(capability, "request", json.encodeToString(body).encodeToByteArray())
        require(MessageDigest.isEqual(expected.encodeToByteArray(), decoded.mac.encodeToByteArray()))
        require(if (sequence == 1) body.operation == "HELLO" else body.operation in setOf(
            "NATIVE_CASE_BEGIN", "NATIVE_CASE_COMPLETE", "RSS_PHASE_BEGIN", "RSS_PHASE_COMPLETE",
            "RSS_CASE_BEGIN", "RSS_CASE_COMPLETE", "CASE_PREPARE", "CASE_START",
            "CASE_AWAIT", "CASE_NATIVE", "CASE_FENCE"))
        var refused = false
        val result = if (sequence == 1) {
            require(body.payload == buildJsonObject { put("scopeSha256", scopeHash) })
            buildJsonObject { put("scopeSha256", scopeHash) }
        } else {
            val key = body.operation + ":" + if (body.operation.contains("CASE"))
                body.payload.jsonObject.getValue("caseDirectory").jsonPrimitive.content +
                    (if (body.operation == "CASE_NATIVE") ":" + body.payload.jsonObject
                        .getValue("request").jsonObject.getValue("sha256").jsonPrimitive.content else "")
                else scope.suiteId
            require(attempted.add(key))
            QualificationOwnerRecords(root.resolve("requests"), owner).intent(sequence,
                json.encodeToString(body).encodeToByteArray())
            try { handle(body, process) } catch (interrupted: InterruptedException) {
                Thread.currentThread().interrupt(); throw interrupted
            } catch (_: Exception) {
                // A handler may have taken an effect before failing. Never classify it as
                // clean INVALID or permit another request; retain intent and fail closed.
                refused = true
                JsonNull
            }
        }
        val reply = QualificationControlReplyBody(suiteId = scope.suiteId, scopeSha256 = scopeHash,
            sequence = sequence, operation = body.operation, status = if (refused) "REFUSED" else "OK",
            payload = if (refused) null else result, errorCode = if (refused) "UNCERTAIN" else null)
        if (sequence != 1) QualificationOwnerRecords(root.resolve("requests"), owner).result(sequence,
            json.encodeToString(reply).encodeToByteArray())
        val serialized = json.encodeToString(QualificationControlReply(reply,
            mac(capability, "response", json.encodeToString(reply).encodeToByteArray()))).encodeToByteArray()
        sequence++
        send(channel, serialized, process)
        check(!refused) { "Qualification request refused; retain one-use intent" }
    }
}
