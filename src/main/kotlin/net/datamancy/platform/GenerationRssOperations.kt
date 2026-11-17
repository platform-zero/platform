package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** One controller-wide exclusion BEFORE generation/member, reference-ledger and repository locks.
 * The same exclusion covers every RSS writer, including staging, reconciliation and qualification,
 * as well as backup/import/check/target isolation/source resume. No timeout or stale-lock deletion. */
internal class GenerationRssOperations(private val generationBase: Path = GenerationRuntime.BASE,
    private val scheduleFactory: (Path) -> RssSchedule = { RssSchedule.real(it) }) {
    private val lock: Path = generationBase.parent.resolve("rss-controller.lock")
    private val mode = PosixFilePermissions.fromString("rw-------")
    private companion object { val held = ThreadLocal.withInitial { mutableSetOf<Path>() } }
    private fun parent() {
        val path = lock.parent
        require(path.isAbsolute && path.normalize() == path && path.toRealPath() == path &&
            Files.isDirectory(path, NOFOLLOW_LINKS) &&
            (Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == UnixSystem().uid &&
            Files.getPosixFilePermissions(path, NOFOLLOW_LINKS).none {
                it.name.startsWith("GROUP_WRITE") || it.name.startsWith("OTHERS_WRITE")
            }) { "Unprotected RSS operation exclusion parent" }
    }
    fun <T> withExclusion(operation: () -> T): T {
        if (lock in held.get()) return operation() // Nested schedule scope on the same thread; never another process.
        parent()
        return JvmNativeLockGate.with(lock) {
            FileChannel.open(lock, setOf(CREATE, READ, WRITE, NOFOLLOW_LINKS), PosixFilePermissions.asFileAttribute(mode)).use { channel ->
                require(Files.getPosixFilePermissions(lock, NOFOLLOW_LINKS) == mode &&
                    (Files.getAttribute(lock, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == UnixSystem().uid &&
                    (Files.getAttribute(lock, "unix:nlink", NOFOLLOW_LINKS) as Number).toLong() == 1L) {
                    "Unsafe RSS operation exclusion"
                }
                channel.lock().use {
                    require(held.get().add(lock))
                    try { operation() } finally { held.get().remove(lock) }
                }
            }
        }
    }
    /** Called within withExclusion before qualification/staging/credential writers. A held restore
     * excludes unrelated writers between controller calls, even though its OS lock was released.
     * An un-enrolled fresh generation has no schedule marker and remains writable. */
    fun requireWritableGeneration(generationRoot: Path, continuationId: String? = null, claimSha256: String? = null,
        phaseClaimSha256: String? = null) {
        require(lock in held.get() && generationRoot.parent == generationBase &&
            generationRoot.fileName.toString().matches(Regex("q-[a-f0-9]{12}"))) {
            "Generation-bound RSS writer requires controller exclusion"
        }
        ReleasePrivateFiles.directory(generationRoot)
        RssQualificationIntents.requireClear(generationRoot, continuationId, claimSha256, phaseClaimSha256)
        val scheduleRoot = generationRoot.resolve("rss/schedule")
        if (Files.exists(scheduleRoot, NOFOLLOW_LINKS)) {
            ReleasePrivateFiles.directory(scheduleRoot)
            val bindingSha256 = ReleasePrivateFiles.read(scheduleRoot.resolve("enrolled")).decodeToString()
            require(bindingSha256.matches(Regex("[a-f0-9]{64}")))
            if (continuationId == null && phaseClaimSha256 == null)
                scheduleFactory(generationBase).requireWritable(scheduleRoot, bindingSha256)
            else {
                // Same controller exclusion is held; exact case continuation must not recursively
                // acquire its own schedule lock. Read-only binding verification is sufficient.
                scheduleFactory(generationBase).units(scheduleRoot, bindingSha256)
                RssMaintenance.requireClear(scheduleRoot, bindingSha256)
                require(!Files.exists(scheduleRoot.resolve("suspended"), NOFOLLOW_LINKS)) {
                    "Retired RSS schedule cannot qualify or write"
                }
            }
        } else {
            require(!Files.exists(generationRoot.resolve("rss-enrollment.intent.json"), NOFOLLOW_LINKS) &&
                !Files.exists(generationRoot.resolve("rss-enrollment.complete.json"), NOFOLLOW_LINKS)) {
                "Missing RSS scheduler after a generation enrollment attempt"
            }
        }
    }
    /** Enrolled generations must retain the schedule lock as well, through *typed durable* completion.
     * No exception, callback return or process exit can clear an unfinished maintenance intent. */
    fun <T> withEnrolledOperation(schedule: RssSchedule, scheduleRoot: Path, bindingSha256: String,
        operationId: String, proof: RssDurableOperationProof, operation: () -> T): T = withExclusion {
        schedule.quiesceProven(scheduleRoot, bindingSha256, operationId, proof, operation)
    }
}

@Serializable internal data class RssQualificationIntent(val schemaVersion: Int = 1, val generation: String,
    val bundleSha256: String, val serviceId: String, val invocationId: String, val phase: String,
    val caseDirectory: String, val caseIntentSha256: String, val contextSha256: String,
    val phaseClaimSha256: String)
@Serializable internal data class RssQualificationCompletion(val schemaVersion: Int = 1,
    val intentSha256: String, val adapterRequestSha256: String, val nativeResultSha256: String,
    val oracleSha256: String, val durableCaseResultSha256: String)
@Serializable internal data class RssQualificationBeginReceipt(val invocationId: String,
    val generationId: String, val serviceId: String, val bundleSha256: String,
    val intentSha256: String, val contextSha256: String, val claimSha256: String,
    val phaseClaimSha256: String)
@Serializable internal data class RssQualificationCaseCompletionReceipt(val invocationId: String,
    val claimSha256: String, val resultSha256: String)
@Serializable internal data class RssQualificationPhaseRequest(val schemaVersion: Int = 1, val trialId: String,
    val generationId: String, val phase: String, val stagedOnly: Boolean, val bundleSha256: String,
    val inventorySha256: String, val manifestSha256: String, val intentSha256: String,
    val journalHead: String, val artifactRoot: String, val phaseIntentPath: String, val phaseResultPath: String)
@Serializable internal data class RssQualificationPhaseIntent(val schemaVersion: Int = 1,
    val request: RssQualificationPhaseRequest, val requestPath: String, val requestSha256: String)
@Serializable internal data class RssQualificationPhaseCompletion(val schemaVersion: Int = 1,
    val phaseClaimSha256: String, val resultSha256: String, val caseClaims: Map<String, String>)
@Serializable internal data class RssQualificationPhaseBeginReceipt(val trialId: String, val generationId: String,
    val phase: String, val stagedOnly: Boolean, val bundleSha256: String, val inventorySha256: String,
    val manifestSha256: String, val intentSha256: String, val phaseClaimSha256: String)
@Serializable internal data class RssQualificationPhaseFinishReceipt(val trialId: String, val generationId: String,
    val phase: String, val phaseClaimSha256: String, val resultSha256: String)

/** Durable whole-case RSS writer exclusion. A BEGIN must precede runner launch; only exact
 * content-addressed continuation may touch fixture state. Failed or interrupted cases remain
 * pending forever until an independent reconciliation (never a timeout or caller boolean).
 * The acceptance module is separate: its coordinator-supplied bridge invokes these typed
 * records via the rss qualification-* CLI, never imports platform internals directly. */
internal object RssQualificationIntents {
    private val json = Json { ignoreUnknownKeys = false; encodeDefaults = true }
    private val hash = Regex("[a-f0-9]{64}")
    private val invocation = Regex("case-[a-f0-9-]{36}")
    private val trial = Regex("[a-z][a-z0-9-]{0,63}")
    private val services = setOf("mastodon-rss-publisher", "rss-jobs", "rss-pack-analysis",
        "rss-pack-aus", "rss-pack-aus-state", "rss-pack-china", "rss-pack-china-state",
        "rss-pack-tas", "rss-pack-us", "rss-pack-us-state", "rss-pack-world")
    private fun root(generation: Path): Path = generation.resolve("rss/qualification-intents")
    private fun value(objectJson: kotlinx.serialization.json.JsonObject, name: String): String =
        requireNotNull(objectJson[name]) { "Missing qualification field $name" }.jsonPrimitive.content
    private fun case(generation: Path, directory: Path, phaseClaimSha256: String): Pair<RssQualificationIntent, ByteArray> {
        require(hash.matches(phaseClaimSha256))
        ReleasePrivateFiles.directory(generation)
        ReleasePrivateFiles.directory(directory)
        val bytes = ReleasePrivateFiles.read(directory.resolve("intent.json"), 1048576)
        val source = json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val binding = requireNotNull(source["binding"]).jsonObject
        val context = ReleasePrivateFiles.read(directory.resolve("context.json"), 4194304)
        val contextObject = json.parseToJsonElement(context.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val id = value(source, "invocationId")
        val generationId = value(binding, "generationId")
        val bundle = value(contextObject, "bundleSha256")
        require(invocation.matches(id) && generation.fileName.toString() == generationId &&
            hash.matches(bundle) && value(source, "serviceId") in services &&
            value(source, "surface") == "HEADLESS" && value(source, "variant") == "NATIVE" &&
            value(binding, "phase") in setOf("INSTALL", "RESTORE") &&
            value(source, "contextSha256") == ReleaseLocks.sha256(context) &&
            directory.fileName.toString() == "${value(source, "serviceId")}--${value(source, "journey")}--headless--native" &&
            directory.isAbsolute && directory.normalize() == directory) { "Foreign RSS qualification case" }
        val bundleBytes = ReleasePrivateFiles.read(generation.resolve("bundle.json"), 4194304)
        val decoded = json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString(throwOnInvalidSequence = true))
        require(ReleaseLocks.sha256(bundleBytes) == bundle && decoded.request.id == generationId &&
            RssControllerPayloads.authorized(decoded, generationId, generation) &&
            Files.exists(generation.resolve("rss/state"), NOFOLLOW_LINKS)) { "Unbound RSS generation for native qualification" }
        return RssQualificationIntent(generation = generationId, bundleSha256 = bundle,
            serviceId = value(source, "serviceId"), invocationId = id, phase = value(binding, "phase"),
            caseDirectory = directory.toString(), caseIntentSha256 = ReleaseLocks.sha256(bytes),
            contextSha256 = ReleaseLocks.sha256(context), phaseClaimSha256 = phaseClaimSha256) to bytes
    }
    private fun phaseStem(request: RssQualificationPhaseRequest): String =
        "${if (request.stagedOnly) "staged" else "phase"}-${request.trialId}-${request.phase.lowercase()}"
    private fun phasePaths(generation: Path, requestPath: Path): Pair<RssQualificationPhaseRequest, ByteArray> {
        ReleasePrivateFiles.directory(generation)
        val bytes = ReleasePrivateFiles.read(requestPath, 16384)
        val request = json.decodeFromString<RssQualificationPhaseRequest>(bytes.decodeToString(throwOnInvalidSequence = true))
        require(request.schemaVersion == 1 && trial.matches(request.trialId) &&
            request.generationId == generation.fileName.toString() && request.phase in setOf("INSTALL", "RESTORE") &&
            listOf(request.bundleSha256, request.inventorySha256, request.manifestSha256,
                request.intentSha256, request.journalHead).all(hash::matches) &&
            requestPath.isAbsolute && requestPath.normalize() == requestPath) {
            "Foreign RSS qualification phase request"
        }
        val root = Path.of(request.artifactRoot)
        val intent = Path.of(request.phaseIntentPath)
        val result = Path.of(request.phaseResultPath)
        require(root.isAbsolute && root.normalize() == root &&
            intent.isAbsolute && intent.normalize() == intent && result.isAbsolute && result.normalize() == result &&
            intent.parent == result.parent &&
            intent.fileName.toString() == phaseStem(request) + ".intent.json" &&
            result.fileName.toString() == phaseStem(request) + ".result.json") {
            "Unbound RSS phase journal slots"
        }
        ReleasePrivateFiles.directory(root.parent)
        ReleasePrivateFiles.directory(intent.parent)
        val source = ReleasePrivateFiles.read(generation.resolve("bundle.json"), 4194304)
        val bundle = json.decodeFromString<GenerationBundle>(source.decodeToString(throwOnInvalidSequence = true))
        require(ReleaseLocks.sha256(source) == request.bundleSha256 && bundle.request.id == request.generationId &&
            RssControllerPayloads.authorized(bundle, request.generationId, generation) &&
            Files.exists(generation.resolve("rss/state"), NOFOLLOW_LINKS)) {
            "Unbound RSS original generation for whole-phase qualification"
        }
        return request to bytes
    }
    private fun phaseName(request: RssQualificationPhaseRequest): String = phaseStem(request) + ".intent.json"
    private fun verifyArtifacts(directory: Path, native: ByteArray) {
        val nativeJson = json.parseToJsonElement(native.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val artifacts = requireNotNull(nativeJson["artifacts"]).jsonObject
        require(artifacts.size in 1..64 && "oracle.json" in artifacts) { "Missing native RSS artifact closure" }
        var total = 0L
        val reserved = setOf("intent.json", "result.json", "native-result.json", "runner.log",
            "context.json", "adapter-request.json", "adapter-result.json")
        for ((relative, expected) in artifacts) {
            val part = Path.of(relative)
            val path = directory.resolve(part).normalize()
            require(relative.isNotBlank() && !part.isAbsolute && part.normalize() == part &&
                path.startsWith(directory) && path != directory && relative !in reserved &&
                hash.matches(expected.jsonPrimitive.content)) { "Foreign RSS native artifact" }
            val bytes = ReleasePrivateFiles.read(path, 64 * 1024 * 1024)
            total += bytes.size
            require(total <= 256L * 1024 * 1024 && ReleaseLocks.sha256(bytes) == expected.jsonPrimitive.content) {
                "Changed original RSS native artifact"
            }
        }
    }
    private fun intents(generation: Path): List<Pair<Path, RssQualificationIntent>> {
        val directory = root(generation)
        if (!Files.exists(directory, NOFOLLOW_LINKS)) return emptyList()
        ReleasePrivateFiles.directory(directory)
        val entries = Files.list(directory).use { it.limit(129).toList() }
        require(entries.size <= 128 && entries.all { it.fileName.toString().matches(Regex("(case-[a-f0-9-]{36}|(phase|staged)-[a-z][a-z0-9-]{0,63}-(install|restore))\\.(intent|complete)\\.json")) }) {
            "Unbounded or foreign RSS qualification history"
        }
        val intentIds = entries.filter { it.fileName.toString().endsWith(".intent.json") }
            .map { it.fileName.toString().removeSuffix(".intent.json") }.toSet()
        require(entries.filter { it.fileName.toString().endsWith(".complete.json") }
            .all { it.fileName.toString().removeSuffix(".complete.json") in intentIds }) {
            "Orphan RSS qualification completion"
        }
        return entries.filter { it.fileName.toString().startsWith("case-") &&
            it.fileName.toString().endsWith(".intent.json") }.map { path ->
            path to json.decodeFromString<RssQualificationIntent>(ReleasePrivateFiles.read(path, 8192)
                .decodeToString(throwOnInvalidSequence = true))
        }
    }
    private fun requireCaseClear(generation: Path, continuationId: String? = null,
        claimSha256: String? = null, phaseClaimSha256: String? = null) {
        require((continuationId == null) == (claimSha256 == null))
        val pending = intents(generation).filter { (path, claim) ->
            require(claim.schemaVersion == 1 && claim.generation == generation.fileName.toString() &&
                claim.invocationId + ".intent.json" == path.fileName.toString()) { "Foreign RSS qualification intent" }
            val complete = path.resolveSibling(claim.invocationId + ".complete.json")
            if (!Files.exists(complete, NOFOLLOW_LINKS)) true else {
                val done = json.decodeFromString<RssQualificationCompletion>(ReleasePrivateFiles.read(complete, 8192)
                    .decodeToString(throwOnInvalidSequence = true))
                require(done.schemaVersion == 1 && done.intentSha256 ==
                    ReleaseLocks.sha256(ReleasePrivateFiles.read(path, 8192)) &&
                    listOf(done.adapterRequestSha256, done.nativeResultSha256, done.oracleSha256,
                        done.durableCaseResultSha256).all(hash::matches)) { "Changed RSS qualification history" }
                val original = Path.of(claim.caseDirectory)
                val native = ReleasePrivateFiles.read(original.resolve("native-result.json"), 1048576)
                require(case(generation, original, claim.phaseClaimSha256).first == claim &&
                    ReleaseLocks.sha256(ReleasePrivateFiles.read(original.resolve("adapter-request.json"), 4194304)) ==
                        done.adapterRequestSha256 && ReleaseLocks.sha256(native) == done.nativeResultSha256 &&
                    ReleaseLocks.sha256(ReleasePrivateFiles.read(original.resolve("oracle.json"), 4194304)) ==
                        done.oracleSha256 &&
                    ReleaseLocks.sha256(ReleasePrivateFiles.read(original.resolve("result.json"), 1048576)) ==
                        done.durableCaseResultSha256) { "Native RSS qualification proof changed after completion" }
                verifyArtifacts(original, native)
                false
            }
        }
        require(pending.isEmpty() || pending.size == 1 && continuationId == pending.single().second.invocationId &&
            claimSha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(pending.single().first, 8192)) &&
            phaseClaimSha256 == pending.single().second.phaseClaimSha256) {
            "Unreconciled RSS qualification forbids unrelated writer or replay"
        }
        if (pending.isEmpty()) require(continuationId == null) { "Completed qualification cannot continue" }
        else if (continuationId != null) require(case(generation, Path.of(pending.single().second.caseDirectory),
            pending.single().second.phaseClaimSha256).first ==
            pending.single().second) { "Qualification continuation lost its original case/context binding" }
    }
    private fun phaseIntents(generation: Path): List<Pair<Path, RssQualificationPhaseIntent>> {
        intents(generation) // Verify the bounded exact combined case/phase filename set first.
        val directory = root(generation)
        if (!Files.exists(directory, NOFOLLOW_LINKS)) return emptyList()
        return Files.list(directory).use { entries -> entries.limit(129).toList() }
            .filter { it.fileName.toString().matches(Regex("(phase|staged)-[a-z][a-z0-9-]{0,63}-(install|restore)\\.intent\\.json")) }
            .map { path -> path to json.decodeFromString<RssQualificationPhaseIntent>(
                ReleasePrivateFiles.read(path, 16384).decodeToString(throwOnInvalidSequence = true)) }
    }
    /** The phase request is written from pure already-admitted inputs before ANY journal lock.
     * A failed journal admission leaves this claim pending and cannot silently retry. */
    fun beginPhase(generation: Path, requestPath: Path): RssQualificationPhaseBeginReceipt {
        val (request, bytes) = phasePaths(generation, requestPath)
        requireClear(generation)
        val directory = root(generation)
        ReleasePrivateFiles.directory(directory.parent)
        if (!Files.exists(directory, NOFOLLOW_LINKS)) Files.createDirectory(directory,
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))).also {
            ReleasePrivateFiles.sync(directory.parent)
        }
        val claim = RssQualificationPhaseIntent(request = request, requestPath = requestPath.toString(),
            requestSha256 = ReleaseLocks.sha256(bytes))
        val claimBytes = json.encodeToString(claim).encodeToByteArray()
        ReleasePrivateFiles.save(directory.resolve(phaseName(request)), claimBytes)
        return RssQualificationPhaseBeginReceipt(request.trialId, request.generationId, request.phase,
            request.stagedOnly, request.bundleSha256, request.inventorySha256, request.manifestSha256,
            request.intentSha256, ReleaseLocks.sha256(claimBytes))
    }
    /** Recheck original source+phase+case proofs whenever any RSS writer seeks admission. */
    fun requireClear(generation: Path, continuationId: String? = null, claimSha256: String? = null,
        phaseClaimSha256: String? = null) {
        requireCaseClear(generation, continuationId, claimSha256, phaseClaimSha256)
        val pending = phaseIntents(generation).filter { (path, phase) ->
            require(phase.schemaVersion == 1 && path.fileName.toString() == phaseName(phase.request) &&
                phase.request.generationId == generation.fileName.toString() &&
                phase.requestSha256.matches(hash)) { "Foreign RSS qualification phase intent" }
            val requestPath = Path.of(phase.requestPath)
            val (request, bytes) = phasePaths(generation, requestPath)
            require(request == phase.request && ReleaseLocks.sha256(bytes) == phase.requestSha256) {
                "Changed RSS whole-phase request"
            }
            val completePath = path.resolveSibling(phaseStem(request) + ".complete.json")
            if (!Files.exists(completePath, NOFOLLOW_LINKS)) true else {
                val done = json.decodeFromString<RssQualificationPhaseCompletion>(
                    ReleasePrivateFiles.read(completePath, 16384).decodeToString(throwOnInvalidSequence = true))
                val phaseSha = ReleaseLocks.sha256(ReleasePrivateFiles.read(path, 16384))
                val result = ReleasePrivateFiles.read(Path.of(request.phaseResultPath), 1048576)
                require(done.schemaVersion == 1 && done.phaseClaimSha256 == phaseSha &&
                    done.resultSha256 == ReleaseLocks.sha256(result) && done.caseClaims.keys == services &&
                    done.caseClaims.values.all(hash::matches) &&
                    ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(request.phaseIntentPath), 1048576)) ==
                        request.intentSha256) { "Changed RSS whole-phase result or journal intent" }
                val cases = intents(generation).filter { it.second.phaseClaimSha256 == phaseSha }
                require(cases.size == services.size && cases.associate { (casePath, caseClaim) ->
                    caseClaim.serviceId to ReleaseLocks.sha256(ReleasePrivateFiles.read(casePath, 8192))
                } == done.caseClaims) { "Changed original RSS per-case phase closure" }
                false
            }
        }
        require(pending.isEmpty() || pending.size == 1 && phaseClaimSha256 ==
            ReleaseLocks.sha256(ReleasePrivateFiles.read(pending.single().first, 16384))) {
            "Unreconciled whole-phase RSS qualification excludes unrelated writers"
        }
        if (pending.isEmpty()) require(phaseClaimSha256 == null) { "Completed RSS phase cannot continue" }
        else if (phaseClaimSha256 != null) {
            val request = pending.single().second.request
            // Case commands may start ONLY after exact journal admission; a phase claim alone
            // never authorizes an effect before its original phase intent is durably present.
            require(ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(request.phaseIntentPath), 1048576)) ==
                request.intentSha256) { "RSS phase journal admission not durable" }
            if (continuationId != null) {
                val caseClaim = intents(generation).single { it.second.invocationId == continuationId }.second
                require(caseClaim.phaseClaimSha256 == phaseClaimSha256 &&
                    caseClaim.generation == request.generationId && caseClaim.phase == request.phase &&
                    Path.of(caseClaim.caseDirectory).parent == Path.of(request.artifactRoot)) {
                    "Case continuation escaped whole RSS phase"
                }
            }
        }
    }
    internal fun matchesNativePhase(request: RssQualificationPhaseRequest, trialId: String,
        phase: String, artifactRoot: Path, phaseIntent: ActivationInput): Boolean =
        request.trialId == trialId && request.phase == phase &&
            Path.of(request.artifactRoot) == artifactRoot && request.phaseIntentPath == phaseIntent.path &&
            request.intentSha256 == phaseIntent.sha256

    /** Same-thread controller continuation for a non-RSS native case in the active RSS phase.
     * Reopens the durable phase request and admitted journal intent; a caller-supplied digest
     * alone cannot suppress the whole-phase exclusion. */
    fun requireNativePhase(generation: Path, phaseClaimSha256: String, trialId: String,
        phase: String, artifactRoot: Path, phaseIntent: ActivationInput) {
        require(hash.matches(phaseClaimSha256))
        val matches = phaseIntents(generation).filter { (path, _) ->
            ReleaseLocks.sha256(ReleasePrivateFiles.read(path, 16384)) == phaseClaimSha256
        }
        require(matches.size == 1)
        val record = matches.single().second
        val (request, bytes) = phasePaths(generation, Path.of(record.requestPath))
        require(request == record.request && ReleaseLocks.sha256(bytes) == record.requestSha256 &&
            matchesNativePhase(request, trialId, phase, artifactRoot, phaseIntent) &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(phaseIntent.path), 1048576)) == phaseIntent.sha256)
        requireClear(generation, phaseClaimSha256 = phaseClaimSha256)
    }
    private fun phaseForCase(generation: Path, phaseClaimSha256: String, claim: RssQualificationIntent): RssQualificationPhaseRequest {
        val matches = phaseIntents(generation).filter { (path, _) ->
            ReleaseLocks.sha256(ReleasePrivateFiles.read(path, 16384)) == phaseClaimSha256
        }
        require(matches.size == 1) { "Exact pending RSS phase claim required" }
        val phase = matches.single().second.request
        val source = json.parseToJsonElement(ReleasePrivateFiles.read(Path.of(claim.caseDirectory).resolve("intent.json"), 1048576)
            .decodeToString(throwOnInvalidSequence = true)).jsonObject
        val binding = requireNotNull(source["binding"]).jsonObject
        require(phase.generationId == claim.generation && phase.bundleSha256 == claim.bundleSha256 &&
            phase.phase == claim.phase && value(binding, "trialId") == phase.trialId &&
            Path.of(claim.caseDirectory).parent == Path.of(phase.artifactRoot)) {
            "RSS case is not inside its sealed whole-phase envelope"
        }
        return phase
    }
    fun completePhase(generation: Path, requestPath: Path, phaseClaimSha256: String,
        expectedResultSha256: String): RssQualificationPhaseFinishReceipt {
        val (request, bytes) = phasePaths(generation, requestPath)
        require(hash.matches(phaseClaimSha256) && hash.matches(expectedResultSha256))
        val claimPath = root(generation).resolve(phaseName(request))
        val claimBytes = ReleasePrivateFiles.read(claimPath, 16384)
        require(ReleaseLocks.sha256(claimBytes) == phaseClaimSha256 &&
            json.decodeFromString<RssQualificationPhaseIntent>(claimBytes.decodeToString(throwOnInvalidSequence = true)) ==
                RssQualificationPhaseIntent(request = request, requestPath = requestPath.toString(),
                    requestSha256 = ReleaseLocks.sha256(bytes))) { "Foreign whole-phase completion claim" }
        requireClear(generation, phaseClaimSha256 = phaseClaimSha256)
        val phaseIntent = ReleasePrivateFiles.read(Path.of(request.phaseIntentPath), 1048576)
        val phaseResult = ReleasePrivateFiles.read(Path.of(request.phaseResultPath), 1048576)
        val intentObject = json.parseToJsonElement(phaseIntent.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val resultObject = json.parseToJsonElement(phaseResult.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val binding = requireNotNull(intentObject["binding"]).jsonObject
        require(ReleaseLocks.sha256(phaseIntent) == request.intentSha256 &&
            value(binding, "trialId") == request.trialId && value(binding, "generationId") == request.generationId &&
            value(binding, "phase") == request.phase && value(intentObject, "artifactRoot") == request.artifactRoot &&
            value(intentObject, "journalHead") == request.journalHead &&
            (intentObject["stagedOnly"]?.jsonPrimitive?.content ?: "false") == request.stagedOnly.toString() &&
            requireNotNull(resultObject["invocation"]).jsonObject == intentObject &&
            value(resultObject, "passed") == "true" && value(resultObject, "failureType") == "null" &&
            value(resultObject, "cases").toInt() >= services.size &&
            hash.matches(value(resultObject, "resultsSha256")) &&
            ReleaseLocks.sha256(phaseResult) == expectedResultSha256) { "Missing durable successful whole-phase result" }
        val cases = intents(generation).filter { it.second.phaseClaimSha256 == phaseClaimSha256 }
        require(cases.size == services.size && cases.map { it.second.serviceId }.toSet() == services && cases.all {
            (casePath, caseClaim) -> Files.exists(casePath.resolveSibling(caseClaim.invocationId + ".complete.json"), NOFOLLOW_LINKS) &&
                caseClaim.phase == request.phase && caseClaim.generation == request.generationId &&
                Path.of(caseClaim.caseDirectory).parent == Path.of(request.artifactRoot)
        }) { "Whole RSS phase lacks eleven original completed native case results" }
        val completion = RssQualificationPhaseCompletion(phaseClaimSha256 = phaseClaimSha256,
            resultSha256 = expectedResultSha256, caseClaims = cases.associate { (path, caseClaim) ->
                caseClaim.serviceId to ReleaseLocks.sha256(ReleasePrivateFiles.read(path, 8192))
            })
        ReleasePrivateFiles.save(claimPath.resolveSibling(phaseStem(request) + ".complete.json"),
            json.encodeToString(completion).encodeToByteArray())
        return RssQualificationPhaseFinishReceipt(request.trialId, request.generationId, request.phase,
            phaseClaimSha256, expectedResultSha256)
    }
    /** Exact case-owned fixture slot, NOT a guess based on a random case UUID. The two
     * actual synthetic bot accounts/tokens are preprovisioned under explicit context fixtureId. */
    fun requireFixtureBinding(generation: Path, caseId: String, fixtureId: String, effectful: Boolean) {
        require(fixtureId.matches(Regex("(?:case-[a-f0-9-]{36}|rssq-[a-f0-9]{12})")))
        val claim = intents(generation).single { it.second.invocationId == caseId }.second
        val context = json.parseToJsonElement(ReleasePrivateFiles.read(
            Path.of(claim.caseDirectory).resolve("context.json"), 4194304)
            .decodeToString(throwOnInvalidSequence = true)).jsonObject
        val selected = context["fixtureId"]?.jsonPrimitive?.content
        if (claim.serviceId in setOf("mastodon-rss-publisher", "rss-jobs"))
            require(selected?.matches(Regex("rssq-[a-f0-9]{12}")) == true && fixtureId == selected) {
                "Canonical synthetic bot fixture slot differs from its predeclared case context"
            }
        else if (effectful || claim.phase == "INSTALL") require(fixtureId == caseId && selected == null) {
            "Read-only pack fixture cannot select another case's credential or feed"
        }
        if (effectful) require(claim.phase == "INSTALL") { "Restored fixture cannot publish or enroll a timer" }
    }
    fun begin(generation: Path, caseDirectory: Path, phaseClaimSha256: String): RssQualificationBeginReceipt {
        val (claim, _) = case(generation, caseDirectory, phaseClaimSha256)
        requireClear(generation, phaseClaimSha256 = phaseClaimSha256)
        phaseForCase(generation, phaseClaimSha256, claim)
        val directory = root(generation)
        ReleasePrivateFiles.directory(directory.parent)
        if (!Files.exists(directory, NOFOLLOW_LINKS)) Files.createDirectory(directory,
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))).also {
            ReleasePrivateFiles.sync(directory.parent)
        }
        ReleasePrivateFiles.directory(directory)
        val bytes = json.encodeToString(claim).encodeToByteArray()
        ReleasePrivateFiles.save(directory.resolve(claim.invocationId + ".intent.json"), bytes)
        return RssQualificationBeginReceipt(claim.invocationId, claim.generation, claim.serviceId,
            claim.bundleSha256, claim.caseIntentSha256, claim.contextSha256, ReleaseLocks.sha256(bytes),
            phaseClaimSha256)
    }
    fun complete(generation: Path, caseDirectory: Path, expectedClaimSha256: String,
        expectedCaseResultSha256: String, phaseClaimSha256: String): RssQualificationCaseCompletionReceipt {
        val (claim, sourceIntent) = case(generation, caseDirectory, phaseClaimSha256)
        require(hash.matches(expectedClaimSha256) && hash.matches(expectedCaseResultSha256))
        val directory = root(generation)
        val intentBytes = ReleasePrivateFiles.read(directory.resolve(claim.invocationId + ".intent.json"), 8192)
        require(ReleaseLocks.sha256(intentBytes) == expectedClaimSha256 &&
            json.decodeFromString<RssQualificationIntent>(intentBytes.decodeToString(throwOnInvalidSequence = true)) == claim &&
            ReleaseLocks.sha256(sourceIntent) == claim.caseIntentSha256) { "Changed RSS qualification begin evidence" }
        requireClear(generation, claim.invocationId, expectedClaimSha256, phaseClaimSha256)
        phaseForCase(generation, phaseClaimSha256, claim)
        val adapter = ReleasePrivateFiles.read(caseDirectory.resolve("adapter-request.json"), 4194304)
        val adapterJson = json.parseToJsonElement(adapter.decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(requireNotNull(adapterJson["invocation"]).jsonObject ==
            json.parseToJsonElement(sourceIntent.decodeToString(throwOnInvalidSequence = true)).jsonObject) {
            "Foreign RSS adapter request"
        }
        val native = ReleasePrivateFiles.read(caseDirectory.resolve("native-result.json"), 1048576)
        verifyArtifacts(caseDirectory, native)
        val oracle = ReleasePrivateFiles.read(caseDirectory.resolve("oracle.json"), 4194304)
        val result = ReleasePrivateFiles.read(caseDirectory.resolve("result.json"), 1048576)
        val resultJson = json.parseToJsonElement(result.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val nativeJson = json.parseToJsonElement(native.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val sourceJson = json.parseToJsonElement(sourceIntent.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val artifacts = requireNotNull(nativeJson["artifacts"]).jsonObject
        val assertions = requireNotNull(nativeJson["assertions"]).jsonObject
        val required = requireNotNull(sourceJson["requiredAssertions"]).jsonArray.map { it.jsonPrimitive.content }.toSet()
        require(value(nativeJson, "schemaVersion") == "2" && required.isNotEmpty() &&
            assertions.keys == required && assertions.values.all { it.jsonPrimitive.content == "true" } &&
            requireNotNull(resultJson["artifactHashes"]).jsonObject == artifacts &&
            value(resultJson, "failureType") == "null" &&
            value(resultJson, "passed") == "true" && value(resultJson, "finished") == "true" &&
            value(resultJson, "exitCode") == "0" &&
            requireNotNull(resultJson["invocation"]).jsonObject ==
                json.parseToJsonElement(sourceIntent.decodeToString(throwOnInvalidSequence = true)).jsonObject &&
            value(nativeJson, "invocationId") == claim.invocationId &&
            value(nativeJson, "serviceId") == claim.serviceId &&
            value(nativeJson, "generationId") == claim.generation &&
            value(nativeJson, "phase") == claim.phase &&
            value(resultJson, "observationSha256") == ReleaseLocks.sha256(native) &&
            value(artifacts, "oracle.json") == ReleaseLocks.sha256(oracle) &&
            ReleaseLocks.sha256(result) == expectedCaseResultSha256) {
            "Missing original native result, oracle, or durable successful RSS case record"
        }
        val completion = RssQualificationCompletion(intentSha256 = expectedClaimSha256,
            adapterRequestSha256 = ReleaseLocks.sha256(adapter), nativeResultSha256 = ReleaseLocks.sha256(native),
            oracleSha256 = ReleaseLocks.sha256(oracle), durableCaseResultSha256 = ReleaseLocks.sha256(result))
        ReleasePrivateFiles.save(directory.resolve(claim.invocationId + ".complete.json"),
            json.encodeToString(completion).encodeToByteArray())
        return RssQualificationCaseCompletionReceipt(claim.invocationId,
            expectedClaimSha256, completion.durableCaseResultSha256)
    }
}

/** Bound to independently durable controller records, never a caller-provided success boolean.
 * The integration backend must verify an exact isolated target and source resume against live audit,
 * and validate the resulting records again before allowing the maintenance completion marker. */
internal data class RssHeldOperation(val root: String, val bindingSha256: String, val operationId: String,
    val intentSha256: String, val generation: String, val bundleSha256: String)

internal interface RssDurableOperationProof {
    fun verifyBefore()
    fun verifyAfter()
}

/** Owned update is NOT a recovery backup. The PREPARED request fixes original source, snapshot
 * ID, site and both inventories without guessing the future target bundle. The typed held claim
 * remains reversible until native rollback+source-resume OR a separately proved site commitment. */
internal class RssOwnedUpdateOperationProof(private val generations: Path, private val runtime: GenerationRuntime,
    private val transactionId: String, private val source: String, private val sourceBundle: String,
    private val snapshotId: String, private val target: String, private val targetBundle: String? = null
) : RssDurableOperationProof {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private val transactionRoot = generations.parent.resolve("release-transactions").resolve(transactionId)
    private val requestPath = transactionRoot.resolve("request.json")
    val operationId: String get() = "upd-${ReleaseLocks.sha256(ReleasePrivateFiles.read(requestPath, 1048576)).take(12)}"
    private fun request(): ReleaseTransactionRequest {
        require(generations == GenerationRuntime.BASE &&
            transactionId.matches(Regex("[a-z][a-z0-9-]{0,63}")) &&
            source.matches(Regex("q-[a-f0-9]{12}")) && target.matches(Regex("q-[a-f0-9]{12}")) && source != target &&
            snapshotId.matches(Regex("cap-[a-f0-9]{12}")) && sourceBundle.matches(Regex("[a-f0-9]{64}")))
        val original = json.decodeFromString<ReleaseTransactionRequest>(
            ReleasePrivateFiles.read(requestPath, 1048576).decodeToString(throwOnInvalidSequence = true))
        val prepared = requireNotNull(original.updatePreparation)
        require(original.transactionId == transactionId && original.deployment == null && original.publication == null &&
            original.snapshotId == snapshotId && original.previous?.id == source &&
            original.previous?.bundleSha256 == sourceBundle && prepared.intent.source == original.previous &&
            prepared.intent.targetGeneration == target)
        prepared.validate(requireNotNull(original.previous), target, generations)
        return original
    }
    fun bind(binding: RssScheduleBinding, operation: String, held: Boolean) {
        require(held && operation == operationId && binding.deployment.generationId == source &&
            binding.deployment.bundleSha256 == sourceBundle &&
            generations == Path.of(binding.stateDirectory).parent.parent.parent) {
            "Foreign RSS owned-update claim or original source bundle"
        }
        request()
    }
    private fun journal(): List<JournalRecord> = TransactionJournal.verify(transactionRoot.resolve("transaction.jsonl"))
    override fun verifyBefore() {
        val prepared = request()
        val records = journal()
        val update = requireNotNull(prepared.updatePreparation)
        val sealed = requireNotNull(records.first().update)
        require(records.first().phase == Phase.PREPARED && records.last().phase == Phase.PREPARED &&
            records.all { it.transactionId == transactionId && it.snapshotId == null && it.update == sealed &&
                it.deployment == null } &&
            sealed.sourceGeneration == source && sealed.sourceBundleSha256 == sourceBundle &&
            sealed.targetGeneration == target && sealed.candidateSha256 == update.intent.candidateSha256 &&
            sealed.sitePolicySha256 == update.intent.sitePolicySha256 &&
            sealed.intentSha256 == ReleaseLocks.sha256(json.encodeToString(update.intent).toByteArray())) {
            "RSS update hold requires the original PREPARED late-bound source and site"
        }
        RssKopiaOperationProof(generations, runtime, source, sourceBundle, snapshotId, heldRestore = true).verifyBefore()
    }
    override fun verifyAfter() {
        val prepared = request()
        val update = requireNotNull(prepared.updatePreparation)
        val actual = requireNotNull(targetBundle) { "Rollback needs actual imported candidate bundle after isolation" }
        require(actual.matches(Regex("[a-f0-9]{64}")) && journal().last().phase == Phase.RECOVERY_REQUIRED) {
            "RSS owned-update rollback cannot be conflated with committed site transfer"
        }
        val bytes = ReleasePrivateFiles.read(generations.resolve(target).resolve("bundle.json"), 4194304)
        require(ReleaseLocks.sha256(bytes) == actual)
        val candidate = json.decodeFromString<GenerationBundle>(bytes.decodeToString(throwOnInvalidSequence = true))
        OwnedReleaseUpdates.validate(candidate)
        val lineage = requireNotNull(candidate.ownedUpdate)
        require(lineage.intent == update.intent && lineage.snapshot.id == snapshotId &&
            lineage.snapshot.generation == source && lineage.snapshot.bundleSha256 == sourceBundle &&
            OwnedReleaseUpdates.original(lineage).request.id == source) {
            "Rollback target lacks actual original-data update lineage"
        }
        val staged = json.decodeFromString<GenerationOutcome>(ReleasePrivateFiles.read(
            generations.resolve(target).resolve("stage.result.json"), 1048576).decodeToString(throwOnInvalidSequence = true))
        require(staged.action == "restore-import" && staged.passed && staged.failureType == null && staged.bundleSha256 == actual)
        val migrationPath = generations.resolve(target).resolve("planka-migration/${update.migrationOperation}.result.json")
        if (Files.exists(migrationPath, NOFOLLOW_LINKS)) {
            val migration = json.decodeFromString<PlankaMigrationResult>(ReleasePrivateFiles.read(
                migrationPath, 1048576).decodeToString(throwOnInvalidSequence = true))
            require(migration.operation == update.migrationOperation &&
                migration.passed && migration.migrationRoleRetired && migration.failureType == null)
        }
        RssKopiaOperationProof(generations, runtime, source, sourceBundle, snapshotId,
            heldRestore = true, target = target, targetBundle = actual).verifyAfter()
    }
    fun verifyCommittedRetirement() {
        val prepared = request()
        val update = requireNotNull(prepared.updatePreparation)
        val actual = requireNotNull(targetBundle)
        require(actual.matches(Regex("[a-f0-9]{64}")))
        val last = journal().last()
        val deployment = requireNotNull(last.deployment)
        require(last.phase == Phase.COMMITTED && deployment.generationId == target &&
            deployment.bundleSha256 == actual &&
            deployment.sitePolicySha256 == update.intent.sitePolicySha256) {
            "Permanent original RSS retirement requires actual committed owned update"
        }
        val bytes = ReleasePrivateFiles.read(generations.resolve(target).resolve("bundle.json"), 4194304)
        require(ReleaseLocks.sha256(bytes) == actual)
        val candidate = json.decodeFromString<GenerationBundle>(bytes.decodeToString(throwOnInvalidSequence = true))
        OwnedReleaseUpdates.validate(candidate)
        val lineage = requireNotNull(candidate.ownedUpdate)
        require(lineage.intent == update.intent && lineage.snapshot.id == snapshotId &&
            OwnedReleaseUpdates.original(lineage).request.id == source)
        val site = requireNotNull(candidate.ownership)
        val consumed = generations.parent.resolve("release-activation-consumptions/$target.consumed.json")
        val selection = ActiveSiteRegistry.real(transactionRoot.resolve("transaction.jsonl"), site.contract.site,
            site.approvedHosts, ReleaseGeneration(source, sourceBundle), consumed)
            .requireCommitted(deployment, requireCompleted = true)
        require(selection.source == ReleaseGeneration(source, sourceBundle) &&
            selection.qualificationSnapshotId == journal().single { it.phase == Phase.ACCEPTED }.qualificationSnapshotId &&
            selection.deployment == deployment) { "Original site did not transfer to the actual qualified candidate" }
        val sourceHeld = json.decodeFromString<GenerationHeldCapture>(ReleasePrivateFiles.read(
            generations.resolve(source).resolve("backups/$snapshotId/held.json"), 1048576)
            .decodeToString(throwOnInvalidSequence = true))
        sourceHeld.validate()
        require(sourceHeld.snapshot == lineage.snapshot && sourceHeld.access.generation == source &&
            sourceHeld.access.bundleSha256 == sourceBundle)
        val sourceAudit = runtime.inspect(source, sourceBundle)
        require(sourceAudit.members.isNotEmpty() && sourceAudit.members.map { it.name }.toSet() == sourceHeld.fences.keys &&
            sourceAudit.members.all { member -> member.maintenanceId == sourceHeld.fences[member.name] &&
                member.statuses.isNotEmpty() && member.statuses.all { it.state == "exited" && it.exitCode in setOf(0, 143) } }) {
            "Original RSS source resumed after global owned site transfer"
        }
        val started = json.decodeFromString<GenerationOutcome>(ReleasePrivateFiles.read(
            generations.resolve(target).resolve("owned-start.result.json"), 1048576)
            .decodeToString(throwOnInvalidSequence = true))
        require(started.action == "owned-start" && started.passed && started.failureType == null &&
            started.bundleSha256 == actual)
        val candidateSchedule = generations.resolve(target).resolve("rss/schedule")
        val enrolled = ReleasePrivateFiles.read(candidateSchedule.resolve("enrolled"), 64).decodeToString()
        require(enrolled.matches(Regex("[a-f0-9]{64}")))
        RssSchedule.real().units(candidateSchedule, enrolled) // Re-read native candidate adoption, not a marker/boolean.
        val candidateAudit = runtime.inspect(target, actual)
        require(candidateAudit.members.isNotEmpty() && candidateAudit.members.all {
            it.existingResources > 0 && it.maintenanceId == null && it.statuses.isNotEmpty() &&
                it.statuses.all { status -> status.state == "running" }
        }) { "Committed candidate stopped or lost original principal adoption" }
    }
}

/** PREPARED owned update with no sealed target: this completion proof is distinct from
 * candidate isolation, a cold restore or a fake target bundle. It can ONLY finish the
 * original already-pending reversible held claim after A02's durable native no-target
 * census, original source resume and still-current site proof have all been read back. */
internal class RssEarlyUpdateRollbackProof(private val generations: Path, private val runtime: GenerationRuntime,
    private val transactionId: String, private val source: String, private val sourceBundle: String,
    private val snapshotId: String, private val target: String) : RssDurableOperationProof {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private val transaction = generations.parent.resolve("release-transactions").resolve(transactionId)
    private val requestPath = transaction.resolve("request.json")
    private var binding: RssScheduleBinding? = null
    val operationId: String get() = "upd-${ReleaseLocks.sha256(ReleasePrivateFiles.read(requestPath, 1048576)).take(12)}"
    fun bind(schedule: RssScheduleBinding, operation: String, held: Boolean) {
        require(held && operation == operationId && binding == null &&
            schedule.deployment.generationId == source && schedule.deployment.bundleSha256 == sourceBundle &&
            generations == GenerationRuntime.BASE &&
            generations == Path.of(schedule.stateDirectory).parent.parent.parent &&
            source.matches(Regex("q-[a-f0-9]{12}")) && target.matches(Regex("q-[a-f0-9]{12}")) &&
            source != target && snapshotId.matches(Regex("cap-[a-f0-9]{12}")) &&
            transactionId.matches(Regex("[a-z][a-z0-9-]{0,63}"))) {
            "Only an existing original RSS owned-update held claim can finish without a target"
        }
        binding = schedule
    }
    override fun verifyBefore(): Nothing = error("No-target rollback cannot start a new RSS source hold")
    private fun <T> pinned(input: ActivationInput, path: Path, decode: (ByteArray) -> T): T {
        require(Path.of(input.path) == path && input.sha256.matches(Regex("[a-f0-9]{64}")))
        val bytes = ReleasePrivateFiles.read(path, 4194304)
        require(ReleaseLocks.sha256(bytes) == input.sha256) { "No-target native evidence changed" }
        return decode(bytes)
    }
    override fun verifyAfter() {
        val schedule = requireNotNull(binding) { "No-target rollback has no original held RSS binding" }
        val request = json.decodeFromString<ReleaseTransactionRequest>(ReleasePrivateFiles.read(
            requestPath, 1048576).decodeToString(throwOnInvalidSequence = true))
        val preparation = requireNotNull(request.updatePreparation)
        require(request.transactionId == transactionId && request.snapshotId == snapshotId &&
            request.previous == ReleaseGeneration(source, sourceBundle) &&
            request.deployment == null && request.publication == null &&
            preparation.intent.source == request.previous && preparation.intent.targetGeneration == target)
        preparation.validate(ReleaseGeneration(source, sourceBundle), target, generations)
        val journal = TransactionJournal.verify(transaction.resolve("transaction.jsonl"))
        val update = requireNotNull(journal.first().update)
        require(journal.first().phase == Phase.PREPARED && journal.first().snapshotId == null &&
            journal.last().phase == Phase.RECOVERY_REQUIRED &&
            journal.none { it.phase in setOf(Phase.STAGED, Phase.CUTOVER_RESTRICTED, Phase.ACCEPTED,
                Phase.ACTIVATION_STARTED, Phase.COMMITTED) } &&
            journal.all { it.transactionId == transactionId && it.update == update && it.deployment == null } &&
            update.sourceGeneration == source && update.sourceBundleSha256 == sourceBundle &&
            update.targetGeneration == target && update.candidateSha256 == preparation.intent.candidateSha256 &&
            update.sitePolicySha256 == preparation.intent.sitePolicySha256 &&
            update.intentSha256 == ReleaseLocks.sha256(json.encodeToString(preparation.intent).toByteArray())) {
            "No-target RSS rollback needs the immutable PREPARED intent and pre-public RECOVERY_REQUIRED journal"
        }
        val sourceRoot = generations.resolve(source)
        val backupRoot = sourceRoot.resolve("backups/$snapshotId")
        val heldBytes = ReleasePrivateFiles.read(backupRoot.resolve("held.json"), 1048576)
        val held = json.decodeFromString<GenerationHeldCapture>(heldBytes.decodeToString(throwOnInvalidSequence = true))
        held.validate()
        require(held.access == RuntimeBackupAccess(source, snapshotId, sourceBundle) &&
            held.snapshot.id == snapshotId && held.snapshot.generation == source &&
            held.snapshot.bundleSha256 == sourceBundle)
        RecoveryReferences(sourceRoot.resolve("recovery-references")).requireBound("rollback", transactionId, held.snapshot)
        val sourceBytes = ReleasePrivateFiles.read(sourceRoot.resolve("bundle.json"), 4194304)
        require(ReleaseLocks.sha256(sourceBytes) == sourceBundle)
        val original = json.decodeFromString<GenerationBundle>(sourceBytes.decodeToString(throwOnInvalidSequence = true))
        SiteOwnerships.checkSealed(original)
        val owner = requireNotNull(original.ownership)
        require(original.request.id == source && original.request.rssPlan != null &&
            original.recoverySourceKopia == null && original.recoverySourceArchiveSha256 == null)
        val targetRoot = generations.resolve(target)
        require(!Files.exists(targetRoot.resolve("bundle.json"), NOFOLLOW_LINKS) &&
            !Files.exists(targetRoot.resolve("stage.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(targetRoot.resolve("stage.result.json"), NOFOLLOW_LINKS) &&
            !Files.exists(targetRoot.resolve("rss-enrollment.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(targetRoot.resolve("rss-enrollment.complete.json"), NOFOLLOW_LINKS) &&
            !Files.exists(targetRoot.resolve("rss/schedule"), NOFOLLOW_LINKS)) {
            "No-target update cannot hide an attempted import or enrolled candidate"
        }
        val bytes = ReleasePrivateFiles.read(backupRoot.resolve("no-target.rollback.result.json"), 1048576)
        val result = json.decodeFromString<OwnedUpdateNoTargetRollbackResult>(bytes.decodeToString(throwOnInvalidSequence = true))
        require(result.schemaVersion == 1 && result.transactionId == transactionId &&
            result.source == ReleaseGeneration(source, sourceBundle) && result.targetGeneration == target &&
            result.originalHeldSha256 == ReleaseLocks.sha256(heldBytes)) {
            "No independently durable original-source no-target native rollback result"
        }
        val absent = pinned(result.nativeAbsence, targetRoot.resolve("no-target.native.json")) {
            json.decodeFromString<NativeOwnedTargetAbsence>(it.decodeToString(throwOnInvalidSequence = true))
        }
        val liveAbsent = PrivateDeployment.observeAbsentOwnedTarget(original, sourceBundle, target)
        require(absent.schemaVersion == 1 && absent.source == result.source &&
            absent.targetGeneration == target && absent.targetMembers == liveAbsent.targetMembers &&
            absent.runtimeMemberDirectoriesEmpty && liveAbsent.runtimeMemberDirectoriesEmpty &&
            absent.podmanInventorySha256.keys == setOf("container", "network", "volume", "secret") &&
            absent.podmanInventorySha256.values.all { it.matches(Regex("[a-f0-9]{64}")) }) {
            "The candidate namespace has native target resources or no real absence census"
        }
        val audit = pinned(result.sourceResumeAudit, backupRoot.resolve("no-target.resume.audit.json")) {
            json.decodeFromString<GenerationInspection>(it.decodeToString(throwOnInvalidSequence = true))
        }
        val resumed = runtime.inspect(source, sourceBundle)
        fun running(inspection: GenerationInspection) = inspection.members.size == original.members.size &&
            inspection.members.zip(original.members).all { (member, pin) ->
                member.name == pin.member.name && member.fingerprint == pin.runtimeFingerprint &&
                member.maintenanceId == null && member.existingResources > 0 &&
                pin.spec.processes.all { process -> member.statuses.singleOrNull { it.id == process.id }?.let { status ->
                    if (process.oneShot) status.state in setOf("completed", "exited") && status.exitCode == 0
                    else status.state == "running"
                } == true }
            }
        require(audit.id == source && audit.bundleSha256 == sourceBundle &&
            audit.members.map { it.name }.toSet() == held.fences.keys && running(audit) &&
            resumed.id == source && resumed.bundleSha256 == sourceBundle &&
            resumed.members.map { it.name }.toSet() == held.fences.keys && running(resumed) &&
            audit.members.map { it.name to it.fingerprint }.toSet() ==
                resumed.members.map { it.name to it.fingerprint }.toSet()) {
            "A source callback cannot substitute for originally pinned actually running native members"
        }
        val resume = pinned(result.sourceResumeProof, backupRoot.resolve("no-target.resume.proof.json")) {
            json.decodeFromString<OwnedUpdateNoTargetSourceResumeProof>(it.decodeToString(throwOnInvalidSequence = true))
        }
        val outcomeBytes = ReleasePrivateFiles.read(backupRoot.resolve("no-target.resume.result.json"), 1048576)
        val outcome = json.decodeFromString<GenerationBackupOutcome>(outcomeBytes.decodeToString(throwOnInvalidSequence = true))
        require(resume.schemaVersion == 1 && resume.originalHeldSha256 == result.originalHeldSha256 &&
            resume.nativeAbsenceSha256 == result.nativeAbsence.sha256 &&
            resume.resumedMembers == held.fences.keys.sorted() &&
            resume.sourceAuditSha256 == result.sourceResumeAudit.sha256 &&
            resume.resumeResultSha256 == ReleaseLocks.sha256(outcomeBytes) &&
            outcome.access == held.access && outcome.snapshot == held.snapshot &&
            outcome.passed && outcome.sourceResumed && outcome.failureType == null) {
            "Source resume lacks exact original held/absent native completion proof"
        }
        val headPath = ActiveSiteRegistry.BASE.resolve(ReleaseLocks.sha256(owner.contract.site.toByteArray()))
            .resolve("head.json")
        val head = pinned(result.originalSiteHead, headPath) {
            json.decodeFromString<ActiveSiteHead>(it.decodeToString(throwOnInvalidSequence = true))
        }
        require(head.ordinal >= 0 && head.revisionSha256.matches(Regex("[a-f0-9]{64}")))
        if (head.ordinal == 0) ActiveSiteRegistry.real(transaction.resolve("transaction.jsonl"),
            owner.contract.site, owner.approvedHosts, ReleaseGeneration(source, sourceBundle),
            generations.parent.resolve("release-activation-consumptions/$source.consumed.json"))
            .requireOriginalBootstrap(ReleaseGeneration(source, sourceBundle),
                schedule.deployment.sitePolicySha256, owner.approvedHosts)
        else ActiveSiteRegistry.requireActive(schedule.deployment, Path.of(schedule.transactionJournal),
            owner.contract.site, owner.approvedHosts)
        require(ReleasePrivateFiles.read(backupRoot.resolve("no-target.rollback.result.json"), 1048576)
            .contentEquals(bytes)) { "No-target rollback evidence changed during RSS held completion" }
    }
}

/** Native generation result reader; exact source/capture, and (for held operations) exact target.
 * `inspect` observes real member maintenance and process statuses, not a caller's `passed` flag. */
internal class RssKopiaOperationProof(private val generations: Path, private val runtime: GenerationRuntime,
    private val source: String, private val sourceBundle: String, private val captureId: String,
    private val heldRestore: Boolean = false, private val target: String? = null,
    private val targetBundle: String? = null) : RssDurableOperationProof {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private val access = RuntimeBackupAccess(source, captureId, sourceBundle).also { it.validate() }
    private val root = generations.resolve(source).resolve("backups/$captureId")
    init {
        require((target == null) == (targetBundle == null) && (heldRestore || target == null) &&
            (target == null || target != source && target.matches(Regex("q-[a-f0-9]{12}")) &&
                targetBundle!!.matches(Regex("[a-f0-9]{64}"))))
    }
    fun bind(binding: RssScheduleBinding, operationId: String, held: Boolean) {
        require(binding.deployment.generationId == source && binding.deployment.bundleSha256 == sourceBundle &&
            generations == Path.of(binding.stateDirectory).parent.parent.parent &&
            operationId == captureId && heldRestore == held) { "Foreign RSS durable completion proof" }
    }
    private inline fun <reified T> record(path: Path): T = json.decodeFromString<T>(
        ReleasePrivateFiles.read(path, 1048576).decodeToString(throwOnInvalidSequence = true))
    override fun verifyBefore() {
        val audit = runtime.inspect(source, sourceBundle)
        require(audit.id == source && audit.bundleSha256 == sourceBundle && audit.members.isNotEmpty() &&
            audit.members.all { it.existingResources > 0 && it.maintenanceId == null &&
                it.statuses.any { status -> status.state == "running" } } &&
            !Files.exists(root.resolve("intent.json"), NOFOLLOW_LINKS)) { "Source is not freshly running for RSS maintenance" }
    }
    override fun verifyAfter() {
        require(!heldRestore || target != null && targetBundle != null) {
            "Held RSS completion requires actual recovered target and bundle after snapshot capture"
        }
        val intent: RuntimeBackupAccess = record(root.resolve("intent.json"))
        val result: GenerationBackupOutcome = record(root.resolve("result.json"))
        val verified: RuntimeBackupAccess = record(root.resolve("resume.verified.json"))
        val capture: KopiaCaptureOutcome = record(generations.resolve(source)
            .resolve("kopia-captures/$captureId/capture.result.json"))
        require(intent == access && verified == access && result.access == access && result.passed &&
            result.failureType == null && result.sourceResumed && result.snapshot != null &&
            result.snapshot.id == captureId && result.snapshot.generation == source &&
            result.snapshot.bundleSha256 == sourceBundle && capture.id == captureId &&
            capture.bundleSha256 == sourceBundle && capture.passed && capture.failureType == null &&
            capture.snapshot == result.snapshot) { "Incomplete RSS capture or source resume" }
        KopiaGenerationStore.validate(requireNotNull(result.snapshot))
        if (target != null) {
            val heldBytes = ReleasePrivateFiles.read(root.resolve("held.json"), 1048576)
            val held: GenerationHeldCapture = json.decodeFromString(heldBytes.decodeToString(throwOnInvalidSequence = true))
            held.validate()
            require(held.access == access && held.snapshot == result.snapshot &&
                ReleaseLocks.sha256(heldBytes) == held.sha256) { "Foreign held RSS snapshot" }
            val authority: HeldSourceResumeAuthority = record(root.resolve("resume.authority.json"))
            require(authority.heldSha256 == held.sha256 && authority.target == target &&
                authority.targetBundleSha256 == targetBundle && authority.targetFences.isNotEmpty()) {
                "RSS source resume is not bound to the isolated target"
            }
            val isolated = runtime.inspect(target, requireNotNull(targetBundle))
            require(isolated.id == target && isolated.bundleSha256 == targetBundle &&
                isolated.members.map { it.name }.toSet() == authority.targetFences.keys &&
                isolated.members.all { it.existingResources > 0 &&
                    it.maintenanceId == authority.targetFences[it.name] && it.statuses.isNotEmpty() &&
                    it.statuses.all { status -> status.state == "exited" && status.exitCode in setOf(0, 143) } }) {
                "Recovered RSS target is not natively isolated"
            }
        }
        val resumed = runtime.inspect(source, sourceBundle)
        require(resumed.id == source && resumed.bundleSha256 == sourceBundle && resumed.members.isNotEmpty() &&
            resumed.members.all { it.maintenanceId == null && it.statuses.any { status -> status.state == "running" } }) {
            "RSS source resume was not observed natively"
        }
    }
}
