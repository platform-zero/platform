package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** Only after acknowledged owner-managed IMPORT, PREPARE and START. No healthy
 * container shortcut, duplicated source lane identity or inferred Pi response. */
@Serializable internal data class ManagedOriginalPiToolAttempt(val schemaVersion: Int = 1,
    val sourceGeneration: String, val sourceBundleSha256: String, val sourceLaneId: String,
    val sourcePiWindowId: String, val sessionFile: String, val uncertainHistorySha256: String,
    val uncertainToolCalls: List<String>, val nativeAttemptIntentSha256: String,
    val nativeAttemptResultSha256: String, val nativeAttemptVerified: Boolean,
    val resultAcknowledged: Boolean = false)
@Serializable internal data class ManagedRestoreStartupReceipt(val sourceGeneration: String,
    val targetGeneration: String, val sourceLaneId: String, val targetLaneId: String,
    val sourceCaptureSha256: String, val oracleSha256: String,
    val importIntentSha256: String, val importResultSha256: String,
    val startIntentSha256: String, val startResultSha256: String,
    val sourceManifestSha256: String, val targetManifestSha256: String,
    val sourcePiWindowId: String, val targetPiWindowId: String,
    val uncertainToolCalls: List<String>, val sourcePiOracleSha256: String,
    val originalAttemptSha256: String, val targetPiReadbackSha256: String)

internal object ManagedRestoreStartupReceiptProducer {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    /** C1 must pass independently completed INSTALL Pi oracle and original
     * tool-attempt result pins. Target Pi window is queried HERE via the native
     * selected Worklane owner, never supplied by a caller or from a title. */
    fun afterNativeStart(bundle: GenerationBundle, root: Path, sourcePiOracle: ActivationInput,
        originalAttempt: ActivationInput): ActivationInput {
        val target = bundle.request.id
        require(bundle.recoverySourceKopia != null && root == GenerationRuntime.BASE.resolve(target) &&
            bundle.request.managedLanes != null)
        val source = bundle.recoverySourceKopia.generation
        val sourceRoot = GenerationRuntime.BASE.resolve(source)
        val original = json.decodeFromString<GenerationBundle>(ReleasePrivateFiles.read(
            sourceRoot.resolve("bundle.json"), 4194304).decodeToString(throwOnInvalidSequence = true))
        require(source != target && original.request.id == source &&
            original.request.managedLanes != null && bundle.recoverySourceKopia.bundleSha256 ==
                ReleaseLocks.sha256(ReleasePrivateFiles.read(sourceRoot.resolve("bundle.json"), 4194304)))
        val sourcePlan = requireNotNull(original.request.managedLanes)
        val targetPlan = requireNotNull(bundle.request.managedLanes)
        val importIntentBytes = ReleasePrivateFiles.read(root.resolve("managed-import.intent.json"), 8192)
        val importIntent = json.decodeFromString<ManagedImportIntent>(importIntentBytes
            .decodeToString(throwOnInvalidSequence = true))
        val importBytes = ReleasePrivateFiles.read(root.resolve("managed-import.result.json"), 65536)
        val imported = json.decodeFromString<ManagedImportResult>(importBytes.decodeToString(throwOnInvalidSequence = true))
        val startIntentBytes = ReleasePrivateFiles.read(root.resolve("managed-start.intent.json"), 8192)
        val startIntent = json.decodeFromString<ManagedGenerationStartIntent>(startIntentBytes
            .decodeToString(throwOnInvalidSequence = true))
        val startBytes = ReleasePrivateFiles.read(root.resolve("managed-start.result.json"), 65536)
        val started = json.decodeFromString<ManagedGenerationStartResult>(startBytes
            .decodeToString(throwOnInvalidSequence = true))
        require(importIntent.sourceGeneration == source && importIntent.targetGeneration == target &&
            importIntent.sourceBundleSha256 == bundle.recoverySourceKopia.bundleSha256 &&
            importIntent.targetBundleSha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(
                root.resolve("bundle.json"), 4194304)) &&
            imported.intentSha256 == ReleaseLocks.sha256(importIntentBytes) &&
            imported.imports.keys == ManagedLaneKind.entries.toSet() &&
            imported.preparations.keys == ManagedLaneKind.entries.toSet() &&
            imported.imports.values.all { it.generation == target &&
                it.operation == ManagedLaneOperation.IMPORT && it.isolated } &&
            imported.preparations.values.all { it.generation == target &&
                it.operation == ManagedLaneOperation.PREPARE && it.isolated } &&
            startIntent.generation == target && startIntent.mode == "recovered-private" &&
            startIntent.importResultSha256 == ReleaseLocks.sha256(importBytes) &&
            started.generation == target && started.mode == "recovered-private" &&
            started.intentSha256 == ReleaseLocks.sha256(startIntentBytes) && !started.promotable &&
            started.bundleSha256 == importIntent.targetBundleSha256 &&
            started.lanes.keys == ManagedLaneKind.entries.toSet() &&
            started.lanes.values.all { it.generation == target &&
                it.operation == ManagedLaneOperation.START && !it.isolated }) {
            "Managed import/start missing a genuine isolated native ACK"
        }
        val sourceManifest = sourcePlan.native.manifest.sha256
        val targetManifest = targetPlan.native.manifest.sha256
        require(sourceManifest != targetManifest &&
            targetManifest == ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(
                targetPlan.native.manifest.path), 1048576)) &&
            sourceManifest == ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(
                sourcePlan.native.manifest.path), 1048576)) &&
            importIntent.oracleSha256.matches(Regex("[a-f0-9]{64}")))
        val sourceLane = sourcePlan.lanes.single { it.kind == ManagedLaneKind.WORKLANE }
        val targetLane = targetPlan.lanes.single { it.kind == ManagedLaneKind.WORKLANE }
        require(sourceLane.laneId != targetLane.laneId && sourcePlan.generation == source &&
            targetPlan.generation == target)
        val sourceOraclePath = Path.of(sourcePiOracle.path)
        val attemptPath = Path.of(originalAttempt.path)
        require(sourceOraclePath.isAbsolute && sourceOraclePath.normalize() == sourceOraclePath &&
            attemptPath.isAbsolute && attemptPath.normalize() == attemptPath &&
            sourceOraclePath.fileName.toString() == "oracle.json" &&
            attemptPath.fileName.toString() == "pi-original-tool-attempt.result.json" &&
            sourceOraclePath.parent == attemptPath.parent &&
            sourceOraclePath.toString().contains("/pi--workflow--headless--native/") &&
            !sourceOraclePath.startsWith(root) && !attemptPath.startsWith(root))
        val oracleBytes = ReleasePrivateFiles.read(sourceOraclePath, 65536)
        val attemptBytes = ReleasePrivateFiles.read(attemptPath, 8192)
        require(ReleaseLocks.sha256(oracleBytes) == sourcePiOracle.sha256 &&
            ReleaseLocks.sha256(attemptBytes) == originalAttempt.sha256)
        val oracle = json.parseToJsonElement(oracleBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val attempted = json.decodeFromString<ManagedOriginalPiToolAttempt>(attemptBytes
            .decodeToString(throwOnInvalidSequence = true))
        val uncertain = oracle.getValue("uncertainToolCalls").jsonArray.map { it.jsonPrimitive.content }
        val sourceWindow = oracle.getValue("hookWindowId").jsonPrimitive.content
        require(oracle.getValue("laneId").jsonPrimitive.content == sourceLane.laneId &&
            uncertain.isNotEmpty() && uncertain.size <= 16 && uncertain.toSet().size == uncertain.size &&
            uncertain.all { it.matches(Regex("[A-Za-z0-9_-]{1,128}")) } &&
            attempted.sourceGeneration == source && attempted.sourceBundleSha256 ==
                bundle.recoverySourceKopia.bundleSha256 && attempted.sourceLaneId == sourceLane.laneId &&
            attempted.sourcePiWindowId == sourceWindow && attempted.uncertainToolCalls == uncertain &&
            attempted.uncertainHistorySha256 == oracle.getValue("uncertainHistorySha256").jsonPrimitive.content &&
            attempted.sessionFile == oracle.getValue("uncertainSessionFile").jsonPrimitive.content &&
            attempted.schemaVersion == 1 &&
            attempted.nativeAttemptIntentSha256.matches(Regex("[a-f0-9]{64}")) &&
            attempted.nativeAttemptResultSha256.matches(Regex("[a-f0-9]{64}")) &&
            attempted.nativeAttemptVerified && !attempted.resultAcknowledged &&
            sourceWindow.isNotBlank()) {
            "Original Pi uncertain tool effect/session is not independently bound to completed INSTALL" }
        val targetReadback = ManagedLaneRuntime.real(root, targetPlan).piWindowReadback()
        val targetBytes = targetReadback.toString().toByteArray()
        val targetWindow = targetReadback.getValue("proof").jsonObject
            .getValue("window_id").jsonPrimitive.content
        require(targetWindow.isNotBlank() && targetWindow != sourceWindow &&
            targetReadback.getValue("lane_id").jsonPrimitive.content == targetLane.laneId)
        val nativeWindow = root.resolve("managed-restore-target-pi-window.observation.json")
        require(!Files.exists(nativeWindow, NOFOLLOW_LINKS))
        ReleasePrivateFiles.save(nativeWindow,targetBytes)
        val receipt = ManagedRestoreStartupReceipt(source,target,sourceLane.laneId,targetLane.laneId,
            importIntent.oracleSha256,importIntent.oracleSha256,ReleaseLocks.sha256(importIntentBytes),
            ReleaseLocks.sha256(importBytes),ReleaseLocks.sha256(startIntentBytes),
            ReleaseLocks.sha256(startBytes),sourceManifest,targetManifest,sourceWindow,targetWindow,
            uncertain,sourcePiOracle.sha256,originalAttempt.sha256,ReleaseLocks.sha256(targetBytes))
        val path = root.resolve("managed-restore-startup.receipt.json")
        require(!Files.exists(path, NOFOLLOW_LINKS)) { "Managed restore receipt already attempted; never replace" }
        val bytes = json.encodeToString(receipt).encodeToByteArray()
        ReleasePrivateFiles.save(path,bytes)
        return ActivationInput(path.toString(),ReleaseLocks.sha256(bytes))
    }
}
