package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** One particular failed q5962 preparation, not a general retry or an inferred original ACK.
 * Original failed files and adopted outputs remain immutable for the lifetime of the generation.
 */
@Serializable internal data class CiPreEffectDisposition(val schemaVersion: Int = 1,
    val generation: String, val originalAssemblySha256: String, val originalFailedResultSha256: String,
    val originalOwnershipSha256: String, val originalControllerSha256: String,
    val priorReadOnlyCensusSha256: String, val adoptedInputSha256: Map<String, String>,
    val originalPassed: Boolean = false, val nativeEffectAttempted: Boolean = false)

internal object GenerationCiPreEffectContinuation {
    const val GENERATION = "q-5962a9fda75b"
    const val ORIGINAL_CONTROLLER = "e74ab9eaac9a68cb8b4e3b8992922e4afa586296c90815273773a4eb4d6849fb"
    const val CENSUS_SHA256 = "c88f7cf804f23bb62a38395985b520087457e6a4f53695325a0f5c990caeb0f5"
    const val FILE = "assembly-ci-pre-effect.disposition.json"
    const val INTENT = "assembly-ci-pre-effect-v2.intent.json"
    const val RESULT = "assembly-ci-pre-effect-v2.result.json"
    const val OWNERSHIP = "ownership-ci-pre-effect-v2.intent.json"
    private val json = Json { ignoreUnknownKeys = false; encodeDefaults = true }
    private val observed = mapOf(
        "assembly.intent.json" to "1159b9f6ef2bfb0f95635eea87744ce35bd2b82052db4a9a339c4923d1b162ed",
        "assembly.result.json" to "e21867be8335440eafca20c98c0c41bd461462c19cbd1c1e5452959e051de1c2",
        "ownership.intent.json" to "4289b857fd99422f6c20ec0fe707ca3e0a832d6ece9a7d2330abe0f4c6a54a14",
        "managed/control/storage.conf" to "6c50337f8d0e10e6f630a48213ff4a199a2cd0850715f2b4440bf0fe7916f19e",
        "managed/inputs/broker.json" to "98b642be24850aca89c538f761b63f9e613c9c064b7873b984b648eea659b641",
        "managed/inputs/target-lane.toml" to "35512f7b2e0cd07cbf3a2d25a94697c3980f3dbeb553a03f29fdda0725cd9825",
        "rss/state/rss-state.json" to "0565c08040e384bd88bd84b584221c0c1178eef468d08d16e8f3f0a480b09af7",
        "rss/state/rss-state.lock" to "8274cd47ed64941977db40de295c4e674459c06f7393c6e05fcf0628832abbe5")
    private fun children(path: Path): Set<String> = Files.list(path).use { stream ->
        stream.map { it.fileName.toString() }.toList().toSet()
    }
    private fun bytes(root: Path, relative: String): ByteArray = ReleasePrivateFiles.read(root.resolve(relative), 4194304)
    internal fun verifyPreEffectFootprint(root: Path) {
        require(children(root) == setOf("assembly.intent.json", "assembly.result.json", "ownership.intent.json", "managed", "rss") &&
            children(root.resolve("managed")) == setOf("inputs", "control") &&
            children(root.resolve("managed/inputs")) == setOf("broker.json", "target-lane.toml") &&
            children(root.resolve("managed/control")) == setOf("storage.conf") &&
            children(root.resolve("rss")) == setOf("state", "tokens") &&
            children(root.resolve("rss/state")) == setOf("rss-state.json", "rss-state.lock") &&
            children(root.resolve("rss/tokens")).isEmpty()) { "Foreign or uncertain original preparation effect; no continuation" }
        observed.forEach { (path, sha) ->
            require(ReleaseLocks.sha256(bytes(root, path)) == sha) { "Original partial preparation bytes changed: $path" }
        }
        val old = json.decodeFromString<AssemblySummary>(bytes(root, "assembly.intent.json").decodeToString(throwOnInvalidSequence = true))
        val result = json.decodeFromString<AssemblyPreparationOutcome>(bytes(root, "assembly.result.json").decodeToString(throwOnInvalidSequence = true))
        require(old.request.id == GENERATION && old.request.quadletControllerSha256 == ORIGINAL_CONTROLLER &&
            old.request.releaseCandidateSha256 == ORIGINAL_CONTROLLER && result.assemblySha256 == observed.getValue("assembly.intent.json") &&
            !result.passed && result.bundleSha256 == null && result.failureType == "java.lang.IllegalArgumentException") {
            "Original preparation is not the independently observed pre-CI failure"
        }
    }
    fun original(root: Path): CiPreEffectDisposition {
        require(root == GenerationRuntime.BASE.resolve(GENERATION))
        verifyPreEffectFootprint(root)
        PinnedBackupController.verifyDistribution(Path.of("/mnt/media/p0-v3/runtime-supervision/releases/$ORIGINAL_CONTROLLER"),
            ORIGINAL_CONTROLLER, "p0-v3-platform")
        val result = json.decodeFromString<AssemblyPreparationOutcome>(bytes(root, "assembly.result.json").decodeToString(throwOnInvalidSequence = true))
        return CiPreEffectDisposition(generation = GENERATION, originalAssemblySha256 = result.assemblySha256,
            originalFailedResultSha256 = observed.getValue("assembly.result.json"),
            originalOwnershipSha256 = observed.getValue("ownership.intent.json"),
            originalControllerSha256 = ORIGINAL_CONTROLLER, priorReadOnlyCensusSha256 = CENSUS_SHA256,
            adoptedInputSha256 = observed.filterKeys { it.startsWith("managed/") || it.startsWith("rss/") })
    }
    fun verify(root: Path, pin: ActivationInput, beforeEffects: Boolean = false): CiPreEffectDisposition {
        require(root == GenerationRuntime.BASE.resolve(GENERATION) &&
            pin.path == root.resolve(FILE).toString()) { "Foreign preparation disposition" }
        val material = bytes(root, FILE)
        require(ReleaseLocks.sha256(material) == pin.sha256) { "Preparation disposition changed" }
        val disposition = json.decodeFromString<CiPreEffectDisposition>(material.decodeToString(throwOnInvalidSequence = true))
        require(disposition.schemaVersion == 1 && disposition.generation == GENERATION && !disposition.originalPassed &&
            !disposition.nativeEffectAttempted && disposition.originalAssemblySha256 == observed.getValue("assembly.intent.json") &&
            disposition.originalFailedResultSha256 == observed.getValue("assembly.result.json") &&
            disposition.originalOwnershipSha256 == observed.getValue("ownership.intent.json") &&
            disposition.originalControllerSha256 == ORIGINAL_CONTROLLER && disposition.priorReadOnlyCensusSha256 == CENSUS_SHA256 &&
            disposition.adoptedInputSha256 == observed.filterKeys { it.startsWith("managed/") || it.startsWith("rss/") } &&
            observed.filterKeys { it.startsWith("assembly.") || it.startsWith("ownership.") }.all { (name, sha) ->
                ReleaseLocks.sha256(bytes(root, name)) == sha
            }) { "Original failed intent/result or ownership was replaced" }
        if (beforeEffects) {
            require(children(root) == setOf("assembly.intent.json", "assembly.result.json", "ownership.intent.json", "managed", "rss", FILE) &&
                observed.all { (name, sha) -> ReleaseLocks.sha256(bytes(root, name)) == sha } &&
                children(root.resolve("rss/tokens")).isEmpty() &&
                !Files.exists(root.resolve(INTENT), NOFOLLOW_LINKS)) { "Uncertain or already attempted continuation; no replay" }
        }
        return disposition
    }
    fun binding(root: Path): ActivationInput = ActivationInput(root.resolve(FILE).toString(),
        ReleaseLocks.sha256(bytes(root, FILE)))
    fun unchangedInputs(root: Path, plan: ManagedLanePlan) {
        val source = Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/$GENERATION")
        for ((rel,sourceFile,pin) in listOf(
            Triple("managed/inputs/target-lane.toml", "source-target-lane.toml", plan.native.manifest),
            Triple("managed/control/storage.conf", "source-storage.conf", plan.native.storageConfig),
            Triple("managed/inputs/broker.json", "source-broker.json", requireNotNull(plan.native.broker).configuration))) {
            val existing = bytes(root,rel)
            require(ReleaseLocks.sha256(existing) == observed.getValue(rel) &&
                pin.path == root.resolve(rel).toString() && pin.sha256 == ReleaseLocks.sha256(existing) &&
                existing.contentEquals(ReleasePrivateFiles.read(source.resolve(sourceFile),1048576))) {
                "Existing immutable managed source differs; do not replay or rewrite"
            }
        }
        require(ReleaseLocks.sha256(bytes(root,"rss/state/rss-state.json")) == observed.getValue("rss/state/rss-state.json") &&
            ReleaseLocks.sha256(bytes(root,"rss/state/rss-state.lock")) == observed.getValue("rss/state/rss-state.lock") &&
            children(root.resolve("rss/tokens")).isEmpty()) { "Original RSS initial state changed" }
    }
}
