package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.int

@Serializable internal data class QuadletInitializerIntent(val schemaVersion: Int = 1, val member: String,
    val process: String, val specSha256: String, val inputFingerprint: String, val imageId: String)
@Serializable internal data class QuadletInitializerResult(val schemaVersion: Int = 1, val intentSha256: String,
    val containerId: String, val observedImageId: String, val observedFingerprint: String,
    val exitCode: Int, val stopped: Boolean)

/** Controller-owned original intent/result seam for Quadlet one-shots. It does not execute
 * StartUnit. The caller must hold generation/member locks across this read and its StartUnit;
 * nativeComplete reads the retained Podman container directly instead of trusting a caller
 * supplied CID or exit status. Missing result remains uncertainty, never a new attempt.
 */
internal class RuntimeQuadletInitializer(private val root: Path, private val spec: PrivateDeploymentSpec,
    private val fingerprint: String, private val runtimeBase: Path = PrivateDeployment.BASE) {
    private val json = Json { encodeDefaults = true }
    private val sha = Regex("[a-f0-9]{64}")
    init {
        PrivateDeployment.validate(spec)
        require(spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2 && sha.matches(fingerprint))
        ReleasePrivateFiles.directory(root)
    }
    private fun process(id: String) = spec.processes.single { it.id == id && it.oneShot }
    private fun paths(id: String): Pair<Path, Path> {
        val p = process(id)
        require(p.id.matches(Regex("[a-z][a-z0-9-]{0,39}")))
        return root.resolve("quadlet-${p.id}.intent.json") to root.resolve("quadlet-${p.id}.result.json")
    }
    private fun expected(id: String): QuadletInitializerIntent {
        val p = process(id)
        return QuadletInitializerIntent(member = spec.name, process = p.id,
            specSha256 = ReleaseLocks.sha256(Json.encodeToString(spec).toByteArray()),
            inputFingerprint = fingerprint, imageId = p.imageId)
    }
    /** Must be fsynced before the sole authorized StartUnit; no implicit re-attempt. */
    fun begin(id: String): String = ReleasePrivateFiles.locked(root) {
        val (intent, result) = paths(id)
        require(!Files.exists(intent, NOFOLLOW_LINKS) && !Files.exists(result, NOFOLLOW_LINKS)) {
            "Generation already attempted; reconcile, do not replay"
        }
        val bytes = json.encodeToString(expected(id)).toByteArray()
        ReleasePrivateFiles.save(intent, bytes)
        ReleaseLocks.sha256(bytes)
    }
    /** Install the original immutable per-process environment *after* begin, before the
     * sole StartUnit, under the owner's still-held member lock. A duplicate matching file
     * is only a readback, not permission to retry an uncertain StartUnit.
     */
    fun prepareEnvironment(id: String): Path = ReleasePrivateFiles.locked(root) {
        val (intent, output) = paths(id)
        val original = ReleasePrivateFiles.read(intent, 4096)
        require(original.contentEquals(json.encodeToString(expected(id)).toByteArray()) &&
            !Files.exists(output, NOFOLLOW_LINKS)) { "Initializer original intent unavailable or completed" }
        val memberRoot = runtimeBase.resolve(spec.name)
        ReleasePrivateFiles.directory(memberRoot)
        val destination = memberRoot.resolve("runtime.quadlet-${process(id).id}.env")
        val value = "P0_RUNTIME_FINGERPRINT=$fingerprint\nP0_INITIALIZER_INTENT=${ReleaseLocks.sha256(original)}\n".toByteArray()
        if (Files.exists(destination, NOFOLLOW_LINKS)) {
            require(ReleasePrivateFiles.read(destination, 256).contentEquals(value)) {
                "Original initializer environment changed; no StartUnit authorized"
            }
        } else ReleasePrivateFiles.save(destination, value)
        destination
    }
    /** Only an already-existing exact named container in the pinned canonical store can
     * complete the original intent. No `run`, `start`, `rm`, `--replace` or retry occurs here.
     * A failed/missing/ambiguous native observation leaves the original intent untouched.
     */
    fun nativeComplete(id: String, commands: RuntimeCommands = PrivateRootfulCommands(30, spec.store)) =
        ReleasePrivateFiles.locked(root) {
            val (intent, output) = paths(id)
            val bytes = ReleasePrivateFiles.read(intent, 4096)
            require(bytes.contentEquals(json.encodeToString(expected(id)).toByteArray())) { "Initializer intent changed" }
            require(!Files.exists(output, NOFOLLOW_LINKS)) { "Initializer result already exists; no replacement" }
            val p = process(id)
            val memberRoot = runtimeBase.resolve(spec.name)
            val env = memberRoot.resolve("runtime.quadlet-${p.id}.env")
            require(ReleasePrivateFiles.read(env, 256).contentEquals(
                "P0_RUNTIME_FINGERPRINT=$fingerprint\nP0_INITIALIZER_INTENT=${ReleaseLocks.sha256(bytes)}\n".toByteArray())) {
                "Original initializer environment changed"
            }
            val name = "p0v3-live-${spec.name}-${p.id}"
            val response = commands.run(listOf("container", "inspect", name))
            require(response.exitCode == 0 && response.output.toByteArray().size in 1..65536) {
                "Original initializer container unavailable; do not replay"
            }
            val observed = json.parseToJsonElement(response.output).jsonArray.single().jsonObject
            val config = observed.getValue("Config").jsonObject
            val labels = config.getValue("Labels").jsonObject
            val state = observed.getValue("State").jsonObject
            val cid = observed.getValue("Id").jsonPrimitive.content
            val image = observed.getValue("Image").jsonPrimitive.content.removePrefix("sha256:")
            require(cid.matches(sha) && observed.getValue("Name").jsonPrimitive.content == name &&
                image == p.imageId && config.getValue("Image").jsonPrimitive.content == p.image &&
                labels.getValue("io.p0v3.private-deployment").jsonPrimitive.content == spec.name &&
                labels.getValue("io.p0v3.runtime-fingerprint").jsonPrimitive.content == fingerprint &&
                labels.getValue("io.p0v3.initializer-intent").jsonPrimitive.content == ReleaseLocks.sha256(bytes) &&
                state.getValue("Status").jsonPrimitive.content == "exited" &&
                !state.getValue("Running").jsonPrimitive.content.toBooleanStrict() &&
                state.getValue("ExitCode").jsonPrimitive.int == 0 &&
                state.getValue("StartedAt").jsonPrimitive.content.startsWith("20") &&
                state.getValue("FinishedAt").jsonPrimitive.content.startsWith("20")) {
                "Original initializer container identity, labels, image or exit changed"
            }
            val result = QuadletInitializerResult(intentSha256 = ReleaseLocks.sha256(bytes),
                containerId = cid, observedImageId = image, observedFingerprint = fingerprint,
                exitCode = 0, stopped = true)
            ReleasePrivateFiles.save(output, json.encodeToString(result).toByteArray())
        }
    /** Read-only completed history. A pending original poisons future attempts. */
    fun completed(id: String): Boolean = ReleasePrivateFiles.locked(root) {
        val (intent, output) = paths(id)
        if (!Files.exists(intent, NOFOLLOW_LINKS)) {
            require(!Files.exists(output, NOFOLLOW_LINKS)) { "Orphan initializer result" }
            return@locked false
        }
        val bytes = ReleasePrivateFiles.read(intent, 4096)
        require(bytes.contentEquals(json.encodeToString(expected(id)).toByteArray())) { "Initializer intent changed" }
        if (!Files.exists(output, NOFOLLOW_LINKS)) return@locked false
        val resultBytes = ReleasePrivateFiles.read(output, 4096)
        val result = json.decodeFromString<QuadletInitializerResult>(resultBytes.decodeToString(throwOnInvalidSequence = true))
        require(result.schemaVersion == 1 && result.intentSha256 == ReleaseLocks.sha256(bytes) &&
            result.containerId.matches(Regex("[a-f0-9]{64}")) &&
            result.observedImageId == process(id).imageId && result.observedFingerprint == fingerprint &&
            result.exitCode == 0 && result.stopped &&
            resultBytes.contentEquals(json.encodeToString(result).toByteArray())) { "Corrupt or foreign initialization journal" }
        true
    }
}
