package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/** Account-owned, symlink-resistant, one-use source handoff. No registration
 * credential is copied. The helper runs with the dedicated UID and receives
 * only pinned config and guard source bytes on stdin (never site secrets).
 */
@Serializable internal data class ForgejoCiAccountStageIntent(val generation: String,
    val bundleSha256: String, val helperSha256: String, val files: Map<String, String>)
@Serializable internal data class ForgejoCiAccountStageResult(val intentSha256: String,
    val files: Map<String, String>, val accountUid: Int = 784)
internal object ForgejoCiNativeAccountStage {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private val baseFiles = listOf("runner-config.yaml", "guard-config.json", "guard.py",
        "transport-ca.pem", "transport-leaf.pem", "transport-leaf-key.pem",
        "transport-upstream-ca.pem", "transport-Caddyfile")
    fun stage(plan: ForgejoCiSourcePlan, root: Path, bundleSha256: String): ForgejoCiAccountStageResult {
        plan.validate(plan.generation)
        require(root == GenerationRuntime.BASE.resolve(plan.generation) &&
            bundleSha256.matches(Regex("[a-f0-9]{64}")))
        ReleasePrivateFiles.directory(root)
        val bundleBytes = ReleasePrivateFiles.read(root.resolve("bundle.json"), 4194304)
        require(ReleaseLocks.sha256(bundleBytes) == bundleSha256)
        val bundle = json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString(throwOnInvalidSequence = true))
        require((bundle.request.forgejoCi == plan && bundle.request.recoveredForgejoCi == null &&
            bundle.recoverySourceKopia == null) ||
            (bundle.request.recoveredForgejoCiTarget == plan && bundle.request.forgejoCi == null &&
                bundle.request.ciRecoveryGrant?.targetPlan(requireNotNull(bundle.request.recoveredForgejoCi)) == plan &&
                bundle.recoverySourceKopia != null))
        SiteOwnerships.checkSealed(bundle)
        val ci = root.resolve("ci")
        ReleasePrivateFiles.directory(ci)
        val helper = ReleasePrivateFiles.read(ci.resolve("account-stage.py"), 32768)
        val packaged = requireNotNull(ForgejoCiNativeAccountStage::class.java.getResourceAsStream(
            "/runtime/forgejo_ci_account_stage.py")).use { it.readBytes() }
        require(helper.contentEquals(packaged)) { "Account handoff source changed since sealing" }
        val filenames = baseFiles + ForgejoCiNativeUnits.render(plan).keys.map { "unit-$it" }
        val inputs = filenames.associateWith { ReleasePrivateFiles.read(ci.resolve(it), 131072) }
        require(inputs.values.sumOf { it.size } < 105000) { "Oversized CI source handoff" }
        val hashes = inputs.mapValues { ReleaseLocks.sha256(it.value) }
        val intent = ForgejoCiAccountStageIntent(plan.generation, bundleSha256,
            ReleaseLocks.sha256(helper), hashes)
        val intentPath = ci.resolve("account-stage.intent.json")
        require(!Files.exists(intentPath, NOFOLLOW_LINKS) &&
            !Files.exists(ci.resolve("account-stage.result.json"), NOFOLLOW_LINKS)) {
            "Existing or uncertain rootless account handoff may not be replayed"
        }
        val data = json.encodeToString(intent).toByteArray()
        ReleasePrivateFiles.save(intentPath, data)
        val handoff = buildJsonObject {
            put("generation", plan.generation)
            put("files", buildJsonObject {
                for ((name, bytes) in inputs) put(name, Base64.getEncoder().encodeToString(bytes))
            })
        }
        val process = ProcessBuilder("/usr/bin/sudo", "-n", "-u", plan.dedicatedAccount,
            "--", "/usr/bin/python3", "-c", helper.decodeToString(throwOnInvalidSequence = true),
            plan.generation).redirectError(ProcessBuilder.Redirect.DISCARD).start()
        try {
            process.outputStream.use { it.write(json.encodeToString(handoff).toByteArray()); it.flush() }
            // The helper returns only hashes of the fixed account-owned files, never source contents.
            require(process.waitFor(45, TimeUnit.SECONDS) && process.exitValue() == 0) {
                "Account handoff may have taken effect; preserve original intent"
            }
            val observed = json.parseToJsonElement(process.inputStream.readNBytes(4096)
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
                .mapValues { it.value.jsonPrimitive.content }
            require(observed == hashes && observed.keys == filenames.toSet()) {
                "Account-owned file readback differs from sealed source"
            }
            val result = ForgejoCiAccountStageResult(ReleaseLocks.sha256(data), observed)
            ReleasePrivateFiles.save(ci.resolve("account-stage.result.json"), json.encodeToString(result).toByteArray())
            return result
        } finally { if (process.isAlive) process.destroyForcibly() }
    }
}
