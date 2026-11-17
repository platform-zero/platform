package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

@Serializable internal data class ForgejoCiRevocationIntent(val sourceGeneration: String,
    val targetGeneration: String, val sourceBundleSha256: String, val targetBundleSha256: String,
    val originalRunnerId: Long, val originalCustodySha256: String,
    val managementTokenSha256: String, val targetPlanSha256: String)
@Serializable internal data class ForgejoCiRevocationResult(val intentSha256: String,
    val originalRunnerId: Long, val deletionStatus: Int,
    val originalGetSha256: String, val terminalGetSha256: String)

/** Original-registration revocation, not an exited-process guess. The private
 * repository API returns the exact original runner before DELETE, confirms the
 * original DELETE ACK, then returns 404. A missing result remains uncertain.
 */
internal object ForgejoCiNativeRecovery {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    fun authenticatedResult(bundle: GenerationBundle, root: Path): ForgejoCiRevocationResult? {
        val grant = bundle.request.ciRecoveryGrant ?: return null
        val ci = root.resolve("ci")
        val bytes = ReleasePrivateFiles.read(ci.resolve("revoke-original.intent.json"), 8192)
        val intent = json.decodeFromString<ForgejoCiRevocationIntent>(bytes.decodeToString(throwOnInvalidSequence = true))
        val result = json.decodeFromString<ForgejoCiRevocationResult>(ReleasePrivateFiles.read(
            ci.resolve("revoke-original.result.json"), 8192).decodeToString(throwOnInvalidSequence = true))
        require(intent.targetGeneration == bundle.request.id && intent.sourceGeneration == grant.sourceGeneration &&
            intent.originalRunnerId == grant.originalRunnerId && intent.sourceBundleSha256 == grant.sourceBundleSha256 &&
            intent.targetBundleSha256 == ReleaseLocks.sha256(json.encodeToString(bundle).toByteArray()) &&
            intent.managementTokenSha256 == grant.managementToken.sha256 &&
            intent.targetPlanSha256 == ReleaseLocks.sha256(json.encodeToString(
                requireNotNull(bundle.request.recoveredForgejoCiTarget)).toByteArray()) &&
            result.intentSha256 == ReleaseLocks.sha256(bytes) && result.originalRunnerId == grant.originalRunnerId &&
            result.deletionStatus == 204)
        return result
    }
    fun verifyFresh(bundle: GenerationBundle, root: Path, registered: ForgejoCiRegistrationResult): String {
        val grant = requireNotNull(bundle.request.ciRecoveryGrant)
        authenticatedResult(bundle, root)
        require(registered.runnerId != grant.originalRunnerId &&
            registered.runnerName == "p0v3-ci-${grant.targetGeneration}")
        val token = GenerationRuntime.privateInput(Path.of(grant.managementToken.path))
        try {
            require(ReleaseLocks.sha256(token) == grant.managementToken.sha256)
            val path = "/api/v1/repos/${grant.repository}/actions/runners/${registered.runnerId}"
            val reply = ForgejoCiPrivateApi.request(requireNotNull(bundle.request.recoveredForgejoCiTarget),
                token, "GET", path)
            require(reply.status == 200)
            val native = json.parseToJsonElement(reply.body.decodeToString()).jsonObject
            require(native.getValue("id").jsonPrimitive.content.toLong() == registered.runnerId &&
                native.getValue("name").jsonPrimitive.content == registered.runnerName &&
                native["uuid"]?.jsonPrimitive?.content?.let { it == registered.runnerUuid } != false) {
                "New private CI registration has no exact repository-scoped native readback"
            }
            val digest = ReleaseLocks.sha256(reply.body)
            ReleasePrivateFiles.save(root.resolve("ci/registration-remote.result.json"),
                json.encodeToString(mapOf("runnerId" to registered.runnerId.toString(),
                    "responseSha256" to digest)).toByteArray())
            return digest
        } finally { token.fill(0) }
    }
    fun revoke(bundle: GenerationBundle, root: Path, sourceBase: Path = GenerationRuntime.BASE): ForgejoCiRevocationResult {
        val grant = requireNotNull(bundle.request.ciRecoveryGrant)
        val originalPlan = requireNotNull(bundle.request.recoveredForgejoCi)
        val targetPlan = requireNotNull(bundle.request.recoveredForgejoCiTarget)
        grant.validate(originalPlan, bundle.request.id)
        require(grant.targetPlan(originalPlan) == targetPlan &&
            root == GenerationRuntime.BASE.resolve(bundle.request.id) &&
            bundle.recoverySourceKopia != null && bundle.request.forgejoCi == null)
        val targetHash = ReleaseLocks.sha256(json.encodeToString(bundle).toByteArray())
        require(ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"), 4194304)) == targetHash)
        val sourceRoot = sourceBase.resolve(grant.sourceGeneration)
        val originalRegistrationBytes = ReleasePrivateFiles.read(sourceRoot.resolve("ci/registration.result.json"), 8192)
        val original = json.decodeFromString<ForgejoCiRegistrationResult>(originalRegistrationBytes.decodeToString())
        val custodyBytes = ReleasePrivateFiles.read(root.resolve("recovered/controller/ci-original/cold-custody.json"), 1048576)
        val custody = json.decodeFromString<ForgejoCiOriginalCustody>(custodyBytes.decodeToString())
        require(original.runnerId == grant.originalRunnerId && original.runnerName ==
            "p0v3-ci-${grant.sourceGeneration}" && original.instance == "https://forgejo.datamancy.net/" &&
            custody.sourceGeneration == grant.sourceGeneration &&
            custody.sourceBundleSha256 == grant.sourceBundleSha256 &&
            custody.registrationResultSha256 == ReleaseLocks.sha256(originalRegistrationBytes) &&
            custody.stopResultSha256.keys == setOf("runner", "guard", "transport", "egress", "internal")) {
            "Original CI job custody or registration identity differs from authenticated snapshot"
        }
        for ((stage, sha) in custody.stopResultSha256) require(ReleaseLocks.sha256(
            ReleasePrivateFiles.read(sourceRoot.resolve("ci/stop-$stage.result.json"), 8192)) == sha)
        val ci = root.resolve("ci")
        ReleasePrivateFiles.directory(ci)
        val intentPath = ci.resolve("revoke-original.intent.json")
        require(!Files.exists(intentPath, NOFOLLOW_LINKS) &&
            !Files.exists(ci.resolve("revoke-original.result.json"), NOFOLLOW_LINKS)) {
            "Original Forgejo CI revocation may not be replayed"
        }
        val token = GenerationRuntime.privateInput(Path.of(grant.managementToken.path))
        try {
            require(ReleaseLocks.sha256(token) == grant.managementToken.sha256)
            val path = "/api/v1/repos/${grant.repository}/actions/runners/${grant.originalRunnerId}"
            val before = ForgejoCiPrivateApi.request(originalPlan, token, "GET", path)
            require(before.status == 200)
            val observed = json.parseToJsonElement(before.body.decodeToString()).jsonObject
            require(observed.getValue("id").jsonPrimitive.content.toLong() == grant.originalRunnerId &&
                observed.getValue("name").jsonPrimitive.content == original.runnerName &&
                observed["uuid"]?.jsonPrimitive?.content?.let { it == original.runnerUuid } != false) {
                "Scoped Forgejo API returned another runner"
            }
            val intent = ForgejoCiRevocationIntent(grant.sourceGeneration, grant.targetGeneration,
                grant.sourceBundleSha256, targetHash, grant.originalRunnerId, ReleaseLocks.sha256(custodyBytes),
                grant.managementToken.sha256, ReleaseLocks.sha256(json.encodeToString(targetPlan).toByteArray()))
            val bytes = json.encodeToString(intent).toByteArray()
            // First possible DELETE RPC occurs only after this sealed one-use intent.
            ReleasePrivateFiles.save(intentPath, bytes)
            val deleted = ForgejoCiPrivateApi.request(originalPlan, token, "DELETE", path)
            require(deleted.status == 204 && deleted.body.isEmpty()) {
                "Original runner DELETE has no native ACK; preserve original intent"
            }
            val terminal = ForgejoCiPrivateApi.request(originalPlan, token, "GET", path)
            require(terminal.status == 404) { "Original runner still has remote authority" }
            val result = ForgejoCiRevocationResult(ReleaseLocks.sha256(bytes), grant.originalRunnerId,
                deleted.status, ReleaseLocks.sha256(before.body), ReleaseLocks.sha256(terminal.body))
            ReleasePrivateFiles.save(ci.resolve("revoke-original.result.json"), json.encodeToString(result).toByteArray())
            return result
        } finally { token.fill(0) }
    }
}
