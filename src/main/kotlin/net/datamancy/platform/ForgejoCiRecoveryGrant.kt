package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.Serializable

/** Target-scoped, externally acquired custody authorization. These are hashes
 * and paths only; management and new registration credentials remain host-only.
 * The original .runner file and original registration token are never copied.
 */
@Serializable internal data class ForgejoCiRecoveryGrant(val schemaVersion: Int = 1,
    val sourceGeneration: String, val sourceBundleSha256: String, val targetGeneration: String,
    val originalRunnerId: Long, val managementToken: ActivationInput,
    val newRegistrationToken: ActivationInput, val repository: String) {
    fun validate(original: ForgejoCiSourcePlan, target: String) {
        original.validate(original.generation)
        val anchor = "/mnt/media/p0-v3/release-bootstrap-anchors/forgejo-ci/recovery/$target/"
        require(schemaVersion == 1 && sourceGeneration == original.generation &&
            targetGeneration == target && target != sourceGeneration &&
            target.matches(Regex("q-[a-f0-9]{12}")) && originalRunnerId > 0 &&
            sourceBundleSha256.matches(Regex("[a-f0-9]{64}")) &&
            repository == original.enrollment.repository &&
            managementToken.path == anchor + "management.token" &&
            newRegistrationToken.path == anchor + "registration.token" &&
            listOf(managementToken, newRegistrationToken).all { input ->
                input.sha256.matches(Regex("[a-f0-9]{64}")) &&
                    Path.of(input.path).isAbsolute && Path.of(input.path).normalize().toString() == input.path
            } && managementToken.sha256 != newRegistrationToken.sha256 &&
            newRegistrationToken.sha256 != original.registrationToken.sha256) {
            "Cold CI recovery must use distinct target-scoped management and registration authority"
        }
    }
    fun targetPlan(original: ForgejoCiSourcePlan): ForgejoCiSourcePlan =
        original.copy(generation = targetGeneration, registrationToken = newRegistrationToken,
            freshIssuerBootstrap = false)
            .also { it.validate(targetGeneration) }
    companion object {
        fun path(target: String): Path {
            require(target.matches(Regex("q-[a-f0-9]{12}")))
            return Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/forgejo-ci/recovery/$target/grant.json")
        }
    }
}
