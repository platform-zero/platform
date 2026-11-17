package net.datamancy.platform

import kotlinx.serialization.Serializable

/** Evidence of one held-source recovery completion, not semantic acceptance or publication authority.
 * Written only while every target member remains locked and isolated, after native source resume.
 */
@Serializable internal data class GenerationCompletionProof(
    val schemaVersion: Int = 1,
    val access: RuntimeBackupAccess,
    val heldSha256: String,
    val snapshotId: String,
    val target: String,
    val targetBundleSha256: String,
    val targetFences: Map<String, String>,
    val sourceResultSha256: String,
    val resumeAuthoritySha256: String,
    val sourceObservations: List<RuntimeAudit>,
    val targetObservations: List<FrozenRuntimeObservation>
) {
    fun validate() {
        access.validate()
        val hash = Regex("[a-f0-9]{64}")
        require(schemaVersion == 1 && hash.matches(heldSha256) && hash.matches(targetBundleSha256) &&
            hash.matches(sourceResultSha256) && hash.matches(resumeAuthoritySha256) &&
            snapshotId.matches(Regex("[a-f0-9]{32,64}")) && target.matches(Regex("q-[a-f0-9]{12}")) &&
            target != access.generation && sourceObservations.isNotEmpty() && targetObservations.isNotEmpty()) {
            "Invalid generation completion evidence"
        }
        require(sourceObservations.map { it.name }.distinct().size == sourceObservations.size &&
            sourceObservations.all { it.name.startsWith(access.generation + "-") && hash.matches(it.fingerprint) &&
                it.maintenanceId == null && it.existingResources > 0 && it.statuses.any { status -> status.state == "running" } }) {
            "Completion lacks observed source resume"
        }
        require(targetObservations.map { it.name }.distinct().size == targetObservations.size &&
            targetObservations.map { it.name }.toSet() == targetFences.keys && targetObservations.all { observed ->
                observed.name.startsWith(target + "-") && hash.matches(observed.fingerprint) &&
                    observed.fenceId.isNotBlank() && observed.fenceId == targetFences[observed.name] &&
                    observed.completedInitializers.isEmpty() && observed.statuses.isNotEmpty() &&
                    observed.statuses.all { it.state == "exited" && it.exitCode in setOf(0, 143) }
            }) { "Completion lacks exact locked target isolation" }
    }
}

/** The path/hash binds the immutable proof, whose contents are independently checked against native records. */
@Serializable internal data class GenerationCompletionReceipt(val proof: GenerationCompletionProof,
    val record: ActivationInput)
