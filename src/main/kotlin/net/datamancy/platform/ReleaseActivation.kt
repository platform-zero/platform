package net.datamancy.platform

import kotlinx.serialization.Serializable

/** Sealed at PREPARED; a caller cannot substitute a different generation/site/configuration at activation. */
@Serializable data class ReleaseDeploymentBinding(val generationId: String, val bundleSha256: String,
    val sitePolicySha256: String, val restrictedConfigurationSha256: String) {
    fun validate() {
        require(generationId.matches(Regex("q-[a-f0-9]{12}")) &&
            listOf(bundleSha256, sitePolicySha256, restrictedConfigurationSha256).all { it.matches(Regex("[a-f0-9]{64}")) }) {
            "Exact activation generation, bundle, site and restricted configuration required"
        }
    }
}

/** PREPARED update authority names the source and future generation, not an invented future bundle. */
@Serializable data class ReleaseUpdateBinding(val sourceGeneration: String, val sourceBundleSha256: String,
    val targetGeneration: String, val candidateSha256: String, val sitePolicySha256: String, val intentSha256: String) {
    fun validate() {
        require(sourceGeneration.matches(Regex("q-[a-f0-9]{12}")) && targetGeneration.matches(Regex("q-[a-f0-9]{12}")) &&
            sourceGeneration != targetGeneration && listOf(sourceBundleSha256, candidateSha256, sitePolicySha256, intentSha256)
                .all { it.matches(Regex("[a-f0-9]{64}")) }) { "Exact immutable source/update intent required" }
    }
}

interface ReleaseQualificationSnapshotEffects {
    /** Post-real-domain capture and qualified functional restore, distinct from pre-cutover rollback capture. */
    fun verifyQualificationSnapshot(): String
}

interface ReleaseUpdateEffects {
    /** Called once after snapshot verification and staged migration, before restricted cutover. */
    fun bindStagedDeployment(snapshotId: String): ReleaseDeploymentBinding
}

data class ReleaseActivationBinding(val transactionId: String, val lockDigest: String,
    val acceptedJournalHead: String, val deployment: ReleaseDeploymentBinding)

/**
 * Required activation authority, deliberately separate from staged/real-domain journey evaluation.
 * Production implementations must verify the current complete qualification history/evidence, identify
 * its second qualified installation, reobserve live bindings, and consume a single-use permit.
 * There is no permissive implementation or default callback. Unit doubles are not production authority.
 */
interface ReleaseActivationAuthorization {
    /** Read-only verification returns the SHA-256 of the exact permit to consume. */
    fun verify(binding: ReleaseActivationBinding): String
    /** Durable, single-use consumption before any public write, bound to the activation journal claim. */
    fun consume(binding: ReleaseActivationBinding, permitSha256: String, activationJournalHead: String)
}
