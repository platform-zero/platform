package net.datamancy.platform

import kotlinx.serialization.Serializable

@Serializable internal data class TrustedForgejoWorkflowEnrollment(val repository: String, val workflowSha256: String,
    val trustedCommit: String, val jobImage: String, val jobImageId: String,
    val rootlessUid: Int, val memoryMiB: Int, val diskMiB: Int,
    val concurrency: Int = 1, val privateRepository: Boolean = true,
    val checkoutActionCommit: String? = null, val uploadActionCommit: String? = null)
@Serializable internal data class ForgejoWorkflowJobShape(val repository: String, val workflowSha256: String,
    val commit: String, val runsOn: String, val effectiveJobImage: String,
    val jobsContainerOverride: String? = null, val serviceContainers: Int = 0,
    val hostMounts: List<String> = emptyList(), val networkMode: String = "private-forgejo-only",
    val privileged: Boolean = false, val hostExecution: Boolean = false, val nestedVm: Boolean = false,
    val jobHasEngineSocket: Boolean = false, val jobHasRegistrationCredential: Boolean = false)
@Serializable internal data class ForgejoWorkflowReview(val repository: String, val workflowSha256: String,
    val pinnedJobImage: String, val pinnedJobImageId: String, val memoryMiB: Int, val diskMiB: Int,
    val rootlessUid: Int, val jobConcurrency: Int = 1,
    val effectiveNativeImageInspected: Boolean = false, val runnerRegistered: Boolean = false,
    val jobExecuted: Boolean = false, val acceptanceVerified: Boolean = false)

/** Review an exact enrolled workflow before any runner registration. Forgejo v17 permits
 * jobs.<id>.container to override the configured label; the label alone is not an
 * execution boundary. This pure review NEVER authorizes an OCI create, accepts an
 * untrusted native image readback or pretends to have run CI. Effective native image,
 * rootless engine/store and job mounts still require audited actuation under custody.
 */
internal object ForgejoRunnerWorkflowPreview {
    fun review(enrollment: TrustedForgejoWorkflowEnrollment, job: ForgejoWorkflowJobShape): ForgejoWorkflowReview {
        val hash = Regex("[a-f0-9]{64}")
        require(enrollment.repository.matches(Regex("[a-z][a-z0-9-]{0,39}/[a-z][a-z0-9-]{0,63}")) &&
            hash.matches(enrollment.workflowSha256) &&
            enrollment.trustedCommit.matches(Regex("[a-f0-9]{40}")) && enrollment.privateRepository &&
            listOfNotNull(enrollment.checkoutActionCommit, enrollment.uploadActionCommit).all {
                it.matches(Regex("[a-f0-9]{40}"))
            } &&
            enrollment.jobImage.matches(Regex("[a-z0-9./_-]+@sha256:[a-f0-9]{64}")) &&
            enrollment.jobImageId.matches(Regex("[a-f0-9]{64}")) &&
            enrollment.rootlessUid == 784 && enrollment.concurrency == 1 &&
            enrollment.memoryMiB in 512..8192 && enrollment.diskMiB in 1024..32768) {
            "Runner enrollment has no exact private repository, pinned worker or bounded rootless limits"
        }
        require(job.repository == enrollment.repository && job.workflowSha256 == enrollment.workflowSha256 &&
            job.commit == enrollment.trustedCommit && job.runsOn == "p0v3-rootless-oci" &&
            job.effectiveJobImage == enrollment.jobImage &&
            (job.jobsContainerOverride == null || job.jobsContainerOverride == enrollment.jobImage) &&
            job.serviceContainers == 0 && job.hostMounts.isEmpty() &&
            job.networkMode == "private-forgejo-only" && !job.privileged && !job.hostExecution &&
            !job.nestedVm && !job.jobHasEngineSocket && !job.jobHasRegistrationCredential) {
            "Unreviewed effective Forgejo workflow container, repository or host/engine reachability"
        }
        return ForgejoWorkflowReview(enrollment.repository, enrollment.workflowSha256, enrollment.jobImage,
            enrollment.jobImageId, enrollment.memoryMiB, enrollment.diskMiB, enrollment.rootlessUid)
    }
}
