package net.datamancy.platform

import kotlin.test.*

class ForgejoRunnerWorkflowPreviewTest {
    private val image = "docker.io/library/node@sha256:${"a".repeat(64)}"
    private val enrolled = TrustedForgejoWorkflowEnrollment("private/trusted-repo", "b".repeat(64),
        "c".repeat(40), image, "d".repeat(64), 784, 2048, 8192)
    private val job = ForgejoWorkflowJobShape(enrolled.repository, enrolled.workflowSha256,
        enrolled.trustedCommit, "p0v3-rootless-oci", image)

    @Test fun `exact immutable private job remains review-only without native CI proof`() {
        val result = ForgejoRunnerWorkflowPreview.review(enrolled, job)
        assertEquals(image, result.pinnedJobImage)
        assertEquals(1, result.jobConcurrency)
        assertFalse(result.effectiveNativeImageInspected || result.runnerRegistered ||
            result.jobExecuted || result.acceptanceVerified)
        assertEquals(result, ForgejoRunnerWorkflowPreview.review(enrolled,
            job.copy(jobsContainerOverride = image)))
    }

    @Test fun `Forgejo job container override cannot escape pinned image despite trusted label`() {
        assertFails { ForgejoRunnerWorkflowPreview.review(enrolled,
            job.copy(jobsContainerOverride = "docker.io/library/node:latest", effectiveJobImage = image)) }
        assertFails { ForgejoRunnerWorkflowPreview.review(enrolled,
            job.copy(jobsContainerOverride = "docker.io/library/node:latest",
                effectiveJobImage = "docker.io/library/node:latest")) }
        assertFails { ForgejoRunnerWorkflowPreview.review(enrolled, job.copy(effectiveJobImage = "node:latest")) }
    }

    @Test fun `untrusted host runner socket mounts network or nested VM are never a reviewed job`() {
        val unsafe = listOf(job.copy(hostMounts = listOf("/run/user/784/podman/podman.sock")),
            job.copy(jobHasEngineSocket = true), job.copy(jobHasRegistrationCredential = true),
            job.copy(networkMode = "host"), job.copy(privileged = true), job.copy(nestedVm = true),
            job.copy(hostExecution = true), job.copy(serviceContainers = 1),
            job.copy(runsOn = "self-hosted"), job.copy(commit = "e".repeat(40)),
            job.copy(repository = "private/untrusted-repo"))
        unsafe.forEach { assertFails { ForgejoRunnerWorkflowPreview.review(enrolled, it) } }
        assertFails { ForgejoRunnerWorkflowPreview.review(enrolled.copy(concurrency = 2), job) }
        assertFails { ForgejoRunnerWorkflowPreview.review(enrolled.copy(privateRepository = false), job) }
        assertFails { ForgejoRunnerWorkflowPreview.review(enrolled.copy(rootlessUid = 0), job) }
    }
}
