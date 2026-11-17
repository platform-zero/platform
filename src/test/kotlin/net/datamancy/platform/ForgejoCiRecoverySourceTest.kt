package net.datamancy.platform

import kotlin.test.*

/** Offline source checks only; no account, socket, images, API or RPC touched. */
class ForgejoCiRecoverySourceTest {
    private val old = "q-0123456789ab"
    private val next = "q-fedcba987654"
    private fun hex(char: Char) = char.toString().repeat(64)
    private fun input(path: String, digest: Char) = ActivationInput(path, hex(digest))
    private fun image(kind: String, id: Char): ManagedLaneImageBinding {
        val digest = hex(id)
        return ManagedLaneImageBinding(input("/mnt/media/p0-v3/ci-archives/$kind.tar", id),
            2048, 4096, "sha256:$digest", "localhost/p0v3-$kind@sha256:$digest",
            "sha256:$digest", listOf("sha256:$digest"))
    }
    private val source = ForgejoCiSourcePlan(
        enrollment = TrustedForgejoWorkflowEnrollment("private/trusted-repo", hex('a'), "b".repeat(40),
            "localhost/p0v3-job@sha256:${hex('c')}", hex('c'), 784, 2048, 8192,
            checkoutActionCommit = "d".repeat(40), uploadActionCommit = "e".repeat(40)),
        workflow = input("/mnt/media/p0-v3/release-bootstrap-anchors/forgejo-ci/workflow.yml", 'a'),
        runnerBinary = input("/mnt/media/p0-v3/ci-runner/bin/forgejo-runner", 'f'),
        rootlessPodman = input("/usr/bin/podman", '1'),
        registrationToken = input("/mnt/media/p0-v3/release-bootstrap-anchors/forgejo-ci/original.token", '2'),
        jobArchive = image("job", 'c'), runnerImage = image("runner", '3'),
        transportImage = image("transport", '4'),
        upstreamCa = input("/mnt/media/p0-v3/release-bootstrap-anchors/forgejo-ci/upstream-ca.pem", '5'),
        privateUpstream = "https://10.2.3.4:443", generation = old)
    private val prefix = "/mnt/media/p0-v3/release-bootstrap-anchors/forgejo-ci/recovery/$next/"
    private val grant = ForgejoCiRecoveryGrant(sourceGeneration = old, sourceBundleSha256 = hex('6'),
        targetGeneration = next, originalRunnerId = 41,
        managementToken = input(prefix + "management.token", '7'),
        newRegistrationToken = input(prefix + "registration.token", '8'),
        repository = source.enrollment.repository)

    @Test fun `target credential is distinct and neither an original runner nor an image substitution`() {
        source.validate(old)
        grant.validate(source, next)
        val projected = grant.targetPlan(source)
        assertEquals(next, projected.generation)
        assertNotEquals(source.registrationToken, projected.registrationToken)
        assertEquals(source.jobArchive, projected.jobArchive)
        assertEquals(source.runnerImage, projected.runnerImage)
        assertEquals(source.transportImage, projected.transportImage)
        val units = ForgejoCiNativeUnits.render(projected)
        assertEquals(5, units.size)
        assertContains(units.getValue("p0v3-ci-$next-internal.network"), "Internal=true")
        assertContains(units.getValue("p0v3-ci-$next-runner.container"),
            "Environment=SSL_CERT_FILE=/etc/ssl/certs/p0v3-ci-forgejo-ca.pem")
        assertContains(units.getValue("p0v3-ci-$next-runner.container"), "guard.sock:ro")
    }

    @Test fun `fresh issuer has no invented credential before Forgejo and restore uses a distinct grant`() {
        val future = ActivationInput("/mnt/media/p0-v3/release-generations/$old/ci/fresh-registration.token", hex('0'))
        val repo = input("/mnt/media/p0-v3/release-bootstrap-anchors/forgejo-ci/repository/trusted.bundle", '9')
        val fresh = source.copy(freshIssuerBootstrap = true, registrationToken = future,
            trustedRepositoryBundle = repo)
        fresh.validate(old)
        val late = fresh.copy(graphOwnedLateUpstream = true, upstreamCa = null, privateUpstream = null)
        late.validate(old)
        val lateTarget = grant.targetPlan(late)
        lateTarget.validate(next)
        assertTrue(lateTarget.graphOwnedLateUpstream && lateTarget.upstreamCa == null &&
            lateTarget.privateUpstream == null)
        assertFails { late.copy(upstreamCa = source.upstreamCa).validate(old) }
        assertFails { late.copy(privateUpstream = source.privateUpstream).validate(old) }
        assertFails { fresh.copy(trustedRepositoryBundle = null).validate(old) }
        assertFails { fresh.copy(registrationToken = source.registrationToken).validate(old) }
        val issued = fresh.copy(freshIssuerBootstrap = false, freshRegistrationIssued = true,
            registrationToken = future.copy(sha256 = hex('a')))
        issued.validate(old)
        assertFails { issued.copy(registrationToken = future).validate(old) }
        assertFails { issued.copy(generation = next).validate(next) }
        grant.validate(fresh, next)
        val restored = grant.targetPlan(fresh)
        assertFalse(restored.freshIssuerBootstrap)
        assertFalse(restored.freshRegistrationIssued)
        assertNotEquals(fresh.registrationToken, restored.registrationToken)
    }

    @Test fun `recovery grant cannot borrow original token or arbitrary repo account and egress`() {
        listOf(grant.copy(targetGeneration = old), grant.copy(repository = "private/other"),
            grant.copy(originalRunnerId = 0), grant.copy(newRegistrationToken = source.registrationToken),
            grant.copy(managementToken = grant.newRegistrationToken),
            grant.copy(newRegistrationToken = input("/tmp/borrowed.token", '8'))).forEach {
            assertFails { it.validate(source, next) }
        }
        assertFails { source.copy(privateUpstream = "https://8.8.8.8:443").validate(old) }
    }
}
