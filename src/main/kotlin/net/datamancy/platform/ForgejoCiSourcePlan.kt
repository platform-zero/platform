package net.datamancy.platform

import java.nio.file.Path
import java.nio.file.Files
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption.READ
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.Json

/** Sealed source requirements for one repository-scoped, one-job runner. This
 * does NOT register a runner, create a Podman job or endorse a caller's claim
 * that a workflow actually executed. All native job effects need a separate
 * rootless owner and effective create/stop evidence before Actions is enabled.
 */
@Serializable internal data class ForgejoCiGraphUpstreamPending(val generation: String,
    val hostname: String, val network: String)

@Serializable internal data class ForgejoCiSourcePlan(val schemaVersion: Int = 1,
    val enrollment: TrustedForgejoWorkflowEnrollment, val workflow: ActivationInput,
    val runnerBinary: ActivationInput, val rootlessPodman: ActivationInput,
    val registrationToken: ActivationInput, val jobArchive: ManagedLaneImageBinding,
    val runnerImage: ManagedLaneImageBinding? = null,
    val transportImage: ManagedLaneImageBinding? = null,
    val upstreamCa: ActivationInput? = null,
    val privateUpstream: String? = null,
    /** Original r9 graph issuer is sealed only after Caddy starts. Declare its
     * exact late native adoption, never a fixture CA or invented future ACK. */
    val graphOwnedLateUpstream: Boolean = false,
    val generation: String, val freshIssuerBootstrap: Boolean = false,
    val freshRegistrationIssued: Boolean = false,
    val trustedRepositoryBundle: ActivationInput? = null,
    val dedicatedAccount: String = "webservices-lab-ci-runner",
    val dedicatedUid: Int = 784, val dedicatedGid: Int = 784) {
    fun validate(generation: String) {
        val hash = Regex("[a-f0-9]{64}")
        require(schemaVersion == 1 && this.generation == generation &&
            generation.matches(Regex("q-[a-f0-9]{12}")) &&
            enrollment.concurrency == 1 && enrollment.privateRepository &&
            enrollment.rootlessUid == dedicatedUid &&
            ((enrollment.checkoutActionCommit == null && enrollment.uploadActionCommit == null) ||
                (enrollment.checkoutActionCommit?.matches(Regex("[a-f0-9]{40}")) == true &&
                    enrollment.uploadActionCommit?.matches(Regex("[a-f0-9]{40}")) == true &&
                    enrollment.checkoutActionCommit != enrollment.uploadActionCommit)) &&
            dedicatedAccount == "webservices-lab-ci-runner" && dedicatedUid == 784 && dedicatedGid == 784 &&
            workflow.sha256 == enrollment.workflowSha256 &&
            runnerBinary.sha256.matches(hash) && rootlessPodman.sha256.matches(hash) &&
            (!freshIssuerBootstrap || !freshRegistrationIssued) &&
            (if (freshIssuerBootstrap) registrationToken == ActivationInput(
                "/mnt/media/p0-v3/release-generations/$generation/ci/fresh-registration.token", "0".repeat(64))
            else registrationToken.sha256.matches(hash) &&
                (if (freshRegistrationIssued) registrationToken.path ==
                    "/mnt/media/p0-v3/release-generations/$generation/ci/fresh-registration.token" &&
                    registrationToken.sha256 != "0".repeat(64)
                else registrationToken.path.startsWith(
                    "/mnt/media/p0-v3/release-bootstrap-anchors/forgejo-ci/"))) &&
            workflow.path.startsWith("/mnt/media/p0-v3/release-bootstrap-anchors/forgejo-ci/"))
        if (freshIssuerBootstrap) requireNotNull(trustedRepositoryBundle).also {
            require(it.path.startsWith("/mnt/media/p0-v3/release-bootstrap-anchors/forgejo-ci/repository/") &&
                it.sha256.matches(hash))
        }
        for (input in listOfNotNull(workflow, runnerBinary, rootlessPodman, registrationToken,
            jobArchive.archive, requireNotNull(runnerImage).archive,
            requireNotNull(transportImage).archive, upstreamCa)) {
            val path = Path.of(input.path)
            require(input.sha256.matches(hash) && path.isAbsolute && path.normalize() == path)
        }
        val runner = requireNotNull(runnerImage) {
            "Dedicated rootless runner image must be acquired separately from the job image"
        }
        require(runner.expectedImageId.matches(Regex("sha256:[a-f0-9]{64}")) &&
            runner.expectedImageId != jobArchive.expectedImageId &&
            runner.sourceImageReference.matches(Regex("[a-z0-9./_-]+@sha256:[a-f0-9]{64}")) &&
            runner.archive.path != jobArchive.archive.path &&
            runner.archive.sha256 != jobArchive.archive.sha256 &&
            runner.expectedLayerDiffIds.isNotEmpty() &&
            runner.archiveBytes in 1024..RecoveryCapsule.MAX_TOTAL &&
            runner.maximumUnpackedBytes in 1024..RecoveryCapsule.MAX_TOTAL)
        val transport = requireNotNull(transportImage) { "Authenticated CI transport image missing" }
        require(transport.expectedImageId.matches(Regex("sha256:[a-f0-9]{64}")) &&
            transport.expectedImageId !in setOf(runner.expectedImageId, jobArchive.expectedImageId) &&
            transport.archive.path != runner.archive.path && transport.archive.path != jobArchive.archive.path &&
            transport.archiveBytes in 1024..RecoveryCapsule.MAX_TOTAL &&
            transport.maximumUnpackedBytes in 1024..RecoveryCapsule.MAX_TOTAL &&
            transport.expectedLayerDiffIds.isNotEmpty())
        if (graphOwnedLateUpstream) require(!freshRegistrationIssued &&
            upstreamCa == null && privateUpstream == null) {
            "Only a fresh r9 graph-owned original Caddy issuer may be adopted after native readiness"
        } else {
            val ca = requireNotNull(upstreamCa)
            require(ca.path.startsWith("/mnt/media/p0-v3/release-bootstrap-anchors/forgejo-ci/") &&
                ForgejoCiTransportSource.validUpstream(requireNotNull(privateUpstream)))
        }
        require(jobArchive.expectedImageId == "sha256:${enrollment.jobImageId}" &&
            jobArchive.sourceImageReference == enrollment.jobImage &&
            jobArchive.archiveBytes in 1024..RecoveryCapsule.MAX_TOTAL &&
            jobArchive.maximumUnpackedBytes in 1024..RecoveryCapsule.MAX_TOTAL &&
            jobArchive.expectedLayerDiffIds.isNotEmpty())
    }

    companion object {
        /** Source-only sealed CI inputs. Do not import the live registration
         * credential into a target or execute a runner from this method. */
        fun prepare(root: Path, plan: ForgejoCiSourcePlan) {
            ReleasePrivateFiles.directory(root)
            plan.validate(root.fileName.toString())
            val workflow = GenerationRuntime.privateInput(Path.of(plan.workflow.path))
            require(ReleaseLocks.sha256(workflow) == plan.workflow.sha256)
            val review = ForgejoWorkflowSource.inspect(plan.enrollment, plan.enrollment.trustedCommit, workflow)
            val config = ForgejoRunnerConfigSource.config(plan.enrollment, review,
                "/home/webservices-lab-ci-runner/.local/share/p0v3-ci/${plan.generation}/.runner")
            val caSource = plan.upstreamCa?.let { input ->
                GenerationRuntime.privateInput(Path.of(input.path)).also { bytes ->
                    require(ReleaseLocks.sha256(bytes) == input.sha256 &&
                        bytes.size in 512..65536 && bytes.decodeToString().contains("BEGIN CERTIFICATE"))
                }
            }
            val tls = PrivateWebPki.generate("forgejo-ci", listOf("forgejo-ci", "forgejo.datamancy.net"))
            require(tls.keys == setOf("ca.pem", "web.pem", "web-key.pem"))
            val ci = root.resolve("ci")
            Files.createDirectory(ci, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            FileChannel.open(root, READ).use { it.force(true) }
            ReleasePrivateFiles.save(ci.resolve("runner-config.yaml"), config.toByteArray())
            ReleasePrivateFiles.save(ci.resolve("transport-ca.pem"), tls.getValue("ca.pem").toByteArray())
            ReleasePrivateFiles.save(ci.resolve("transport-leaf.pem"), tls.getValue("web.pem").toByteArray())
            ReleasePrivateFiles.save(ci.resolve("transport-leaf-key.pem"), tls.getValue("web-key.pem").toByteArray())
            if (plan.graphOwnedLateUpstream) {
                ReleasePrivateFiles.save(ci.resolve("transport-upstream.pending.json"),
                    Json.encodeToString(ForgejoCiGraphUpstreamPending(plan.generation,
                        "forgejo.datamancy.net", "ingress-control")).toByteArray())
            } else {
                ReleasePrivateFiles.save(ci.resolve("transport-upstream-ca.pem"), requireNotNull(caSource))
                ReleasePrivateFiles.save(ci.resolve("transport-Caddyfile"), ForgejoCiTransportSource.config(
                    plan.generation, "/etc/ci/forgejo-ca.pem", requireNotNull(plan.privateUpstream)).toByteArray())
            }
            val guardBytes = requireNotNull(ForgejoCiSourcePlan::class.java.getResourceAsStream(
                "/runtime/forgejo_ci_socket_guard.py")) { "Packaged CI guard is missing" }.use { it.readBytes() }
            require(guardBytes.size in 1024..131072)
            val accountRoot = "/home/webservices-lab-ci-runner/.local/share/p0v3-ci/${plan.generation}"
            val guardConfig = buildJsonObject {
                put("schemaVersion", 1); put("generation", plan.generation)
                put("state", "$accountRoot/guard-state")
                put("listen", "$accountRoot/guard.sock")
                put("backend", "/run/user/784/podman/podman.sock")
                put("image", plan.enrollment.jobImage)
                put("imageId", plan.enrollment.jobImageId)
                put("network", "p0v3-ci-${plan.generation}-internal")
                put("caMount", "$accountRoot/transport-ca.pem:/etc/ssl/certs/p0v3-ci-forgejo-ca.pem:ro")
                put("memoryMiB", plan.enrollment.memoryMiB)
            }
            ReleasePrivateFiles.save(ci.resolve("guard-config.json"),
                (Json.encodeToString(kotlinx.serialization.json.JsonObject.serializer(), guardConfig) + "\n").toByteArray())
            ReleasePrivateFiles.save(ci.resolve("guard.py"), guardBytes)
            val staging = requireNotNull(ForgejoCiSourcePlan::class.java.getResourceAsStream(
                "/runtime/forgejo_ci_account_stage.py")) { "Packaged CI account handoff is missing" }.use { it.readBytes() }
            require(staging.size in 1024..32768)
            ReleasePrivateFiles.save(ci.resolve("account-stage.py"), staging)
            ReleasePrivateFiles.save(ci.resolve("guard.sha256"), (ReleaseLocks.sha256(guardBytes) + "\n").toByteArray())
            for ((unit, source) in ForgejoCiNativeUnits.render(plan))
                ReleasePrivateFiles.save(ci.resolve("unit-$unit"), source.toByteArray())
            ReleasePrivateFiles.save(ci.resolve("workflow.sha256"), (plan.workflow.sha256 + "\n").toByteArray())
        }

        /** Retain original registration lineage as inert metadata only. No
         * restored worker may claim the original token or replay an old job. */
        fun coldRecoveryTarget(source: GenerationRequest, projected: GenerationRequest): GenerationRequest {
            val original = source.forgejoCi ?: source.recoveredForgejoCiTarget ?: source.recoveredForgejoCi
                ?: error("Missing authenticated original CI plan")
            require(source.forgejoCi == null || source.recoveredForgejoCi == null &&
                source.recoveredForgejoCiTarget == null)
            require(projected.id != source.id && projected.forgejoCi == source.forgejoCi &&
                projected.recoveredForgejoCi == source.recoveredForgejoCi &&
                projected.recoveredForgejoCiTarget == source.recoveredForgejoCiTarget)
            original.validate(original.generation)
            return projected.copy(forgejoCi = null, recoveredForgejoCi = original,
                recoveredForgejoCiTarget = null, ciRecoveryGrant = null)
        }
    }
}
