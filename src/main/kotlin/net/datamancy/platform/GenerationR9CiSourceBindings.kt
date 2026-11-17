package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** Bind reviewed local Git/OCI source with genuine original hashes. No token,
 * issuer result, native runner registration, image import or job ACK is issued.
 * The only zero digest is the existing typed *future* fresh-registration grant.
 */
internal object GenerationR9CiSourceBindings {
    private val json = Json { ignoreUnknownKeys = false; encodeDefaults = true }
    private val root = Path.of("/mnt/media/p0-v3/image-acquisition-receipts/forgejo-ci-minimal-bound-r2")
    private val repo = Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/forgejo-ci/repository/p0v3-local-reviewed-v4")
    private val measures = Path.of("/home/gerald/p0_v3/.coord/rapid-completion/core-r9-ci-oci-layer-source-measurements-501.json")
    private fun pin(path: Path): ActivationInput {
        require(Files.isRegularFile(path, NOFOLLOW_LINKS) && !Files.isSymbolicLink(path))
        return ActivationInput(path.toAbsolutePath().toString(),RecoveryCapsule.fileHash(path))
    }
    fun bind(generation: String): ForgejoCiSourcePlan {
        require(generation.matches(Regex("q-[a-f0-9]{12}")))
        val source = json.parseToJsonElement(ReleasePrivateFiles.read(repo.resolve("source.json"),8192)
            .decodeToString(throwOnInvalidSequence = true)).jsonObject
        val measurements = json.parseToJsonElement(Files.readString(measures)).jsonObject
        require(measurements.getValue("scope").jsonPrimitive.content ==
            "source-only-uncompressed-oci-layer-byte-count-not-native-image-size-or-acceptance" &&
            measurements.getValue("nativeImageStoreVerified").jsonPrimitive.boolean == false &&
            measurements.getValue("archiveRoot").jsonPrimitive.content == root.toString())
        val sizes = measurements.getValue("measurements").jsonObject
        fun image(kind: String): ManagedLaneImageBinding {
            val receipt = root.resolve("$kind.normalize.result.json")
            val proof = json.parseToJsonElement(ReleasePrivateFiles.read(receipt,8192)
                .decodeToString(throwOnInvalidSequence=true)).jsonObject
            val intent = pin(root.resolve("$kind.normalize.intent.json"))
            val archive = pin(root.resolve("$kind.oci.tar"))
            require(proof.getValue("kind").jsonPrimitive.content == kind &&
                proof.getValue("intentSha256").jsonPrimitive.content == intent.sha256 &&
                proof.getValue("archiveSha256").jsonPrimitive.content == archive.sha256 &&
                !proof.getValue("applicationStarted").jsonPrimitive.boolean &&
                !proof.getValue("qualificationEvidence").jsonPrimitive.boolean)
            val bound = sizes.getValue(kind).jsonObject
            val layerBytes = bound.getValue("uncompressedLayerBytes").jsonPrimitive.long
            require(bound.getValue("archiveSha256").jsonPrimitive.content == archive.sha256 &&
                layerBytes in 1024L..(128L*1024*1024) &&
                proof.getValue("archiveBytes").jsonPrimitive.long == Files.size(Path.of(archive.path)))
            val imageId = proof.getValue("imageId").jsonPrimitive.content
            val manifest = proof.getValue("ociManifestDigest").jsonPrimitive.content
            val reference = proof.getValue("sourceImageReference").jsonPrimitive.content
            require(reference == "localhost/p0v3-ci-$kind@$manifest")
            // Source-only uncompressed OCI layer measurement plus 32 MiB
            // extraction/metadata margin; native image Size remains a separate
            // obligatory effective readback, never inferred from this forecast.
            return ManagedLaneImageBinding(archive,Files.size(Path.of(archive.path)),
                Math.addExact(layerBytes,32L*1024*1024),"sha256:$imageId",reference,
                manifest,proof.getValue("diffIds").jsonArray.map { it.jsonPrimitive.content })
        }
        val job = image("job")
        val runner = image("runner")
        val transport = image("transport")
        val workflow = pin(Path.of(source.getValue("workflowPath").jsonPrimitive.content))
        val repository = pin(repo.resolve("trusted.bundle"))
        require(workflow.sha256 == source.getValue("workflowSha256").jsonPrimitive.content &&
            repository.sha256 == source.getValue("repositoryBundleSha256").jsonPrimitive.content &&
            source.getValue("repositoryBundlePath").jsonPrimitive.content == repository.path &&
            source.getValue("jobImage").jsonPrimitive.content == job.sourceImageReference &&
            source.getValue("jobImageId").jsonPrimitive.content == job.expectedImageId.removePrefix("sha256:"))
        val enrollment = TrustedForgejoWorkflowEnrollment(
            source.getValue("repository").jsonPrimitive.content,workflow.sha256,
            source.getValue("trustedCommit").jsonPrimitive.content,job.sourceImageReference,
            job.expectedImageId.removePrefix("sha256:"),784,2048,8192)
        ForgejoWorkflowSource.inspect(enrollment,enrollment.trustedCommit,
            GenerationRuntime.privateInput(Path.of(workflow.path)))
        return ForgejoCiSourcePlan(enrollment=enrollment,workflow=workflow,
            runnerBinary=pin(Path.of("/mnt/media/p0-v3/image-acquisition-receipts/forgejo-ci-runner-minimal-r2/context/forgejo-runner")),
            rootlessPodman=pin(Path.of("/usr/bin/podman")),
            registrationToken=ActivationInput("/mnt/media/p0-v3/release-generations/$generation/ci/fresh-registration.token",
                "0".repeat(64)),jobArchive=job,runnerImage=runner,transportImage=transport,
            graphOwnedLateUpstream=true,generation=generation,freshIssuerBootstrap=true,
            trustedRepositoryBundle=repository).also { it.validate(generation) }
    }
    fun issue(generation: String): ActivationInput {
        val plan = bind(generation)
        val dir = Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/$generation")
        ReleasePrivateFiles.directory(dir)
        require(Files.isRegularFile(dir.resolve("inventory.json"),NOFOLLOW_LINKS))
        val file = dir.resolve("forgejo-ci-source.json")
        val bytes = json.encodeToString(plan).toByteArray()
        require(!Files.exists(file,NOFOLLOW_LINKS)) { "Previously sealed CI source must not be replaced" }
        ReleasePrivateFiles.save(file,bytes)
        return ActivationInput(file.toString(),ReleaseLocks.sha256(bytes))
    }
}
