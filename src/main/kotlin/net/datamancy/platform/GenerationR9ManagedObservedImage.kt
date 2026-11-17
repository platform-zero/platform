package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** Independent content-observed Worklane OCI source. The original build has
 * NO durable ACK: only a separately journaled OCI export with verified blobs
 * can be pinned here. Native UID 784 image import/start is still outstanding.
 */
internal object GenerationR9ManagedObservedImage {
    private val json=Json { encodeDefaults=true; ignoreUnknownKeys=false }
    private val root=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/q-5962a9fda75b")
    fun bind(generation: String): ManagedLaneImageBinding {
        require(generation=="q-5962a9fda75b")
        val observationPath=Path.of("/home/gerald/p0_v3/.coord/rapid-completion/core-r9-managed-original-readonly-reconcile-526.json")
        require(Files.isRegularFile(observationPath,NOFOLLOW_LINKS) && !Files.isSymbolicLink(observationPath) &&
            Files.size(observationPath) in 1..8192)
        val observationBytes=Files.readAllBytes(observationPath)
        val observed=json.parseToJsonElement(observationBytes.decodeToString(throwOnInvalidSequence=true)).jsonObject
        val original=json.parseToJsonElement(ReleasePrivateFiles.read(root.resolve("worklane-export.result.json"),8192)
            .decodeToString(throwOnInvalidSequence=true)).jsonObject
        val source=Path.of("/home/gerald/p0_v3/worklane/Containerfile.v3")
        val intent=json.parseToJsonElement(ReleasePrivateFiles.read(root.resolve("fresh-image-build.intent.json"),8192)
            .decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(intent.getValue("sourceHashes").jsonObject.getValue("Containerfile.v3").jsonPrimitive.content ==
            ReleaseLocks.sha256(Files.readAllBytes(source)) &&
            !observed.getValue("originalBuildAcknowledged").jsonPrimitive.boolean &&
            !original.getValue("originalBuildAcknowledged").jsonPrimitive.boolean &&
            original.getValue("separateExportAcknowledged").jsonPrimitive.boolean &&
            original.getValue("observationSha256").jsonPrimitive.content ==
                ReleaseLocks.sha256(observationBytes) &&
            original.getValue("exportExitSha256").jsonPrimitive.content ==
                ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("worklane-export-exit.result.json"),8192)))
        val archive=root.resolve("worklane-observed.oci.tar")
        require(Files.isRegularFile(archive,NOFOLLOW_LINKS) && !Files.isSymbolicLink(archive))
        val digest=RecoveryCapsule.fileHash(archive)
        val id=original.getValue("imageId").jsonPrimitive.content
        val manifest=original.getValue("ociManifestDigest").jsonPrimitive.content
        val size=original.getValue("imageSizeBytes").jsonPrimitive.long
        require(original.getValue("archiveSha256").jsonPrimitive.content==digest &&
            original.getValue("archiveBytes").jsonPrimitive.long==Files.size(archive) &&
            observed.getValue("imageId").jsonPrimitive.content==id &&
            observed.getValue("imageSizeBytes").jsonPrimitive.long==size &&
            manifest.matches(Regex("sha256:[a-f0-9]{64}")) && id.matches(Regex("sha256:[a-f0-9]{64}")))
        val layers=original.getValue("layerDiffIds").jsonArray.map { it.jsonPrimitive.content }
        require(layers==observed.getValue("layerDiffIds").jsonArray.map { it.jsonPrimitive.content })
        // Measured source image Size plus 128 MiB import/metadata margin; this
        // bounds rootless admission, not a claim of future running RSS.
        return ManagedLaneImageBinding(ActivationInput(archive.toString(),digest),Files.size(archive),
            Math.addExact(size,128L*1048576),id,
            "localhost/p0v3-r9-worklane@$manifest",manifest,layers)
    }
    fun issue(generation: String): ActivationInput {
        require(generation.matches(Regex("q-[a-f0-9]{12}")))
        // A failed source generation cannot be used for identity or runtime
        // state, but its separately acknowledged, immutable OCI archive is a
        // content-addressed product image: re-observe it without rebuilding or
        // inventing the original missing build ACK.
        val image=bind("q-5962a9fda75b")
        val original=root.resolve("worklane-observed-image-binding.json")
        val bytes=ReleasePrivateFiles.read(original,16384)
        require(ReleaseLocks.sha256(bytes)=="405f836b19f15c750dd7294caa74bdeea32ee40187acd6725c527a0b84cee0bd" &&
            json.decodeFromString<ManagedLaneImageBinding>(bytes.decodeToString(throwOnInvalidSequence=true))==image)
        val target=if(generation=="q-5962a9fda75b") root else
            Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/$generation").also {
                ReleasePrivateFiles.directory(it)
                require(Files.exists(it.resolve("source-seed.json"),NOFOLLOW_LINKS))
            }
        val file=target.resolve("worklane-observed-image-binding.json")
        require(!Files.exists(file,NOFOLLOW_LINKS)) { "Observed managed image source already pinned; no replacement" }
        ReleasePrivateFiles.save(file,bytes)
        return ActivationInput(file.toString(),ReleaseLocks.sha256(bytes))
    }
}
