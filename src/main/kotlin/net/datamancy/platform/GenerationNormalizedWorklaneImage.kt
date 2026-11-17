package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** NEW generation binds locally normalized platform index, never retroactively
 * acknowledges the lost original build. Full OCI VFS census precedes pinning. */
internal object GenerationNormalizedWorklaneImage {
    private val json=Json { encodeDefaults=true;ignoreUnknownKeys=false }
    private const val generation="q-4d3c1cb287e5"
    private const val archiveSha="8c1cc42df10cd5086b33e817012e08a63b3ae6899270b1c76494dd831224e7bd"
    private val r2=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/worklane-platform-r2")
    private const val r2ResultSha="67bc6a57deb494066ef1d2090a2fcdd03bd707a93c942847ed6b7afedb2145db"
    private val normalized=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/worklane-platform-r3")
    private val anchor=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/$generation")
    private val archive=normalized.resolve("worklane-platform.oci.tar")
    private val source=anchor.resolve("worklane-normalized-image-binding.json")
    /** Same immutable r3 authority at prospective assembly and sealed runtime load. */
    fun requireSelected(candidate:ManagedLaneImageBinding?):ManagedLaneImageBinding {
        val selected=requireNotNull(candidate)
        require(selected.archive.path==archive.toString() && selected.archive.sha256==archiveSha &&
            selected.maximumUnpackedBytes==34359738368L &&
            Files.isRegularFile(archive,NOFOLLOW_LINKS) && archive.toRealPath()==archive &&
            Files.size(archive)==selected.archiveBytes &&
            Files.getPosixFilePermissions(archive)==PosixFilePermissions.fromString("r--------") &&
            RecoveryCapsule.fileHash(archive)==archiveSha) {
            "Only the immutable mode-0400 r3 Worklane source is admitted" }
        return selected
    }
    fun planned():ManagedLaneImageBinding {
        val original=GenerationR9ManagedObservedImage.bind("q-5962a9fda75b")
        val originalBytes=ReleasePrivateFiles.read(Path.of(
            "/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/q-5962a9fda75b/worklane-export.result.json"),8192)
        val old=json.parseToJsonElement(originalBytes.decodeToString(throwOnInvalidSequence=true)).jsonObject
        val r2Bytes=ReleasePrivateFiles.read(r2.resolve("normalize.result.json"),32768)
        val r2Proof=json.parseToJsonElement(r2Bytes.decodeToString(throwOnInvalidSequence=true)).jsonObject
        val r2Archive=r2.resolve("worklane-platform.oci.tar")
        val intent=ReleasePrivateFiles.read(normalized.resolve("pin.intent.json"),32768)
        val proof=json.parseToJsonElement(ReleasePrivateFiles.read(normalized.resolve("pin.result.json"),32768)
            .decodeToString(throwOnInvalidSequence=true)).jsonObject
        val claim=json.parseToJsonElement(intent.decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(!old.getValue("originalBuildAcknowledged").jsonPrimitive.boolean &&
            old.getValue("separateExportAcknowledged").jsonPrimitive.boolean &&
            proof.getValue("intentSha256").jsonPrimitive.content==ReleaseLocks.sha256(intent) &&
            ReleaseLocks.sha256(r2Bytes)==r2ResultSha &&
            proof.getValue("r2NormalizeResultSha256").jsonPrimitive.content==r2ResultSha &&
            proof.getValue("r2ArchiveSha256").jsonPrimitive.content==archiveSha &&
            claim.getValue("r2NormalizeResultSha256").jsonPrimitive.content==r2ResultSha &&
            claim.getValue("sourceMode").jsonPrimitive.content=="0600" &&
            claim.getValue("outputMode").jsonPrimitive.content=="0400" &&
            !claim.getValue("originalBuildAcknowledged").jsonPrimitive.boolean &&
            !claim.getValue("nativeImportOccurred").jsonPrimitive.boolean &&
            proof.getValue("before")==r2Proof.getValue("before") &&
            proof.getValue("after")==r2Proof.getValue("after") &&
            proof.getValue("originalArchiveSha256")==r2Proof.getValue("originalArchiveSha256") &&
            Files.isRegularFile(r2Archive,NOFOLLOW_LINKS) &&
            Files.getPosixFilePermissions(r2Archive)==PosixFilePermissions.fromString("rw-------") &&
            RecoveryCapsule.fileHash(r2Archive)==archiveSha &&
            !proof.getValue("originalBuildAcknowledged").jsonPrimitive.boolean &&
            proof.getValue("separateExportAcknowledged").jsonPrimitive.boolean &&
            !proof.getValue("nativeImportOccurred").jsonPrimitive.boolean &&
            !proof.getValue("nativeApplicationStarted").jsonPrimitive.boolean &&
            !proof.getValue("qualificationEvidence").jsonPrimitive.boolean &&
            proof.getValue("originalArchiveSha256").jsonPrimitive.content==original.archive.sha256 &&
            proof.getValue("archiveSha256").jsonPrimitive.content==archiveSha &&
            proof.getValue("archiveMode").jsonPrimitive.content=="0400")
        // Mirror the PREPARE backend's archive-source gate BEFORE hash or OCI
        // inspection: absolute, outside managed control, regular, exact size,
        // nonwritable, and VFS graph + 10 GiB free on the target store.
        val base=GenerationRuntime.BASE
        require(archive.isAbsolute && archive.normalize()==archive && archive.toRealPath()==archive &&
            !archive.startsWith(base.resolve(generation).resolve("managed/control")) &&
            Files.isRegularFile(archive,NOFOLLOW_LINKS) && !Files.isSymbolicLink(archive) &&
            Files.size(archive)==proof.getValue("archiveBytes").jsonPrimitive.long &&
            Files.getPosixFilePermissions(archive)==PosixFilePermissions.fromString("r--------") &&
            Files.getFileStore(base).usableSpace>=Math.addExact(34359738368L,10L*1024*1024*1024)) {
            "Read-only Worklane OCI archive or prospective VFS/headroom missing before hash" }
        require(RecoveryCapsule.fileHash(archive)==archiveSha) {
            "Read-only Worklane OCI archive bytes differ from local pin result" }
        val before=proof.getValue("before").jsonObject
        val after=proof.getValue("after").jsonObject
        require(before["platform"]==JsonNull &&
            after.getValue("platform").jsonObject.getValue("os").jsonPrimitive.content=="linux" &&
            after.getValue("platform").jsonObject.getValue("architecture").jsonPrimitive.content=="amd64" &&
            after.getValue("imageId").jsonPrimitive.content==original.expectedImageId &&
            after.getValue("manifestDigest").jsonPrimitive.content==original.expectedManifestDigest &&
            listOf("configSha256","manifestSha256","layers","configPlatform").all { before[it]==after[it] })
        return original.copy(archive=ActivationInput(archive.toString(),archiveSha),
            archiveBytes=Files.size(archive),maximumUnpackedBytes=34359738368L).also {
            ManagedLaneOciArchive.inspect(archive,it,System.currentTimeMillis()+600000L,
                Files.getFileStore(archive).blockSize)
        }
    }
    private fun target(value:String):Path = if(value==generation)source else
        Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/$value/worklane-normalized-image-binding.json")
    fun issue(value:String):ActivationInput {
        require(value in setOf(generation,GenerationAfterNativeImportLineage.generation,
            GenerationAfterCapacityRefusalLineage.generation,GenerationAfterQ273Lineage.generation,
            GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
            GenerationAfterQ07Lineage.generation) &&
            !Files.exists(GenerationRuntime.BASE.resolve(value),NOFOLLOW_LINKS))
        GenerationAfterNativeImportLineage.beforeSourceIssue(value)
        GenerationAfterCapacityRefusalLineage.beforeSourceIssue(value)
        GenerationAfterQ273Lineage.beforeSourceIssue(value)
        GenerationAfterQ583Lineage.beforeSourceIssue(value)
        GenerationAfterQ9bLineage.beforeSourceIssue(value)
        GenerationAfterQ07Lineage.beforeSourceIssue(value)
        val file=target(value)
        ReleasePrivateFiles.directory(file.parent)
        val plan=planned()
        require(!Files.exists(file,NOFOLLOW_LINKS))
        val bytes=json.encodeToString(plan).encodeToByteArray()
        ReleasePrivateFiles.save(file,bytes)
        return ActivationInput(file.toString(),ReleaseLocks.sha256(bytes))
    }
    fun verify(value:String):ManagedLaneImageBinding {
        require(value in setOf(generation,GenerationAfterNativeImportLineage.generation,
            GenerationAfterCapacityRefusalLineage.generation,GenerationAfterQ273Lineage.generation,
            GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
            GenerationAfterQ07Lineage.generation))
        GenerationAfterNativeImportLineage.beforeSourceIssue(value)
        GenerationAfterCapacityRefusalLineage.beforeSourceIssue(value)
        GenerationAfterQ273Lineage.beforeSourceIssue(value)
        GenerationAfterQ583Lineage.beforeSourceIssue(value)
        GenerationAfterQ9bLineage.beforeSourceIssue(value)
        GenerationAfterQ07Lineage.beforeSourceIssue(value)
        val bytes=ReleasePrivateFiles.read(target(value),65536)
        val image=json.decodeFromString<ManagedLaneImageBinding>(bytes.decodeToString(throwOnInvalidSequence=true))
        require(image==planned())
        return image
    }
}
