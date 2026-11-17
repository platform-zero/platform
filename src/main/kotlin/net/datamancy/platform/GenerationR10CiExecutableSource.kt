package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.*

/** Versioned CI source for the fresh no-start successor. The historical
 * image-context source is promised 0600 and MUST NOT be chmodded. Only the
 * original module-verified host build is selected here; native installation
 * still copies into UID 784 mode 0700 and verifies the installed executable. */
internal object GenerationR10CiExecutableSource {
    private const val successor="q-dd36ebcf43ef"
    private const val sha="0c4a3f0c4a60632a5914981752a7afe9791a98bdd481296992b412abef5faf0a"
    private val binary=Path.of("/mnt/media/p0-v3/ci-runner/bin/forgejo-runner-v3.5.1")
    private val receipt=Path.of("/mnt/media/p0-v3/image-acquisition-receipts/forgejo-runner-binary-r2")
    private val json=Json { encodeDefaults=true; ignoreUnknownKeys=false }
    fun bind(generation:String):ForgejoCiSourcePlan {
        require(generation==successor && Files.isRegularFile(binary,NOFOLLOW_LINKS) &&
            !Files.isSymbolicLink(binary) && Files.getPosixFilePermissions(binary)==
            PosixFilePermissions.fromString("rwx------") && Files.isExecutable(binary) &&
            Files.size(binary) in 1024L..24000000L && RecoveryCapsule.fileHash(binary)==sha)
        val intent=ReleasePrivateFiles.read(receipt.resolve("build.intent.json"),8192)
        val result=json.parseToJsonElement(ReleasePrivateFiles.read(receipt.resolve("build.result.json"),8192)
            .decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(result.getValue("intentSha256").jsonPrimitive.content==ReleaseLocks.sha256(intent) &&
            result.getValue("binarySha256").jsonPrimitive.content==sha &&
            result.getValue("binaryBytes").jsonPrimitive.long==Files.size(binary) &&
            !result.getValue("applicationStarted").jsonPrimitive.boolean &&
            !result.getValue("runnerRegistered").jsonPrimitive.boolean &&
            !result.getValue("qualificationEvidence").jsonPrimitive.boolean)
        val original=Path.of("/mnt/media/p0-v3/image-acquisition-receipts/forgejo-ci-runner-minimal-r2/context/forgejo-runner")
        require(Files.getPosixFilePermissions(original)==PosixFilePermissions.fromString("rw-------") &&
            RecoveryCapsule.fileHash(original)==sha)
        return GenerationR9CiSourceBindings.bind(generation).copy(
            runnerBinary=ActivationInput(binary.toString(),sha)).also { it.validate(generation) }
    }
    fun rebudgeted(generation:String):ForgejoCiSourcePlan {
        require(generation==successor)
        val earlier=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/$successor/forgejo-ci-source.r3-executable.json")
        val bytes=ReleasePrivateFiles.read(earlier,65536)
        require(ReleaseLocks.sha256(bytes)=="019dca2c9243c481ed9647a317bd29a339cb5f05aababc72eb1403c2b70a3dfe")
        val old=json.decodeFromString<ForgejoCiSourcePlan>(bytes.decodeToString(throwOnInvalidSequence=true))
        require(old==bind(generation))
        val vfsLimit=1024L*1024*1024
        val plan=old.copy(jobArchive=old.jobArchive.copy(maximumUnpackedBytes=vfsLimit),
            runnerImage=requireNotNull(old.runnerImage).copy(maximumUnpackedBytes=vfsLimit),
            transportImage=requireNotNull(old.transportImage).copy(maximumUnpackedBytes=vfsLimit))
        plan.validate(generation)
        ForgejoCiNativeSourceAdmission.checkProspective(plan)
        return plan
    }
    fun issueRebudgeted(generation:String):ActivationInput {
        val plan=rebudgeted(generation)
        val dir=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/$generation")
        ReleasePrivateFiles.directory(dir)
        val file=dir.resolve("forgejo-ci-source.r4-vfs-budget.json")
        require(!Files.exists(file,NOFOLLOW_LINKS))
        val bytes=json.encodeToString(plan).encodeToByteArray()
        ReleasePrivateFiles.save(file,bytes)
        return ActivationInput(file.toString(),ReleaseLocks.sha256(bytes))
    }
    fun freshAfterPreUnit(generation:String):ForgejoCiSourcePlan {
        require(generation in setOf("q-4d3c1cb287e5",GenerationAfterNativeImportLineage.generation,
            GenerationAfterCapacityRefusalLineage.generation,GenerationAfterQ273Lineage.generation,
            GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
            GenerationAfterQ07Lineage.generation) &&
            Files.isRegularFile(binary,NOFOLLOW_LINKS) &&
            Files.getPosixFilePermissions(binary)==PosixFilePermissions.fromString("rwx------") &&
            Files.isExecutable(binary) && RecoveryCapsule.fileHash(binary)==sha)
        GenerationAfterNativeImportLineage.beforeSourceIssue(generation)
        GenerationAfterCapacityRefusalLineage.beforeSourceIssue(generation)
        GenerationAfterQ273Lineage.beforeSourceIssue(generation)
        GenerationAfterQ583Lineage.beforeSourceIssue(generation)
        GenerationAfterQ9bLineage.beforeSourceIssue(generation)
        GenerationAfterQ07Lineage.beforeSourceIssue(generation)
        require(bind(successor).runnerBinary.sha256==sha)
        val base=GenerationR9CiSourceBindings.bind(generation)
        val max=1024L*1024*1024
        val plan=base.copy(runnerBinary=ActivationInput(binary.toString(),sha),
            jobArchive=base.jobArchive.copy(maximumUnpackedBytes=max),
            runnerImage=requireNotNull(base.runnerImage).copy(maximumUnpackedBytes=max),
            transportImage=requireNotNull(base.transportImage).copy(maximumUnpackedBytes=max))
        ForgejoCiNativeSourceAdmission.checkProspective(plan)
        return plan
    }
    fun issueAfterPreUnit(generation:String):ActivationInput {
        val plan=freshAfterPreUnit(generation)
        val dir=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/$generation")
        ReleasePrivateFiles.directory(dir)
        require(Files.isRegularFile(dir.resolve("inventory.json"),NOFOLLOW_LINKS))
        val file=dir.resolve("forgejo-ci-source.r4-vfs-budget.json")
        require(!Files.exists(file,NOFOLLOW_LINKS))
        val bytes=json.encodeToString(plan).encodeToByteArray()
        ReleasePrivateFiles.save(file,bytes)
        return ActivationInput(file.toString(),ReleaseLocks.sha256(bytes))
    }
    fun issue(generation:String):ActivationInput {
        val plan=bind(generation)
        val dir=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/$generation")
        ReleasePrivateFiles.directory(dir)
        require(Files.isRegularFile(dir.resolve("inventory.json"),NOFOLLOW_LINKS))
        val file=dir.resolve("forgejo-ci-source.r3-executable.json")
        require(!Files.exists(file,NOFOLLOW_LINKS))
        val bytes=json.encodeToString(plan).encodeToByteArray()
        ReleasePrivateFiles.save(file,bytes)
        return ActivationInput(file.toString(),ReleaseLocks.sha256(bytes))
    }
}
