package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable internal data class RecoveryMemberCheck(val name: String, val fingerprint: String, val retiredInitializers: Set<String>,
    val volumeEntries: Map<String, Int>)
@Serializable internal data class GenerationRecoveryCheck(val generation: String, val capsule: String, val bundleSha256: String,
    val archiveSha256: String, val members: List<RecoveryMemberCheck>, val runtimeImported: Boolean = false,
    val functionalRestoreVerified: Boolean = false, val kopiaSnapshotId: String? = null, val kopiaReceiptSha256: String? = null)
internal data class RecoveredGeneration(val bundle: GenerationBundle, val manifest: CapsuleManifest, val root: Path,
    val check: GenerationRecoveryCheck)

/** Re-bind recovered plaintext to a verification obtained directly from the encrypted capsule, never a caller-authored receipt.
 * This is a pre-import gate, not authorization to execute arbitrary archived process definitions.
 */
internal object GenerationRecovery {
    private val json = Json { ignoreUnknownKeys = false; encodeDefaults = true }
    private fun directory(path: Path) {
        require(path.isAbsolute && path.normalize() == path && path.toRealPath() == path && Files.isDirectory(path, NOFOLLOW_LINKS) &&
            Files.getPosixFilePermissions(path) == PosixFilePermissions.fromString("rwx------") &&
            (Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == UnixSystem().uid) { "Private recovery directory required" }
    }
    private data class PayloadSeal(val id: String, val generation: String, val bundleSha256: String,
        val manifestSha256: String, val files: Int, val plaintextBytes: Long, val archiveSha256: String = "",
        val kopiaSnapshotId: String? = null, val kopiaReceiptSha256: String? = null)
    fun validate(root: Path, verified: CapsuleVerification): RecoveredGeneration {
        require(verified.authenticated && !verified.functionalRestoreVerified)
        return validatePayload(root, PayloadSeal(verified.id, verified.generation, verified.bundleSha256,
            verified.manifestSha256, verified.files, verified.plaintextBytes, verified.archiveSha256))
    }
    /** Caller must first perform native read-only Kopia verification/restoration with this exact receipt. */
    fun validateKopia(root: Path, verified: KopiaSnapshotReceipt): RecoveredGeneration {
        KopiaGenerationStore.validate(verified)
        return validatePayload(root, PayloadSeal(verified.id, verified.generation, verified.bundleSha256,
            verified.manifestSha256, verified.files, verified.plaintextBytes, kopiaSnapshotId = verified.snapshotId,
            kopiaReceiptSha256 = KopiaGenerationStore.receiptHash(verified)))
    }
    private fun validatePayload(root: Path, verified: PayloadSeal): RecoveredGeneration {
        directory(root)
        fun bytes(relative: String): ByteArray {
            val path = root.resolve(relative)
            RecoveryCapsule.guard(path, 1048576)
            return Files.readAllBytes(path)
        }
        val manifestBytes = bytes("manifest.json")
        require(ReleaseLocks.sha256(manifestBytes) == verified.manifestSha256) { "Recovered manifest changed" }
        val manifest = json.decodeFromString<CapsuleManifest>(manifestBytes.decodeToString(throwOnInvalidSequence = true))
        require(manifest.schemaVersion == 1 && manifest.id == verified.id && manifest.generation == verified.generation &&
            manifest.bundleSha256 == verified.bundleSha256 && manifest.files.size == verified.files &&
            manifest.files.sumOf { it.bytes } == verified.plaintextBytes) { "Foreign recovery observation" }
        RecoverySegments.validate(manifest)
        RecoveryControllerPayloads.validate(manifest)
        val reconstructed = manifest.volumes.associateBy { it.name }
        val files = manifest.files.associateBy { it.name }
        require(files.size == manifest.files.size && files.size in 1..4096 &&
            manifest.files.all { it.bytes in 1..RecoveryCapsule.MAX_FILE && it.sha256.matches(Regex("[a-f0-9]{64}")) } &&
            manifest.files.sumOf { it.bytes } <= RecoveryCapsule.MAX_TOTAL)
        val actual = mutableSetOf<String>()
        Files.walk(root).use { paths -> paths.forEach { path ->
            if (Files.isDirectory(path, NOFOLLOW_LINKS)) directory(path)
            else {
                val name = root.relativize(path).toString()
                RecoveryCapsule.guard(path, if (name in reconstructed) RecoveryCapsule.MAX_TOTAL else RecoveryCapsule.MAX_FILE)
                actual += name
            }
        } }
        require(actual - reconstructed.keys == files.keys + "manifest.json") { "Unexpected or missing recovered file" }
        for (file in manifest.files) {
            val path = root.resolve(file.name)
            require(path.normalize() == path && path.startsWith(root) && file.name.split('/').none { it in setOf("", ".", "..") })
            require(Files.size(path) == file.bytes && RecoveryCapsule.fileHash(path) == file.sha256) { "Recovered payload changed" }
        }
        RecoverySegments.materialize(root, manifest)
        val bundleBytes = bytes("source/bundle.json")
        require(ReleaseLocks.sha256(bundleBytes) == verified.bundleSha256) { "Recovered bundle does not match expected source" }
        val bundle = json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString(throwOnInvalidSequence = true))
        require(bundle.members.all { it.spec.store == bundle.request.store }) { "Mixed recovered runtime stores" }
        require(bundle.request.id == verified.generation && bundle.members.map { it.member } == GenerationRuntime.validateScope(bundle.request))
        SiteOwnerships.checkSealed(bundle)
        val memory = bundle.members.sumOf { p -> p.spec.processes.filterNot { it.oneShot }.sumOf { it.memoryMiB.toLong() } +
            (p.spec.processes.filter { it.oneShot }.maxOfOrNull { it.memoryMiB } ?: 0) }
        require(memory == bundle.memoryReservationMiB && bundle.request.diskReservationMiB >= bundle.members.sumOf { it.spec.volumes.size.toLong() * 1024 })
        require(manifest.members.map { it.name } == bundle.members.map { it.member.name }) { "Recovery member cohort mismatch" }
        val expectedFiles = mutableSetOf("source/bundle.json").apply { addAll(manifest.controllerFiles) }
        val checked = bundle.members.map { pin ->
            val name = pin.member.name
            require(pin.spec.name == name)
            PrivateDeployment.validate(pin.spec)
            val specBytes = bytes("$name/spec.json"); expectedFiles += "$name/spec.json"
            require(ReleaseLocks.sha256(specBytes) == pin.manifestSha256 &&
                json.decodeFromString<PrivateDeploymentSpec>(specBytes.decodeToString()) == pin.spec) { "Foreign recovered process definition" }
            require(PrivateDeployment.expectedFingerprint(pin.spec, pin.inputHashes) == pin.runtimeFingerprint)
            for ((file, digest) in pin.inputHashes) {
                val relative = "$name/inputs/$file"; expectedFiles += relative
                require(ReleaseLocks.sha256(bytes(relative)) == digest) { "Recovered credential or configuration mismatch" }
            }
            val observation = manifest.members.single { it.name == name }
            val initialized = pin.spec.processes.filter { it.oneShot }.map { it.id }.toSet()
            require(observation.fingerprint == pin.runtimeFingerprint && observation.fenceId.isNotBlank() &&
                observation.completedInitializers == initialized && observation.statuses.map { it.id }.toSet() == pin.spec.processes.map { it.id }.toSet() &&
                observation.statuses.size == pin.spec.processes.size && observation.statuses.all {
                    if (it.id in initialized) it.state in setOf("completed", "exited") && it.exitCode == 0
                    else it.state == "exited" && it.exitCode in setOf(0, 143)
                }) { "Unfinished initialization or unclean source state" }
            val jobsPath = "$name/jobs.json"
            if (jobsPath in files) {
                expectedFiles += jobsPath
                val data = bytes(jobsPath)
                val jobs = json.decodeFromString<RuntimeJobs>(data.decodeToString())
                val checksum = ReleaseLocks.sha256(Json.encodeToString(jobs.copy(checksum = "")).toByteArray())
                require(jobs.fingerprint == pin.runtimeFingerprint && jobs.started == initialized && jobs.completed == initialized &&
                    jobs.checksum == checksum && Json.encodeToString(jobs).toByteArray().contentEquals(data) &&
                    ReleaseLocks.sha256(data) == observation.jobsSha256) { "Invalid recovered initializer ledger" }
            } else require(initialized.isEmpty() && observation.jobsSha256 == ReleaseLocks.sha256("no-initializers\n${pin.runtimeFingerprint}\n".toByteArray())) {
                "Missing recovered initializer ledger"
            }
            val volumes = pin.spec.volumes.associate { volume ->
                val relative = "$name/volumes/${volume.id}.tar"
                expectedFiles += reconstructed[relative]?.segments ?: listOf(relative)
                volume.id to VolumeTar.inspect(root.resolve(relative), volume.userId).size
            }
            RecoveryMemberCheck(name, pin.runtimeFingerprint, initialized, volumes)
        }
        require(files.keys == expectedFiles && reconstructed.keys.all { name -> bundle.members.any { pin ->
            pin.spec.volumes.any { name == "${pin.member.name}/volumes/${it.id}.tar" }
        } }) { "Recovery payload set is not the exact declared cohort" }
        return RecoveredGeneration(bundle, manifest, root, GenerationRecoveryCheck(verified.generation, verified.id,
            verified.bundleSha256, verified.archiveSha256, checked, kopiaSnapshotId = verified.kopiaSnapshotId,
            kopiaReceiptSha256 = verified.kopiaReceiptSha256))
    }
}
