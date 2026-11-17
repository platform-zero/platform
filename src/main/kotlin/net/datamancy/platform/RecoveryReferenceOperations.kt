package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** Externally retained bootstrap anchor. Recovery control is reconstructed, not the original
 * source journals, original custody, encryption keys, functional proof or activation rights.
 */
@Serializable internal data class RecoveryBootstrapAnchor(val generation: String, val receipts: List<KopiaSnapshotReceipt>,
    val custodySha256: String, val imageId: String)

/** Called while GenerationRuntime holds generation.lock. This is the production census/bootstrap,
 * not a public caller-supplied protection list. Historic references are conservatively retained.
 */
internal object RecoveryReferenceOperations {
    private val json = Json { encodeDefaults = true }
    fun bootstrapStandalone(root: Path, externalAnchor: Path, expectedAnchorSha256: String, custody: Path): RecoveryReferences {
        require(expectedAnchorSha256.matches(Regex("[a-f0-9]{64}")) && root.isAbsolute &&
            root.normalize() == root && externalAnchor.isAbsolute && custody.isAbsolute &&
            !externalAnchor.startsWith(root) && !custody.startsWith(root)) { "External anchor must be independent of recovered control" }
        RecoveryCapsule.guard(externalAnchor, 1048576)
        RecoveryCapsule.guard(custody, 1048576)
        val anchorBytes = Files.readAllBytes(externalAnchor)
        require(ReleaseLocks.sha256(anchorBytes) == expectedAnchorSha256) { "Bootstrap source not externally anchored" }
        val anchor = json.decodeFromString<RecoveryBootstrapAnchor>(anchorBytes.decodeToString(throwOnInvalidSequence = true))
        require(anchor.generation.matches(Regex("q-[a-f0-9]{12}")) && root.fileName.toString() == "recovery-references" &&
            root.parent.fileName.toString() == anchor.generation && anchor.receipts.size in 1..128 &&
            anchor.receipts.map { it.snapshotId }.distinct().size == anchor.receipts.size &&
            anchor.custodySha256 == RecoveryCapsule.fileHash(custody) && anchor.imageId.matches(Regex("[a-f0-9]{64}"))) {
            "Recovered control anchor, custody or cohort mismatch"
        }
        anchor.receipts.forEach { receipt ->
            KopiaGenerationStore.validate(receipt)
            require(receipt.generation == anchor.generation && receipt.imageId == anchor.imageId)
        }
        ReleasePrivateFiles.directory(root.parent)
        // initialize uses exclusive creation. Partial bootstrap can never be silently repaired.
        return RecoveryReferences.initialize(root, anchor.receipts)
    }
    fun authority(base: Path, generation: String, bundle: String): RecoveryReferences {
        require(generation.matches(Regex("q-[a-f0-9]{12}")) && bundle.matches(Regex("[a-f0-9]{64}")))
        val source = base.resolve(generation); ReleasePrivateFiles.directory(source)
        require(ReleaseLocks.sha256(ReleasePrivateFiles.read(source.resolve("bundle.json"))) == bundle)
        val root = source.resolve("recovery-references")
        if (Files.exists(root, NOFOLLOW_LINKS)) return RecoveryReferences(root)
        // An absent ledger is NOT an empty history. Prior backup operations may have
        // attempted repository effects before their capture receipt was known.
        val backups = source.resolve("backups")
        if (Files.exists(backups, NOFOLLOW_LINKS)) {
            ReleasePrivateFiles.directory(backups)
            Files.list(backups).use { require(it.findAny().isEmpty) {
                "Existing held, pending or uncertain backup forbids an empty reference bootstrap"
            } }
        }
        val captures = source.resolve("kopia-captures")
        val receipts = if (Files.exists(captures, NOFOLLOW_LINKS)) {
            ReleasePrivateFiles.directory(captures)
            val paths = Files.list(captures).use { it.limit(129).toList() }; require(paths.size <= 128)
            paths.map { receipt(base, generation, bundle, it.fileName.toString()) }
        } else emptyList()
        val repository = source.resolve("kopia-store/repository")
        require(!Files.exists(repository, NOFOLLOW_LINKS)) {
            "Existing Kopia repository without an anchored reference ledger cannot be treated as a complete local census"
        }
        return RecoveryReferences.initialize(root, receipts)
    }
    fun receipt(base: Path, generation: String, bundle: String, capture: String): KopiaSnapshotReceipt {
        RuntimeBackupAccess(generation, capture, bundle).validate()
        val path = base.resolve("$generation/kopia-captures/$capture/capture.result.json")
        val outcome = json.decodeFromString<KopiaCaptureOutcome>(ReleasePrivateFiles.read(path).decodeToString())
        val snapshot = requireNotNull(outcome.snapshot)
        require(outcome.passed && outcome.failureType == null && outcome.id == capture && outcome.bundleSha256 == bundle && snapshot.id == capture &&
            snapshot.generation == generation && snapshot.bundleSha256 == bundle)
        KopiaGenerationStore.validate(snapshot)
        return snapshot
    }
    /** COORD invokes under the generation lock BEFORE the first Kopia repository/capture
     * intent/effect. This protects an as-yet-unknown snapshot ID and blocks all retention.
     */
    fun beginCapture(base: Path, access: RuntimeBackupAccess, kind: String, id: String): PendingRecoveryOperation {
        val pin = PendingRecoveryOperation(kind, id, access).also { it.validate() }
        authority(base, access.generation, access.bundleSha256).protectPending(pin)
        return pin
    }
    /** COORD invokes after reading the actual completed native capture.result.json; the
     * pending fence is replaced with an exact protected snapshot claim under one ledger lock.
     */
    fun bindCaptured(base: Path, pin: PendingRecoveryOperation, receipt: KopiaSnapshotReceipt) {
        pin.validate()
        authority(base, pin.access.generation, pin.access.bundleSha256).bindCaptured(pin, receipt)
    }
    /** COORD calls after result.json, resume.verified.json AND actual source audit saved. */
    fun completeBackup(base: Path, access: RuntimeBackupAccess) {
        access.validate()
        authority(base, access.generation, access.bundleSha256).completeBackup(access)
    }
    fun captured(base: Path, snapshot: KopiaSnapshotReceipt) {
        KopiaGenerationStore.validate(snapshot)
        authority(base, snapshot.generation, snapshot.bundleSha256).register(snapshot)
    }
    fun protect(base: Path, snapshot: KopiaSnapshotReceipt, kind: String, operation: String) {
        val refs = authority(base, snapshot.generation, snapshot.bundleSha256)
        refs.register(snapshot); refs.protect(kind, operation, setOf(snapshot.snapshotId))
    }
    fun retain(base: Path, inventory: AcquiredInventory, generation: String, bundleHash: String, operation: String,
        custody: Path = Path.of("/mnt/media/p0-v3/kopia-custody")): KopiaRetentionResult {
        val refs = authority(base, generation, bundleHash)
        val bundle = json.decodeFromString<GenerationBundle>(ReleasePrivateFiles.read(base.resolve("$generation/bundle.json")).decodeToString())
        require(bundle.request.id == generation)
        return KopiaGenerationStore.real(inventory, bundle.request.store).retain(base.resolve("$generation/kopia-store/repository"),
            custody.resolve("$generation.env"), generation, operation, refs)
    }
}
