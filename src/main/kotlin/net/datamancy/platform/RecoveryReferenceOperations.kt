package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.json.Json

/** Called while GenerationRuntime holds generation.lock. This is the production census/bootstrap,
 * not a public caller-supplied protection list. Historic references are conservatively retained.
 */
internal object RecoveryReferenceOperations {
    private val json = Json { encodeDefaults = true }
    fun authority(base: Path, generation: String, bundle: String): RecoveryReferences {
        require(generation.matches(Regex("q-[a-f0-9]{12}")) && bundle.matches(Regex("[a-f0-9]{64}")))
        val source = base.resolve(generation); ReleasePrivateFiles.directory(source)
        require(ReleaseLocks.sha256(ReleasePrivateFiles.read(source.resolve("bundle.json"))) == bundle)
        val root = source.resolve("recovery-references")
        if (Files.exists(root, NOFOLLOW_LINKS)) return RecoveryReferences(root)
        val captures = source.resolve("kopia-captures")
        val receipts = if (Files.exists(captures, NOFOLLOW_LINKS)) {
            ReleasePrivateFiles.directory(captures)
            val paths = Files.list(captures).use { it.limit(129).toList() }; require(paths.size <= 128)
            paths.map { receipt(base, generation, bundle, it.fileName.toString()) }
        } else emptyList()
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
