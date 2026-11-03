package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable internal data class RecoveryReferenceEvent(
    val sequence: Int, val previous: String, val kind: String, val id: String,
    val snapshots: Set<String> = emptySet(), val receipt: KopiaSnapshotReceipt? = null,
    val evidenceSha256: String? = null
)

/** Private write-ahead authority shared by every recovery-reference writer and native retention.
 * References are intentionally monotonic: rollback, imports, qualification, activation and unknown
 * outcomes never lose protection because a process exited or a timeout elapsed. No caller-supplied
 * list can subtract a reference. Bootstrap protects every pre-existing recovery point.
 *
 * Lock order: generation -> reference ledger -> native retention repository. Writers publish a
 * claim BEFORE acquiring a repository lock, releasing this ledger lock before their effects.
 */
internal class RecoveryReferences(private val root: Path) : KopiaRetentionAuthority {
    companion object {
        private val json = Json { encodeDefaults = true }
        private val hash = Regex("[a-f0-9]{64}")
        private val kinds = setOf("rollback", "import", "qualification", "activation", "weekly", "unknown")
        fun initialize(root: Path, existing: List<KopiaSnapshotReceipt>): RecoveryReferences {
            Files.createDirectory(root, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(root.parent)
            val ledger = RecoveryReferences(root)
            // Partial bootstrap has no ready marker and cannot authorize retention or new claims.
            existing.forEach(KopiaGenerationStore::validate)
            require(existing.map { it.snapshotId }.distinct().size == existing.size)
            ReleasePrivateFiles.save(root.resolve("bootstrap.json"), json.encodeToString(existing).toByteArray())
            ReleasePrivateFiles.save(root.resolve("ready"), ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bootstrap.json"))).toByteArray())
            return ledger
        }
    }
    private data class State(val receipts: MutableMap<String, KopiaSnapshotReceipt>, val references: MutableSet<String>,
        val verified: MutableSet<String>, val retired: MutableSet<String>, var sequence: Int, var head: String)
    private fun state(): State {
        val bootstrap = ReleasePrivateFiles.read(root.resolve("bootstrap.json"))
        val head = ReleaseLocks.sha256(bootstrap)
        require(ReleasePrivateFiles.read(root.resolve("ready")).decodeToString() == head) { "Incomplete reference bootstrap" }
        val initial = json.decodeFromString<List<KopiaSnapshotReceipt>>(bootstrap.decodeToString())
        initial.forEach(KopiaGenerationStore::validate)
        require(initial.map { it.snapshotId }.distinct().size == initial.size)
        val state = State(initial.associateBy { it.snapshotId }.toMutableMap(), initial.map { it.snapshotId }.toMutableSet(), mutableSetOf(), mutableSetOf(), 0, head)
        val files = Files.list(root).use { it.limit(4097).toList() }
        require(files.size <= 4096 && files.all { it.fileName.toString() in setOf("bootstrap.json", "ready", "control.lock", "retention.pending") ||
            it.fileName.toString().matches(Regex("[0-9]{8}\\.json")) }) { "Unknown reference ledger entry or history limit" }
        for (file in files.filter { it.fileName.toString().matches(Regex("[0-9]{8}\\.json")) }.sorted()) {
            val bytes = ReleasePrivateFiles.read(file)
            val event = json.decodeFromString<RecoveryReferenceEvent>(bytes.decodeToString())
            require(event.sequence == state.sequence + 1 && file.fileName.toString() == "%08d.json".format(event.sequence) && event.previous == state.head)
            apply(state, event)
            state.sequence = event.sequence; state.head = ReleaseLocks.sha256(bytes)
        }
        return state
    }
    private fun apply(state: State, event: RecoveryReferenceEvent) {
        require(event.id.matches(Regex("[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")))
        when (event.kind) {
            "snapshot" -> {
                val receipt = requireNotNull(event.receipt); KopiaGenerationStore.validate(receipt)
                require(event.snapshots == setOf(receipt.snapshotId) && receipt.snapshotId !in state.receipts && receipt.snapshotId !in state.retired)
                state.receipts[receipt.snapshotId] = receipt
            }
            in kinds -> { require(state.receipts.keys.containsAll(event.snapshots) && event.snapshots.isNotEmpty()); state.references += event.snapshots }
            "verified" -> {
                require(state.receipts.keys.containsAll(event.snapshots) && event.snapshots.size == 1 && event.evidenceSha256?.matches(hash) == true)
                state.verified += event.snapshots
            }
            "deleted" -> {
                require(state.receipts.keys.containsAll(event.snapshots) && event.snapshots.none { it in state.references })
                event.snapshots.forEach { state.receipts.remove(it); state.verified.remove(it); state.retired.add(it) }
            }
            else -> error("Unknown reference event")
        }
    }
    private fun append(state: State, kind: String, id: String, snapshots: Set<String>, receipt: KopiaSnapshotReceipt? = null, evidence: String? = null) {
        require(state.sequence < 4000) { "Reference history full; evidence is never compacted implicitly" }
        val event = RecoveryReferenceEvent(state.sequence + 1, state.head, kind, id, snapshots, receipt, evidence)
        apply(state, event)
        ReleasePrivateFiles.save(root.resolve("%08d.json".format(event.sequence)), json.encodeToString(event).toByteArray())
    }
    private fun <T> mutate(action: (State) -> T): T = ReleasePrivateFiles.locked(root) {
        require(!Files.exists(root.resolve("retention.pending"), NOFOLLOW_LINKS)) { "Unknown retention outcome; reference changes refused" }
        action(state())
    }
    fun retentionReady(): Boolean = mutate { it.verified.size >= 2 }
    fun register(receipt: KopiaSnapshotReceipt) = mutate { state ->
        val prior = state.receipts[receipt.snapshotId]
        if (prior != null) require(prior == receipt) else append(state, "snapshot", receipt.id, setOf(receipt.snapshotId), receipt)
    }
    fun protect(kind: String, id: String, snapshots: Set<String>) = mutate { state ->
        require(kind in kinds); append(state, kind, id, snapshots)
    }
    fun <T> withReference(kind: String, id: String, snapshots: Set<String>, action: () -> T): T {
        protect(kind, id, snapshots) // Durable even if action throws, is interrupted or never returns.
        return action()
    }
    fun verified(result: WeeklyRestoreResult) = mutate { state ->
        WeeklyRestoreSchedule.validateResult(result)
        val receipt = result.snapshot
        require(state.receipts[receipt.snapshotId] == receipt)
        append(state, "verified", result.operation, setOf(receipt.snapshotId), evidence = ReleaseLocks.sha256(json.encodeToString(result).toByteArray()))
    }
    override fun withProtection(action: (KopiaRetentionProtection) -> KopiaRetentionResult): KopiaRetentionResult = mutate { state ->
        require(state.verified.size >= 2) { "At least two functional restore points required before retention" }
        val intent = state.head.toByteArray()
        ReleasePrivateFiles.save(root.resolve("retention.pending"), intent)
        val result = action(KopiaRetentionProtection(state.head, state.receipts.values.toList(), state.references.toSet(), state.verified.toSet()))
        require(result.plan.referenceHeadSha256 == state.head && result.plan.delete.none { it in state.references } &&
            result.plan.retain.toSet() + result.plan.delete.toSet() == state.receipts.keys &&
            result.plan.retain.toSet().intersect(result.plan.delete.toSet()).isEmpty() &&
            result.plan.retain.count { it in state.verified } >= 2) { "Retention result changed reference protection" }
        append(state, "deleted", result.plan.id, result.plan.delete.toSet())
        ReleasePrivateFiles.removeExact(root.resolve("retention.pending"), intent)
        result
    }
}
