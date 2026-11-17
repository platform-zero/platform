package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable internal data class RecoveryLedgerCheckpoint(val firstSequence: Int, val lastSequence: Int,
    val previousCheckpointSha256: String, val lastHeadSha256: String, val eventSha256: List<String>,
    val receipts: List<KopiaSnapshotReceipt>, val references: Set<String>, val verified: Set<String>,
    val verificationProofs: Map<String, String>, val retired: Set<String>,
    val claims: Map<String, Set<String>>, val bootstrap: Set<String>,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val pendingOperations: Map<String, String> = emptyMap())

@Serializable internal data class PendingRecoveryOperation(val kind: String, val id: String,
    val access: RuntimeBackupAccess) {
    fun validate() {
        require(kind in setOf("rollback", "import", "qualification", "activation", "weekly",
                "capture", "backup", "held") &&
            id.matches(Regex("[A-Za-z0-9][A-Za-z0-9_.:-]{0,110}")))
        access.validate()
        if (kind in setOf("capture", "backup", "held")) require(id == access.operation) {
            "Native operation fence must use exact capture ID, not an outer caller alias"
        }
    }
}

@Serializable internal data class InstallReferenceTerminal(val schemaVersion: Int = 1,
    val transactionId: String, val source: ReleaseGeneration, val first: KopiaSnapshotReceipt,
    val second: KopiaSnapshotReceipt, val firstCompletion: GenerationCompletionReceipt,
    val secondCompletion: GenerationCompletionReceipt, val activeSite: ActivationInput,
    val committedJournalSha256: String, val selectedTrialId: String) {
    fun validate() {
        source.validate(); KopiaGenerationStore.validate(first); KopiaGenerationStore.validate(second)
        firstCompletion.proof.validate(); secondCompletion.proof.validate()
        require(schemaVersion == 1 && transactionId.matches(Regex("[a-z][a-z0-9-]{0,63}")) &&
            first.generation == source.id && second.generation == source.id &&
            first.bundleSha256 == source.bundleSha256 && second.bundleSha256 == source.bundleSha256 &&
            first.id != second.id && first.snapshotId != second.snapshotId &&
            listOf(activeSite.sha256, committedJournalSha256).all { it.matches(Regex("[a-f0-9]{64}")) } &&
            selectedTrialId.matches(Regex("[a-z][a-z0-9-]{0,95}")) &&
            firstCompletion.proof.access == RuntimeBackupAccess(source.id, first.id, source.bundleSha256) &&
            secondCompletion.proof.access == RuntimeBackupAccess(source.id, second.id, source.bundleSha256) &&
            firstCompletion.proof.snapshotId == first.snapshotId &&
            secondCompletion.proof.snapshotId == second.snapshotId) {
            "First-install references require two exact distinct native functional results"
        }
    }
}

@Serializable internal data class RecoveryReferenceEvent(
    val sequence: Int, val previous: String, val kind: String, val id: String,
    val snapshots: Set<String> = emptySet(), val receipt: KopiaSnapshotReceipt? = null,
    val evidenceSha256: String? = null
)

/** Later committed succession may release exactly the former site's functional snapshot.
 * The successor's protection and old source native hold are independent immutable evidence. */
@Serializable internal data class SiteSuccessionTerminal(val transactionId: String, val siteId: String,
    val source: ReleaseGeneration, val successor: ReleaseGeneration,
    val priorRevisionSha256: String, val successorRevisionSha256: String,
    val oldSnapshot: KopiaSnapshotReceipt, val successorSnapshot: KopiaSnapshotReceipt,
    val originalHeld: ActivationInput, val oldNativeAudit: ActivationInput,
    val priorPublication: ReleasePublication, val successorClaimEvent: ActivationInput,
    val successorCompletion: ActivationInput)

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
        private val kinds = setOf("rollback", "import", "qualification", "activation", "weekly", "unknown", "site-selection")
        private const val PAGE = 128
        private const val MAX_CHECKPOINTS = 4096
        fun initialize(root: Path, existing: List<KopiaSnapshotReceipt>): RecoveryReferences {
            if (existing.isEmpty()) {
                val backups = root.parent.resolve("backups")
                if (Files.exists(backups, NOFOLLOW_LINKS)) {
                    ReleasePrivateFiles.directory(backups)
                    Files.list(backups).use { require(it.findAny().isEmpty) {
                        "Never initialize empty references over any old or uncertain backup attempt"
                    } }
                }
                require(!Files.exists(root.parent.resolve("kopia-store/repository"), NOFOLLOW_LINKS)) {
                    "Never initialize empty references over a pre-existing Kopia repository"
                }
            }
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
        val verified: MutableSet<String>, val retired: MutableSet<String>, var sequence: Int, var head: String,
        val claims: MutableMap<String, Set<String>> = mutableMapOf(), val bootstrap: Set<String> = emptySet(),
        val verificationProofs: MutableMap<String, String> = mutableMapOf(),
        val pendingOperations: MutableMap<String, String> = mutableMapOf())
    private fun state(): State {
        val bootstrap = ReleasePrivateFiles.read(root.resolve("bootstrap.json"))
        val head = ReleaseLocks.sha256(bootstrap)
        require(ReleasePrivateFiles.read(root.resolve("ready")).decodeToString() == head) { "Incomplete reference bootstrap" }
        val initial = json.decodeFromString<List<KopiaSnapshotReceipt>>(bootstrap.decodeToString())
        initial.forEach(KopiaGenerationStore::validate)
        require(initial.map { it.snapshotId }.distinct().size == initial.size)
        val initialIds = initial.map { it.snapshotId }.toSet()
        val state = State(initial.associateBy { it.snapshotId }.toMutableMap(), initialIds.toMutableSet(),
            mutableSetOf(), mutableSetOf(), 0, head, bootstrap = initialIds)
        val eraFile = root.resolve("checkpoint.era")
        val eraBytes = if (Files.exists(eraFile, NOFOLLOW_LINKS)) ReleasePrivateFiles.read(eraFile) else null
        val era = eraBytes?.decodeToString()?.also { require(it.matches(Regex("[0-9]{8}"))) }?.toInt()
        var events = 0; var checkpointFiles = 0
        Files.list(root).use { paths -> paths.forEach { path ->
            val name = path.fileName.toString()
            when {
                name.matches(Regex("[0-9]{8}\\.json")) -> events++
                name.matches(Regex("checkpoint-[0-9]{8}(\\.intent|\\.complete)?\\.json")) -> checkpointFiles++
                name in setOf("bootstrap.json", "ready", "control.lock", "retention.pending", "checkpoint.era") -> Unit
                else -> error("Unknown recovery reference ledger entry")
            }
            require(events <= PAGE * MAX_CHECKPOINTS && checkpointFiles <= MAX_CHECKPOINTS * 3)
        } }
        require(era == null || era in 1..(events + 1))
        val expectedCheckpoints = if (era == null) 0 else events / PAGE - (era - 1) / PAGE
        require(checkpointFiles == expectedCheckpoints * 3) { "Partial or foreign reference checkpoint; never append" }
        val page = mutableListOf<String>()
        var checkpointHead = eraBytes?.let { ReleaseLocks.sha256(it) } ?: ""
        var first = era ?: 0
        for (sequence in 1..events) {
            val file = root.resolve("%08d.json".format(sequence))
            val bytes = ReleasePrivateFiles.read(file)
            val event = json.decodeFromString<RecoveryReferenceEvent>(bytes.decodeToString())
            require(event.sequence == sequence && event.previous == state.head)
            apply(state, event)
            state.sequence = sequence; state.head = ReleaseLocks.sha256(bytes)
            if (era != null && sequence >= era) page += state.head
            if (era != null && sequence >= era && sequence % PAGE == 0) {
                val prefix = "checkpoint-%08d".format(sequence)
                val intent = ReleasePrivateFiles.read(root.resolve("$prefix.intent.json"))
                val checkpointBytes = ReleasePrivateFiles.read(root.resolve("$prefix.json"))
                val checkpoint = json.decodeFromString<RecoveryLedgerCheckpoint>(checkpointBytes.decodeToString())
                require(intent.decodeToString() == "$first\n$sequence\n$checkpointHead\n" &&
                    ReleasePrivateFiles.read(root.resolve("$prefix.complete.json")).decodeToString() == ReleaseLocks.sha256(checkpointBytes) &&
                    checkpoint == RecoveryLedgerCheckpoint(first, sequence, checkpointHead, state.head, page.toList(),
                        state.receipts.values.sortedBy { it.snapshotId }, state.references.toSet(), state.verified.toSet(),
                        state.verificationProofs.toMap(), state.retired.toSet(), state.claims.toMap(), state.bootstrap,
                        state.pendingOperations.toMap())) {
                    "Reference checkpoint diverges from full original event chain and protected state"
                }
                checkpointHead = ReleaseLocks.sha256(checkpointBytes)
                first = sequence + 1
                page.clear()
            }
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
            "operation-terminal" -> {
                require(event.evidenceSha256?.matches(hash) == true && event.snapshots.size == 1 &&
                    event.id.matches(Regex("(?:backup|held):cap-[a-f0-9]{12}")) &&
                    state.claims.remove(event.id) == event.snapshots)
                state.references.clear()
                state.references += state.bootstrap
                state.claims.values.forEach { state.references += it }
            }
            "operation-pending" -> {
                require(event.snapshots.isEmpty() && event.receipt == null && event.evidenceSha256?.matches(hash) == true &&
                    event.id.matches(Regex("(?:rollback|import|qualification|activation|weekly|capture|backup|held):[A-Za-z0-9_.:-]+")) &&
                    event.id !in state.pendingOperations && event.id !in state.claims)
                state.pendingOperations[event.id] = requireNotNull(event.evidenceSha256)
            }
            "operation-bound" -> {
                require(event.receipt == null && event.evidenceSha256?.matches(hash) == true &&
                    event.snapshots.size == 1 && state.receipts.keys.containsAll(event.snapshots) &&
                    state.pendingOperations.remove(event.id) == event.evidenceSha256 &&
                    state.claims.putIfAbsent(event.id, event.snapshots) == null) {
                    "Unknown pending operation or unverified native capture cannot bind a snapshot"
                }
                state.references += event.snapshots
            }
            in kinds -> {
                require(state.receipts.keys.containsAll(event.snapshots) && event.snapshots.isNotEmpty() &&
                    state.claims.putIfAbsent("${event.kind}:${event.id}", event.snapshots) == null) { "Reference claim already exists" }
                state.references += event.snapshots
            }
            "weekly-terminal", "held-terminal", "owned-terminal", "install-terminal", "site-terminal" -> {
                val origin = when (event.kind) {
                    "weekly-terminal" -> "weekly:${event.id}"
                    "held-terminal" -> "unknown:${event.id}"
                    else -> event.id
                }
                require(event.evidenceSha256?.matches(hash) == true && event.snapshots.isNotEmpty() &&
                    state.claims.remove(origin) == event.snapshots) { "Unbound terminal proof" }
                state.references.clear()
                state.references += state.bootstrap
                state.claims.values.forEach { state.references += it }
            }
            "verified" -> {
                require(state.receipts.keys.containsAll(event.snapshots) && event.snapshots.size == 1 && event.evidenceSha256?.matches(hash) == true)
                // Historical journals may contain repeated attestations of the same old
                // snapshot. Preserve their reads, but never replace the first exact proof.
                state.verificationProofs.putIfAbsent(event.snapshots.single(), requireNotNull(event.evidenceSha256))
                state.verified += event.snapshots
            }
            "deleted" -> {
                require(state.receipts.keys.containsAll(event.snapshots) && event.snapshots.none { it in state.references })
                event.snapshots.forEach {
                    state.receipts.remove(it); state.verified.remove(it); state.verificationProofs.remove(it); state.retired.add(it)
                }
            }
            else -> error("Unknown reference event")
        }
    }
    private fun append(state: State, kind: String, id: String, snapshots: Set<String>, receipt: KopiaSnapshotReceipt? = null, evidence: String? = null) {
        require(state.sequence < PAGE * MAX_CHECKPOINTS) { "Reference history archive full; never discard evidence" }
        val event = RecoveryReferenceEvent(state.sequence + 1, state.head, kind, id, snapshots, receipt, evidence)
        val eraFile = root.resolve("checkpoint.era")
        if (!Files.exists(eraFile, NOFOLLOW_LINKS)) {
            ReleasePrivateFiles.save(eraFile, "%08d".format(event.sequence).toByteArray())
        }
        apply(state, event)
        val bytes = json.encodeToString(event).toByteArray()
        ReleasePrivateFiles.save(root.resolve("%08d.json".format(event.sequence)), bytes)
        state.sequence = event.sequence
        state.head = ReleaseLocks.sha256(bytes)
        if (event.sequence % PAGE == 0) {
            val eraBytes = ReleasePrivateFiles.read(eraFile)
            val era = eraBytes.decodeToString().toInt()
            val first = maxOf(era, event.sequence - PAGE + 1)
            val previous = if (first == era) ReleaseLocks.sha256(eraBytes) else
                ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("checkpoint-%08d.json".format(event.sequence - PAGE))))
            val page = (first..event.sequence).map { index ->
                ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("%08d.json".format(index))))
            }
            val checkpoint = RecoveryLedgerCheckpoint(first, event.sequence, previous, state.head, page,
                state.receipts.values.sortedBy { it.snapshotId }, state.references.toSet(), state.verified.toSet(),
                state.verificationProofs.toMap(), state.retired.toSet(), state.claims.toMap(), state.bootstrap,
                state.pendingOperations.toMap())
            val prefix = "checkpoint-%08d".format(event.sequence)
            ReleasePrivateFiles.save(root.resolve("$prefix.intent.json"), "$first\n${event.sequence}\n$previous\n".toByteArray())
            val encoded = json.encodeToString(checkpoint).toByteArray()
            ReleasePrivateFiles.save(root.resolve("$prefix.json"), encoded)
            ReleasePrivateFiles.save(root.resolve("$prefix.complete.json"), ReleaseLocks.sha256(encoded).toByteArray())
        }
    }
    private fun <T> mutate(action: (State) -> T): T = ReleasePrivateFiles.locked(root) {
        require(!Files.exists(root.resolve("retention.pending"), NOFOLLOW_LINKS)) { "Unknown retention outcome; reference changes refused" }
        action(state())
    }
    fun retentionReady(): Boolean = mutate { it.verified.size >= 2 && it.pendingOperations.isEmpty() }
    /** Publish a pending operation BEFORE any Kopia repository/capture effect. An unknown
     * snapshot ID cannot yet be referenced, so this fence also forbids all broad retention.
     */
    fun protectPending(pin: PendingRecoveryOperation) = mutate { state ->
        pin.validate()
        require(pin.access.generation == root.parent.fileName.toString() &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(root.parent.resolve("bundle.json"))) == pin.access.bundleSha256 &&
            pin.access.operation.matches(Regex("cap-[a-f0-9]{12}")))
        val key = "${pin.kind}:${pin.id}"
        val digest = ReleaseLocks.sha256(json.encodeToString(pin).toByteArray())
        append(state, "operation-pending", key, emptySet(), evidence = digest)
    }
    /** Bind only an actual completed native capture receipt; a caller-supplied Boolean or
     * expected future snapshot ID never authorizes reference protection. Partial binds remain
     * pending and require explicit observation-only reconciliation, not normal replay.
     */
    fun bindCaptured(pin: PendingRecoveryOperation, receipt: KopiaSnapshotReceipt) = mutate { state ->
        pin.validate(); KopiaGenerationStore.validate(receipt)
        val key = "${pin.kind}:${pin.id}"
        val digest = ReleaseLocks.sha256(json.encodeToString(pin).toByteArray())
        require(state.pendingOperations[key] == digest &&
            receipt.generation == pin.access.generation && receipt.bundleSha256 == pin.access.bundleSha256 &&
            receipt.id == pin.access.operation &&
            state.receipts[receipt.snapshotId]?.let { it == receipt } != false)
        val path = root.parent.resolve("kopia-captures/${receipt.id}/capture.result.json")
        val native = json.decodeFromString<KopiaCaptureOutcome>(ReleasePrivateFiles.read(path).decodeToString())
        require(native.id == receipt.id && native.bundleSha256 == receipt.bundleSha256 &&
            native.passed && native.failureType == null && native.snapshot == receipt)
        if (state.receipts[receipt.snapshotId] == null)
            append(state, "snapshot", receipt.id, setOf(receipt.snapshotId), receipt)
        append(state, "operation-bound", key, setOf(receipt.snapshotId), evidence = digest)
    }
    fun register(receipt: KopiaSnapshotReceipt) = mutate { state ->
        val prior = state.receipts[receipt.snapshotId]
        if (prior != null) require(prior == receipt) else append(state, "snapshot", receipt.id, setOf(receipt.snapshotId), receipt)
    }
    fun protect(kind: String, id: String, snapshots: Set<String>) = mutate { state ->
        require(kind in kinds); append(state, kind, id, snapshots)
    }
    fun requireProtected(kind: String, id: String, snapshot: KopiaSnapshotReceipt) = mutate { state ->
        KopiaGenerationStore.validate(snapshot)
        require(state.claims["$kind:$id"] == setOf(snapshot.snapshotId) &&
            state.receipts[snapshot.snapshotId] == snapshot && state.pendingOperations.isEmpty()) {
            "Exact bound snapshot must remain protected before repository or target effects"
        }
    }
    fun requireBound(kind: String, id: String, snapshot: KopiaSnapshotReceipt) = mutate { state ->
        KopiaGenerationStore.validate(snapshot)
        require(kind in kinds && state.receipts[snapshot.snapshotId] == snapshot &&
            state.claims["$kind:$id"] == setOf(snapshot.snapshotId) &&
            "$kind:$id" !in state.pendingOperations) {
            "Pre-repository operation fence has not bound an actual protected native receipt"
        }
    }
    fun <T> withReference(kind: String, id: String, snapshots: Set<String>, action: () -> T): T {
        protect(kind, id, snapshots) // Durable even if action throws, is interrupted or never returns.
        return action()
    }
    fun verified(result: WeeklyRestoreResult) = mutate { state ->
        WeeklyRestoreSchedule.validateResult(result)
        val proof = requireNotNull(result.completionProof) { "Typed target-isolation and source-resume evidence required" }
        // Production verification is rooted in native GenerationRuntime journals, not a
        // callback-supplied Boolean. Unit-only ledgers without a source bundle use fixture proof.
        if (Files.exists(root.parent.resolve("bundle.json"), NOFOLLOW_LINKS)) {
            val source = root.parent.resolve("backups/${result.operation}")
            val target = root.parent.parent.resolve("${result.target}/isolate.result.json")
            val heldBytes = ReleasePrivateFiles.read(source.resolve("held.json"))
            val isolationBytes = ReleasePrivateFiles.read(target)
            val authorityBytes = ReleasePrivateFiles.read(source.resolve("resume.authority.json"))
            val resumeBytes = ReleasePrivateFiles.read(source.resolve("result.json"))
            val held = json.decodeFromString<GenerationHeldCapture>(heldBytes.decodeToString()).also { it.validate() }
            val authority = json.decodeFromString<HeldSourceResumeAuthority>(authorityBytes.decodeToString())
            val receipt = requireNotNull(result.nativeCompletion) { "Native locked generation completion receipt required" }
            val completionPath = source.resolve("completion.proof.json")
            val completionBytes = ReleasePrivateFiles.read(completionPath)
            require(receipt.record == ActivationInput(completionPath.toString(), ReleaseLocks.sha256(completionBytes)) &&
                json.decodeFromString<GenerationCompletionProof>(completionBytes.decodeToString()) == receipt.proof &&
                receipt.proof.targetObservations.map { it.name }.toSet() == result.targetIsolation.fences.keys)
            require(held.snapshot == result.snapshot && held.access.operation == result.operation &&
                authority == HeldSourceResumeAuthority(ReleaseLocks.sha256(heldBytes), result.target,
                    result.targetBundleSha256, result.targetIsolation.fences) &&
                json.decodeFromString<GenerationBackupOutcome>(resumeBytes.decodeToString()) ==
                    GenerationBackupOutcome(held.access, true, held.snapshot, true) &&
                json.decodeFromString<GenerationOutcome>(isolationBytes.decodeToString()) == result.targetIsolation &&
                json.decodeFromString<RuntimeBackupAccess>(ReleasePrivateFiles.read(
                    source.resolve("resume.verified.json")).decodeToString()) == held.access &&
                proof == WeeklyCompletionProof(ReleaseLocks.sha256(heldBytes), ReleaseLocks.sha256(isolationBytes),
                    ReleaseLocks.sha256(authorityBytes), ReleaseLocks.sha256(resumeBytes))) {
                "Native completion proof differs from durable source/target journals"
            }
        }
        val receipt = result.snapshot
        require(state.receipts[receipt.snapshotId] == receipt && receipt.snapshotId !in state.verificationProofs) {
            "Functional proof cannot be submitted twice or replaced"
        }
        append(state, "verified", result.operation, setOf(receipt.snapshotId), evidence = ReleaseLocks.sha256(json.encodeToString(result).toByteArray()))
    }
    /** Only the exactly matching, completed weekly result may retire its own non-bootstrap reference.
     * Bootstrap and unknown references are deliberately non-expiring. Retain the terminal event forever.
     */
    fun retireHeldSource(capture: String, target: String, targetBundleSha256: String) = mutate { state ->
        require(capture.matches(Regex("cap-[a-f0-9]{12}")) && target.matches(Regex("q-[a-f0-9]{12}")) &&
            targetBundleSha256.matches(hash))
        val source = root.parent
        val generation = source.fileName.toString()
        val base = source.parent
        val operation = source.resolve("backups/$capture")
        val heldBytes = ReleasePrivateFiles.read(operation.resolve("held.json"))
        val held = json.decodeFromString<GenerationHeldCapture>(heldBytes.decodeToString()).also { it.validate() }
        require(held.access.generation == generation && held.access.operation == capture &&
            state.receipts[held.snapshot.snapshotId] == held.snapshot &&
            (state.claims["unknown:held-$capture"] == setOf(held.snapshot.snapshotId) ||
                state.claims["held:$capture"] == setOf(held.snapshot.snapshotId)))
        val resumedBytes = ReleasePrivateFiles.read(operation.resolve("result.json"))
        val resumed = json.decodeFromString<GenerationBackupOutcome>(resumedBytes.decodeToString())
        val authority = json.decodeFromString<HeldSourceResumeAuthority>(
            ReleasePrivateFiles.read(operation.resolve("resume.authority.json")).decodeToString())
        val verified = json.decodeFromString<RuntimeBackupAccess>(
            ReleasePrivateFiles.read(operation.resolve("resume.verified.json")).decodeToString())
        val proof = json.decodeFromString<GenerationCompletionProof>(
            ReleasePrivateFiles.read(operation.resolve("completion.proof.json")).decodeToString()).also { it.validate() }
        require(resumed == GenerationBackupOutcome(held.access, true, held.snapshot, true) && verified == held.access &&
            proof.access == held.access && proof.snapshotId == held.snapshot.snapshotId &&
            proof.heldSha256 == ReleaseLocks.sha256(heldBytes) && proof.target == target &&
            proof.targetBundleSha256 == targetBundleSha256 &&
            proof.sourceResultSha256 == ReleaseLocks.sha256(resumedBytes) &&
            proof.resumeAuthoritySha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(operation.resolve("resume.authority.json"))) &&
            authority.heldSha256 == ReleaseLocks.sha256(heldBytes) && authority.target == target &&
            authority.targetBundleSha256 == targetBundleSha256 && authority.targetFences == proof.targetFences &&
            authority.targetFences.isNotEmpty()) {
            "Source-resume proof absent or foreign"
        }
        val isolation = json.decodeFromString<GenerationOutcome>(
            ReleasePrivateFiles.read(base.resolve("$target/isolate.result.json")).decodeToString())
        require(isolation.action == "isolate" && isolation.passed && isolation.failureType == null &&
            isolation.bundleSha256 == targetBundleSha256 && isolation.fences == authority.targetFences &&
            isolation.fences.keys.all { it.startsWith("$target-") }) { "Target-isolation proof absent or foreign" }
        val evidence = ReleaseLocks.sha256(resumedBytes + ReleasePrivateFiles.read(operation.resolve("resume.authority.json")))
        if (state.claims["unknown:held-$capture"] == setOf(held.snapshot.snapshotId))
            append(state, "held-terminal", "held-$capture", setOf(held.snapshot.snapshotId), evidence = evidence)
        if (state.claims["held:$capture"] == setOf(held.snapshot.snapshotId))
            append(state, "operation-terminal", "held:$capture", setOf(held.snapshot.snapshotId), evidence = evidence)
    }
    /** Exact lifecycle retirement, with immutable terminal written before the ledger event.
     * The caller MUST hold controller and ordered source/target isolation locks. This reader
     * does not call GenerationRuntime while holding the ledger (which would invert lock order).
     * It never treats callback completion or an expiry time as terminal authority.
     */
    fun retireOwned(terminal: OwnedUpdateReferenceTerminal) = mutate { state ->
        val generationBase = root.parent.parent
        val transactionRoot = generationBase.parent.resolve("release-transactions")
        terminal.validate(transactionRoot, generationBase)
        val original = terminal.source
        val owner = if (terminal.kind == "qualification") terminal.targetGeneration else original.id
        require(root.parent.fileName.toString() == owner && transactionRoot.isAbsolute)
        val key = "${terminal.kind}:${terminal.transactionId}"
        val claimedId = state.claims[key]?.singleOrNull()
        val claimed = if (terminal.kind == "qualification") claimedId?.let(state.receipts::get) else terminal.original
        require(claimed != null && state.claims[key] == setOf(claimed.snapshotId) &&
            state.receipts[claimed.snapshotId] == claimed && state.pendingOperations.isEmpty()) {
            "Unknown or unbound owned reference must remain protected"
        }
        if (terminal.kind == "qualification") require(claimed.generation == terminal.targetGeneration &&
            claimed.bundleSha256 == terminal.targetBundleSha256 && claimed.snapshotId != terminal.original.snapshotId &&
            (terminal.qualifiedSnapshot == null || terminal.qualifiedSnapshot == claimed)) {
            "Candidate qualification claim cannot alias the held original"
        }
        val requestPath = transactionRoot.resolve(terminal.transactionId).resolve("request.json")
        val request = json.decodeFromString<ReleaseTransactionRequest>(ReleasePrivateFiles.read(requestPath).decodeToString())
        val intent = requireNotNull(request.updatePreparation).intent
        require(request.transactionId == terminal.transactionId && request.snapshotId == terminal.original.id &&
            intent.source == original && intent.targetGeneration == terminal.targetGeneration &&
            terminal.sitePolicySha256 == intent.sitePolicySha256 &&
            terminal.intentSha256 == ReleaseLocks.sha256(json.encodeToString(intent).toByteArray()))
        val journal = TransactionJournal.verify(transactionRoot.resolve(terminal.transactionId).resolve("transaction.jsonl"))
        val last = journal.last()
        require(last.transactionId == terminal.transactionId && last.update?.sourceGeneration == original.id &&
            last.update?.targetGeneration == terminal.targetGeneration &&
            last.deployment?.bundleSha256 == terminal.targetBundleSha256 &&
            last.deployment?.sitePolicySha256 == terminal.sitePolicySha256 &&
            last.phase == (if (terminal.activeSite != null) Phase.COMMITTED else Phase.RECOVERY_REQUIRED)) {
            "Owned reference terminal disagrees with durable transaction outcome"
        }
        val sourceBytes = ReleasePrivateFiles.read(generationBase.resolve(original.id).resolve("bundle.json"))
        require(ReleaseLocks.sha256(sourceBytes) == original.bundleSha256)
        val originalHeld = ReleasePrivateFiles.read(generationBase.resolve(original.id)
            .resolve("backups/${terminal.original.id}/held.json"))
        val held = json.decodeFromString<GenerationHeldCapture>(originalHeld.decodeToString()).also { it.validate() }
        require(held.snapshot == terminal.original && held.access.generation == original.id &&
            held.access.bundleSha256 == original.bundleSha256)
        val candidateBytes = ReleasePrivateFiles.read(generationBase.resolve(terminal.targetGeneration).resolve("bundle.json"))
        require(ReleaseLocks.sha256(candidateBytes) == terminal.targetBundleSha256)
        val candidate = json.decodeFromString<GenerationBundle>(candidateBytes.decodeToString())
        OwnedReleaseUpdates.validate(candidate)
        require(candidate.ownedUpdate?.intent == intent && candidate.ownedUpdate?.snapshot == terminal.original &&
            candidate.ownedUpdate?.original == json.decodeFromString<GenerationBundle>(sourceBytes.decodeToString()))
        if (terminal.kind == "qualification") {
            val qualifiedHeld = json.decodeFromString<GenerationHeldCapture>(ReleasePrivateFiles.read(generationBase
                .resolve(terminal.targetGeneration).resolve("backups/${claimed.id}/held.json")).decodeToString())
            qualifiedHeld.validate()
            require(qualifiedHeld.snapshot == claimed && qualifiedHeld.access == RuntimeBackupAccess(
                terminal.targetGeneration, claimed.id, terminal.targetBundleSha256)) {
                "Qualification reference lacks actual bound native candidate hold"
            }
        }
        fun pinned(pin: ActivationInput): ByteArray = ReleasePrivateFiles.read(Path.of(pin.path)).also {
            require(ReleaseLocks.sha256(it) == pin.sha256) { "Native owned terminal pin changed" }
        }
        fun verifyNativeCompletion(receipt: GenerationCompletionReceipt, generation: String,
            capture: KopiaSnapshotReceipt, target: String, targetHash: String) {
            val access = RuntimeBackupAccess(generation, capture.id, capture.bundleSha256).also { it.validate() }
            val attempt = generationBase.resolve(generation).resolve("backups/${capture.id}")
            val heldBytes = ReleasePrivateFiles.read(attempt.resolve("held.json"))
            val nativeHeld = json.decodeFromString<GenerationHeldCapture>(heldBytes.decodeToString()).also { it.validate() }
            val resultBytes = ReleasePrivateFiles.read(attempt.resolve("result.json"))
            val result = json.decodeFromString<GenerationBackupOutcome>(resultBytes.decodeToString())
            val authorityBytes = ReleasePrivateFiles.read(attempt.resolve("resume.authority.json"))
            val authority = json.decodeFromString<HeldSourceResumeAuthority>(authorityBytes.decodeToString())
            val verified = json.decodeFromString<RuntimeBackupAccess>(ReleasePrivateFiles.read(
                attempt.resolve("resume.verified.json")).decodeToString())
            val proof = json.decodeFromString<GenerationCompletionProof>(pinned(receipt.record).decodeToString())
            proof.validate()
            val targetBytes = ReleasePrivateFiles.read(generationBase.resolve(target).resolve("bundle.json"))
            require(ReleaseLocks.sha256(targetBytes) == targetHash)
            val targetBundle = json.decodeFromString<GenerationBundle>(targetBytes.decodeToString())
            require(targetBundle.request.id == target &&
                (targetBundle.recoverySourceKopia == capture || targetBundle.ownedUpdate?.snapshot == capture)) {
                "Native terminal target lacks actual original-data snapshot lineage"
            }
            val isolated = json.decodeFromString<GenerationOutcome>(ReleasePrivateFiles.read(
                generationBase.resolve(target).resolve("isolate.result.json")).decodeToString())
            require(proof == receipt.proof && proof.access == access && proof.snapshotId == capture.snapshotId &&
                nativeHeld.access == access && nativeHeld.snapshot == capture &&
                proof.heldSha256 == ReleaseLocks.sha256(heldBytes) &&
                result == GenerationBackupOutcome(access, true, capture, true) && verified == access &&
                proof.sourceResultSha256 == ReleaseLocks.sha256(resultBytes) &&
                proof.resumeAuthoritySha256 == ReleaseLocks.sha256(authorityBytes) &&
                proof.target == target && proof.targetBundleSha256 == targetHash &&
                authority == HeldSourceResumeAuthority(proof.heldSha256, target, targetHash, proof.targetFences) &&
                isolated.action == "isolate" && isolated.passed && isolated.failureType == null &&
                isolated.bundleSha256 == targetHash && isolated.fences == proof.targetFences) {
                "Owned reference release lacks exact native held, isolated target and source-resume proof"
            }
        }
        val imported = json.decodeFromString<GenerationOutcome>(pinned(terminal.importResult).decodeToString())
        require(imported.action == "restore-import" && imported.passed && imported.failureType == null &&
            imported.bundleSha256 == terminal.targetBundleSha256)
        if (terminal.activeSite != null) {
            require(ReleaseLocks.sha256(originalHeld) == requireNotNull(terminal.originalHeld).sha256)
            val start = json.decodeFromString<GenerationOutcome>(pinned(requireNotNull(terminal.ownedStart)).decodeToString())
            require(start.action == "owned-start" && start.passed && start.failureType == null &&
                start.bundleSha256 == terminal.targetBundleSha256)
            val site = requireNotNull(candidate.ownership)
            val siteDir = transactionRoot.resolve("active-sites")
                .resolve(ReleaseLocks.sha256(site.contract.site.toByteArray()))
            val activePin = requireNotNull(terminal.activeSite)
            require(Path.of(activePin.path).parent == siteDir &&
                activePin.path.endsWith(".completed.json"))
            val completed = json.decodeFromString<ActiveSiteCompletion>(pinned(activePin).decodeToString())
            val head = json.decodeFromString<ActiveSiteHead>(ReleasePrivateFiles.read(siteDir.resolve("head.json")).decodeToString())
            val activation = requireNotNull(terminal.activationJournal)
            pinned(activation)
            require(activePin.path == siteDir.resolve("${head.revisionSha256}.completed.json").toString() &&
                completed.selectionSha256 == head.revisionSha256 &&
                completed.transactionId == terminal.transactionId && completed.committedJournalHead == last.hash &&
                completed.target == last.deployment && terminal.secondTrialId != null)
            val selectedBytes = ReleasePrivateFiles.read(siteDir.resolve("rev-${head.ordinal}.json"))
            require(ReleaseLocks.sha256(selectedBytes) == head.revisionSha256)
            val selected = json.decodeFromString<ActiveSiteSelection>(selectedBytes.decodeToString())
            require(selected.source == original && selected.deployment == last.deployment &&
                selected.siteId == site.contract.site && selected.hosts == site.approvedHosts.sorted() &&
                selected.selectedTrialId == terminal.secondTrialId &&
                selected.qualificationSnapshotId == requireNotNull(terminal.qualifiedSnapshot).id)
        } else {
            val isolated = json.decodeFromString<GenerationOutcome>(pinned(requireNotNull(terminal.isolationResult)).decodeToString())
            val receipt = requireNotNull(terminal.sourceCompletion)
            val sourceProof = json.decodeFromString<GenerationCompletionProof>(pinned(receipt.record).decodeToString())
            sourceProof.validate()
            require(isolated.action == "isolate" && isolated.passed && isolated.failureType == null &&
                isolated.bundleSha256 == terminal.targetBundleSha256 && isolated.fences == sourceProof.targetFences &&
                sourceProof == receipt.proof && sourceProof.heldSha256 == ReleaseLocks.sha256(originalHeld) &&
                sourceProof.target == terminal.targetGeneration && sourceProof.targetBundleSha256 == terminal.targetBundleSha256)
            verifyNativeCompletion(receipt, original.id, terminal.original, terminal.targetGeneration, terminal.targetBundleSha256)
        }
        if (terminal.qualifiedSnapshot != null) {
            val receipt = requireNotNull(terminal.qualifiedCompletion)
            val qualifiedProof = json.decodeFromString<GenerationCompletionProof>(pinned(receipt.record).decodeToString())
            qualifiedProof.validate()
            require(qualifiedProof == receipt.proof && qualifiedProof.access.generation == terminal.targetGeneration &&
                qualifiedProof.snapshotId == terminal.qualifiedSnapshot.snapshotId &&
                qualifiedProof.target == terminal.qualifiedTargetGeneration &&
                qualifiedProof.targetBundleSha256 == terminal.qualifiedTargetBundleSha256)
            verifyNativeCompletion(receipt, terminal.targetGeneration, terminal.qualifiedSnapshot,
                requireNotNull(terminal.qualifiedTargetGeneration), requireNotNull(terminal.qualifiedTargetBundleSha256))
        }
        if (terminal.kind == "qualification" && terminal.activeSite != null) {
            val siteId = requireNotNull(candidate.ownership).contract.site
            val selectedSha = Path.of(requireNotNull(terminal.activeSite).path).fileName.toString()
                .removeSuffix(".completed.json")
            val siteKey = "site-selection:$siteId-$selectedSha"
            require(claimed.snapshotId == requireNotNull(terminal.qualifiedSnapshot).snapshotId)
            if (state.claims[siteKey] == null) append(state, "site-selection", "$siteId-$selectedSha",
                setOf(claimed.snapshotId), evidence = terminal.activeSite.sha256)
            else require(state.claims[siteKey] == setOf(claimed.snapshotId)) {
                "Selected functional snapshot protection changed"
            }
        }
        val bytes = json.encodeToString(terminal).toByteArray()
        val marker = transactionRoot.resolve(terminal.transactionId).resolve("reference-${terminal.kind}.terminal.json")
        ReleasePrivateFiles.save(marker, bytes)
        append(state, "owned-terminal", key, setOf(claimed.snapshotId), evidence = ReleaseLocks.sha256(bytes))
    }
    /** Pre-seal owned failure closes only the three original operation claims and held lease,
     * never a fabricated candidate qualification claim. A04 must have completed its SAME
     * reversible original RSS operation against independent native no-target evidence. */
    fun retireEarlyOwned(result: OwnedUpdateNoTargetRollbackResult) = mutate { state ->
        val generations = root.parent.parent
        val transactions = generations.parent.resolve("release-transactions")
        result.source.validate()
        require(result.schemaVersion == 1 && result.transactionId.matches(Regex("[a-z][a-z0-9-]{0,63}")) &&
            root.parent.fileName.toString() == result.source.id &&
            result.targetGeneration.matches(Regex("q-[a-f0-9]{12}")) &&
            state.pendingOperations.isEmpty())
        val tx = transactions.resolve(result.transactionId)
        val requestBytes = ReleasePrivateFiles.read(tx.resolve("request.json"))
        val request = json.decodeFromString<ReleaseTransactionRequest>(requestBytes.decodeToString())
        val journal = TransactionJournal.verify(tx.resolve("transaction.jsonl"))
        require(request.transactionId == result.transactionId &&
            request.updatePreparation?.intent?.source == result.source &&
            request.updatePreparation?.intent?.targetGeneration == result.targetGeneration &&
            journal.last().phase == Phase.RECOVERY_REQUIRED &&
            journal.none { it.phase in setOf(Phase.STAGED, Phase.CUTOVER_RESTRICTED, Phase.ACCEPTED,
                Phase.ACTIVATION_STARTED, Phase.COMMITTED) }) {
            "No-target ledger terminal cannot follow any candidate/public write"
        }
        fun pinned(pin: ActivationInput, path: Path): ByteArray {
            require(Path.of(pin.path) == path)
            return ReleasePrivateFiles.read(path).also { require(ReleaseLocks.sha256(it) == pin.sha256) }
        }
        val originalBytes = ReleasePrivateFiles.read(generations.resolve(result.source.id).resolve("bundle.json"))
        val original = json.decodeFromString<GenerationBundle>(originalBytes.decodeToString())
        SiteOwnerships.checkSealed(original)
        require(ReleaseLocks.sha256(originalBytes) == result.source.bundleSha256 &&
            original.request.id == result.source.id && original.ownedUpdate == null)
        val captureRoot = generations.resolve(result.source.id).resolve("backups/${request.snapshotId}")
        val heldBytes = ReleasePrivateFiles.read(captureRoot.resolve("held.json"))
        val held = json.decodeFromString<GenerationHeldCapture>(heldBytes.decodeToString()).also { it.validate() }
        require(held.snapshot.id == request.snapshotId && held.snapshot.generation == result.source.id &&
            held.snapshot.bundleSha256 == result.source.bundleSha256 &&
            ReleaseLocks.sha256(heldBytes) == result.originalHeldSha256 &&
            state.receipts[held.snapshot.snapshotId] == held.snapshot &&
            listOf("rollback", "import", "activation").all { kind ->
                state.claims["$kind:${result.transactionId}"] == setOf(held.snapshot.snapshotId)
            } && (state.claims["unknown:held-${request.snapshotId}"] == setOf(held.snapshot.snapshotId) ||
                state.claims["held:${request.snapshotId}"] == setOf(held.snapshot.snapshotId))) {
            "Pre-seal rollback must retain the exact original held and pre-repository claims"
        }
        val functionalBytes = ReleasePrivateFiles.read(generations.resolve(request.restoreTarget).resolve("bundle.json"))
        val functionalHash = ReleaseLocks.sha256(functionalBytes)
        val functional = json.decodeFromString<GenerationBundle>(functionalBytes.decodeToString())
        val functionalIsolation = json.decodeFromString<GenerationOutcome>(ReleasePrivateFiles.read(
            generations.resolve(request.restoreTarget).resolve("isolate.result.json")).decodeToString())
        require(functional.recoverySourceKopia == held.snapshot && functional.ownership == null &&
            functional.request.id == request.restoreTarget &&
            functional.members.all { it.spec.ingress == null && it.spec.nativeIngress == null &&
                it.spec.processes.none(RuntimeProcess::oneShot) } &&
            functionalIsolation.action == "isolate" && functionalIsolation.passed &&
            functionalIsolation.bundleSha256 == functionalHash &&
            functionalIsolation.fences.keys == functional.members.map { it.spec.name }.toSet()) {
            "Original RESTORE target must remain privately isolated during no-target rollback"
        }
        val targetRoot = generations.resolve(result.targetGeneration)
        require(!Files.exists(targetRoot.resolve("bundle.json"), NOFOLLOW_LINKS) &&
            !Files.exists(targetRoot.resolve("stage.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(targetRoot.resolve("stage.result.json"), NOFOLLOW_LINKS))
        val nativeBytes = pinned(result.nativeAbsence, targetRoot.resolve("no-target.native.json"))
        val native = json.decodeFromString<NativeOwnedTargetAbsence>(nativeBytes.decodeToString())
        val names = original.members.map { result.targetGeneration +
            it.spec.name.removePrefix(result.source.id) }.sorted()
        require(native.schemaVersion == 1 && native.source == result.source &&
            native.targetGeneration == result.targetGeneration && native.targetMembers == names &&
            native.runtimeMemberDirectoriesEmpty &&
            native.podmanInventorySha256.keys == setOf("container", "network", "volume", "secret") &&
            native.podmanInventorySha256.values.all(hash::matches))
        val nativeResult = ReleasePrivateFiles.read(captureRoot.resolve("no-target.resume.result.json"))
        val resumed = json.decodeFromString<GenerationBackupOutcome>(nativeResult.decodeToString())
        val auditBytes = pinned(result.sourceResumeAudit, captureRoot.resolve("no-target.resume.audit.json"))
        val audit = json.decodeFromString<GenerationInspection>(auditBytes.decodeToString())
        val proofBytes = pinned(result.sourceResumeProof, captureRoot.resolve("no-target.resume.proof.json"))
        val proof = json.decodeFromString<OwnedUpdateNoTargetSourceResumeProof>(proofBytes.decodeToString())
        require(resumed == GenerationBackupOutcome(held.access, true, held.snapshot, true) &&
            proof.schemaVersion == 1 && proof.originalHeldSha256 == result.originalHeldSha256 &&
            proof.nativeAbsenceSha256 == result.nativeAbsence.sha256 &&
            proof.resumeResultSha256 == ReleaseLocks.sha256(nativeResult) &&
            proof.sourceAuditSha256 == result.sourceResumeAudit.sha256 &&
            proof.resumedMembers == original.members.map { it.spec.name }.sorted() &&
            audit.id == result.source.id && audit.bundleSha256 == result.source.bundleSha256 &&
            audit.members.size == original.members.size && audit.members.zip(original.members).all { (member, pin) ->
                member.name == pin.spec.name && member.fingerprint == pin.runtimeFingerprint &&
                    member.maintenanceId == null && member.existingResources > 0 &&
                    pin.spec.processes.filterNot { it.oneShot }.all { process ->
                        member.statuses.singleOrNull { it.id == process.id }?.state == "running"
                    }
            }) { "Original source resume or native no-target audit cannot be inferred from callback" }
        val ownership = requireNotNull(original.ownership)
        val siteRoot = transactions.resolve("active-sites")
            .resolve(ReleaseLocks.sha256(ownership.contract.site.toByteArray()))
        val headBytes = pinned(result.originalSiteHead, siteRoot.resolve("head.json"))
        val head = json.decodeFromString<ActiveSiteHead>(headBytes.decodeToString())
        val ownerBytes = ReleasePrivateFiles.read(siteRoot.resolve(if (head.ordinal == 0)
            "bootstrap.json" else "rev-${head.ordinal}.json"))
        require(head.ordinal in 0..256 && head.revisionSha256 == ReleaseLocks.sha256(ownerBytes) &&
            (if (head.ordinal == 0) {
                val approved = json.decodeFromString<ActiveSiteBootstrap>(ownerBytes.decodeToString())
                ActiveSiteRegistry.real(tx.resolve("transaction.jsonl"), ownership.contract.site,
                    ownership.approvedHosts, result.source,
                    Path.of("/mnt/media/p0-v3/release-activation-consumptions")
                        .resolve("${result.source.id}.consumed.json"))
                    .validateBootstrap(approved, siteRoot)
                approved.source == result.source
            } else json.decodeFromString<ActiveSiteSelection>(ownerBytes.decodeToString()).deployment.let {
                it.generationId == result.source.id && it.bundleSha256 == result.source.bundleSha256
            })) { "A different active site cannot permit original source restart" }
        val publication = requireNotNull(request.previousPublication)
        val schedule = Path.of(publication.root)
        val op = "upd-${ReleaseLocks.sha256(requestBytes).take(12)}"
        require(schedule == generations.resolve(result.source.id).resolve("rss/schedule") &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(schedule.resolve("binding.json"))) == publication.bindingSha256 &&
            ReleasePrivateFiles.read(schedule.resolve("maintenance-$op.complete")).decodeToString() ==
                "p0v3-rss-maintenance-v1\n${publication.bindingSha256}\n$op\n" &&
            !Files.exists(schedule.resolve("suspended"), NOFOLLOW_LINKS)) {
            "Original RSS held operation has not been completed by its distinct no-target proof"
        }
        val bytes = json.encodeToString(result).toByteArray()
        ReleasePrivateFiles.save(tx.resolve("reference-no-target.terminal.json"), bytes)
        listOf("rollback", "import", "activation").forEach { kind ->
            append(state, "owned-terminal", "$kind:${result.transactionId}",
                setOf(held.snapshot.snapshotId), evidence = ReleaseLocks.sha256(bytes))
        }
        if (state.claims["unknown:held-${request.snapshotId}"] == setOf(held.snapshot.snapshotId))
            append(state, "held-terminal", "held-${request.snapshotId}",
                setOf(held.snapshot.snapshotId), evidence = ReleaseLocks.sha256(bytes))
        if (state.claims["held:${request.snapshotId}"] == setOf(held.snapshot.snapshotId))
            append(state, "operation-terminal", "held:${request.snapshotId}",
                setOf(held.snapshot.snapshotId), evidence = ReleaseLocks.sha256(bytes))
    }
    /** First install closes its THREE exact claims only after the second fresh installation
     * and functional restore, actual COMMITTED first site, and native isolated-target/source
     * resume evidence. Establish the long-lived current-site snapshot claim FIRST. Caller
     * holds ordered generation/site isolation; this reader never acquires those locks. */
    fun retireInstall(terminal: InstallReferenceTerminal) = mutate { state ->
        terminal.validate()
        require(root.parent.fileName.toString() == terminal.source.id && state.pendingOperations.isEmpty())
        val generationBase = root.parent.parent
        val transactionRoot = generationBase.parent.resolve("release-transactions")
        val transaction = transactionRoot.resolve(terminal.transactionId)
        val request = json.decodeFromString<ReleaseTransactionRequest>(ReleasePrivateFiles.read(
            transaction.resolve("request.json")).decodeToString())
        val journal = TransactionJournal.verify(transaction.resolve("transaction.jsonl"))
        val committed = journal.last()
        val accepted = journal.single { it.phase == Phase.ACCEPTED }
        require(request.transactionId == terminal.transactionId && request.previous == null &&
            request.updatePreparation == null && request.deployment == committed.deployment &&
            request.snapshotId == terminal.first.id && accepted.qualificationSnapshotId == terminal.second.id &&
            committed.phase == Phase.COMMITTED && committed.hash == terminal.committedJournalSha256 &&
            committed.deployment?.generationId == terminal.source.id &&
            committed.deployment?.bundleSha256 == terminal.source.bundleSha256 &&
            state.receipts[terminal.first.snapshotId] == terminal.first &&
            state.receipts[terminal.second.snapshotId] == terminal.second &&
            state.claims["rollback:${terminal.transactionId}"] == setOf(terminal.first.snapshotId) &&
            state.claims["activation:${terminal.transactionId}"] == setOf(terminal.first.snapshotId) &&
            state.claims["qualification:${terminal.transactionId}"] == setOf(terminal.second.snapshotId)) {
            "First-install source, second snapshot or native claims differ from committed history"
        }
        val sourceBytes = ReleasePrivateFiles.read(root.parent.resolve("bundle.json"))
        require(ReleaseLocks.sha256(sourceBytes) == terminal.source.bundleSha256)
        val original = json.decodeFromString<GenerationBundle>(sourceBytes.decodeToString())
        SiteOwnerships.checkSealed(original)
        require(original.request.id == terminal.source.id && original.ownership != null &&
            original.ownedUpdate == null && original.recoverySourceKopia == null)
        fun native(receipt: KopiaSnapshotReceipt, completion: GenerationCompletionReceipt) {
            val attempt = root.parent.resolve("backups/${receipt.id}")
            val access = RuntimeBackupAccess(terminal.source.id, receipt.id, terminal.source.bundleSha256)
            val resultBytes = ReleasePrivateFiles.read(attempt.resolve("result.json"))
            val result = json.decodeFromString<GenerationBackupOutcome>(resultBytes.decodeToString())
            val heldBytes = ReleasePrivateFiles.read(attempt.resolve("held.json"))
            val held = json.decodeFromString<GenerationHeldCapture>(heldBytes.decodeToString()).also { it.validate() }
            val authBytes = ReleasePrivateFiles.read(attempt.resolve("resume.authority.json"))
            val authority = json.decodeFromString<HeldSourceResumeAuthority>(authBytes.decodeToString())
            val verified = json.decodeFromString<RuntimeBackupAccess>(ReleasePrivateFiles.read(
                attempt.resolve("resume.verified.json")).decodeToString())
            val proofBytes = ReleasePrivateFiles.read(attempt.resolve("completion.proof.json"))
            val proof = json.decodeFromString<GenerationCompletionProof>(proofBytes.decodeToString())
            proof.validate()
            val targetBytes = ReleasePrivateFiles.read(generationBase.resolve(proof.target).resolve("bundle.json"))
            val target = json.decodeFromString<GenerationBundle>(targetBytes.decodeToString())
            val isolated = json.decodeFromString<GenerationOutcome>(ReleasePrivateFiles.read(
                generationBase.resolve(proof.target).resolve("isolate.result.json")).decodeToString())
            require(completion.proof == proof && completion.record.path == attempt.resolve("completion.proof.json").toString() &&
                completion.record.sha256 == ReleaseLocks.sha256(proofBytes) && proof.access == access &&
                proof.snapshotId == receipt.snapshotId && proof.heldSha256 == ReleaseLocks.sha256(heldBytes) &&
                held.access == access && held.snapshot == receipt &&
                result == GenerationBackupOutcome(access, true, receipt, true) && verified == access &&
                proof.sourceResultSha256 == ReleaseLocks.sha256(resultBytes) &&
                proof.resumeAuthoritySha256 == ReleaseLocks.sha256(authBytes) &&
                authority == HeldSourceResumeAuthority(proof.heldSha256, proof.target,
                    proof.targetBundleSha256, proof.targetFences) &&
                ReleaseLocks.sha256(targetBytes) == proof.targetBundleSha256 &&
                target.recoverySourceKopia == receipt && target.ownership == null &&
                isolated.action == "isolate" && isolated.passed && isolated.bundleSha256 == proof.targetBundleSha256 &&
                isolated.fences == proof.targetFences && isolated.failureType == null) {
                "Native first-install target isolation/source-resume evidence missing"
            }
        }
        native(terminal.first, terminal.firstCompletion)
        native(terminal.second, terminal.secondCompletion)
        val siteOwner = requireNotNull(original.ownership)
        val siteDir = transactionRoot.resolve("active-sites").resolve(ReleaseLocks.sha256(
            siteOwner.contract.site.toByteArray()))
        val before = ReleasePrivateFiles.read(siteDir.resolve("head.json"))
        val head = json.decodeFromString<ActiveSiteHead>(before.decodeToString())
        val selectedBytes = ReleasePrivateFiles.read(siteDir.resolve("rev-${head.ordinal}.json"))
        require(ReleaseLocks.sha256(selectedBytes) == head.revisionSha256)
        val selected = json.decodeFromString<ActiveSiteSelection>(selectedBytes.decodeToString())
        val completePath = siteDir.resolve("${head.revisionSha256}.completed.json")
        val completionBytes = ReleasePrivateFiles.read(completePath)
        val complete = json.decodeFromString<ActiveSiteCompletion>(completionBytes.decodeToString())
        require(selected.fresh && selected.ordinal == 1 && selected.transactionId == terminal.transactionId &&
            selected.source == terminal.source && selected.deployment == committed.deployment &&
            selected.siteId == siteOwner.contract.site && selected.hosts == siteOwner.approvedHosts.sorted() &&
            selected.qualificationSnapshotId == terminal.second.id && selected.selectedTrialId == terminal.selectedTrialId &&
            selected.activationJournalHead == committed.prevHash &&
            selected.consumedPermitSha256 == committed.activationPermitSha256 &&
            complete.selectionSha256 == head.revisionSha256 && complete.committedJournalHead == committed.hash &&
            complete.transactionId == terminal.transactionId && complete.target == committed.deployment &&
            terminal.activeSite == ActivationInput(completePath.toString(), ReleaseLocks.sha256(completionBytes)) &&
            ReleasePrivateFiles.read(siteDir.resolve("head.json")).contentEquals(before)) {
            "First-install site or second-installation authority changed during native retirement"
        }
        val siteKey = "${selected.siteId}-${head.revisionSha256}"
        append(state, "site-selection", siteKey, setOf(terminal.second.snapshotId),
            evidence = terminal.activeSite.sha256)
        val terminalBytes = json.encodeToString(terminal).toByteArray()
        ReleasePrivateFiles.save(transaction.resolve("reference-install.terminal.json"), terminalBytes)
        for ((kind, receipt) in listOf("rollback" to terminal.first, "activation" to terminal.first,
            "qualification" to terminal.second)) append(state, "install-terminal", "$kind:${terminal.transactionId}",
            setOf(receipt.snapshotId), evidence = ReleaseLocks.sha256(terminalBytes))
    }

    /** Read the exact still-protected successor snapshot without releasing any ledger lock
     * across a repository or a second ledger. The caller holds ordered generation isolation. */
    fun siteSelectionEvent(siteId: String, selectionSha256: String,
        snapshot: KopiaSnapshotReceipt): ActivationInput = mutate { state ->
        KopiaGenerationStore.validate(snapshot)
        require(siteId.matches(Regex("[a-z][a-z0-9-]{0,39}")) && selectionSha256.matches(hash) &&
            root.parent.fileName.toString() == snapshot.generation &&
            state.receipts[snapshot.snapshotId] == snapshot &&
            state.claims["site-selection:$siteId-$selectionSha256"] == setOf(snapshot.snapshotId)) {
            "Successor functional snapshot has no current site-selection protection"
        }
        val sequence = (1..state.sequence).lastOrNull { n ->
            val event = json.decodeFromString<RecoveryReferenceEvent>(ReleasePrivateFiles.read(
                root.resolve("%08d.json".format(n))).decodeToString())
            event.kind == "site-selection" && event.id == "$siteId-$selectionSha256" &&
                event.snapshots == setOf(snapshot.snapshotId)
        } ?: error("Missing exact immutable site-selection event")
        val path = root.resolve("%08d.json".format(sequence))
        ActivationInput(path.toString(), ReleaseLocks.sha256(ReleasePrivateFiles.read(path)))
    }

    /** Retire ONLY a superseded selected snapshot after a later actual COMMITTED global-site
     * succession. Never infer this from a new active callback or a native running process. */
    fun retireSupersededSite(terminal: SiteSuccessionTerminal) = mutate { state ->
        val generationBase = root.parent.parent
        val transactions = generationBase.parent.resolve("release-transactions")
        val siteRoot = transactions.resolve("active-sites")
            .resolve(ReleaseLocks.sha256(terminal.siteId.toByteArray()))
        val pattern = Regex("[a-f0-9]{64}")
        terminal.source.validate(); terminal.successor.validate()
        KopiaGenerationStore.validate(terminal.oldSnapshot); KopiaGenerationStore.validate(terminal.successorSnapshot)
        require(terminal.siteId.matches(Regex("[a-z][a-z0-9-]{0,39}")) &&
            terminal.transactionId.matches(Regex("[a-z][a-z0-9-]{0,63}")) &&
            listOf(terminal.priorRevisionSha256, terminal.successorRevisionSha256).all(pattern::matches) &&
            root.parent.fileName.toString() == terminal.source.id && terminal.source != terminal.successor &&
            terminal.oldSnapshot.generation == terminal.source.id &&
            terminal.oldSnapshot.bundleSha256 == terminal.source.bundleSha256 &&
            terminal.successorSnapshot.generation == terminal.successor.id &&
            terminal.successorSnapshot.bundleSha256 == terminal.successor.bundleSha256 &&
            terminal.oldSnapshot.snapshotId != terminal.successorSnapshot.snapshotId &&
            state.pendingOperations.isEmpty() &&
            state.receipts[terminal.oldSnapshot.snapshotId] == terminal.oldSnapshot) {
            "Uncertain previous selected snapshot remains protected"
        }
        fun pinned(pin: ActivationInput, path: Path): ByteArray {
            require(Path.of(pin.path) == path)
            return ReleasePrivateFiles.read(path).also { require(ReleaseLocks.sha256(it) == pin.sha256) }
        }
        val transaction = transactions.resolve(terminal.transactionId)
        val last = TransactionJournal.verify(transaction.resolve("transaction.jsonl")).last()
        val request = json.decodeFromString<ReleaseTransactionRequest>(ReleasePrivateFiles.read(
            transaction.resolve("request.json")).decodeToString())
        val head = json.decodeFromString<ActiveSiteHead>(ReleasePrivateFiles.read(
            siteRoot.resolve("head.json")).decodeToString())
        require(head.ordinal in 1..256 && head.revisionSha256 == terminal.successorRevisionSha256)
        val priorBytes = ReleasePrivateFiles.read(siteRoot.resolve(
            if (head.ordinal == 1) "bootstrap.json" else "rev-${head.ordinal - 1}.json"))
        val successorBytes = ReleasePrivateFiles.read(siteRoot.resolve("rev-${head.ordinal}.json"))
        require(ReleaseLocks.sha256(priorBytes) == terminal.priorRevisionSha256 &&
            ReleaseLocks.sha256(successorBytes) == head.revisionSha256)
        val prior = if (head.ordinal == 1) null else json.decodeFromString<ActiveSiteSelection>(priorBytes.decodeToString())
        val bootstrap = if (head.ordinal == 1) json.decodeFromString<ActiveSiteBootstrap>(priorBytes.decodeToString())
            else null
        bootstrap?.let { approved ->
            ActiveSiteRegistry.real(transaction.resolve("transaction.jsonl"), terminal.siteId,
                approved.hosts.toSet(), terminal.source,
                Path.of("/mnt/media/p0-v3/release-activation-consumptions")
                    .resolve("${terminal.source.id}.consumed.json"))
                .validateBootstrap(approved, siteRoot)
        }
        val selected = json.decodeFromString<ActiveSiteSelection>(successorBytes.decodeToString())
        val original = json.decodeFromString<GenerationBundle>(ReleasePrivateFiles.read(
            generationBase.resolve(terminal.source.id).resolve("bundle.json")).decodeToString())
        val candidate = json.decodeFromString<GenerationBundle>(ReleasePrivateFiles.read(
            generationBase.resolve(terminal.successor.id).resolve("bundle.json")).decodeToString())
        SiteOwnerships.checkSealed(original); SiteOwnerships.checkSealed(candidate)
        require(request.updatePreparation?.intent?.source == terminal.source &&
            request.previousPublication == terminal.priorPublication &&
            last.transactionId == terminal.transactionId && last.phase == Phase.COMMITTED &&
            last.deployment?.generationId == terminal.successor.id &&
            last.deployment?.bundleSha256 == terminal.successor.bundleSha256 &&
            (if (prior != null) prior.deployment.generationId == terminal.source.id &&
                prior.deployment.bundleSha256 == terminal.source.bundleSha256 &&
                prior.qualificationSnapshotId == terminal.oldSnapshot.id &&
                state.claims["site-selection:${terminal.siteId}-${terminal.priorRevisionSha256}"] ==
                    setOf(terminal.oldSnapshot.snapshotId)
            else requireNotNull(bootstrap).let { approved -> approved.source == terminal.source &&
                approved.siteId == terminal.siteId && approved.hosts == selected.hosts }) &&
            selected.source == terminal.source && selected.deployment == last.deployment &&
            selected.transactionId == terminal.transactionId &&
            selected.qualificationSnapshotId == terminal.successorSnapshot.id &&
            selected.previousHeadSha256 == ReleaseLocks.sha256(json.encodeToString(
                ActiveSiteHead(head.ordinal - 1, terminal.priorRevisionSha256)).toByteArray()) &&
            (prior == null || prior.siteId == terminal.siteId && prior.hosts == selected.hosts) &&
            selected.siteId == terminal.siteId &&
            selected.hosts == requireNotNull(candidate.ownership).approvedHosts.sorted()) {
            "Previous and successor active-site chain is not the exact owned COMMITTED succession"
        }
        val completion = pinned(terminal.successorCompletion,
            siteRoot.resolve("${terminal.successorRevisionSha256}.completed.json"))
        val completed = json.decodeFromString<ActiveSiteCompletion>(completion.decodeToString())
        require(completed.selectionSha256 == head.revisionSha256 &&
            completed.transactionId == terminal.transactionId && completed.target == selected.deployment &&
            completed.committedJournalHead == last.hash)
        val claimPath = Path.of(terminal.successorClaimEvent.path)
        require(claimPath.parent == generationBase.resolve(terminal.successor.id).resolve("recovery-references") &&
            claimPath.fileName.toString().matches(Regex("[0-9]{8}\\.json")))
        val claim = json.decodeFromString<RecoveryReferenceEvent>(pinned(terminal.successorClaimEvent,
            claimPath).decodeToString())
        require(claim.kind == "site-selection" &&
            claim.id == "${terminal.siteId}-${terminal.successorRevisionSha256}" &&
            claim.snapshots == setOf(terminal.successorSnapshot.snapshotId) &&
            claim.evidenceSha256 == terminal.successorCompletion.sha256)
        val heldPath = generationBase.resolve(terminal.source.id).resolve(
            "backups/${request.snapshotId}/held.json")
        val held = json.decodeFromString<GenerationHeldCapture>(pinned(terminal.originalHeld,
            heldPath).decodeToString()).also { it.validate() }
        require((prior != null || terminal.oldSnapshot == held.snapshot) &&
            (state.claims["unknown:held-${request.snapshotId}"] == setOf(held.snapshot.snapshotId) ||
                state.claims["held:${request.snapshotId}"] == setOf(held.snapshot.snapshotId))) {
            "Historical original still requires its exact held capture reference"
        }
        val auditPath = transaction.resolve("previous-site-held.audit.json")
        val audit = json.decodeFromString<GenerationInspection>(pinned(terminal.oldNativeAudit,
            auditPath).decodeToString())
        require(held.snapshot.generation == terminal.source.id &&
            held.snapshot.bundleSha256 == terminal.source.bundleSha256 &&
            audit.id == terminal.source.id && audit.bundleSha256 == terminal.source.bundleSha256 &&
            audit.members.size == original.members.size &&
            audit.members.zip(original.members).all { (member, pin) ->
                member.name == pin.spec.name && member.fingerprint == pin.runtimeFingerprint &&
                    member.maintenanceId == held.fences[member.name] &&
                    member.statuses.all { it.state in setOf("completed", "exited") && it.exitCode in setOf(0, 143) }
            }) { "Original site still needs its actual native held source before releasing old snapshot" }
        val rssOperationId = "upd-${ReleaseLocks.sha256(ReleasePrivateFiles.read(
            transaction.resolve("request.json"), 1048576)).take(12)}"
        val priorSchedule = Path.of(terminal.priorPublication.root)
        require(priorSchedule == generationBase.resolve(terminal.source.id).resolve("rss/schedule") &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(priorSchedule.resolve("binding.json"))) ==
                terminal.priorPublication.bindingSha256 &&
            ReleasePrivateFiles.read(priorSchedule.resolve("suspended")).decodeToString() ==
                terminal.priorPublication.bindingSha256 &&
            ReleasePrivateFiles.read(priorSchedule.resolve(
                "maintenance-$rssOperationId.complete")).decodeToString() ==
                "p0v3-rss-maintenance-v1\n${terminal.priorPublication.bindingSha256}\n$rssOperationId\n") {
            "Original schedule not permanently retired after committed source succession"
        }
        val bytes = json.encodeToString(terminal).toByteArray()
        ReleasePrivateFiles.save(transaction.resolve("site-succession.terminal.json"), bytes)
        if (prior != null) append(state, "site-terminal",
            "site-selection:${terminal.siteId}-${terminal.priorRevisionSha256}",
            setOf(terminal.oldSnapshot.snapshotId), evidence = ReleaseLocks.sha256(bytes))
        if (state.claims["unknown:held-${request.snapshotId}"] == setOf(held.snapshot.snapshotId))
            append(state, "held-terminal", "held-${request.snapshotId}",
                setOf(held.snapshot.snapshotId), evidence = ReleaseLocks.sha256(bytes))
        if (state.claims["held:${request.snapshotId}"] == setOf(held.snapshot.snapshotId))
            append(state, "operation-terminal", "held:${request.snapshotId}",
                setOf(held.snapshot.snapshotId), evidence = ReleaseLocks.sha256(bytes))
    }
    /** Nonheld daily backup closes only after durable success, exact original receipt, native
     * resume verification AND separately retained native source audit. COORD writes audit under
     * generation locks after actual resume; a Boolean result is never sufficient.
     */
    fun completeBackup(access: RuntimeBackupAccess) = mutate { state ->
        access.validate()
        require(root.parent.fileName.toString() == access.generation)
        val key = "backup:${access.operation}"
        val operation = root.parent.resolve("backups/${access.operation}")
        val bytes = ReleasePrivateFiles.read(operation.resolve("result.json"))
        val result = json.decodeFromString<GenerationBackupOutcome>(bytes.decodeToString())
        val receipt = requireNotNull(result.snapshot)
        val verified = json.decodeFromString<RuntimeBackupAccess>(ReleasePrivateFiles.read(
            operation.resolve("resume.verified.json")).decodeToString())
        val auditBytes = ReleasePrivateFiles.read(operation.resolve("resume.audit.json"))
        val audit = json.decodeFromString<GenerationInspection>(auditBytes.decodeToString())
        val bundleBytes = ReleasePrivateFiles.read(root.parent.resolve("bundle.json"))
        require(ReleaseLocks.sha256(bundleBytes) == access.bundleSha256)
        val bundle = json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString())
        require(bundle.request.id == access.generation && result.access == access && result.passed && result.sourceResumed && result.failureType == null &&
            verified == access && receipt.generation == access.generation &&
            receipt.bundleSha256 == access.bundleSha256 && receipt.id == access.operation &&
            state.receipts[receipt.snapshotId] == receipt && state.claims[key] == setOf(receipt.snapshotId) &&
            audit.id == access.generation && audit.bundleSha256 == access.bundleSha256 &&
            audit.memoryReservationMiB == bundle.memoryReservationMiB &&
            audit.members.size == bundle.members.size && audit.members.zip(bundle.members).all { (member, pin) ->
                member.name == pin.member.name && member.fingerprint == pin.runtimeFingerprint &&
                    member.maintenanceId == null && member.existingResources > 0 &&
                    member.statuses.map { it.id }.toSet() == pin.spec.processes.map { it.id }.toSet() &&
                    pin.spec.processes.all { process -> member.statuses.singleOrNull { it.id == process.id }?.let {
                        if (process.oneShot) it.state in setOf("completed", "exited") && it.exitCode == 0
                        else it.state == "running"
                    } == true }
            }) { "Native daily backup lacks typed source resume or exact running member readback" }
        append(state, "operation-terminal", key, setOf(receipt.snapshotId),
            evidence = ReleaseLocks.sha256(bytes + auditBytes))
    }
    fun requireTerminalDaily(result: GenerationBackupOutcome) = mutate { state ->
        val access = result.access.also { it.validate() }
        val receipt = requireNotNull(result.snapshot).also { KopiaGenerationStore.validate(it) }
        require(result.passed && result.sourceResumed && result.failureType == null &&
            access.operation == receipt.id && access.generation == receipt.generation &&
            access.bundleSha256 == receipt.bundleSha256 &&
            "backup:${access.operation}" !in state.claims &&
            "backup:${access.operation}" !in state.pendingOperations &&
            (state.receipts[receipt.snapshotId] == receipt || receipt.snapshotId in state.retired)) {
            "Daily operation is unproven or not terminal; never index its original evidence"
        }
        val source = root.parent.resolve("backups/${access.operation}/result.json")
        require(json.decodeFromString<GenerationBackupOutcome>(ReleasePrivateFiles.read(source).decodeToString()) == result)
    }
    fun requireTerminalWeekly(result: WeeklyRestoreResult) = mutate { state ->
        WeeklyRestoreSchedule.validateResult(result)
        if (Files.exists(root.parent.resolve("bundle.json"), NOFOLLOW_LINKS)) {
            val completion = requireNotNull(result.nativeCompletion)
            val path = root.parent.resolve("backups/${result.operation}/completion.proof.json")
            val bytes = ReleasePrivateFiles.read(path)
            val source = path.parent
            val proof = requireNotNull(result.completionProof)
            require(completion.record == ActivationInput(path.toString(), ReleaseLocks.sha256(bytes)) &&
                json.decodeFromString<GenerationCompletionProof>(bytes.decodeToString()) == completion.proof &&
                proof == WeeklyCompletionProof(
                    ReleaseLocks.sha256(ReleasePrivateFiles.read(source.resolve("held.json"))),
                    ReleaseLocks.sha256(ReleasePrivateFiles.read(root.parent.parent.resolve("${result.target}/isolate.result.json"))),
                    ReleaseLocks.sha256(ReleasePrivateFiles.read(source.resolve("resume.authority.json"))),
                    ReleaseLocks.sha256(ReleasePrivateFiles.read(source.resolve("result.json")))))
        }
        val snapshot = result.snapshot.snapshotId
        require(result.completionProof != null && state.receipts[snapshot] == result.snapshot &&
            snapshot in state.verified && state.verificationProofs[snapshot] ==
                ReleaseLocks.sha256(json.encodeToString(result).toByteArray()) &&
            "weekly:${result.operation}" !in state.claims &&
            "unknown:held-${result.operation}" !in state.claims &&
            "held:${result.operation}" !in state.claims &&
            "held:${result.operation}" !in state.pendingOperations) {
            "Weekly slot has no retired operation references or typed durable completion proof"
        }
    }
    fun retireWeekly(result: WeeklyRestoreResult) = mutate { state ->
        WeeklyRestoreSchedule.validateResult(result)
        val snapshot = result.snapshot.snapshotId
        require(result.completionProof != null && state.receipts[snapshot] == result.snapshot && snapshot in state.verified &&
            state.verificationProofs[snapshot] == ReleaseLocks.sha256(json.encodeToString(result).toByteArray()) &&
            state.claims["weekly:${result.operation}"] == setOf(snapshot))
        append(state, "weekly-terminal", result.operation, setOf(snapshot),
            evidence = ReleaseLocks.sha256(json.encodeToString(result).toByteArray()))
    }
    override fun withProtection(action: (KopiaRetentionProtection) -> KopiaRetentionResult): KopiaRetentionResult {
        // Never hold the reference ledger while waiting for the repository lock. A durable fence
        // blocks every writer (including late recovery claims) until the exact deletion is committed.
        val protection = mutate { state ->
            require(state.verified.size >= 2 && state.pendingOperations.isEmpty()) {
                "Two functional points and no unknown pre-repository operation required before retention"
            }
            ReleasePrivateFiles.save(root.resolve("retention.pending"), state.head.toByteArray())
            KopiaRetentionProtection(state.head, state.receipts.values.toList(), state.references.toSet(), state.verified.toSet(),
                KopiaRetention.censusPages(state.head, state.receipts.keys, state.references, state.retired))
        }
        val result = action(protection) // Unknown/failed effects retain the pending fence; NEVER auto retry.
        return ReleasePrivateFiles.locked(root) {
            val state = state()
            val intent = state.head.toByteArray()
            require(state.head == protection.referenceHeadSha256 &&
                ReleasePrivateFiles.read(root.resolve("retention.pending")).contentEquals(intent) &&
                result.plan.referenceHeadSha256 == state.head && result.plan.delete.none { it in state.references } &&
                result.plan.retain.toSet() + result.plan.delete.toSet() == state.receipts.keys &&
                result.plan.retain.toSet().intersect(result.plan.delete.toSet()).isEmpty() &&
                result.plan.retain.count { it in state.verified } >= 2) { "Retention result changed reference protection" }
            append(state, "deleted", result.plan.id, result.plan.delete.toSet())
            ReleasePrivateFiles.removeExact(root.resolve("retention.pending"), intent)
            result
        }
    }
}
