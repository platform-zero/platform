package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Injectable native-effect boundary. Production always delegates to the audited GenerationRuntime;
 * unit clients supply deterministic observations without starting any runtime or external process. */
internal interface ReleaseRuntimeOperations {
    fun stage(generation: String, bundle: String): GenerationOutcome
    fun startRestored(inventory: AcquiredInventory, generation: String, bundle: String): GenerationOutcome
    fun inspect(generation: String, bundle: String): GenerationInspection
    fun holdKopiaForRestore(inventory: AcquiredInventory, generation: String, bundle: String, capture: String): GenerationHeldCapture
    fun resumeHeldSourceAfterIsolation(inventory: AcquiredInventory, generation: String, bundle: String, capture: String,
        held: String, target: String, targetBundle: String): GenerationBackupOutcome
    fun isolate(generation: String, bundle: String): GenerationOutcome
    fun reconcileBackup(generation: String, bundle: String, capture: String, reconciliation: String, prior: String): GenerationOutcome
    fun reconcileIsolation(generation: String, bundle: String, reconciliation: String, prior: String): GenerationOutcome
    fun backupKopia(inventory: AcquiredInventory, generation: String, bundle: String, capture: String): GenerationBackupOutcome
}
internal class NativeReleaseRuntime(private val runtime: GenerationRuntime) : ReleaseRuntimeOperations {
    override fun stage(generation: String, bundle: String) = runtime.stage(generation, bundle)
    override fun startRestored(inventory: AcquiredInventory, generation: String, bundle: String) = runtime.startRestored(inventory, generation, bundle)
    override fun inspect(generation: String, bundle: String) = runtime.inspect(generation, bundle)
    override fun holdKopiaForRestore(inventory: AcquiredInventory, generation: String, bundle: String, capture: String) =
        runtime.holdKopiaForRestore(inventory, generation, bundle, capture)
    override fun resumeHeldSourceAfterIsolation(inventory: AcquiredInventory, generation: String, bundle: String, capture: String,
        held: String, target: String, targetBundle: String) = runtime.resumeHeldSourceAfterIsolation(inventory, generation, bundle, capture, held, target, targetBundle)
    override fun isolate(generation: String, bundle: String) = runtime.isolate(generation, bundle)
    override fun reconcileBackup(generation: String, bundle: String, capture: String, reconciliation: String, prior: String) =
        runtime.reconcileBackup(generation, bundle, capture, reconciliation, prior)
    override fun reconcileIsolation(generation: String, bundle: String, reconciliation: String, prior: String) =
        runtime.reconcileIsolation(generation, bundle, reconciliation, prior)
    override fun backupKopia(inventory: AcquiredInventory, generation: String, bundle: String, capture: String) =
        runtime.backupKopia(inventory, generation, bundle, capture)
}

/** Native install control: generation startup, held Kopia capture, fresh cold import, real pinned
 * functional journeys, target isolation and only then exact held-source resume. No action here grants
 * recovery identity promotion. Owned update generation creation is a distinct runtime capability. */
internal class NativeReleaseControl(private val request: ReleaseTransactionRequest, runtime: GenerationRuntime,
    private val acceptance: ReleaseAcceptance,
    private val restore: (AcquiredInventory, ReleaseGeneration, String, String) -> GenerationOutcome,
    private val operations: ReleaseRuntimeOperations = NativeReleaseRuntime(runtime),
    private val generationBase: Path = GenerationRuntime.BASE) : ReleaseGenerationControl {
    private val source = request.previous ?: ReleaseGeneration(request.deployment.generationId, request.deployment.bundleSha256)
    private var held: GenerationHeldCapture? = null
    private var target: GenerationOutcome? = null
    private var tested = false
    private var resumed = false
    private var activeCapture = request.snapshotId
    private fun inventory(): AcquiredInventory {
        val bytes = ReleasePrivateFiles.read(Path.of(request.inventory.path))
        require(ReleaseLocks.sha256(bytes) == request.inventory.sha256)
        return Json.decodeFromString(bytes.decodeToString())
    }
    private fun bundle(): GenerationBundle {
        val bytes = ReleasePrivateFiles.read(generationBase.resolve(source.id).resolve("bundle.json"))
        require(ReleaseLocks.sha256(bytes) == source.bundleSha256)
        return Json { ignoreUnknownKeys = false }.decodeFromString<GenerationBundle>(bytes.decodeToString()).also {
            require(it.request.id == source.id && it.request.store == RuntimeStore.CANONICAL_V2 &&
                it.ownership != null && it.recoverySourceKopia == null && it.recoverySourceArchiveSha256 == null)
        }
    }
    override fun preflight() {
        request.deployment.validate(); inventory(); bundle()
        // A cold recovery has no site authority; do not relabel it as an owned update candidate.
        require(request.previous == null) {
            "Owned update lineage compiler is not registered; recovery imports cannot be promoted as updates"
        }
        require(request.migration == null)
        val generationRoot = generationBase.resolve(source.id)
        val references = generationRoot.resolve("recovery-references")
        if (!Files.exists(references, NOFOLLOW_LINKS)) {
            val captures = generationRoot.resolve("kopia-captures")
            require(!Files.exists(captures, NOFOLLOW_LINKS) || Files.list(captures).use { !it.findAny().isPresent }) {
                "Existing captures require conservative reference bootstrap before release"
            }
            RecoveryReferences.initialize(references, emptyList())
        }
        require(request.restoreTarget != source.id)
        val qualified = requireNotNull(request.qualifiedRestore) { "Post-real-domain qualified capture/restore required" }
        require(qualified.captureId.matches(Regex("cap-[a-f0-9]{12}")) && qualified.captureId != request.snapshotId &&
            qualified.targetGeneration.matches(Regex("q-[a-f0-9]{12}")) && qualified.targetGeneration !in setOf(source.id, request.restoreTarget))
        val qualifiedBytes = ReleasePrivateFiles.read(Path.of(qualified.acceptance.input.path))
        require(ReleaseLocks.sha256(qualifiedBytes) == qualified.acceptance.input.sha256)
        val qualifiedBinding = Json.parseToJsonElement(qualifiedBytes.decodeToString()).jsonObject
        require(qualifiedBinding.getValue("generationId").jsonPrimitive.content == qualified.targetGeneration &&
            qualifiedBinding.getValue("phase").jsonPrimitive.content == "RESTORE")
        val binding = ReleasePrivateFiles.read(Path.of(request.restore.input.path))
        require(ReleaseLocks.sha256(binding) == request.restore.input.sha256)
        val value = Json.parseToJsonElement(binding.decodeToString()).jsonObject
        require(value.getValue("generationId").jsonPrimitive.content == request.restoreTarget &&
            value.getValue("phase").jsonPrimitive.content == "RESTORE")
    }
    override fun stage() { check(operations.stage(source.id, source.bundleSha256).passed) { "Candidate staging failed" } }
    override fun readiness() {
        val observed = operations.inspect(source.id, source.bundleSha256)
        val expected = bundle()
        require(observed.members.size == expected.members.size && observed.members.zip(expected.members).all { (audit, pin) ->
            audit.name == pin.member.name && audit.fingerprint == pin.runtimeFingerprint && audit.maintenanceId == null &&
                pin.spec.processes.all { process -> audit.statuses.singleOrNull { it.id == process.id }?.let {
                    if (process.oneShot) it.state in setOf("completed", "exited") && it.exitCode == 0 else it.state == "running"
                } == true }
        }) { "Candidate readiness/fingerprint observation failed" }
    }
    override fun freeze() {
        require(held == null)
        held = operations.holdKopiaForRestore(inventory(), source.id, source.bundleSha256, request.snapshotId)
    }
    override fun verifyQuiesced() {
        val held = requireNotNull(held)
        held.validate()
        val observed = operations.inspect(source.id, source.bundleSha256)
        require(observed.members.map { it.name }.toSet() == held.fences.keys && observed.members.all { audit ->
            audit.maintenanceId == held.fences[audit.name] && audit.statuses.all { it.state in setOf("completed", "exited") && it.exitCode in setOf(0, 143) }
        }) { "Source quiescence not observed" }
    }
    override fun capture(): String {
        val held = requireNotNull(held); verifyQuiesced()
        val references = RecoveryReferences(generationBase.resolve(source.id).resolve("recovery-references"))
        // Unknown/unbootstrapped ledger fails closed. Never initialize an empty census over old snapshots.
        references.register(held.snapshot)
        references.protect("rollback", request.transactionId, setOf(held.snapshot.snapshotId))
        references.protect("activation", request.transactionId, setOf(held.snapshot.snapshotId))
        return held.snapshot.id
    }
    override fun restoreTest(snapshot: String) {
        require(snapshot == requireNotNull(held).snapshot.id && target == null)
        val imported = restore(inventory(), source, snapshot, request.restoreTarget)
        target = imported
        check(imported.passed) { "Functional restore import failed" }
        var interrupted = false
        try {
            check(operations.startRestored(inventory(), request.restoreTarget, imported.bundleSha256).passed) { "Staged restore startup failed" }
            acceptance.run("execute-staged", request.restore)
            tested = true
        } catch (failure: InterruptedException) { interrupted = true; throw failure }
        finally {
            interrupted = Thread.interrupted() || interrupted
            try { check(operations.isolate(request.restoreTarget, imported.bundleSha256).passed) { "Restore target isolation uncertain; source stays held" } }
            finally { if (interrupted) Thread.currentThread().interrupt() }
        }
    }
    override fun migrate() { error("Owned update lineage compiler required before invoking a versioned migration") }
    override fun resumeRestrictedCandidate() {
        require(tested)
        val held = requireNotNull(held); val target = requireNotNull(target)
        val result = operations.resumeHeldSourceAfterIsolation(inventory(), source.id, source.bundleSha256,
            request.snapshotId, held.sha256, request.restoreTarget, target.bundleSha256)
        check(result.passed && result.sourceResumed)
        resumed = true
    }
    override fun isolateCandidate() {
        val root = generationBase.resolve(request.deployment.generationId)
        val backupIntent = root.resolve("backups/$activeCapture/intent.json")
        if (!resumed && Files.exists(backupIntent, NOFOLLOW_LINKS)) {
            val resultPath = backupIntent.resolveSibling("result.json")
            val completed = Files.exists(resultPath, NOFOLLOW_LINKS) && Json.decodeFromString<GenerationBackupOutcome>(
                ReleasePrivateFiles.read(resultPath).decodeToString()).let { it.passed && it.sourceResumed }
            if (!completed) {
                check(operations.reconcileBackup(source.id, source.bundleSha256, activeCapture, request.ingress.rollback,
                    ReleaseLocks.sha256(ReleasePrivateFiles.read(backupIntent))).passed)
                return
            }
        }
        val prior = root.resolve("isolate.intent.json")
        val result = if (Files.exists(prior, NOFOLLOW_LINKS)) operations.reconcileIsolation(request.deployment.generationId,
            request.deployment.bundleSha256, request.ingress.rollback, ReleaseLocks.sha256(ReleasePrivateFiles.read(prior)))
        else operations.isolate(request.deployment.generationId, request.deployment.bundleSha256)
        check(result.passed) { "Candidate isolation remains uncertain" }
    }
    override fun qualificationSnapshot(): String {
        require(resumed && tested)
        val qualified = requireNotNull(request.qualifiedRestore)
        activeCapture = qualified.captureId
        resumed = false
        val held = operations.holdKopiaForRestore(inventory(), source.id, source.bundleSha256, qualified.captureId)
        val references = RecoveryReferences(generationBase.resolve(source.id).resolve("recovery-references"))
        references.register(held.snapshot)
        references.protect("qualification", request.transactionId, setOf(held.snapshot.snapshotId))
        val imported = restore(inventory(), source, qualified.captureId, qualified.targetGeneration)
        check(imported.passed)
        var verified = false
        var interrupted = false
        try {
            check(operations.startRestored(inventory(), qualified.targetGeneration, imported.bundleSha256).passed) { "Qualified restore startup failed" }
            acceptance.run("execute-qualified", qualified.acceptance)
            verified = true
        } catch (failure: InterruptedException) { interrupted = true; throw failure }
        finally {
            interrupted = Thread.interrupted() || interrupted
            try { check(operations.isolate(qualified.targetGeneration, imported.bundleSha256).passed) { "Qualified restore target isolation unverified" } }
            finally { if (interrupted) Thread.currentThread().interrupt() }
        }
        require(verified)
        val resumedSource = operations.resumeHeldSourceAfterIsolation(inventory(), source.id, source.bundleSha256,
            qualified.captureId, held.sha256, qualified.targetGeneration, imported.bundleSha256)
        check(resumedSource.passed && resumedSource.sourceResumed)
        resumed = true
        return qualified.captureId
    }
    override fun restorePrevious(snapshot: String) { error("No previous owned generation in native install control") }
    override fun verifyPrevious() { error("No previous owned generation in native install control") }
}

/** Candidate schedule stays unenabled during staging; only an already active previous schedule is
 * permanently suspended. An activation failure suspends the candidate. No suspension is undone. */
internal class NativeReleasePublication(private val request: ReleaseTransactionRequest, private val journal: Path,
    private val scheduler: RssSchedule = RssSchedule.real()) : ReleasePublicationControl {
    override fun pause() {
        val phase = TransactionJournal.verify(journal).last().phase
        if (phase in setOf(Phase.ACTIVATION_STARTED, Phase.RECOVERY_REQUIRED, Phase.COMMITTED)) {
            scheduler.pause(Path.of(request.publication.root), request.publication.bindingSha256)
        } else {
            request.previousPublication?.let { scheduler.pause(Path.of(it.root), it.bindingSha256) }
            val root = Path.of(request.publication.root)
            ReleasePrivateFiles.locked(root) {
                val bytes = ReleasePrivateFiles.read(root.resolve("binding.json"))
                require(ReleaseLocks.sha256(bytes) == request.publication.bindingSha256)
                val binding = RssSchedule.decode(bytes)
                require(binding.deployment == request.deployment && Path.of(binding.transactionJournal) == journal &&
                    !Files.exists(root.resolve("enabled"), NOFOLLOW_LINKS) && !Files.exists(root.resolve("suspended"), NOFOLLOW_LINKS)) {
                    "Candidate publication must be enrolled but never enabled or suspended"
                }
            }
        }
    }
    override fun release() = scheduler.release(Path.of(request.publication.root), request.publication.bindingSha256)
}
