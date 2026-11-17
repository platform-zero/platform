package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.encodeToString
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
    fun holdKopiaForRestore(inventory: AcquiredInventory, generation: String, bundle: String, capture: String,
        reference: PendingRecoveryOperation): GenerationHeldCapture =
        error("Native held capture must publish exact pre-repository transaction reference")
    fun resumeHeldSourceAfterIsolation(inventory: AcquiredInventory, generation: String, bundle: String, capture: String,
        held: String, target: String, targetBundle: String): GenerationBackupOutcome
    fun isolate(generation: String, bundle: String): GenerationOutcome
    fun reconcileBackup(generation: String, bundle: String, capture: String, reconciliation: String, prior: String): GenerationOutcome
    fun reconcileIsolation(generation: String, bundle: String, reconciliation: String, prior: String): GenerationOutcome
    fun backupKopia(inventory: AcquiredInventory, generation: String, bundle: String, capture: String): GenerationBackupOutcome
    /** Exact owned-update import, not generic cold recovery promotion. */
    fun importOwnedUpdate(preparation: ReleaseUpdatePreparation, capture: String, transactionId: String): GenerationOutcome =
        error("Owned native import is not registered")
    fun proveOwnedTargetAbsent(preparation: ReleaseUpdatePreparation,
        transactionId: String): NativeOwnedTargetAbsence =
        error("Native no-target isolation census required before source rollback")
    fun resumeOwnedWithoutTarget(preparation: ReleaseUpdatePreparation, capture: String,
        transactionId: String): OwnedUpdateNoTargetRollbackResult =
        error("Native no-target namespace audit and original resume required")
    fun prepareOwnedMigration(candidate: AcquiredInventory, target: String, bundle: String): GenerationOutcome =
        error("Isolated native migration startup is not registered")
    fun startOwnedUpdate(candidate: AcquiredInventory, target: String, bundle: String): GenerationOutcome =
        error("Owned native serving startup is not registered")
}
internal class NativeReleaseRuntime(private val runtime: GenerationRuntime) : ReleaseRuntimeOperations {
    override fun stage(generation: String, bundle: String) = runtime.stage(generation, bundle)
    override fun startRestored(inventory: AcquiredInventory, generation: String, bundle: String) = runtime.startRestored(inventory, generation, bundle)
    override fun inspect(generation: String, bundle: String) = runtime.inspect(generation, bundle)
    override fun holdKopiaForRestore(inventory: AcquiredInventory, generation: String, bundle: String, capture: String) =
        runtime.holdKopiaForRestore(inventory, generation, bundle, capture)
    override fun holdKopiaForRestore(inventory: AcquiredInventory, generation: String, bundle: String, capture: String,
        reference: PendingRecoveryOperation) = runtime.holdKopiaForRestore(inventory, generation, bundle, capture,
            reference = reference)
    override fun resumeHeldSourceAfterIsolation(inventory: AcquiredInventory, generation: String, bundle: String, capture: String,
        held: String, target: String, targetBundle: String) = runtime.resumeHeldSourceAfterIsolation(inventory, generation, bundle, capture, held, target, targetBundle)
    override fun isolate(generation: String, bundle: String) = runtime.isolate(generation, bundle)
    override fun reconcileBackup(generation: String, bundle: String, capture: String, reconciliation: String, prior: String) =
        runtime.reconcileBackup(generation, bundle, capture, reconciliation, prior)
    override fun reconcileIsolation(generation: String, bundle: String, reconciliation: String, prior: String) =
        runtime.reconcileIsolation(generation, bundle, reconciliation, prior)
    override fun backupKopia(inventory: AcquiredInventory, generation: String, bundle: String, capture: String) =
        runtime.backupKopia(inventory, generation, bundle, capture)
    override fun importOwnedUpdate(preparation: ReleaseUpdatePreparation, capture: String, transactionId: String) =
        runtime.importOwnedUpdate(preparation, capture, transactionId)
    override fun proveOwnedTargetAbsent(preparation: ReleaseUpdatePreparation,
        transactionId: String) = runtime.proveOwnedTargetAbsent(preparation, transactionId)
    override fun resumeOwnedWithoutTarget(preparation: ReleaseUpdatePreparation, capture: String,
        transactionId: String) = runtime.resumeOwnedWithoutTarget(preparation, capture, transactionId)
    override fun prepareOwnedMigration(candidate: AcquiredInventory, target: String, bundle: String) =
        runtime.prepareOwnedMigration(candidate, target, bundle)
    override fun startOwnedUpdate(candidate: AcquiredInventory, target: String, bundle: String) =
        runtime.startOwnedUpdate(candidate, target, bundle)
}

/** Native install control: generation startup, held Kopia capture, fresh cold import, real pinned
 * functional journeys, target isolation and only then exact held-source resume. No action here grants
 * recovery identity promotion. Owned update generation creation is a distinct runtime capability. */
internal class NativeReleaseControl(private val request: ReleaseTransactionRequest, private val runtime: GenerationRuntime,
    private val acceptance: ReleaseAcceptance,
    private val restore: (AcquiredInventory, ReleaseGeneration, String, String) -> GenerationOutcome,
    private val operations: ReleaseRuntimeOperations = NativeReleaseRuntime(runtime),
    private val generationBase: Path = GenerationRuntime.BASE,
    private val restoredJourneys: ReleaseRestoredJourneys? = null,
    private val restoredVerifier: RestoredReleaseVerifier = RestoredReleaseVerifier.NATIVE) : ReleaseGenerationControl {
    private val source = request.previous ?: requireNotNull(request.deployment).let {
        ReleaseGeneration(it.generationId, it.bundleSha256)
    }
    private val update = request.updatePreparation
    private var updated: GenerationOutcome? = null
    private var updatedBundle: GenerationBundle? = null
    private var held: GenerationHeldCapture? = null
    private var target: GenerationOutcome? = null
    private var tested = false
    private var stagedRestoreProof: ActivationInput? = null
    private var qualifiedRestoreProof: ActivationInput? = null
    private var resumed = false
    private var activeCapture = request.snapshotId
    private var earlyRollback: OwnedUpdateNoTargetRollbackResult? = null
    private fun requireRestoredBridgeProof(pin: ActivationInput, targetGeneration: String, targetHash: String) {
        val path = Path.of(pin.path)
        val bytes = ReleasePrivateFiles.read(path)
        require(ReleaseLocks.sha256(bytes) == pin.sha256 &&
            (generationBase != GenerationRuntime.BASE ||
                path.parent == Path.of("/mnt/media/p0-v3/restored-bridges")
                    .resolve(request.ingress.site.site).resolve(targetGeneration)) &&
            path.fileName.toString().matches(Regex("r-[a-f0-9]{12}\\.resume-proof\\.json"))) {
            "RESTORE bridge source-resume record must come from the actual target/site"
        }
        val proof = Json.decodeFromString<BridgeResumeProof>(bytes.decodeToString())
        val removal = Json.decodeFromString<RestoredBridgeResult>(ReleasePrivateFiles.read(path.parent.resolve(
            "${proof.removal.operation}.result.json")).decodeToString())
        val isolationBytes = ReleasePrivateFiles.read(generationBase.resolve(targetGeneration).resolve("isolate.result.json"))
        val isolation = Json.decodeFromString<GenerationOutcome>(isolationBytes.decodeToString())
        require(proof.binding.sourceGeneration == source.id && proof.binding.targetGeneration == targetGeneration &&
            proof.binding.site == request.ingress.site.site &&
            proof.binding.originalHosts == request.ingress.site.approvedHosts &&
            proof.binding.qualifierClientInvocationId != null && proof.binding.qualifierClientContainerId != null &&
            proof.binding.qualifierClientAddress?.let { clientIp ->
                clientIp != proof.binding.clientAddress &&
                    Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}").matches(clientIp) &&
                    java.net.InetAddress.getByName(clientIp).isSiteLocalAddress
            } == true &&
            proof.binding.allowedClients.all { member ->
                member.matches(Regex("[a-z][a-z0-9-]{0,39}"))
            } &&
            proof.binding.clientNetwork == "qualification-web" && proof.binding.server == "https" &&
            proof.removal == removal && removal.action == "remove" &&
            proof.isolationSha256 == ReleaseLocks.sha256(isolationBytes) &&
            proof.proofSha256 == ReleaseLocks.sha256(Json.encodeToString(removal).toByteArray() +
                proof.isolationSha256.toByteArray()) &&
            isolation.action == "isolate" && isolation.passed && isolation.failureType == null &&
            isolation.bundleSha256 == targetHash) {
            "Original-host RESTORE client, bridge removal or native target isolation unproven"
        }
    }
    private fun pinnedInventory(pin: ActivationInput): AcquiredInventory {
        val bytes = ReleasePrivateFiles.read(Path.of(pin.path))
        require(ReleaseLocks.sha256(bytes) == pin.sha256)
        return Json.decodeFromString(bytes.decodeToString())
    }
    private fun inventory(): AcquiredInventory = pinnedInventory(update?.previousInventory ?: request.inventory)
    private fun candidateInventory(): AcquiredInventory = pinnedInventory(requireNotNull(update).candidateInventory)
    private fun candidate(): Pair<GenerationBundle, String> {
        val imported = requireNotNull(updated) { "Owned update import not complete" }
        val path = generationBase.resolve(requireNotNull(update).intent.targetGeneration).resolve("bundle.json")
        val bytes = ReleasePrivateFiles.read(path)
        require(ReleaseLocks.sha256(bytes) == imported.bundleSha256)
        val bundle = Json { ignoreUnknownKeys = false }.decodeFromString<GenerationBundle>(bytes.decodeToString())
        OwnedReleaseUpdates.validate(bundle)
        require(bundle.ownedUpdate?.intent == update.intent && bundle.ownedUpdate?.snapshot == requireNotNull(held).snapshot &&
            bundle.request.id == update.intent.targetGeneration)
        return bundle to imported.bundleSha256
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
        request.deployment?.validate(); inventory(); bundle()
        requireNotNull(restoredJourneys) { "RESTORE Acceptance needs source-stopped SNI bridge, native client fence and source-resume proof" }
        require((update == null) == (request.previous == null) && request.migration == null)
        update?.let { preparation ->
            preparation.validate(source, preparation.intent.targetGeneration, generationBase)
            val (previous, candidate) = OwnedReleaseUpdates.preflight(
                ReleasePrivateFiles.read(Path.of(preparation.previousInventory.path)),
                ReleasePrivateFiles.read(Path.of(preparation.candidateInventory.path)), preparation.intent)
            val original = bundle()
            val site = requireNotNull(original.ownership)
            require(request.ingress.site.site == site.contract.site &&
                request.ingress.site.approvedHosts == site.approvedHosts &&
                request.ingress.upstreams.map { it.host }.toSet() == site.contract.routes.map { it.host }.toSet() &&
                request.ingress.upstreams.all { it.host in site.approvedHosts }) {
                "Owned update must keep exact original active site and hostname scope"
            }
            val oldPin = previous.images.single { it.product == "planka" }
            val originalApp = original.members.flatMap { it.spec.processes }.single { it.id == "planka" }
            require(originalApp.image == oldPin.pinnedImage && originalApp.imageId == oldPin.imageId &&
                candidate.images.single { it.product == "planka" }.imageId != originalApp.imageId &&
                request.deployment == null && request.inventory == preparation.candidateInventory &&
                request.snapshotId != requireNotNull(request.qualifiedRestore).captureId &&
                request.publication == null && request.previousPublication != null) {
                "Update candidate inventory or original Planka image changed before source hold"
            }
        }
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
    override fun stage() {
        if (update == null) check(operations.stage(source.id, source.bundleSha256).passed) { "Candidate staging failed" }
        else {
            val original = requireNotNull(held).also { it.validate() }
            require(original.snapshot.id == request.snapshotId && updated == null)
            // A fresh import is a separate repository/target effect from original backup.
            // Publish its exact source-snapshot reference before any native import intent.
            RecoveryReferences(generationBase.resolve(source.id).resolve("recovery-references"))
                .protect("import", request.transactionId, setOf(original.snapshot.snapshotId))
            val imported = operations.importOwnedUpdate(requireNotNull(update), original.snapshot.id, request.transactionId)
            require(imported.action == "restore-import" && imported.passed && imported.failureType == null)
            updated = imported
            candidate() // Revalidate actual sealed native bundle, not a caller future deployment.
        }
    }
    override fun readiness() {
        val (expected, digest) = if (update == null) bundle() to source.bundleSha256 else candidate()
        val observed = operations.inspect(expected.request.id, digest)
        require(observed.members.size == expected.members.size && observed.members.zip(expected.members).all { (audit, pin) ->
            audit.name == pin.member.name && audit.fingerprint == pin.runtimeFingerprint && audit.maintenanceId == null &&
                pin.spec.processes.all { process -> audit.statuses.singleOrNull { it.id == process.id }?.let {
                    if (process.oneShot) it.state in setOf("completed", "exited") && it.exitCode == 0 else it.state == "running"
                } == true }
        }) { "Candidate readiness/fingerprint observation failed" }
    }
    override fun freeze() {
        require(held == null)
        held = operations.holdKopiaForRestore(inventory(), source.id, source.bundleSha256, request.snapshotId,
            PendingRecoveryOperation("rollback", request.transactionId,
                RuntimeBackupAccess(source.id, request.snapshotId, source.bundleSha256)))
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
        references.requireBound("rollback", request.transactionId, held.snapshot)
        references.protect("activation", request.transactionId, setOf(held.snapshot.snapshotId))
        return held.snapshot.id
    }
    override fun restoreTest(snapshot: String) {
        require(snapshot == requireNotNull(held).snapshot.id && target == null)
        val imported = restore(inventory(), source, snapshot, request.restoreTarget)
        target = imported
        check(imported.passed) { "Functional restore import failed" }
        check(operations.startRestored(inventory(), request.restoreTarget, imported.bundleSha256).passed) {
            "Staged restore startup failed"
        }
        val restoreTarget = ReleaseGeneration(request.restoreTarget, imported.bundleSha256)
        val heldPath = generationBase.resolve(source.id).resolve("backups/${held!!.snapshot.id}/held.json")
        val heldPin = ActivationInput(heldPath.toString(), held!!.sha256)
        val ownedPin = if (update == null) null else {
            val path = ReleaseDispatch.BASE.resolve(request.transactionId).resolve("request.json")
            val bytes = ReleasePrivateFiles.read(path)
            require(Json.decodeFromString<ReleaseTransactionRequest>(bytes.decodeToString()) == request)
            ActivationInput(path.toString(), ReleaseLocks.sha256(bytes))
        }
        val proof = requireNotNull(restoredJourneys).execute("execute-staged", request.restore, source,
            restoreTarget, acceptance, { operations.isolate(restoreTarget.id, restoreTarget.bundleSha256) },
            RestoredOwnerLifecycle(heldPin, ownedPin, if (update != null) null else { isolation ->
                require(isolation.action == "isolate" && isolation.passed &&
                    isolation.bundleSha256 == restoreTarget.bundleSha256)
                val resumed = operations.resumeHeldSourceAfterIsolation(inventory(), source.id, source.bundleSha256,
                    held!!.snapshot.id, held!!.sha256, restoreTarget.id, restoreTarget.bundleSha256)
                require(resumed.passed && resumed.sourceResumed && resumed.snapshot == held!!.snapshot)
                val path = generationBase.resolve(source.id).resolve("backups/${held!!.snapshot.id}/result.json")
                ActivationInput(path.toString(), ReleaseLocks.sha256(ReleasePrivateFiles.read(path)))
            }, request.ingress))
        restoredVerifier.verify(proof, request.restore, "execute-staged", source, restoreTarget, update != null)
        stagedRestoreProof = proof
        tested = true
    }
    override fun migrate() {
        val prepared = requireNotNull(update) { "Clean install has no versioned migration" }
        val (target, targetHash) = candidate()
        val candidate = candidateInventory()
        val provider = operations.prepareOwnedMigration(candidate, prepared.intent.targetGeneration, targetHash)
        require(provider.passed && provider.bundleSha256 == targetHash && provider.failureType == null)
        val pin = target.members.single { member -> member.spec.processes.any { it.id == "planka" } }
        val app = pin.spec.processes.single { it.id == "planka" }
        val sourceBundle = bundle()
        val root = generationBase.resolve(prepared.intent.targetGeneration)
        val secret = PlankaMigration.prepareEnvironment(sourceBundle, PrivateDeployment.BASE, root.resolve("migration.env"))
        val manifest = PrivateDeployment.BASE.resolve("${pin.spec.name}.json")
        val manifestBytes = ReleasePrivateFiles.read(manifest)
        require(ReleaseLocks.sha256(manifestBytes) == pin.manifestSha256)
        val fence = requireNotNull(updated).fences.getValue(pin.spec.name)
        val request = PlankaMigrationRequest(operation = prepared.migrationOperation, transition = prepared.intent.transition,
            generation = target.request.id, bundleSha256 = targetHash, snapshotId = requireNotNull(held).snapshot.id,
            manifest = ActivationInput(manifest.toString(), pin.manifestSha256), migrationEnvironment = secret,
            image = ActivationImagePin(app.image, app.imageId), fenceId = fence)
        val attempt = root.resolve("planka-migration")
        Files.createDirectory(attempt, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
            java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.sync(root)
        val result = PlankaMigration.real(attempt, RuntimeStore.CANONICAL_V2).migrate(request)
        require(result.passed && result.migrationRoleRetired && result.operation == prepared.migrationOperation)
        val started = operations.startOwnedUpdate(candidate, target.request.id, targetHash)
        require(started.action == "owned-start" && started.passed && started.bundleSha256 == targetHash &&
            started.failureType == null) { "Owned candidate native startup/adoption remains unproven" }
        updatedBundle = target
    }
    override fun retireInstalledAfterCommittedSite() {
        require(update == null && generationBase == GenerationRuntime.BASE && source.id == request.deployment?.generationId &&
            request.snapshotId == requireNotNull(held).snapshot.id && tested && resumed)
        val qualified = requireNotNull(request.qualifiedRestore)
        val firstTarget = requireNotNull(target)
        require(firstTarget.action == "restore-import" && firstTarget.passed)
        val secondBytes = ReleasePrivateFiles.read(generationBase.resolve(qualified.targetGeneration)
            .resolve("stage.result.json"))
        val second = Json.decodeFromString<GenerationOutcome>(secondBytes.decodeToString())
        require(second.action == "restore-import" && second.passed && second.failureType == null)
        val tx = ActiveSiteRegistry.BASE.parent.resolve(request.transactionId)
        val last = TransactionJournal.verify(tx.resolve("transaction.jsonl")).last()
        require(last.phase == Phase.COMMITTED && last.deployment == request.deployment)
        val ownership = requireNotNull(bundle().ownership)
        val selected = ActiveSiteRegistry.requireActive(requireNotNull(request.deployment),
            tx.resolve("transaction.jsonl"), ownership.contract.site, ownership.approvedHosts)
        require(selected.fresh && selected.qualificationSnapshotId == qualified.captureId &&
            selected.deployment.generationId == source.id)
        val completed = ActiveSiteRegistry.BASE.resolve(ReleaseLocks.sha256(
            ownership.contract.site.toByteArray())).resolve("${ReleaseLocks.sha256(
            Json { encodeDefaults = true }.encodeToString(selected).toByteArray())}.completed.json")
        val completedBytes = ReleasePrivateFiles.read(completed)
        runtime.retireInstallReferences(request.transactionId, source, request.snapshotId,
            request.restoreTarget, firstTarget.bundleSha256, qualified.captureId,
            qualified.targetGeneration, second.bundleSha256,
            ActivationInput(completed.toString(), ReleaseLocks.sha256(completedBytes)),
            selected.selectedTrialId, last.hash)
    }
    private fun retireOwned(committed: Boolean) {
        val prepared = requireNotNull(update)
        require(generationBase == GenerationRuntime.BASE && request.snapshotId.matches(Regex("cap-[a-f0-9]{12}")))
        val candidate = candidate()
        val original = requireNotNull(held).snapshot
        require(original.id == request.snapshotId && candidate.first.ownedUpdate?.snapshot == original)
        val targetRoot = generationBase.resolve(prepared.intent.targetGeneration)
        fun pin(path: Path) = ActivationInput(path.toString(), ReleaseLocks.sha256(ReleasePrivateFiles.read(path)))
        val importResult = pin(targetRoot.resolve("stage.result.json"))
        val heldPin = pin(generationBase.resolve(source.id).resolve("backups/${original.id}/held.json"))
        val qualified = request.qualifiedRestore
        val qualifiedPin = qualified?.let { q ->
            val bytes = ReleasePrivateFiles.read(generationBase.resolve(candidate.first.request.id)
                .resolve("backups/${q.captureId}/held.json"))
            val result = Json.decodeFromString<GenerationHeldCapture>(bytes.decodeToString()).also { it.validate() }
            require(result.access.generation == candidate.first.request.id &&
                result.access.bundleSha256 == candidate.second && result.snapshot.id == q.captureId)
            result.snapshot
        }
        val functionalBundle = qualifiedPin?.let { q ->
            val id = requireNotNull(qualified).targetGeneration
            val bytes = ReleasePrivateFiles.read(generationBase.resolve(id).resolve("bundle.json"))
            id to ReleaseLocks.sha256(bytes)
        }
        val functionalCompletion = qualifiedPin?.let { q ->
            runtime.completionProof(candidate.first.request.id, candidate.second, q.id,
                requireNotNull(functionalBundle).first, functionalBundle.second)
        }
        val transactionRoot = ActiveSiteRegistry.BASE.parent.resolve(request.transactionId)
        val journal = transactionRoot.resolve("transaction.jsonl")
        val last = TransactionJournal.verify(journal).last()
        require(last.phase == if (committed) Phase.COMMITTED else Phase.RECOVERY_REQUIRED)
        val selected = if (committed) ActiveSiteRegistry.requireActive(requireNotNull(request.deployment), journal,
            requireNotNull(candidate.first.ownership).contract.site,
            requireNotNull(candidate.first.ownership).approvedHosts) else null
        val activeSite = selected?.let {
            pin(ActiveSiteRegistry.BASE.resolve(ReleaseLocks.sha256(it.siteId.toByteArray()))
                .resolve("${ReleaseLocks.sha256(Json { encodeDefaults = true }.encodeToString(it).toByteArray())}.completed.json"))
        }
        val completion = if (committed) null else runtime.completionProof(source.id, source.bundleSha256,
            original.id, prepared.intent.targetGeneration, candidate.second)
        val terminals = listOf("rollback", "import", "qualification", "activation").map { kind ->
            OwnedUpdateReferenceTerminal(kind = kind, transactionId = request.transactionId,
                intentSha256 = ReleaseLocks.sha256(Json.encodeToString(prepared.intent).toByteArray()),
                original = original, source = source, targetGeneration = prepared.intent.targetGeneration,
                targetBundleSha256 = candidate.second, sitePolicySha256 = prepared.intent.sitePolicySha256,
                importResult = importResult,
                isolationResult = if (committed) null else pin(targetRoot.resolve("isolate.result.json")),
                sourceCompletion = completion, qualifiedSnapshot = qualifiedPin,
                qualifiedTargetGeneration = functionalBundle?.first,
                qualifiedTargetBundleSha256 = functionalBundle?.second,
                qualifiedCompletion = functionalCompletion,
                activationJournal = if (committed) pin(journal) else null,
                activeSite = activeSite, secondTrialId = selected?.selectedTrialId,
                originalHeld = if (committed) heldPin else null,
                ownedStart = if (committed) pin(targetRoot.resolve("owned-start.result.json")) else null)
        }
        runtime.retireOwnedReferences(terminals)
        if (committed) {
            val current = requireNotNull(selected)
            runtime.retirePriorSiteSelection(request.transactionId, source,
                ReleaseGeneration(candidate.first.request.id, candidate.second), current.siteId, current)
        }
    }
    override fun retireOwnedAfterCommittedSite() = retireOwned(committed = true)
    override fun retireOwnedAfterRollback() {
        val early = earlyRollback
        if (early != null) runtime.retireOwnedEarlyRollback(early)
        else retireOwned(committed = false)
    }
    override fun bindStagedDeployment(snapshotId: String): ReleaseStagedGeneration {
        val prepared = requireNotNull(update)
        require(snapshotId == requireNotNull(held).snapshot.id && updatedBundle != null)
        val (actual, hash) = candidate()
        require(actual == updatedBundle && actual.ownership?.contract?.site != null)
        return ReleaseStagedGeneration(actual.request.id, hash, prepared.intent.sitePolicySha256)
    }
    override fun resumeRestrictedCandidate() {
        require(tested)
        if (update != null) {
            require(updatedBundle != null)
            verifyQuiesced() // Old source remains held throughout restricted target acceptance.
            readiness()
            return
        }
        val held = requireNotNull(held); val target = requireNotNull(target)
        restoredVerifier.verify(requireNotNull(stagedRestoreProof), request.restore, "execute-staged", source,
            ReleaseGeneration(request.restoreTarget, target.bundleSha256), false)
        val resultPath = generationBase.resolve(source.id).resolve("backups/${held.snapshot.id}/result.json")
        val result = Json.decodeFromString<GenerationBackupOutcome>(ReleasePrivateFiles.read(resultPath).decodeToString())
        require(result.access == held.access && result.snapshot == held.snapshot && result.passed && result.sourceResumed)
        resumed = true
    }
    override fun isolateCandidate() {
        val early = update?.let { prepared ->
            if (!Files.exists(generationBase.resolve(prepared.intent.targetGeneration).resolve("bundle.json"), NOFOLLOW_LINKS))
                prepared else null
        }
        if (early != null) {
            val absence = operations.proveOwnedTargetAbsent(early, request.transactionId)
            val actual = Json.decodeFromString<NativeOwnedTargetAbsence>(ReleasePrivateFiles.read(generationBase
                .resolve(early.intent.targetGeneration).resolve("no-target.isolate.json")).decodeToString())
            require(absence == actual && actual.source == source &&
                actual.targetGeneration == early.intent.targetGeneration && actual.runtimeMemberDirectoriesEmpty)
            return
        }
        val target = if (update == null) requireNotNull(request.deployment).let { ReleaseGeneration(it.generationId, it.bundleSha256) }
            else {
                val targetRoot = generationBase.resolve(update.intent.targetGeneration)
                val bytes = ReleasePrivateFiles.read(targetRoot.resolve("bundle.json"))
                val sealed = Json { ignoreUnknownKeys = false }.decodeFromString<GenerationBundle>(bytes.decodeToString())
                OwnedReleaseUpdates.validate(sealed)
                require(sealed.ownedUpdate?.intent == update.intent && sealed.ownedUpdate?.original == bundle())
                ReleaseGeneration(update.intent.targetGeneration, ReleaseLocks.sha256(bytes))
            }
        val root = generationBase.resolve(target.id)
        val backupOwner = if (update != null && activeCapture != request.snapshotId) target else source
        val backupIntent = generationBase.resolve(backupOwner.id).resolve("backups/$activeCapture/intent.json")
        if (!resumed && Files.exists(backupIntent, NOFOLLOW_LINKS)) {
            val resultPath = backupIntent.resolveSibling("result.json")
            val completed = Files.exists(resultPath, NOFOLLOW_LINKS) && Json.decodeFromString<GenerationBackupOutcome>(
                ReleasePrivateFiles.read(resultPath).decodeToString()).let { it.passed && it.sourceResumed }
            if (!completed) {
                check(operations.reconcileBackup(backupOwner.id, backupOwner.bundleSha256, activeCapture, request.ingress.rollback,
                    ReleaseLocks.sha256(ReleasePrivateFiles.read(backupIntent))).passed)
                return
            }
        }
        val prior = root.resolve("isolate.intent.json")
        val result = if (Files.exists(prior, NOFOLLOW_LINKS)) operations.reconcileIsolation(target.id,
            target.bundleSha256, request.ingress.rollback, ReleaseLocks.sha256(ReleasePrivateFiles.read(prior)))
        else operations.isolate(target.id, target.bundleSha256)
        check(result.passed) { "Candidate isolation remains uncertain" }
    }
    override fun qualificationSnapshot(): String {
        require((resumed || update != null && updatedBundle != null) && tested)
        val qualified = requireNotNull(request.qualifiedRestore)
        val qualifiedSource = if (update == null) source else candidate().let { (bundle, hash) ->
            ReleaseGeneration(bundle.request.id, hash)
        }
        val qualifiedInventory = if (update == null) inventory() else candidateInventory()
        activeCapture = qualified.captureId
        resumed = false
        val held = operations.holdKopiaForRestore(qualifiedInventory, qualifiedSource.id, qualifiedSource.bundleSha256, qualified.captureId,
            PendingRecoveryOperation("qualification", request.transactionId,
                RuntimeBackupAccess(qualifiedSource.id, qualified.captureId, qualifiedSource.bundleSha256)))
        val references = RecoveryReferences(generationBase.resolve(qualifiedSource.id).resolve("recovery-references"))
        references.requireBound("qualification", request.transactionId, held.snapshot)
        val imported = restore(qualifiedInventory, qualifiedSource, qualified.captureId, qualified.targetGeneration)
        check(imported.passed)
        check(operations.startRestored(qualifiedInventory, qualified.targetGeneration, imported.bundleSha256).passed) {
            "Qualified restore startup failed"
        }
        val restoreTarget = ReleaseGeneration(qualified.targetGeneration, imported.bundleSha256)
        val heldPath = generationBase.resolve(qualifiedSource.id).resolve("backups/${held.snapshot.id}/held.json")
        val proof = requireNotNull(restoredJourneys).execute("execute-qualified", qualified.acceptance, qualifiedSource,
            restoreTarget, acceptance, { operations.isolate(restoreTarget.id, restoreTarget.bundleSha256) },
            RestoredOwnerLifecycle(ActivationInput(heldPath.toString(), held.sha256), null, { isolation ->
                require(isolation.action == "isolate" && isolation.passed &&
                    isolation.bundleSha256 == restoreTarget.bundleSha256)
                val resumed = operations.resumeHeldSourceAfterIsolation(qualifiedInventory, qualifiedSource.id,
                    qualifiedSource.bundleSha256, qualified.captureId, held.sha256,
                    restoreTarget.id, restoreTarget.bundleSha256)
                require(resumed.passed && resumed.sourceResumed && resumed.snapshot == held.snapshot)
                val path = generationBase.resolve(qualifiedSource.id).resolve("backups/${held.snapshot.id}/result.json")
                ActivationInput(path.toString(), ReleaseLocks.sha256(ReleasePrivateFiles.read(path)))
            }, request.ingress))
        restoredVerifier.verify(proof, qualified.acceptance, "execute-qualified", qualifiedSource, restoreTarget, false)
        qualifiedRestoreProof = proof
        // In an owned update this resumes the CANDIDATE after its own functional restore;
        // the original rollback source is still held. Conflating them forbids safe rollback.
        resumed = update == null
        return qualified.captureId
    }
    override fun restorePrevious(snapshot: String) {
        val prepared = requireNotNull(update) { "No prior owned generation to restore" }
        require(snapshot == request.snapshotId && !resumed)
        if (!Files.exists(generationBase.resolve(prepared.intent.targetGeneration).resolve("bundle.json"), NOFOLLOW_LINKS)) {
            earlyRollback = operations.resumeOwnedWithoutTarget(prepared, snapshot, request.transactionId)
            require(earlyRollback?.source == source && earlyRollback?.targetGeneration == prepared.intent.targetGeneration)
            resumed = true
            return
        }
        val bytes = ReleasePrivateFiles.read(generationBase.resolve(prepared.intent.targetGeneration).resolve("bundle.json"))
        val sealed = Json { ignoreUnknownKeys = false }.decodeFromString<GenerationBundle>(bytes.decodeToString())
        OwnedReleaseUpdates.validate(sealed)
        require(sealed.ownedUpdate?.intent == prepared.intent && sealed.ownedUpdate?.original == bundle() &&
            sealed.ownedUpdate?.snapshot?.id == snapshot)
        val targetHash = ReleaseLocks.sha256(bytes)
        val target = Json.decodeFromString<GenerationOutcome>(ReleasePrivateFiles.read(generationBase.resolve(prepared.intent.targetGeneration)
            .resolve("stage.result.json")).decodeToString())
        require(target.action == "restore-import" && target.passed && target.bundleSha256 == targetHash)
        val originalHeld = Json.decodeFromString<GenerationHeldCapture>(ReleasePrivateFiles.read(
            generationBase.resolve(source.id).resolve("backups/$snapshot/held.json")).decodeToString()).also { it.validate() }
        require(originalHeld.snapshot == sealed.ownedUpdate?.snapshot && originalHeld.access.bundleSha256 == source.bundleSha256)
        // Outer rollback cannot bypass an interrupted owner journey in either restored target.
        // An absent journey marker predates ALL owner client/bridge effects; even then the
        // restored target must have stopped before original source resume.
        fun requireRestoredTargetClosed(targetId: String, ownerSource: ReleaseGeneration,
            invocation: ReleaseAcceptanceInvocation, operation: String, heldSha256: String?,
            completed: ActivationInput?) {
            val root = generationBase.resolve(targetId)
            if (!Files.exists(root.resolve("bundle.json"), NOFOLLOW_LINKS)) return
            val bytes = ReleasePrivateFiles.read(root.resolve("bundle.json"))
            val restoredTarget = ReleaseGeneration(targetId, ReleaseLocks.sha256(bytes))
            val scope = QualificationOwnerControl.scope(invocation, operation)
            if (completed == null)
                RestoredFailureSafetyEvidence.requireIfStarted(scope, ownerSource, restoredTarget, heldSha256)
            else RestoredAggregateEvidence.read(completed, scope, operation, ownerSource, restoredTarget, false)
            val stopped = operations.inspect(targetId, restoredTarget.bundleSha256)
            require(stopped.members.isNotEmpty() && stopped.members.all { member ->
                member.maintenanceId != null && member.statuses.all { it.state in setOf("exited", "completed") }
            }) { "Restored target can still write; original source remains fenced" }
        }
        requireRestoredTargetClosed(request.restoreTarget, source, request.restore,
            "execute-staged", originalHeld.sha256, stagedRestoreProof)
        request.qualifiedRestore?.let { qualified ->
            val candidate = ReleaseGeneration(prepared.intent.targetGeneration, targetHash)
            val qualifiedHeld = generationBase.resolve(candidate.id)
                .resolve("backups/${qualified.captureId}/held.json")
            val heldSha = if (Files.exists(qualifiedHeld, NOFOLLOW_LINKS))
                ReleaseLocks.sha256(ReleasePrivateFiles.read(qualifiedHeld)) else null
            requireRestoredTargetClosed(qualified.targetGeneration, candidate, qualified.acceptance,
                "execute-qualified", heldSha, qualifiedRestoreProof)
        }
        val isolated = operations.inspect(prepared.intent.targetGeneration, target.bundleSha256)
        require(isolated.members.isNotEmpty() && isolated.members.all { member ->
            member.maintenanceId != null && member.statuses.all { it.state in setOf("exited", "completed") }
        }) { "Candidate can still write: original source must remain fenced" }
        val result = operations.resumeHeldSourceAfterIsolation(inventory(), source.id, source.bundleSha256,
            snapshot, originalHeld.sha256, prepared.intent.targetGeneration, target.bundleSha256)
        require(result.passed && result.sourceResumed && result.snapshot == originalHeld.snapshot)
        resumed = true
    }
    override fun verifyPrevious() {
        require(update != null && resumed)
        earlyRollback?.let { proof ->
            val path = generationBase.resolve(source.id).resolve("backups/${request.snapshotId}/no-target.rollback.result.json")
            require(Json.decodeFromString<OwnedUpdateNoTargetRollbackResult>(ReleasePrivateFiles.read(path).decodeToString()) == proof &&
                proof.originalHeldSha256 == requireNotNull(held).sha256 &&
                proof.transactionId == request.transactionId &&
                !Files.exists(generationBase.resolve(proof.targetGeneration).resolve("bundle.json"), NOFOLLOW_LINKS)) {
                "No-target original resume cannot be inferred from a native callback"
            }
        }
        val original = bundle()
        val observed = operations.inspect(source.id, source.bundleSha256)
        require(observed.members.size == original.members.size && observed.members.zip(original.members).all { (audit, pin) ->
            audit.name == pin.spec.name && audit.fingerprint == pin.runtimeFingerprint && audit.maintenanceId == null &&
                pin.spec.processes.filterNot { it.oneShot }.all { process ->
                    audit.statuses.singleOrNull { it.id == process.id }?.state == "running"
                }
        }) { "Original native source was not restored to its exact running identity" }
    }
}

internal interface NativeRssTimerControl {
    fun start(root: Path, expected: String)
    fun stopIfOwned(root: Path, expected: String)
}
internal object SystemdRssTimerControl : NativeRssTimerControl {
    override fun start(root: Path, expected: String) = RssNativeTimerOwner.start(root, expected)
    override fun stopIfOwned(root: Path, expected: String) {
        RssNativeTimerOwner.stopIfOwned(root, expected)
    }
}

/** Candidate schedule stays unenabled during staging; only an already active previous schedule is
 * permanently suspended. An activation failure suspends the candidate. No suspension is undone. */
internal class NativeReleasePublication(private val request: ReleaseTransactionRequest, private val journal: Path,
    private val scheduler: RssSchedule = RssSchedule.real(),
    private val runtime: GenerationRuntime = GenerationRuntime.real(),
    private val generationBase: Path = GenerationRuntime.BASE,
    private val timer: NativeRssTimerControl = SystemdRssTimerControl) : ReleasePublicationControl {
    private fun ownedTarget(): ReleasePublication {
        val prepared = requireNotNull(request.updatePreparation)
        val generation = prepared.intent.targetGeneration
        val bundleBytes = ReleasePrivateFiles.read(generationBase.resolve(generation).resolve("bundle.json"))
        val bundle = Json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString())
        OwnedReleaseUpdates.validate(bundle)
        require(bundle.ownedUpdate?.intent == prepared.intent)
        val root = generationBase.resolve(generation).resolve("rss/schedule")
        val binding = ReleasePrivateFiles.read(root.resolve("binding.json"))
        val hash = ReleaseLocks.sha256(binding)
        val decoded = RssSchedule.decode(binding)
        require(decoded.deployment == TransactionJournal.verify(journal).last().deployment &&
            decoded.deployment.generationId == generation &&
            decoded.deployment.bundleSha256 == ReleaseLocks.sha256(bundleBytes) &&
            ReleasePrivateFiles.read(root.resolve("enrolled")).decodeToString() == hash) {
            "Owned target RSS must be enrolled from the actual sealed candidate and transaction"
        }
        return ReleasePublication(root.toString(), hash)
    }
    override fun pause() {
        val history = TransactionJournal.verify(journal)
        val phase = history.last().phase
        require(phase != Phase.COMMITTED) { "Committed site RSS retirement needs active-site authority, not generic pause" }
        val activationAttempted = history.any { it.phase == Phase.ACTIVATION_STARTED }
        if (request.updatePreparation != null) {
            val prepared = requireNotNull(request.updatePreparation)
            val prior = requireNotNull(request.previousPublication)
            if (activationAttempted && phase in setOf(Phase.ACTIVATION_STARTED, Phase.RECOVERY_REQUIRED)) {
                val candidate = ownedTarget()
                scheduler.pause(Path.of(candidate.root), candidate.bindingSha256)
                timer.stopIfOwned(Path.of(candidate.root), candidate.bindingSha256)
            } else {
                val source = prepared.intent.source
                val proof = RssOwnedUpdateOperationProof(generationBase, runtime, request.transactionId,
                    source.id, source.bundleSha256, request.snapshotId, prepared.intent.targetGeneration)
                scheduler.beginHeld(Path.of(prior.root), prior.bindingSha256, proof.operationId, proof)
            }
            return
        }
        if (activationAttempted && phase in setOf(Phase.ACTIVATION_STARTED, Phase.RECOVERY_REQUIRED)) {
            val candidate = requireNotNull(request.publication)
            scheduler.pause(Path.of(candidate.root), candidate.bindingSha256)
            timer.stopIfOwned(Path.of(candidate.root), candidate.bindingSha256)
        } else {
            request.previousPublication?.let {
                scheduler.pause(Path.of(it.root), it.bindingSha256)
                timer.stopIfOwned(Path.of(it.root), it.bindingSha256)
            }
            val candidate = requireNotNull(request.publication)
            val root = Path.of(candidate.root)
            ReleasePrivateFiles.locked(root) {
                val bytes = ReleasePrivateFiles.read(root.resolve("binding.json"))
                require(ReleaseLocks.sha256(bytes) == candidate.bindingSha256)
                val binding = RssSchedule.decode(bytes)
                require(binding.deployment == request.deployment && Path.of(binding.transactionJournal) == journal &&
                    !Files.exists(root.resolve("enabled"), NOFOLLOW_LINKS) && !Files.exists(root.resolve("suspended"), NOFOLLOW_LINKS)) {
                    "Candidate publication must be enrolled but never enabled or suspended"
                }
            }
        }
    }
    override fun release() {
        if (request.updatePreparation != null) {
            val candidate = ownedTarget()
            // The old source remains reversibly held. A04 permanently retires its original
            // schedule ONLY after observed COMMITTED+consumed permit+global active-site proof.
            scheduler.release(Path.of(candidate.root), candidate.bindingSha256)
            timer.start(Path.of(candidate.root), candidate.bindingSha256)
        } else {
            val candidate = requireNotNull(request.publication)
            scheduler.release(Path.of(candidate.root), candidate.bindingSha256)
            timer.start(Path.of(candidate.root), candidate.bindingSha256)
        }
    }
    override fun commitOwnedRetirement() {
        val prepared = requireNotNull(request.updatePreparation)
        val original = prepared.intent.source
        val prior = requireNotNull(request.previousPublication)
        val candidate = ownedTarget()
        val proof = RssOwnedUpdateOperationProof(generationBase, runtime, request.transactionId,
            original.id, original.bundleSha256, request.snapshotId, prepared.intent.targetGeneration,
            RssSchedule.decode(ReleasePrivateFiles.read(Path.of(candidate.root).resolve("binding.json")))
                .deployment.bundleSha256)
        scheduler.commitRetirement(Path.of(prior.root), prior.bindingSha256, proof.operationId, proof)
        timer.stopIfOwned(Path.of(prior.root), prior.bindingSha256)
    }
    override fun completeOwnedRollback() {
        val prepared = requireNotNull(request.updatePreparation)
        val source = prepared.intent.source
        val prior = requireNotNull(request.previousPublication)
        val target = prepared.intent.targetGeneration
        val early = generationBase.resolve(source.id).resolve("backups/${request.snapshotId}/no-target.rollback.result.json")
        if (Files.exists(early, NOFOLLOW_LINKS)) {
            require(!Files.exists(generationBase.resolve(target).resolve("bundle.json"), NOFOLLOW_LINKS)) {
                "A sealed owned target cannot use early no-target source completion"
            }
            val proof = RssEarlyUpdateRollbackProof(generationBase, runtime, request.transactionId,
                source.id, source.bundleSha256, request.snapshotId, target)
            val claim = RssHeldOperation(prior.root, prior.bindingSha256, proof.operationId,
                RssMaintenance.pending(Path.of(prior.root), prior.bindingSha256, proof.operationId),
                source.id, source.bundleSha256)
            scheduler.completeHeld(claim, proof)
            return
        }
        val bytes = ReleasePrivateFiles.read(generationBase.resolve(target).resolve("bundle.json"))
        val digest = ReleaseLocks.sha256(bytes)
        val proof = RssOwnedUpdateOperationProof(generationBase, runtime, request.transactionId,
            source.id, source.bundleSha256, request.snapshotId, target, digest)
        val claim = RssHeldOperation(prior.root, prior.bindingSha256, proof.operationId,
            RssMaintenance.pending(Path.of(prior.root), prior.bindingSha256, proof.operationId), source.id, source.bundleSha256)
        scheduler.completeHeld(claim, proof)
    }
}
