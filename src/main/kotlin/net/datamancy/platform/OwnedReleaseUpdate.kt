package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** Immutable PREPARED update identity. The future bundle digest is deliberately not guessed. */
@Serializable internal data class ReleaseUpdateIntent(val source: ReleaseGeneration, val targetGeneration: String,
    val candidateSha256: String, val sitePolicySha256: String, val previousInventorySha256: String,
    val candidateInventorySha256: String, val transition: PlankaVersionTransition) {
    fun validate() {
        source.validate(); transition.validate()
        require(targetGeneration.matches(Regex("q-[a-f0-9]{12}")) && targetGeneration != source.id &&
            listOf(candidateSha256, sitePolicySha256, previousInventorySha256, candidateInventorySha256).all { it.matches(Regex("[a-f0-9]{64}")) })
    }
}
/** PREPARED has no future bundle or credential. All five pins are immutable original authority;
 * a distinct candidate bundle is sealed only AFTER the verified original Kopia snapshot.
 */
@Serializable internal data class ReleaseUpdatePreparation(val schemaVersion: Int = 1, val intent: ReleaseUpdateIntent,
    val previousInventory: ActivationInput, val candidateInventory: ActivationInput,
    val sourceBundle: ActivationInput, val sitePolicy: ActivationInput, val migrationOperation: String) {
    fun validate(source: ReleaseGeneration, target: String, generationBase: Path) {
        intent.validate()
        require(schemaVersion == 1 && migrationOperation.matches(Regex("r-[a-f0-9]{12}")) &&
            intent.source == source && intent.targetGeneration == target &&
            sourceBundle.sha256 == source.bundleSha256 && sitePolicy.sha256 == intent.sitePolicySha256 &&
            previousInventory.sha256 == intent.previousInventorySha256 &&
            candidateInventory.sha256 == intent.candidateInventorySha256 &&
            Path.of(sourceBundle.path) == generationBase.resolve(source.id).resolve("bundle.json")) {
            "Update PREPARED authority must name immutable original bundle, inventories and site"
        }
        listOf(previousInventory, candidateInventory, sourceBundle, sitePolicy).forEach { pin ->
            require(ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(pin.path))) == pin.sha256) {
                "Update pinned source/candidate input changed before snapshot"
            }
        }
    }
}

/** Immutable pointer set for A03 ledger retirement. It is NEVER itself proof of success: A03
 * independently reads and compares exact native journals and Acceptance second-cycle evidence
 * at these fixed derived paths under ledger locks before appending a terminal event.
 */
@Serializable internal data class OwnedUpdateReferenceTerminal(val schemaVersion: Int = 1, val kind: String,
    val transactionId: String, val intentSha256: String, val original: KopiaSnapshotReceipt,
    val source: ReleaseGeneration, val targetGeneration: String, val targetBundleSha256: String,
    val sitePolicySha256: String, val importResult: ActivationInput, val isolationResult: ActivationInput? = null,
    val sourceCompletion: GenerationCompletionReceipt? = null, val qualifiedSnapshot: KopiaSnapshotReceipt? = null,
    val qualifiedTargetGeneration: String? = null, val qualifiedTargetBundleSha256: String? = null,
    val qualifiedCompletion: GenerationCompletionReceipt? = null, val activationJournal: ActivationInput? = null,
    val activeSite: ActivationInput? = null, val secondTrialId: String? = null,
    val originalHeld: ActivationInput? = null, val ownedStart: ActivationInput? = null) {
    fun validate(transactionRoot: Path, generationBase: Path) {
        source.validate(); KopiaGenerationStore.validate(original)
        val hash = Regex("[a-f0-9]{64}")
        val committed = activeSite != null
        require(schemaVersion == 1 && kind in setOf("rollback", "import", "qualification", "activation") &&
            transactionId.matches(Regex("[a-z][a-z0-9-]{0,63}")) &&
            listOf(intentSha256, targetBundleSha256, sitePolicySha256).all(hash::matches) &&
            targetGeneration.matches(Regex("q-[a-f0-9]{12}")) && targetGeneration != source.id &&
            original.generation == source.id && original.bundleSha256 == source.bundleSha256 &&
            importResult.path == generationBase.resolve(targetGeneration).resolve("stage.result.json").toString() &&
            hash.matches(importResult.sha256) &&
            committed == (isolationResult == null && sourceCompletion == null) &&
            (!committed || originalHeld?.path == generationBase.resolve(source.id)
                .resolve("backups/${original.id}/held.json").toString() &&
                ownedStart?.path == generationBase.resolve(targetGeneration).resolve("owned-start.result.json").toString() &&
                listOf(requireNotNull(originalHeld).sha256, requireNotNull(ownedStart).sha256).all(hash::matches))) {
            "Native update reference terminal must bind fixed original/target paths"
        }
        if (!committed) {
            val isolated = requireNotNull(isolationResult)
            val completed = requireNotNull(sourceCompletion)
            completed.proof.validate()
            require(isolated.path == generationBase.resolve(targetGeneration).resolve("isolate.result.json").toString() &&
                hash.matches(isolated.sha256) &&
                completed.proof.access.generation == source.id &&
                completed.proof.snapshotId == original.snapshotId &&
                completed.proof.target == targetGeneration &&
                completed.proof.targetBundleSha256 == targetBundleSha256 &&
                completed.record.path == generationBase.resolve(source.id)
                    .resolve("backups/${original.id}/completion.proof.json").toString() &&
                hash.matches(completed.record.sha256)) { "Original source resume and isolated update target required" }
        }
        val qualified = qualifiedSnapshot != null
        require((qualifiedTargetGeneration != null) == qualified &&
            (qualifiedTargetBundleSha256 != null) == qualified && (qualifiedCompletion != null) == qualified &&
            (!committed || qualified)) {
            "Qualified snapshot must include separately isolated target and source-resume proof"
        }
        if (qualified) {
            val receipt = requireNotNull(qualifiedSnapshot)
            val target = requireNotNull(qualifiedTargetGeneration)
            val completion = requireNotNull(qualifiedCompletion)
            KopiaGenerationStore.validate(receipt); completion.proof.validate()
            require(receipt.id != original.id && receipt.snapshotId != original.snapshotId &&
                receipt.generation == targetGeneration && receipt.bundleSha256 == targetBundleSha256 &&
                target.matches(Regex("q-[a-f0-9]{12}")) && target !in setOf(source.id, targetGeneration) &&
                completion.proof.access.generation == targetGeneration &&
                completion.proof.snapshotId == receipt.snapshotId && completion.proof.target == target &&
                completion.proof.targetBundleSha256 == qualifiedTargetBundleSha256 &&
                completion.record.path == generationBase.resolve(targetGeneration)
                    .resolve("backups/${receipt.id}/completion.proof.json").toString()) {
                "Distinct post-real-domain functional restore completion required"
            }
        }
        require((activationJournal != null) == committed &&
            (secondTrialId != null) == committed &&
            (originalHeld != null) == committed && (ownedStart != null) == committed) {
            "Committed site transfer and rollback terminal evidence must remain distinct"
        }
        if (committed) require(requireNotNull(activationJournal).path ==
            transactionRoot.resolve(transactionId).resolve("transaction.jsonl").toString() &&
            requireNotNull(secondTrialId).matches(Regex("[a-z][a-z0-9-]{0,95}")) &&
            listOf(requireNotNull(activationJournal).sha256, requireNotNull(activeSite).sha256).all(hash::matches)) {
            "Activation requires exact second-cycle journal and active-site record"
        }
    }
}

@Serializable internal data class GenerationCertificatePublishIntent(val schemaVersion: Int = 1,
    val operation: String, val generation: ReleaseGeneration, val host: String,
    val approvedHosts: Set<String>, val trust: ActivationInput,
    val originalBundleSha256: String? = null, val originalManifestSha256: String? = null,
    val recoveredRoot: String? = null)

@Serializable internal data class NativeOwnedTargetAbsence(val schemaVersion: Int = 1,
    val source: ReleaseGeneration, val targetGeneration: String,
    val targetMembers: List<String>, val podmanInventorySha256: Map<String, String>,
    val runtimeMemberDirectoriesEmpty: Boolean)

/** An early PREPARED update failed before a sealed target ever existed. This is a distinct
 * typed rollback, NOT ordinary recovered-target completion or an invented target import. */
@Serializable internal data class OwnedUpdateNoTargetRollbackResult(val schemaVersion: Int = 1,
    val transactionId: String, val source: ReleaseGeneration, val originalHeldSha256: String,
    val targetGeneration: String, val nativeAbsence: ActivationInput,
    val sourceResumeAudit: ActivationInput, val sourceResumeProof: ActivationInput,
    val originalSiteHead: ActivationInput)

@Serializable internal data class OwnedUpdateNoTargetSourceResumeProof(val schemaVersion: Int = 1,
    val originalHeldSha256: String, val nativeAbsenceSha256: String,
    val resumedMembers: List<String>, val resumeResultSha256: String, val sourceAuditSha256: String)

@Serializable internal data class OwnedUpdateLineage(val schemaVersion: Int = 1, val intent: ReleaseUpdateIntent,
    val snapshot: KopiaSnapshotReceipt,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val original: GenerationBundle? = null) {
    fun validate() {
        intent.validate(); KopiaGenerationStore.validate(snapshot)
        require(schemaVersion == 1 && snapshot.generation == intent.source.id && snapshot.bundleSha256 == intent.source.bundleSha256)
    }
}

/** Version-aware compiler for a fresh OWNED update, not a recovery-promotion escape hatch.
 * Cold restoration checks the exact old compiler before this narrowly supported image substitution.
 * Original state bytes and surviving credential hashes are retained. All initializer roles stay retired.
 */
internal object OwnedReleaseUpdates {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    /** Pure transition proof BEFORE a source hold, repository mutation, or candidate credentials.
     * The installed source bundle is checked separately; here all non-Planka pins are immutable.
     */
    fun preflight(previousInventoryBytes: ByteArray, candidateInventoryBytes: ByteArray,
        intent: ReleaseUpdateIntent): Pair<AcquiredInventory, AcquiredInventory> {
        intent.validate()
        require(ReleaseLocks.sha256(previousInventoryBytes) == intent.previousInventorySha256 &&
            ReleaseLocks.sha256(candidateInventoryBytes) == intent.candidateInventorySha256)
        val previous = json.decodeFromString<AcquiredInventory>(previousInventoryBytes.decodeToString(throwOnInvalidSequence = true))
        val candidate = json.decodeFromString<AcquiredInventory>(candidateInventoryBytes.decodeToString(throwOnInvalidSequence = true))
        require(previous.schemaVersion == 1 && candidate.schemaVersion == 1 &&
            previous.images.map { it.product }.distinct().size == previous.images.size &&
            candidate.images.map { it.product }.distinct().size == candidate.images.size)
        val old = previous.images.associateBy { it.product }; val next = candidate.images.associateBy { it.product }
        require(old.keys == next.keys && old.filterKeys { it != "planka" } == next.filterKeys { it != "planka" }) {
            "Only the reviewed Planka patch may change; unsupported provider or application updates refused"
        }
        val oldPlanka = old.getValue("planka"); val newPlanka = next.getValue("planka")
        require(oldPlanka.reference == "ghcr.io/plankanban/planka:2.2.0" && newPlanka.reference == "ghcr.io/plankanban/planka:2.2.1" &&
            oldPlanka.os == "linux" && newPlanka.os == "linux" && oldPlanka.architecture == "amd64" && newPlanka.architecture == "amd64" &&
            oldPlanka.pinnedImage != newPlanka.pinnedImage && oldPlanka.imageId != newPlanka.imageId)
        return previous to candidate
    }
    /** Only a feature-owned update can replace the generic recovery projection's inert RSS plan.
     * This seals a definition, NOT an enrollment, timer, permit, or publication authority.
     */
    internal fun ownedRssProjection(source: GenerationRequest, cold: GenerationRequest): GenerationRequest {
        require(source.store == RuntimeStore.CANONICAL_V2 && source.recoveredRssPlan == null &&
            cold.id != source.id && cold.store == RuntimeStore.CANONICAL_V2 && cold.rssPlan == null &&
            cold.recoveredRssPlan == source.rssPlan) { "Owned update RSS must originate from an active original plan" }
        source.rssPlan?.validate()
        // The cold restore's extra capacity was already admitted into diskReservationMiB.
        // The recovery-only marker must not grant inert import authority to an owned site.
        return cold.copy(rssPlan = source.rssPlan, recoveredRssPlan = null,
            recoveryStateReservationMiB = null)
    }
    fun compile(original: GenerationBundle, previousInventoryBytes: ByteArray, candidateInventoryBytes: ByteArray,
        intent: ReleaseUpdateIntent, snapshot: KopiaSnapshotReceipt, managedSourceManifest: ByteArray? = null): GenerationBundle {
        intent.validate()
        val lineage = OwnedUpdateLineage(intent = intent, snapshot = snapshot, original = original).also { it.validate() }
        require(original.request.id == intent.source.id && original.request.store == RuntimeStore.CANONICAL_V2 &&
            original.recoverySourceArchiveSha256 == null && original.recoverySourceKopia == null && original.ownedUpdate == null &&
            ReleaseLocks.sha256(json.encodeToString(original).toByteArray()) == intent.source.bundleSha256) {
            "Update requires the exact original owned source, never a recovery or unverified chained update"
        }
        SiteOwnerships.checkSealed(original)
        val sourceOwner = requireNotNull(original.ownership)
        val (previous, candidate) = preflight(previousInventoryBytes, candidateInventoryBytes, intent)
        val oldPlanka = previous.images.single { it.product == "planka" }
        val newPlanka = candidate.images.single { it.product == "planka" }
        val restored = FoundationRestore.bundle(original, previous, intent.targetGeneration, KopiaGenerationStore.receiptHash(snapshot),
            ColdRestoreCohort.WHOLE_RELEASE, RuntimeStore.CANONICAL_V2, managedSourceManifest,
            original.request.managedLanes?.native?.imageArchive)
        var replaced = 0
        val pins = restored.members.map { pin ->
            val spec = pin.spec.copy(processes = pin.spec.processes.map { process ->
                if (process.image == oldPlanka.pinnedImage && process.imageId == oldPlanka.imageId) {
                    require(process.id == "planka" && !process.oneShot && process.command == listOf("app.js", "--prod"))
                    replaced++
                    process.copy(image = newPlanka.pinnedImage, imageId = newPlanka.imageId)
                } else process
            }).also { PrivateDeployment.validate(it) }
            pin.copy(spec = spec, manifestSha256 = ReleaseLocks.sha256(Json.encodeToString(spec).toByteArray()),
                runtimeFingerprint = PrivateDeployment.expectedFingerprint(spec, pin.inputHashes))
        }
        require(replaced == 1) { "Exactly one compiled Planka daemon required" }
        val request = ownedRssProjection(original.request, restored.request).copy(
            candidateSha256 = intent.candidateSha256, releaseCandidateSha256 = null)
        val assemblyRequest = sourceOwner.assembly.request.copy(id = intent.targetGeneration,
            candidateSha256 = intent.candidateSha256, inventorySha256 = intent.candidateInventorySha256,
            // Cold import raises disk reservation for authenticated extraction. Ownership must
            // bind that actual capacity policy, not silently project the smaller source policy.
            diskReservationMiB = request.diskReservationMiB, memoryHeadroomMiB = request.memoryHeadroomMiB,
            diskHeadroomMiB = request.diskHeadroomMiB, store = request.store)
        fun renamed(value: String): String {
            require(value.startsWith(original.request.id + "-")) { "Foreign ownership reference" }
            return intent.targetGeneration + value.removePrefix(original.request.id)
        }
        val summaries = pins.mapIndexed { index, pin ->
            val spec = pin.spec
            val source = sourceOwner.assembly.members[index]
            require(renamed(source.name) == pin.member.name)
            source.copy(name = spec.name, dependencies = pin.member.dependencies,
                specSha256 = ReleaseLocks.sha256(Json.encodeToString(spec).toByteArray()),
                images = spec.processes.associate { it.image to it.imageId },
                daemons = spec.processes.map { it.id }, initializers = emptyList(),
                state = spec.volumes.map { volume -> AssemblyState(volume.id, volume.userId,
                    spec.processes.filter { p -> p.volumes.any { it.volume == volume.id } }.map { it.id }.sorted()) },
                inputs = PrivateDeployment.inputNames(spec).map { file -> AssemblyInput(file,
                    spec.processes.filter { it.environmentFile == file || it.files.any { f -> f.file == file } }.map { it.id }.sorted()) })
        }
        val summary = sourceOwner.assembly.copy(request = assemblyRequest, members = summaries,
            globalIntegrationValidated = false, fullStackQualification = false, publicActivation = false)
        val specs = pins.map { it.spec }
        val plan = AssemblyPlan(summary, request, candidate, specs, emptyList())
        val processNames = specs.flatMap { s -> s.processes.map { "${s.name}/${it.id}" } }.toSet()
        val inputNames = specs.flatMap { s -> PrivateDeployment.inputNames(s).map { "${s.name}/$it" } }.toSet()
        val contract = sourceOwner.contract.copy(assemblySha256 = SiteOwnerships.assemblyDigest(plan),
            processes = sourceOwner.contract.processes.map { it.copy(process = renamed(it.process)) }.filter { it.process in processNames },
            state = sourceOwner.contract.state.map { it.copy(volume = renamed(it.volume)) },
            inputs = sourceOwner.contract.inputs.map { it.copy(input = renamed(it.input), consumers = it.consumers.map(::renamed).filter(processNames::contains)) }
                .filter { it.input in inputNames },
            routes = sourceOwner.contract.routes.map { it.copy(process = renamed(it.process)) })
        val ownership = SiteOwnerships.bind(plan, contract, sourceOwner.approvedHosts, lineage)
        val result = restored.copy(request = request, members = pins, assemblySha256 = contract.assemblySha256,
            recoverySourceArchiveSha256 = null, recoverySourceKopia = null, ownership = ownership, ownedUpdate = lineage)
        validate(result)
        return result
    }
    /** Authenticated source metadata, not a caller-selected list of roles to omit. No update chains. */
    fun original(lineage: OwnedUpdateLineage): GenerationBundle {
        lineage.validate()
        val source = requireNotNull(lineage.original) { "Owned update requires retained original ownership evidence" }
        require(source.ownedUpdate == null && source.recoverySourceKopia == null && source.recoverySourceArchiveSha256 == null &&
            source.ownership != null && source.request.id == lineage.intent.source.id &&
            source.request.store == RuntimeStore.CANONICAL_V2 &&
            ReleaseLocks.sha256(json.encodeToString(source).toByteArray()) == lineage.intent.source.bundleSha256) {
            "Owned update original evidence differs from the verified snapshot"
        }
        SiteOwnerships.checkSealed(source)
        return source
    }

    fun validate(bundle: GenerationBundle) {
        val lineage = requireNotNull(bundle.ownedUpdate).also { it.validate() }
        val source = original(lineage)
        require(bundle.request.rssPlan == source.request.rssPlan && bundle.request.recoveredRssPlan == null &&
            bundle.request.recoveryStateReservationMiB == null &&
            source.request.recoveredRssPlan == null &&
            bundle.request.id == lineage.intent.targetGeneration && bundle.request.candidateSha256 == lineage.intent.candidateSha256 &&
            bundle.request.store == RuntimeStore.CANONICAL_V2 && bundle.recoverySourceArchiveSha256 == null && bundle.recoverySourceKopia == null &&
            bundle.ownership != null && bundle.members.all { it.spec.ingress == null && it.spec.nativeIngress == null &&
                it.spec.processes.none { process -> process.oneShot } }) {
            "Foreign owned-update lineage or initializer resurrection"
        }
        SiteOwnerships.checkSealed(bundle)
    }
}
