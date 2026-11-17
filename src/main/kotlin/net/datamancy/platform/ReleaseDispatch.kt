package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerialName
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

@Serializable internal data class ReleaseAcceptanceInvocation(val controllerSha256: String,
    val products: ActivationInput, val manifest: ActivationInput, val input: ActivationInput,
    val journal: String, val expectedHead: String, val artifacts: String? = null,
    val contexts: ActivationInput? = null)
@Serializable internal data class ReleaseFunctionalRestore(val captureId: String, val targetGeneration: String,
    val acceptance: ReleaseAcceptanceInvocation)
@Serializable internal data class ReleaseTransactionRequest(val schemaVersion: Int = 1, val transactionId: String,
    val lockDigest: String,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val deployment: ReleaseDeploymentBinding? = null, val inventory: ActivationInput,
    val snapshotId: String, val restoreTarget: String, val ingress: ReleaseIngress,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val publication: ReleasePublication? = null, val staged: ReleaseAcceptanceInvocation,
    val realDomain: ReleaseAcceptanceInvocation, val restore: ReleaseAcceptanceInvocation,
    val previous: ReleaseGeneration? = null, val previousPublication: ReleasePublication? = null,
    val migration: PlankaMigrationRequest? = null, val qualifiedRestore: ReleaseFunctionalRestore? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val updatePreparation: ReleaseUpdatePreparation? = null)
@Serializable internal sealed class ReleaseRequest {
    @Serializable @SerialName("install") data class Install(val transaction: ReleaseTransactionRequest) : ReleaseRequest()
    @Serializable @SerialName("update") data class Update(val transaction: ReleaseTransactionRequest) : ReleaseRequest()
    @Serializable @SerialName("backup") data class Backup(val generation: ReleaseGeneration, val inventory: ActivationInput, val capture: String) : ReleaseRequest()
    @Serializable @SerialName("restore-test") data class RestoreTest(val generation: ReleaseGeneration, val inventory: ActivationInput,
        val capture: String, val target: String, val acceptance: ReleaseAcceptanceInvocation) : ReleaseRequest()
    @Serializable @SerialName("rollback") data class Rollback(val transaction: ReleaseTransactionRequest, val expectedHead: String) : ReleaseRequest()
    @Serializable @SerialName("reconcile") data class Reconcile(val transaction: ReleaseTransactionRequest, val expectedHead: String,
        val reconciliationId: String, val isolationIntentSha256: String, val caddyIntentSha256: String? = null) : ReleaseRequest()
    @Serializable @SerialName("qualify") data class Qualify(val finish: ReleaseAcceptanceInvocation, val assess: ReleaseAcceptanceInvocation) : ReleaseRequest()
    @Serializable @SerialName("qualify-bound") data class QualifyBound(val finish: ReleaseAcceptanceInvocation,
        val candidate: ActivationInput) : ReleaseRequest()
    @Serializable @SerialName("activate") data class Activate(val transaction: ReleaseTransactionRequest, val expectedHead: String,
        val evidence: ActivationEvidenceBinding) : ReleaseRequest()
}

/** A production RESTORE journey MUST own the source-stopped original-host/SNI Caddy bridge,
 * native QClient fence, target isolation and bridge source-resume proof as ONE operation. This
 * is never a callback-only acceptance.run; COORD injects the A13 materialized actor after
 * original certificate/key custody and per-case official client provenance are sealed. */
internal interface ReleaseRestoredJourneys {
    fun execute(operation: String, invocation: ReleaseAcceptanceInvocation, source: ReleaseGeneration,
        target: ReleaseGeneration, acceptance: ReleaseAcceptance,
        isolateTarget: () -> GenerationOutcome): ActivationInput
    /** Only the original release owner supplies held/owned custody and the actual resume actor.
     * The serialized acceptance invocation cannot choose a source disposition. */
    fun execute(operation: String, invocation: ReleaseAcceptanceInvocation, source: ReleaseGeneration,
        target: ReleaseGeneration, acceptance: ReleaseAcceptance, isolateTarget: () -> GenerationOutcome,
        lifecycle: RestoredOwnerLifecycle): ActivationInput =
        error("Typed source-custody RESTORE actor not registered")
}

/** Pinned local Acceptance invocation, never a user-selected executable/shell. execute-qualified
 * requires the existing current BEGIN and freshly creates its artifact directory; FINISH and assessment
 * independently validate exact native artifacts and candidate-bound complete unit coverage. */
internal class ReleaseAcceptance(private val work: Path, private val process: AcceptanceControllerProcess,
    private val controlledExecution: ((String, ReleaseAcceptanceInvocation, List<String>, Path) -> RuntimeCommandResult)? = null,
    private val verifyDistribution: (Path, String) -> Unit = { root, hash ->
        PinnedBackupController.verifyDistribution(root, hash, "p0-v3-acceptance")
    }) {
    private fun arguments(operation: String, request: ReleaseAcceptanceInvocation): List<String> {
        require(operation in setOf("execute-staged", "execute-qualified", "finish-qualified", "assess-qualified"))
        require(request.controllerSha256.matches(Regex("[a-f0-9]{64}")) && request.expectedHead.matches(Regex("[a-f0-9]{64}")))
        val root = Path.of("/mnt/media/p0-v3/runtime-supervision/acceptance-releases/${request.controllerSha256}")
        verifyDistribution(root, request.controllerSha256)
        for (input in listOf(request.products, request.manifest)) QualificationSuiteClosure.readPinnedDocument(input)
        for (input in listOfNotNull(request.input, request.contexts))
            require(ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(input.path))) == input.sha256) { "Acceptance input changed" }
        // Validate private journal without interpreting its different Acceptance hash-chain schema.
        ReleasePrivateFiles.read(Path.of(request.journal), 16 * 1024 * 1024)
        val args = mutableListOf(root.resolve("bin/p0-v3-acceptance").toString(), operation,
            request.products.path, request.manifest.path, request.input.path, request.journal, request.expectedHead)
        if (operation in setOf("execute-staged", "execute-qualified")) {
            val artifacts = Path.of(requireNotNull(request.artifacts))
            require(artifacts.isAbsolute && artifacts.normalize() == artifacts && !Files.exists(artifacts, NOFOLLOW_LINKS))
            ReleasePrivateFiles.directory(artifacts.parent)
            args += artifacts.toString()
            request.contexts?.let { args += it.path }
        } else require(request.artifacts == null && request.contexts == null)
        return args
    }
    fun preflight(operation: String, request: ReleaseAcceptanceInvocation) { arguments(operation, request) }
    fun run(operation: String, request: ReleaseAcceptanceInvocation): String {
        val args = arguments(operation, request)
        val result = try {
            if (operation in setOf("execute-staged", "execute-qualified") && controlledExecution != null)
                controlledExecution.invoke(operation, request, args, work)
            else process.run(args, work)
        } catch (interrupted: InterruptedException) {
            Thread.currentThread().interrupt(); throw interrupted
        }
        check(result.exitCode == 0) { "Pinned Acceptance refused $operation; retained attempt must not be replayed" }
        return result.output
    }
}

/** Real operational dispatch. Generation-control registration is explicit: the coordinator supplies
 * the runtime's lease/cold-restore implementation, not a permissive callback or default mock. */
internal class ReleaseDispatch(private val root: Path, runtime: GenerationRuntime,
    private val controls: (ReleaseTransactionRequest, Path) -> ReleaseGenerationControl,
    private val acceptance: ReleaseAcceptance,
    private val restoreGeneration: (AcquiredInventory, ReleaseGeneration, String, String) -> GenerationOutcome,
    private val publications: (ReleaseTransactionRequest, Path) -> ReleasePublicationControl,
    private val caddyFactory: (ReleaseIngress) -> TransactionalCaddy = ReleaseCaddyEndpoints::real,
    private val authorization: (ReleaseRequest.Activate, Path, TransactionalCaddy) -> ReleaseActivationAuthorization = { request, journal, caddy ->
        val prepared = request.transaction.updatePreparation
        val source = prepared?.intent?.source ?: requireNotNull(request.transaction.deployment).let {
            ReleaseGeneration(it.generationId, it.bundleSha256)
        }
        val bytes = ReleasePrivateFiles.read(GenerationRuntime.BASE.resolve(source.id).resolve("bundle.json"))
        require(ReleaseLocks.sha256(bytes) == source.bundleSha256)
        val original = Json.decodeFromString<GenerationBundle>(bytes.decodeToString(throwOnInvalidSequence = true))
        SiteOwnerships.checkSealed(original)
        require(original.request.id == source.id && original.ownedUpdate == null &&
            original.recoverySourceKopia == null && original.recoverySourceArchiveSha256 == null)
        val ownership = requireNotNull(original.ownership)
        val consumption = Path.of("/mnt/media/p0-v3/release-activation-consumptions")
            .resolve("${prepared?.intent?.targetGeneration ?: source.id}.consumed.json")
        val site = if (prepared == null) ActiveSiteRegistry.realFresh(journal, ownership.contract.site,
            ownership.approvedHosts, consumption) else ActiveSiteRegistry.real(journal, ownership.contract.site,
            ownership.approvedHosts, source, consumption)
        QualifiedActivationAuthorization.real(request.evidence, journal,
            Path.of("/mnt/media/p0-v3/release-activation-consumptions"), caddy, site)
    }, private val operations: ReleaseRuntimeOperations = NativeReleaseRuntime(runtime),
    private val generationBase: Path = GenerationRuntime.BASE,
    private val restoredJourneys: ReleaseRestoredJourneys? = null) {
    companion object {
        val BASE: Path = Path.of("/mnt/media/p0-v3/release-transactions")
        private val json = Json { ignoreUnknownKeys = false; encodeDefaults = true; classDiscriminator = "operation" }
        fun real(runtime: GenerationRuntime,
            restoreWhole: (AcquiredInventory, ReleaseGeneration, String, String) -> GenerationOutcome,
            restoredJourneys: ReleaseRestoredJourneys? = null): ReleaseDispatch {
            val acceptance = ReleaseAcceptance(BASE, LocalAcceptanceControllerProcess(),
                controlledExecution = { operation, invocation, args, work ->
                    val scope = QualificationOwnerControl.scope(invocation, operation)
                    val bindingBytes = ReleasePrivateFiles.read(Path.of(scope.binding.path))
                    require(ReleaseLocks.sha256(bindingBytes) == scope.binding.sha256)
                    val phase = json.parseToJsonElement(bindingBytes.decodeToString(throwOnInvalidSequence = true))
                        .jsonObject.getValue("phase").jsonPrimitive.content
                    require(phase == "INSTALL") {
                        "RESTORE qualification requires a source+target owner bridge scope, not unbridged acceptance"
                    }
                    runtime.withInstallQualificationScope(scope.generationId, scope.bundleSha256) {
                        // First-use principals are enrolled by the ORIGINAL complete
                        // INSTALL journey, not before issuer/app startup. Seal their
                        // source grants only after all original cases succeeded and
                        // before any whole-generation capture can include custody.
                        if (operation == "execute-staged") {
                            runtime.requireOriginalDonetickActorsUnderHeldScope(scope)
                            runtime.enrollOriginalForgejoActorsUnderHeldScope(scope)
                        }
                        val result = QualificationOwnerControl.real(scope).run(args, work)
                        if (operation == "execute-staged" && result.exitCode == 0) {
                            val sourceRoot = GenerationRuntime.BASE.resolve(scope.generationId)
                            val contexts = requireNotNull(scope.contexts) {
                                "Original INSTALL context missing; never mint RESTORE credentials"
                            }
                            val originals = GenerationNativeActorIssuance.produce(sourceRoot,
                                scope.bundleSha256, scope)
                            runtime.stageOriginalQualificationActorsUnderHeldScope(scope.generationId,
                                scope.bundleSha256, contexts, originals)
                        }
                        result
                    }
                })
            return ReleaseDispatch(BASE, runtime,
                { request, _ -> NativeReleaseControl(request, runtime, acceptance, restoreWhole,
                    restoredJourneys = restoredJourneys) }, acceptance, restoreWhole,
                { request, journal -> NativeReleasePublication(request, journal) },
                restoredJourneys = restoredJourneys)
        }
        fun read(path: Path): ReleaseRequest = try {
            json.decodeFromString(ReleasePrivateFiles.read(path).decodeToString(throwOnInvalidSequence = true))
        } catch (_: kotlinx.serialization.SerializationException) {
            // Serializer diagnostics can embed the entire private request, including rejected fields.
            throw IllegalArgumentException("Invalid typed release request; private contents withheld")
        }
        fun operation(request: ReleaseRequest) = when (request) {
            is ReleaseRequest.Install -> "install"; is ReleaseRequest.Update -> "update"; is ReleaseRequest.Backup -> "backup"
            is ReleaseRequest.RestoreTest -> "restore-test"; is ReleaseRequest.Rollback -> "rollback"; is ReleaseRequest.Reconcile -> "reconcile"
            is ReleaseRequest.Qualify, is ReleaseRequest.QualifyBound -> "qualify"; is ReleaseRequest.Activate -> "activate"
        }
    }
    private fun inventory(pin: ActivationInput): AcquiredInventory {
        val bytes = ReleasePrivateFiles.read(Path.of(pin.path))
        require(ReleaseLocks.sha256(bytes) == pin.sha256)
        return json.decodeFromString(bytes.decodeToString())
    }
    private fun transactionRoot(request: ReleaseTransactionRequest): Path {
        val target = request.deployment?.generationId ?: requireNotNull(request.updatePreparation).intent.targetGeneration
        require(request.schemaVersion == 1 && request.transactionId.matches(Regex("[a-z][a-z0-9-]{0,63}")) &&
            request.lockDigest.matches(Regex("[a-f0-9]{64}")) && request.snapshotId.matches(Regex("cap-[a-f0-9]{12}")) &&
            request.restoreTarget.matches(Regex("q-[a-f0-9]{12}")) && request.restoreTarget != target)
        request.deployment?.validate(); request.previous?.validate()
        require((request.previous == null) == (request.previousPublication == null))
        require(if (request.previous == null) request.deployment != null && request.publication != null && request.updatePreparation == null
            else request.deployment == null && request.publication == null && request.updatePreparation != null && request.previous.id != target)
        request.updatePreparation?.validate(requireNotNull(request.previous), target, generationBase)
        val path = root.resolve(request.transactionId)
        if (!Files.exists(path, NOFOLLOW_LINKS)) Files.createDirectory(path,
            java.nio.file.attribute.PosixFilePermissions.asFileAttribute(java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.directory(path)
        val bytes = json.encodeToString(request).toByteArray()
        val binding = path.resolve("request.json")
        if (Files.exists(binding, NOFOLLOW_LINKS)) require(ReleasePrivateFiles.read(binding).contentEquals(bytes)) { "Transaction definition changed" }
        else ReleasePrivateFiles.save(binding, bytes)
        return path
    }
    private fun effects(request: ReleaseTransactionRequest, directory: Path, caddy: TransactionalCaddy): GenerationReleaseEffects =
        GenerationReleaseEffects(directory, request.transactionId, ReleaseLocks.sha256(json.encodeToString(request).toByteArray()),
            request.deployment, request.ingress, controls(request, directory), publications(request, directory.resolve("transaction.jsonl")), caddy,
            request.updatePreparation)
    private fun qualification(request: ReleaseTransactionRequest) = object : ReleaseQualification {
        override fun verifyStagedJourneys() { verifyExecutionBinding(request.staged, targetGeneration(request)); acceptance.run("execute-staged", request.staged) }
        override fun verifyRealDomainJourneys() { verifyExecutionBinding(request.realDomain, targetGeneration(request)); acceptance.run("execute-qualified", request.realDomain) }
    }
    private fun verifyExecutionBinding(invocation: ReleaseAcceptanceInvocation, generation: String) {
        val bytes = ReleasePrivateFiles.read(Path.of(invocation.input.path))
        require(ReleaseLocks.sha256(bytes) == invocation.input.sha256)
        val binding = json.parseToJsonElement(bytes.decodeToString()).jsonObject
        require(binding.getValue("generationId").jsonPrimitive.content == generation) { "Acceptance execution targets another generation" }
    }
    private fun targetGeneration(request: ReleaseTransactionRequest): String =
        request.deployment?.generationId ?: requireNotNull(request.updatePreparation).intent.targetGeneration
    private fun exactHead(request: ReleaseTransactionRequest, journal: Path, expected: String): JournalRecord = TransactionJournal.verify(journal).last().also {
        require(it.hash == expected && it.transactionId == request.transactionId && it.lockDigest == request.lockDigest &&
            (request.deployment?.let { bound -> it.deployment == bound } ?: (it.deployment?.let { bound ->
                bound.generationId == targetGeneration(request) &&
                    bound.sitePolicySha256 == request.updatePreparation!!.intent.sitePolicySha256
            } == true)))
    }
    fun execute(request: ReleaseRequest): String = ReleasePrivateFiles.locked(root) {
        when (request) {
            is ReleaseRequest.Install -> {
                require(request.transaction.previous == null && request.transaction.migration == null && request.transaction.updatePreparation == null)
                runTransaction(request.transaction)
            }
            is ReleaseRequest.Update -> {
                require(request.transaction.previous != null && request.transaction.migration == null && request.transaction.updatePreparation != null && request.transaction.deployment == null)
                request.transaction.updatePreparation.intent.transition.validate()
                runTransaction(request.transaction)
            }
            is ReleaseRequest.Backup -> {
                request.generation.validate()
                val result = operations.backupKopia(inventory(request.inventory), request.generation.id, request.generation.bundleSha256, request.capture)
                check(result.passed && result.sourceResumed) { "Backup incomplete; source must not be resumed or snapshot replayed" }
                json.encodeToString(result)
            }
            is ReleaseRequest.RestoreTest -> {
                request.generation.validate()
                require(request.target.matches(Regex("q-[a-f0-9]{12}")) && request.target != request.generation.id)
                verifyExecutionBinding(request.acceptance, request.target)
                val journey = requireNotNull(restoredJourneys) {
                    "Direct RESTORE acceptance without the source-stopped original-host bridge is forbidden"
                }
                val originalInventory = inventory(request.inventory)
                val originalAuthority = (journey as? NativeRestoredJourneys)?.directAuthority(
                    request.acceptance, request.generation, request.target)
                val imported = restoreGeneration(originalInventory, request.generation, request.capture, request.target)
                check(imported.passed) { "Restore import incomplete; target remains isolated" }
                check(operations.startRestored(originalInventory, request.target, imported.bundleSha256).passed) {
                        "Restore startup incomplete; target must remain isolated"
                    }
                    val restoredTarget = ReleaseGeneration(request.target, imported.bundleSha256)
                    val isolation = { operations.isolate(request.target, imported.bundleSha256) }
                    val proof = if (journey is NativeRestoredJourneys) journey.execute("execute-qualified",
                        request.acceptance, request.generation, restoredTarget, acceptance, isolation,
                        RestoredOwnerLifecycle(heldCapture = null, ownedUpdate = null, resumeSource = null,
                            directInventory = originalInventory, directCaptureId = request.capture,
                            originalRouteAuthority = requireNotNull(originalAuthority)))
                    else journey.execute("execute-qualified", request.acceptance, request.generation,
                        restoredTarget, acceptance, isolation)
                    val bytes = ReleasePrivateFiles.read(Path.of(proof.path))
                    if (json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
                            ["schemaVersion"]?.jsonPrimitive?.int == 2) {
                        val verified = RestoredAggregateEvidence.read(proof,
                            QualificationOwnerControl.scope(request.acceptance, "execute-qualified"),
                            "execute-qualified", request.generation,
                            ReleaseGeneration(request.target, imported.bundleSha256), false)
                        require(verified.sourceDisposition == RestoredSourceDisposition.RESUMED &&
                            verified.heldCapture == null && verified.sourceResume != null)
                        proof.sha256
                    } else {
                    val sourceBytes = ReleasePrivateFiles.read(generationBase.resolve(request.generation.id)
                        .resolve("bundle.json"))
                    val sourceBundle = json.decodeFromString<GenerationBundle>(sourceBytes.decodeToString())
                    SiteOwnerships.checkSealed(sourceBundle)
                    val site = requireNotNull(sourceBundle.ownership)
                    val resume = json.decodeFromString<BridgeResumeProof>(bytes.decodeToString())
                    val removed = json.decodeFromString<RestoredBridgeResult>(ReleasePrivateFiles.read(
                        Path.of(proof.path).parent.resolve("${resume.removal.operation}.result.json")).decodeToString())
                    val isolated = json.decodeFromString<GenerationOutcome>(ReleasePrivateFiles.read(
                        generationBase.resolve(request.target).resolve("isolate.result.json")).decodeToString())
                    require(ReleaseLocks.sha256(bytes) == proof.sha256 &&
                        ReleaseLocks.sha256(sourceBytes) == request.generation.bundleSha256 &&
                        (generationBase != GenerationRuntime.BASE || Path.of(proof.path).parent ==
                            Path.of("/mnt/media/p0-v3/restored-bridges").resolve(site.contract.site)
                                .resolve(request.target)) &&
                        resume.binding.sourceGeneration == request.generation.id &&
                        resume.binding.targetGeneration == request.target &&
                        resume.binding.site == site.contract.site &&
                        resume.binding.originalHosts == site.approvedHosts &&
                        resume.binding.qualifierClientInvocationId != null &&
                        resume.binding.qualifierClientContainerId != null &&
                        resume.binding.qualifierClientAddress?.let { address ->
                            address != resume.binding.clientAddress &&
                                Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}").matches(address) &&
                                java.net.InetAddress.getByName(address).isSiteLocalAddress
                        } == true &&
                        resume.binding.allowedClients.all { it.matches(Regex("[a-z][a-z0-9-]{0,39}")) } &&
                        resume.binding.clientNetwork == "qualification-web" && resume.binding.server == "https" &&
                        resume.removal == removed && resume.removal.action == "remove" &&
                        resume.proofSha256 == ReleaseLocks.sha256(json.encodeToString(removed).toByteArray() +
                            resume.isolationSha256.toByteArray()) &&
                        resume.isolationSha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(
                            generationBase.resolve(request.target).resolve("isolate.result.json"))) &&
                        isolated.action == "isolate" && isolated.passed && isolated.failureType == null &&
                        isolated.bundleSha256 == imported.bundleSha256) {
                        "RESTORE bridge removal, target isolation or source-resume proof missing"
                    }
                    proof.sha256 // Legacy semantic validator only; no new production V1 proof writer.
                    }
            }
            is ReleaseRequest.Qualify -> {
                require(request.assess.copy(input = request.finish.input, expectedHead = request.finish.expectedHead) == request.finish)
                ReleaseQualificationDispatch(root, acceptance).finishAndAssess(request.finish, request.assess.input,
                    request.assess.expectedHead)
            }
            is ReleaseRequest.QualifyBound -> ReleaseQualificationDispatch(root, acceptance)
                .finishAndAssess(request.finish, request.candidate)
            is ReleaseRequest.Activate -> {
                val tx = request.transaction; val directory = transactionRoot(tx); val journal = directory.resolve("transaction.jsonl")
                exactHead(tx, journal, request.expectedHead)
                val caddy = caddyFactory(tx.ingress)
                json.encodeToString(ReleaseTransaction(journal, effects(tx, directory, caddy), qualification(tx)).activate(
                    tx.transactionId, tx.lockDigest, request.expectedHead, authorization(request, journal, caddy)))
            }
            is ReleaseRequest.Rollback -> {
                val tx = request.transaction; val directory = transactionRoot(tx); val journal = directory.resolve("transaction.jsonl")
                val head = exactHead(tx, journal, request.expectedHead)
                require(head.phase in setOf(Phase.SNAPSHOT_VERIFIED, Phase.STAGED, Phase.CUTOVER_RESTRICTED, Phase.ACCEPTED) &&
                    head.activationPermitSha256 == null && tx.previous != null && head.snapshotId != null) { "Possible escaped writes or unverified snapshot: rollback refused" }
                val effects = effects(tx, directory, caddyFactory(tx.ingress))
                // Durable terminal claim BEFORE effects: no lost-ack retry or stale rollback.
                TransactionJournal.appendExisting(journal, Phase.RECOVERY_REQUIRED, head.snapshotId, head.hash)
                if (head.phase in setOf(Phase.CUTOVER_RESTRICTED, Phase.ACCEPTED)) effects.reloadPreviousCaddyConfig()
                effects.isolateCandidate()
                effects.restoreOldSnapshot(head.snapshotId)
                effects.verifyOldStack()
                json.encodeToString(TransactionJournal.verify(journal).last())
            }
            is ReleaseRequest.Reconcile -> {
                val tx = request.transaction; val directory = transactionRoot(tx); val journal = directory.resolve("transaction.jsonl")
                val head = exactHead(tx, journal, request.expectedHead)
                require(head.phase != Phase.COMMITTED) { "Committed release is not failed-attempt reconciliation authority" }
                // Observe Caddy only; never retries a PATCH, opens writes, resumes source or republishes.
                request.caddyIntentSha256?.let { caddyFactory(tx.ingress).reconcile(tx.ingress.cutover, it) }
                val bound = requireNotNull(head.deployment)
                val result = operations.reconcileIsolation(bound.generationId, bound.bundleSha256,
                    request.reconciliationId, request.isolationIntentSha256)
                check(result.passed) { "Candidate isolation remains unverified" }
                json.encodeToString(result)
            }
        }
    }
    private fun runTransaction(request: ReleaseTransactionRequest): String {
        val directory = transactionRoot(request)
        val tx = ReleaseTransaction(directory.resolve("transaction.jsonl"), effects(request, directory, caddyFactory(request.ingress)), qualification(request))
        val update = request.updatePreparation?.let { preparation -> ReleaseUpdateBinding(preparation.intent.source.id,
            preparation.intent.source.bundleSha256, preparation.intent.targetGeneration, preparation.intent.candidateSha256,
            preparation.intent.sitePolicySha256, ReleaseLocks.sha256(json.encodeToString(preparation.intent).toByteArray())) }
        return json.encodeToString(tx.execute(request.transactionId, request.lockDigest, request.previous?.id, request.deployment, update))
    }
}
