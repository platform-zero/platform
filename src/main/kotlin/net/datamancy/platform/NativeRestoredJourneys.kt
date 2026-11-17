package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** V2 only; the legacy single-client BridgeResumeProof remains byte-for-byte unchanged. */
@Serializable internal enum class RestoredSourceDisposition { RESUMED, RETAINED_FOR_OWNED_UPDATE }
@Serializable internal data class RestoredAggregateProof(val schemaVersion: Int = 2,
    val operation: String, val suiteId: String, val source: ReleaseGeneration, val target: ReleaseGeneration,
    val sourceDisposition: RestoredSourceDisposition, val quiescence: ActivationInput,
    val heldCapture: ActivationInput?, val ownedUpdate: ActivationInput?,
    val retainedSource: ActivationInput?, val sourceResume: ActivationInput?,
    val caseClosures: List<ActivationInput>, val finalIsolation: ActivationInput)
@Serializable internal data class RestoredDirectSourceQuiesce(val schemaVersion: Int = 2,
    val suiteId: String, val source: ReleaseGeneration, val target: ReleaseGeneration,
    val captureId: String, val fences: Map<String, String>, val snapshotSha256: String,
    val originalRouteSha256: String)
@Serializable internal data class RestoredDirectSourceResume(val schemaVersion: Int = 2,
    val suiteId: String, val source: ReleaseGeneration, val target: ReleaseGeneration,
    val quiescenceSha256: String, val finalIsolationSha256: String,
    val resumed: Boolean, val sourceAuditSha256: String)
@Serializable internal data class RestoredFailureSafety(val schemaVersion: Int = 2,
    val suiteId: String, val source: ReleaseGeneration, val target: ReleaseGeneration,
    val heldCaptureSha256: String?, val quiescenceSha256: String,
    val caseSafety: List<ActivationInput>, val finalIsolation: ActivationInput,
    val sourceDisposition: String = "HELD_NO_PROMOTION")

/** Production-used owner-thread sequencing seam. An acceptance error does NOT skip
 * bounded native safety readback or the ONE target-isolation attempt. */
internal class RestoredLifecycleDriver(private val owner: Thread = Thread.currentThread()) {
    data class Attempt<T>(val completion: T?, val failure: Throwable?,
        val safety: List<ActivationInput>, val isolation: GenerationOutcome) {
        fun requireForSourceDisposition(): T {
            if (failure != null) throw failure
            require(isolation.action == "isolate" && isolation.passed && isolation.failureType == null)
            return requireNotNull(completion)
        }
    }
    /** Independent original-case evidence must reject BEFORE any retained-source receipt,
     * source resume, or successful aggregate write. The caller's view stays in memory. */
    fun <T> verifiedCasesBeforeDisposition(attempt: Attempt<List<ActivationInput>>,
        verify: (List<ActivationInput>) -> T): T {
        check(Thread.currentThread() === owner)
        val closures = attempt.requireForSourceDisposition()
        require(closures.isNotEmpty() && closures.size == attempt.safety.size)
        return verify(closures)
    }
    fun <T> settle(run: () -> T, safety: () -> List<ActivationInput>,
        isolate: () -> GenerationOutcome): Attempt<T> {
        check(Thread.currentThread() === owner)
        var interrupted = Thread.interrupted()
        fun <V> observed(block: () -> V): Result<V> = runCatching(block).also {
            interrupted = interrupted || Thread.interrupted() || it.exceptionOrNull() is InterruptedException
        }
        try {
            val completion = observed(run)
            val safe = observed(safety)
            val isolated = observed(isolate)
            if (safe.isFailure || isolated.isFailure) throw IllegalStateException(
                "Native case teardown or target isolation uncertain; source stays held").also { failure ->
                listOfNotNull(completion.exceptionOrNull(), safe.exceptionOrNull(),
                    isolated.exceptionOrNull()).forEach(failure::addSuppressed)
            }
            return Attempt(completion.getOrNull(), completion.exceptionOrNull(),
                safe.getOrThrow(), isolated.getOrThrow())
        } finally { if (interrupted) Thread.currentThread().interrupt() }
    }
}

internal object RestoredSourceDispositionPolicy {
    fun select(attempt: RestoredLifecycleDriver.Attempt<List<ActivationInput>>,
        heldCapture: ActivationInput?, ownedUpdate: ActivationInput?): RestoredSourceDisposition {
        val closures = attempt.requireForSourceDisposition()
        require(closures.isNotEmpty() && attempt.safety.size == closures.size)
        return if (ownedUpdate == null) RestoredSourceDisposition.RESUMED
        else {
            require(heldCapture != null) { "An owned rollback source cannot be presumed from an empty capture" }
            RestoredSourceDisposition.RETAINED_FOR_OWNED_UPDATE
        }
    }
}

@Serializable internal data class RestoredRetainedSource(val schemaVersion: Int = 2,
    val operation: String, val source: ReleaseGeneration, val target: ReleaseGeneration,
    val heldCaptureSha256: String, val ownedUpdateSha256: String, val originalFences: Map<String, String>,
    val pendingDisposition: String = "OWNED_UPDATE_COMMIT_OR_ROLLBACK",
    val isolatedTargetSha256: String)

/** Sole private owner context; never serialized into acceptance input or C1 capability. */
internal data class RestoredOwnerLifecycle(val heldCapture: ActivationInput?, val ownedUpdate: ActivationInput?,
    val resumeSource: ((GenerationOutcome) -> ActivationInput)?, val originalIngress: ReleaseIngress? = null,
    val directInventory: AcquiredInventory? = null, val directCaptureId: String? = null,
    val originalRouteAuthority: RestoredOriginalRouteAuthority? = null)

internal data class RestoredOwnerScope(val source: ReleaseGeneration, val target: ReleaseGeneration,
    val sourcePin: GenerationPin, val targetPin: GenerationPin,
    val quiescence: ActivationInput, val listener: ListenerBridgeQuiesceResult,
    val heldCapture: ActivationInput?, val readiness: ActivationInput,
    val upstreams: List<CaddyUpstream>, val sourceCertificates: Map<String, ActivationInput>,
    val sourcePrivateKeys: Map<String, ActivationInput>, val certificateFiles: Map<String, String>,
    val keyFiles: Map<String, String>, val site: String, val approvedHosts: Set<String>,
    val actorProjections: Map<String, Pair<JsonObject, List<ActivationInput>>> = emptyMap())

/** Production entry retains the globally sorted source+target cohort from first quiesce
 * through every case, final target isolation, and exact source disposition. */
internal class NativeRestoredJourneys(private val runtime: GenerationRuntime) : ReleaseRestoredJourneys {
    companion object { fun real(runtime: GenerationRuntime) = NativeRestoredJourneys(runtime) }
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private fun pin(path: Path, max: Int = 4194304): ActivationInput = ActivationInput(path.toString(),
        ReleaseLocks.sha256(ReleasePrivateFiles.read(path, max)))
    /** Direct release dispatch calls this while holding the root controller lock, before
     * target import and before acquiring the retained native/source+target cohort. */
    fun directAuthority(invocation: ReleaseAcceptanceInvocation, source: ReleaseGeneration,
        targetId: String): RestoredOriginalRouteAuthority {
        source.validate()
        require(targetId.matches(Regex("q-[a-f0-9]{12}")) && targetId != source.id)
        val input = ReleasePrivateFiles.read(Path.of(invocation.input.path), 1048576)
        require(ReleaseLocks.sha256(input) == invocation.input.sha256)
        val binding = json.parseToJsonElement(input.decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(binding.getValue("phase").jsonPrimitive.content == "RESTORE" &&
            binding.getValue("generationId").jsonPrimitive.content == targetId)
        val bytes = ReleasePrivateFiles.read(GenerationRuntime.BASE.resolve(source.id).resolve("bundle.json"))
        require(ReleaseLocks.sha256(bytes) == source.bundleSha256)
        val sourceBundle = json.decodeFromString<GenerationBundle>(bytes.decodeToString(throwOnInvalidSequence = true))
        SiteOwnerships.checkSealed(sourceBundle)
        val candidate = binding.getValue("candidate").jsonObject
        val fields = listOf("implementationSha256", "artifactsSha256", "configurationSha256",
            "acceptanceSha256", "sitePolicySha256")
        require(candidate.keys == fields.toSet() && sourceBundle.request.candidateSha256 ==
            ReleaseLocks.sha256(JsonObject(fields.associateWith { candidate.getValue(it) }).toString().toByteArray()))
        val owner = requireNotNull(sourceBundle.ownership)
        return ActiveSiteRegistry.readOriginalRoutes(source, owner.contract.site, owner.approvedHosts,
            candidate.getValue("sitePolicySha256").jsonPrimitive.content)
    }
    override fun execute(operation: String, invocation: ReleaseAcceptanceInvocation, source: ReleaseGeneration,
        target: ReleaseGeneration, acceptance: ReleaseAcceptance, isolateTarget: () -> GenerationOutcome): ActivationInput =
        error("Direct RESTORE requires the bound original inventory and capture ID in the owner lifecycle")
    override fun execute(operation: String, invocation: ReleaseAcceptanceInvocation, source: ReleaseGeneration,
        target: ReleaseGeneration, acceptance: ReleaseAcceptance, isolateTarget: () -> GenerationOutcome,
        lifecycle: RestoredOwnerLifecycle): ActivationInput {
        require(operation in setOf("execute-staged", "execute-qualified") && source.id != target.id)
        val scope = QualificationOwnerControl.scope(invocation, operation)
        val phaseBytes = ReleasePrivateFiles.read(Path.of(scope.binding.path), 1048576)
        val phaseBinding = json.parseToJsonElement(phaseBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(scope.generationId == target.id && phaseBinding.getValue("phase").jsonPrimitive.content == "RESTORE")
        val originalAuthority = if (lifecycle.heldCapture == null)
            lifecycle.originalRouteAuthority ?: directAuthority(invocation, source, target.id)
        else null
        require(lifecycle.heldCapture == null || lifecycle.originalRouteAuthority == null)
        originalAuthority?.let { require(it.source == source && it.sitePolicySha256 ==
            phaseBinding.getValue("candidate").jsonObject.getValue("sitePolicySha256").jsonPrimitive.content) }
        originalAuthority?.recheck() // Global registry lock is released before the native cohort.
        return runtime.withRestoredIsolationLocks(source, target) {
        var isolationAttempted = false
        try {
        originalAuthority?.recheck() // A raw head pin check, not a nested registry lock.
        val scope = QualificationOwnerControl.scope(invocation, operation)
        val phaseBytes = ReleasePrivateFiles.read(Path.of(scope.binding.path), 1048576)
        require(scope.generationId == target.id && scope.bundleSha256 == target.bundleSha256 &&
            json.parseToJsonElement(phaseBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
                .getValue("phase").jsonPrimitive.content == "RESTORE")
        val sourceBytes = ReleasePrivateFiles.read(GenerationRuntime.BASE.resolve(source.id).resolve("bundle.json"))
        val targetBytes = ReleasePrivateFiles.read(GenerationRuntime.BASE.resolve(target.id).resolve("bundle.json"))
        require(ReleaseLocks.sha256(sourceBytes) == source.bundleSha256 &&
            ReleaseLocks.sha256(targetBytes) == target.bundleSha256)
        val sourceBundle = json.decodeFromString<GenerationBundle>(sourceBytes.decodeToString(throwOnInvalidSequence = true))
        val targetBundle = json.decodeFromString<GenerationBundle>(targetBytes.decodeToString(throwOnInvalidSequence = true))
        SiteOwnerships.checkSealed(sourceBundle); SiteOwnerships.checkSealed(targetBundle)
        val sourcePin = QualificationCanonicalTopology.require(sourceBundle,
            allowOwnedUpdateSource = sourceBundle.ownedUpdate != null)
        val targetPin = QualificationCanonicalTopology.require(targetBundle, restoredTarget = true)
        require(targetBundle.recoverySourceKopia?.let { it.generation == source.id &&
            it.bundleSha256 == source.bundleSha256 } == true)
        val owner = requireNotNull(sourceBundle.ownership)
        val site = owner.contract.site
        val originalUpstreams = originalAuthority?.also { authority ->
            require(authority.source == source && authority.site == site &&
                authority.approvedHosts == owner.approvedHosts)
        }?.upstreams ?: requireNotNull(lifecycle.originalIngress) { "Actual held ingress authority required" }
            .also { ingress -> require(ingress.site.site == site &&
                ingress.site.approvedHosts == owner.approvedHosts && ingress.site.server == "https") }.upstreams
        require(originalUpstreams.map { it.host }.toSet() ==
            owner.contract.routes.map { it.host }.toSet() - "start.datamancy.net")
        val publicOrigin = if (originalAuthority != null) source.id
            else sourceBundle.ownedUpdate?.intent?.source?.id ?: source.id
        val translated = originalUpstreams.map { original ->
            val prefix = "p0v3-live-$publicOrigin-"
            require(original.dial.startsWith(prefix))
            val memberProcessAndPort = original.dial.removePrefix(prefix)
            val suffix = memberProcessAndPort.substringAfterLast(':').toIntOrNull()
            require(suffix in 1..65535 && memberProcessAndPort.startsWith("v2-") &&
                targetPin.spec.processes.any { process ->
                    memberProcessAndPort == "v2-${process.id}:$suffix" && !process.oneShot
                })
            original.copy(dial = "p0v3-live-${target.id}-$memberProcessAndPort")
        }
        val direct = lifecycle.heldCapture == null
        val op = "r-${ReleaseLocks.sha256("${scope.suiteId}\n${source.id}\n${target.id}\n"
            .encodeToByteArray()).take(12)}"
        val listenerBinding = ListenerSuccessionBinding(op, site, source.id, sourcePin.runtimeFingerprint,
            target.id, targetPin.runtimeFingerprint, owner.approvedHosts)
        val listenerRoot = Path.of("/mnt/media/p0-v3/ingress-succession").resolve(site)
        val listener = IngressListenerSuccession.real(listenerRoot, listenerBinding, sourcePin.spec,
            targetPin.spec, forBridge = true)
        val targetRuntime = PrivateDeployment.real(mapOf(targetPin.spec.name to targetPin.runtimeFingerprint))
        val readiness = targetRuntime.audit(targetPin.spec)
        require(targetPin.spec.ingress == null && "ingress-egress" !in targetPin.spec.networks &&
            readiness.maintenanceId == null && targetPin.spec.processes.all { process ->
                readiness.statuses.singleOrNull { it.id == process.id }?.let { status ->
                    if (process.oneShot) status.state in setOf("completed", "exited") && status.exitCode == 0
                    else status.state == "running"
                } == true
            } && readiness.fingerprint == targetPin.runtimeFingerprint)
        val readinessRoot = privateControlDirectory(GenerationRuntime.BASE.resolve(target.id)
            .resolve("qualification-restored"))
        val readinessDir = privateControlDirectory(readinessRoot.resolve(scope.suiteId))
        val readinessPath = readinessDir.resolve("private-readiness.json")
        ReleasePrivateFiles.save(readinessPath, Json.encodeToString(readiness).encodeToByteArray())
        val readinessPin = pin(readinessPath, 65536)
        val caddyFiles = targetPin.spec.processes.single { it.id == "caddy" }.files
        val certificateFiles = linkedMapOf<String, String>()
        val keyFiles = linkedMapOf<String, String>()
        val certificates = linkedMapOf<String, ActivationInput>()
        val keys = linkedMapOf<String, ActivationInput>()
        for (host in owner.approvedHosts.sorted()) {
            val original = json.decodeFromString<PublicCertificateRevision>(NativeCredentialRevision.readOriginal(targetBundle, host)
                .decodeToString(throwOnInvalidSequence = true))
            val revision = requireNotNull(NativeCredentialRevision.readHead(GenerationRuntime.BASE.resolve(target.id))
                ?.revisions?.get(host))
            val adopted = GenerationCredentialRevisions.readPublicCertificate(revision, target.id,
                target.bundleSha256, owner.approvedHosts, NativeCredentialRevision.readOriginal(targetBundle, host))
            require(original.host == host && adopted.sourceRevisionSha256 ==
                ReleaseLocks.sha256(NativeCredentialRevision.readOriginal(targetBundle, host)) &&
                original.chainPemSha256 == adopted.chainPemSha256 &&
                original.privateKeyPemSha256 == adopted.privateKeyPemSha256)
            fun originalInput(expectedSha: String): Pair<String, ActivationInput> {
                val matches = caddyFiles.filter { file -> targetPin.inputHashes[file.file] == expectedSha &&
                    file.target.matches(Regex("/run/secrets/[a-z][a-z0-9-]{0,63}\\.pem")) }
                require(matches.size == 1)
                val file = matches.single()
                val input = PrivateDeployment.BASE.resolve(targetPin.spec.name).resolve(file.file)
                require(pin(input, 65536).sha256 == expectedSha)
                return file.target to ActivationInput(input.toString(), expectedSha)
            }
            val (certTarget, cert) = originalInput(original.chainPemSha256)
            val (keyTarget, key) = originalInput(original.privateKeyPemSha256)
            certificateFiles[host] = certTarget; keyFiles[host] = keyTarget
            certificates[host] = cert; keys[host] = key
        }
        // Validate ORIGINAL route, certificate/key, restored target and private readiness
        // before the direct-source first stop; afterward no uncertain effect is replayed.
        val sourceProof = lifecycle.heldCapture ?: runtime.directRestoreQuiesce(
            requireNotNull(lifecycle.directInventory), source, target,
            requireNotNull(lifecycle.directCaptureId), scope.suiteId, requireNotNull(originalAuthority))
        val held = if (direct) null else json.decodeFromString<GenerationHeldCapture>(
            ReleasePrivateFiles.read(Path.of(sourceProof.path), 65536)
                .decodeToString(throwOnInvalidSequence = true)).also { it.validate() }
        if (held != null) require(sourceProof.sha256 == ReleaseLocks.sha256(
            ReleasePrivateFiles.read(Path.of(sourceProof.path), 65536)) &&
            held.access.generation == source.id && held.access.bundleSha256 == source.bundleSha256 &&
            targetBundle.recoverySourceKopia == held.snapshot &&
            Path.of(sourceProof.path) == GenerationRuntime.BASE.resolve(source.id)
                .resolve("backups/${held.snapshot.id}/held.json"))
        val quiesce = if (direct) listener.quiescedDirectSourceForBridge(listenerBinding,
            sourceProof, sourcePin.spec) else listener.heldQuiesceForBridge(listenerBinding, sourceProof,
            sourcePin.spec)
        val quiescePin = pin(listenerRoot.resolve("$op.bridge-result.json"), 65536)
        require(quiesce == json.decodeFromString<ListenerBridgeQuiesceResult>(ReleasePrivateFiles.read(
            Path.of(quiescePin.path), 65536).decodeToString(throwOnInvalidSequence = true)))
        val originalContexts = requireNotNull(scope.contexts) { "Original sealed INSTALL contexts required for RESTORE actors" }
        val contextsBytes = ReleasePrivateFiles.read(Path.of(originalContexts.path), 4194304)
        require(ReleaseLocks.sha256(contextsBytes) == originalContexts.sha256)
        val contextMap = json.parseToJsonElement(contextsBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val actorServices = setOf("bookstack", "erpnext", "firefly-iii", "forgejo", "donetick")
        val actorProjections = contextMap.mapNotNull { (caseId, context) ->
            val service = caseId.substringBefore("--")
            if (service !in actorServices || "ownerCredentialFile" !in context.jsonObject) null
            else {
                require("outsiderCredentialFile" in context.jsonObject)
                caseId to runtime.projectRestoredQualificationActors(source, target, service,
                    originalContexts.sha256, context.jsonObject)
            }
        }.toMap()
        require(actorProjections.keys.map { it.substringBefore("--") }.toSet() == actorServices) {
            "Complete original new-stack owner/outsider context required before RESTORE cases"
        }
        val ownerScope = RestoredOwnerScope(source, target, sourcePin, targetPin, quiescePin, quiesce,
            lifecycle.heldCapture, readinessPin, translated, certificates, keys, certificateFiles, keyFiles,
            site, owner.approvedHosts, actorProjections)
        val control = QualificationOwnerControl.real(scope, ownerScope)
        val runner = ReleaseAcceptance(ReleaseDispatch.BASE, LocalAcceptanceControllerProcess(),
            controlledExecution = { actual, request, argv, work ->
                require(actual == operation && request == invocation)
                control.run(argv, work)
            })
        val journeyIntent = readinessDir.resolve("journey.intent.json")
        ReleasePrivateFiles.save(journeyIntent, json.encodeToString(buildJsonObject {
            put("suiteId", scope.suiteId); put("source", source.id); put("target", target.id)
            put("quiescenceSha256", quiescePin.sha256); put("bindingSha256", scope.binding.sha256)
        }).encodeToByteArray())
        val lifecycleDriver = RestoredLifecycleDriver()
        val attempt = lifecycleDriver.settle(
            run = { runner.run(operation, invocation); control.completedCaseClosures() },
            safety = { control.safeCaseReceipts() }, isolate = {
                isolationAttempted = true // Before the native effect: no retry after an unknown result.
                isolateTarget()
            })
        val isolation = attempt.isolation
        require(isolation.action == "isolate" && isolation.bundleSha256 == target.bundleSha256 &&
            isolation.passed && isolation.failureType == null)
        val isolationPin = pin(GenerationRuntime.BASE.resolve(target.id).resolve("isolate.result.json"), 1048576)
        require(json.decodeFromString<GenerationOutcome>(ReleasePrivateFiles.read(Path.of(isolationPin.path))
            .decodeToString(throwOnInvalidSequence = true)) == isolation)
        if (attempt.failure != null) {
            val safety = RestoredFailureSafety(suiteId = scope.suiteId, source = source, target = target,
                heldCaptureSha256 = lifecycle.heldCapture?.sha256, quiescenceSha256 = quiescePin.sha256,
                caseSafety = attempt.safety, finalIsolation = isolationPin)
            ReleasePrivateFiles.save(readinessDir.resolve("failure-safety.json"),
                json.encodeToString(safety).encodeToByteArray())
            throw attempt.failure
        }
        val disposition = RestoredSourceDispositionPolicy.select(attempt,
            lifecycle.heldCapture, lifecycle.ownedUpdate)
        val closures = attempt.requireForSourceDisposition()
        val retained = disposition == RestoredSourceDisposition.RETAINED_FOR_OWNED_UPDATE
        require(!retained || !direct && operation == "execute-staged" && lifecycle.resumeSource == null)
        // C2V reads the ORIGINAL scope, manifest, acceptance results and V1 bridge pairs
        // before any successful source disposition. This incomplete in-memory view is
        // NEVER saved as a provisional success aggregate or used for activation.
        val caseView = RestoredAggregateProof(operation = operation, suiteId = scope.suiteId,
            source = source, target = target, sourceDisposition = disposition,
            quiescence = quiescePin, heldCapture = lifecycle.heldCapture,
            ownedUpdate = lifecycle.ownedUpdate, retainedSource = null, sourceResume = null,
            caseClosures = closures, finalIsolation = isolationPin)
        lifecycleDriver.verifiedCasesBeforeDisposition(attempt) { originals ->
            require(originals == closures)
            RestoredCaseClosureEvidence.verify(scope, caseView, targetPin)
        }
        val retainedPin = if (retained) {
            val updatePin = requireNotNull(lifecycle.ownedUpdate)
            val transaction = json.decodeFromString<ReleaseTransactionRequest>(ReleasePrivateFiles.read(Path.of(updatePin.path))
                .decodeToString(throwOnInvalidSequence = true))
            require(updatePin.sha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(updatePin.path))) &&
                transaction.updatePreparation?.intent?.source == source &&
                transaction.snapshotId == requireNotNull(held).snapshot.id &&
                transaction.restoreTarget == target.id)
            val audit = PrivateDeployment.real(mapOf(sourcePin.spec.name to sourcePin.runtimeFingerprint)).audit(sourcePin.spec)
            require(audit.maintenanceId == requireNotNull(held).fences[sourcePin.spec.name] &&
                audit.statuses.all { it.state in setOf("exited", "completed") } &&
                !Files.exists(GenerationRuntime.BASE.resolve(source.id)
                    .resolve("backups/${requireNotNull(held).snapshot.id}/resume.authority.json"), NOFOLLOW_LINKS))
            val record = RestoredRetainedSource(operation = operation, source = source, target = target,
                heldCaptureSha256 = sourceProof.sha256, ownedUpdateSha256 = updatePin.sha256,
                originalFences = requireNotNull(held).fences, isolatedTargetSha256 = isolationPin.sha256)
            val path = readinessDir.resolve("retained-source.json")
            ReleasePrivateFiles.save(path, json.encodeToString(record).encodeToByteArray())
            pin(path, 65536)
        } else null
        val resumed = if (retained) null else if (direct) runtime.directRestoreResume(
            requireNotNull(lifecycle.directInventory), sourceProof, isolationPin)
        else requireNotNull(lifecycle.resumeSource) {
            "The exact original source must resume after all client closures and isolation"
        }.invoke(isolation)
        val proof = RestoredAggregateProof(operation = operation, suiteId = scope.suiteId,
            source = source, target = target,
            sourceDisposition = disposition,
            quiescence = quiescePin, heldCapture = lifecycle.heldCapture,
            ownedUpdate = lifecycle.ownedUpdate,
            retainedSource = retainedPin, sourceResume = resumed,
            caseClosures = closures, finalIsolation = isolationPin)
        val root = privateControlDirectory(Path.of("/mnt/media/p0-v3/restored-bridges"))
        val sourceRoot = privateControlDirectory(root.resolve(source.id))
        val targetRoot = privateControlDirectory(sourceRoot.resolve(target.id))
        val path = targetRoot.resolve("$op.aggregate-v2.json")
        ReleasePrivateFiles.save(path, json.encodeToString(proof).encodeToByteArray())
        pin(path).also { RestoredAggregateEvidence.read(it, scope, operation, source, target, retained) }
        } catch (failure: Throwable) {
            // Also covers pre-client failure after the RESTORE target was started. Never
            // reissue an uncertain isolation or turn failed acceptance into a resume permit.
            if (!isolationAttempted) {
                isolationAttempted = true
                val interrupted = Thread.interrupted()
                try {
                    val stopped = isolateTarget()
                    require(stopped.action == "isolate" && stopped.passed && stopped.failureType == null &&
                        stopped.bundleSha256 == target.bundleSha256)
                    val path = GenerationRuntime.BASE.resolve(target.id).resolve("isolate.result.json")
                    require(json.decodeFromString<GenerationOutcome>(ReleasePrivateFiles.read(path, 1048576)
                        .decodeToString(throwOnInvalidSequence = true)) == stopped)
                } catch (uncertain: Throwable) { failure.addSuppressed(uncertain) }
                finally { if (interrupted) Thread.currentThread().interrupt() }
            }
            throw failure
        }
        }
    }
}

/** Rollback safety barrier for a failed owner journey. This never converts a failed
 * acceptance result into an aggregate or activation authority. */
internal object RestoredFailureSafetyEvidence {
    private val json = Json { encodeDefaults = true; explicitNulls = true; ignoreUnknownKeys = false }
    /** Production reader and synthetic byte-fixture tests use the SAME original-result census.
     * An attempted COMPLETE cannot close an uncertain external native/RSS effect. */
    internal fun originalEffectCensus(scope: QualificationControlScope, names: List<Path>,
        read: (Path, Int) -> ByteArray): Set<String> {
        require(names.size <= 8192 && names.distinct().size == names.size && names.all {
            it.fileName.toString().matches(Regex("[1-9][0-9]*\\.(intent|result)\\.json"))
        })
        val scopeHash = ReleaseLocks.sha256(QualificationOwnerControl.json.encodeToString(scope).encodeToByteArray())
        val bodies = names.filter { it.fileName.toString().endsWith(".intent.json") }.map { path ->
            val body = json.decodeFromString<QualificationControlRequestBody>(read(path, 65536)
                .decodeToString(throwOnInvalidSequence = true))
            require(body.schemaVersion == 1 && body.suiteId == scope.suiteId &&
                body.scopeSha256 == scopeHash && body.sequence > 1 &&
                path.fileName.toString() == "${body.sequence}.intent.json")
            body to path
        }
        require(bodies.map { it.first.sequence }.distinct().size == bodies.size)
        val effectOps = setOf("NATIVE_CASE_BEGIN", "NATIVE_CASE_COMPLETE", "RSS_CASE_BEGIN", "RSS_CASE_COMPLETE")
        val effects = bodies.filter { it.first.operation in effectOps }.map { (body, path) ->
            val resultPath = path.resolveSibling("${body.sequence}.result.json")
            require(resultPath in names)
            val reply = json.decodeFromString<QualificationControlReplyBody>(read(resultPath, 65536)
                .decodeToString(throwOnInvalidSequence = true))
            require(reply.schemaVersion == 1 && reply.suiteId == scope.suiteId &&
                reply.scopeSha256 == scopeHash && reply.sequence == body.sequence &&
                reply.operation == body.operation && reply.status == "OK" &&
                reply.errorCode == null && reply.payload != null && reply.payload != JsonNull)
            Triple(body, reply, body.operation.substringBefore("_CASE") to
                body.payload.jsonObject.getValue("caseDirectory").jsonPrimitive.content)
        }
        require(effects.map { it.third to it.first.operation }.distinct().size == effects.size)
        val begins = effects.filter { it.first.operation.endsWith("_BEGIN") }.associateBy { it.third }
        val completions = effects.filter { it.first.operation.endsWith("_COMPLETE") }.associateBy { it.third }
        require(begins.keys == completions.keys)
        for ((key, begin) in begins) {
            val finish = requireNotNull(completions[key])
            require(begin.first.sequence < finish.first.sequence &&
                Path.of(key.second).parent == Path.of(scope.artifactRoot))
            if (key.first == "NATIVE") {
                val admitted = json.decodeFromJsonElement<NativeCaseClaimEnvelope>(requireNotNull(begin.second.payload))
                val request = json.decodeFromJsonElement<NativeCaseCompletionRequest>(finish.first.payload)
                val completed = json.decodeFromJsonElement<NativeCaseCompletionEnvelope>(requireNotNull(finish.second.payload))
                require(admitted.generationId == scope.generationId && admitted.phase == "RESTORE" &&
                    request.caseDirectory == key.second && request.claimSha256 == admitted.claimSha256 &&
                    completed.invocationId == admitted.invocationId && completed.claimSha256 == admitted.claimSha256 &&
                    completed.resultSha256 == request.resultSha256)
            } else {
                val admitted = json.decodeFromJsonElement<RssQualificationBeginReceipt>(requireNotNull(begin.second.payload))
                val request = json.decodeFromJsonElement<QualificationControlRssCaseFinish>(finish.first.payload)
                val completed = json.decodeFromJsonElement<RssQualificationCaseCompletionReceipt>(requireNotNull(finish.second.payload))
                require(admitted.generationId == scope.generationId &&
                    request.caseDirectory == key.second && request.claimSha256 == admitted.claimSha256 &&
                    request.phaseClaimSha256 == admitted.phaseClaimSha256 &&
                    completed.invocationId == admitted.invocationId && completed.claimSha256 == admitted.claimSha256 &&
                    completed.resultSha256 == request.resultSha256)
            }
        }
        return bodies.filter { it.first.operation == "CASE_START" }.map {
            it.first.payload.jsonObject.getValue("caseDirectory").jsonPrimitive.content
        }.toSet()
    }
    fun requireIfStarted(scope: QualificationControlScope, source: ReleaseGeneration,
        target: ReleaseGeneration, heldCaptureSha256: String?) {
        val directory = GenerationRuntime.BASE.resolve(target.id)
            .resolve("qualification-restored/${scope.suiteId}")
        val intent = directory.resolve("journey.intent.json")
        if (!Files.exists(intent, NOFOLLOW_LINKS)) return // No owner client/bridge effect preceded this marker.
        val record = json.parseToJsonElement(ReleasePrivateFiles.read(intent, 65536)
            .decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(record.getValue("suiteId").jsonPrimitive.content == scope.suiteId &&
            record.getValue("source").jsonPrimitive.content == source.id &&
            record.getValue("target").jsonPrimitive.content == target.id &&
            record.getValue("bindingSha256").jsonPrimitive.content == scope.binding.sha256)
        val failure = json.decodeFromString<RestoredFailureSafety>(ReleasePrivateFiles.read(
            directory.resolve("failure-safety.json"), 1048576).decodeToString(throwOnInvalidSequence = true))
        val isolationPath = GenerationRuntime.BASE.resolve(target.id).resolve("isolate.result.json")
        val isolatedBytes = ReleasePrivateFiles.read(isolationPath, 1048576)
        val isolated = json.decodeFromString<GenerationOutcome>(isolatedBytes.decodeToString(throwOnInvalidSequence = true))
        require(failure.schemaVersion == 2 && failure.sourceDisposition == "HELD_NO_PROMOTION" &&
            failure.suiteId == scope.suiteId && failure.source == source && failure.target == target &&
            failure.heldCaptureSha256 == heldCaptureSha256 &&
            record.getValue("quiescenceSha256").jsonPrimitive.content == failure.quiescenceSha256 &&
            Path.of(failure.finalIsolation.path) == isolationPath &&
            failure.finalIsolation.sha256 == ReleaseLocks.sha256(isolatedBytes) &&
            isolated.action == "isolate" && isolated.passed && isolated.failureType == null &&
            isolated.bundleSha256 == target.bundleSha256 &&
            failure.caseSafety.size <= 256 && failure.caseSafety.map { it.path }.distinct().size == failure.caseSafety.size)
        val requests = GenerationRuntime.BASE.resolve(target.id)
            .resolve("qualification-control/${scope.suiteId}/requests")
        val started = if (Files.exists(requests, NOFOLLOW_LINKS)) Files.list(requests).use { files ->
            val names = files.limit(8193).toList()
            require(names.size <= 8192)
            originalEffectCensus(scope, names) { path, limit -> ReleasePrivateFiles.read(path, limit) }
        } else emptySet()
        require(started.size == failure.caseSafety.size &&
            failure.caseSafety.map { receiptPin ->
                val p = Path.of(receiptPin.path)
                require(p.parent == GenerationRuntime.BASE.resolve(target.id)
                    .resolve("qualification-control/${scope.suiteId}/case-safety") &&
                    p.fileName.toString().matches(Regex("case-[a-f0-9-]{36}\\.json")))
                val bytes = ReleasePrivateFiles.read(p, 65536)
                require(ReleaseLocks.sha256(bytes) == receiptPin.sha256)
                val receipt = json.decodeFromString<OwnerCaseSafetyReceipt>(bytes
                    .decodeToString(throwOnInvalidSequence = true))
                require(receipt.schemaVersion == 2 && receipt.clientStopped && receipt.bridgeAbsent &&
                    receipt.suiteId == scope.suiteId && receipt.generationId == target.id &&
                    p.fileName.toString() == "${receipt.invocationId}.json" &&
                    Path.of(receipt.caseDirectory).parent == Path.of(scope.artifactRoot))
                val caseIntent = json.parseToJsonElement(ReleasePrivateFiles.read(Path.of(receipt.caseDirectory)
                    .resolve("intent.json"), 65536).decodeToString(throwOnInvalidSequence = true)).jsonObject
                require(caseIntent.getValue("invocationId").jsonPrimitive.content == receipt.invocationId &&
                    caseIntent.getValue("binding").jsonObject.getValue("generationId").jsonPrimitive.content == target.id &&
                    caseIntent.getValue("binding").jsonObject.getValue("phase").jsonPrimitive.content == "RESTORE")
                val clientJournal = GenerationRuntime.BASE.resolve(target.id)
                    .resolve("qualification-client/${receipt.invocationId}")
                if (receipt.clientFence == null) require(!receipt.clientAttempted ||
                    !Files.exists(clientJournal.resolve("intent.json"), NOFOLLOW_LINKS))
                else {
                    require(receipt.clientAttempted)
                    val fencePath = clientJournal.resolve("fenced.json")
                    val fenceBytes = ReleasePrivateFiles.read(fencePath, 65536)
                    require(Path.of(receipt.clientFence.path) == fencePath &&
                        receipt.clientFence.sha256 == ReleaseLocks.sha256(fenceBytes))
                    val fence = json.decodeFromString<QualificationClientFence>(fenceBytes
                        .decodeToString(throwOnInvalidSequence = true))
                    require(fence.invocationId == receipt.invocationId && fence.generationId == target.id)
                    val targetBytes = ReleasePrivateFiles.read(GenerationRuntime.BASE.resolve(target.id).resolve("bundle.json"))
                    require(ReleaseLocks.sha256(targetBytes) == target.bundleSha256)
                    val spec = json.decodeFromString<GenerationBundle>(targetBytes
                        .decodeToString(throwOnInvalidSequence = true)).members.single().spec
                    nativeQualificationClientFence(target.id, spec, fence)
                }
                val site = json.decodeFromString<GenerationBundle>(ReleasePrivateFiles.read(
                    GenerationRuntime.BASE.resolve(source.id).resolve("bundle.json"))
                    .decodeToString(throwOnInvalidSequence = true)).ownership?.contract?.site
                    ?: error("Original site missing")
                val bridgeRoot = Path.of("/mnt/media/p0-v3/restored-bridges").resolve(site).resolve(target.id)
                val installOp = qualificationCaseBridgeOperation(scope.suiteId, receipt.invocationId, "install")
                val removeOp = qualificationCaseBridgeOperation(scope.suiteId, receipt.invocationId, "remove")
                require(!Files.exists(bridgeRoot.resolve("bridge.pending"), NOFOLLOW_LINKS) &&
                    !Files.exists(bridgeRoot.resolve("client.pending"), NOFOLLOW_LINKS))
                if (receipt.bridgeRemoval == null) {
                    val install = bridgeRoot.resolve("$installOp.intent.json")
                    if (!Files.exists(install, NOFOLLOW_LINKS))
                        require(!Files.exists(bridgeRoot.resolve("$installOp.result.json"), NOFOLLOW_LINKS))
                    else {
                        require(receipt.bridgeAttempted)
                        val bytes = ReleasePrivateFiles.read(install, 1048576)
                        val intent = json.decodeFromString<RestoredBridgeIntent>(bytes
                            .decodeToString(throwOnInvalidSequence = true))
                        val result = json.decodeFromString<RestoredBridgeResult>(ReleasePrivateFiles.read(
                            bridgeRoot.resolve("$installOp.result.json"), 1048576)
                            .decodeToString(throwOnInvalidSequence = true))
                        require(intent.action == "install" && intent.binding.operation == installOp &&
                            result.operation == installOp && result.action == "not-applied" &&
                            result.intentSha256 == ReleaseLocks.sha256(bytes) &&
                            result.beforeSha256 == result.afterSha256)
                    }
                } else {
                    require(receipt.bridgeAttempted)
                    val installBytes = ReleasePrivateFiles.read(bridgeRoot.resolve("$installOp.intent.json"), 1048576)
                    val removeBytes = ReleasePrivateFiles.read(bridgeRoot.resolve("$removeOp.intent.json"), 1048576)
                    val installIntent = json.decodeFromString<RestoredBridgeIntent>(installBytes
                        .decodeToString(throwOnInvalidSequence = true))
                    val removeIntent = json.decodeFromString<RestoredBridgeIntent>(removeBytes
                        .decodeToString(throwOnInvalidSequence = true))
                    val installed = json.decodeFromString<RestoredBridgeResult>(ReleasePrivateFiles.read(
                        bridgeRoot.resolve("$installOp.result.json"), 1048576).decodeToString(throwOnInvalidSequence = true))
                    val removedPath = bridgeRoot.resolve("$removeOp.result.json")
                    val removedBytes = ReleasePrivateFiles.read(removedPath, 1048576)
                    val removed = json.decodeFromString<RestoredBridgeResult>(removedBytes
                        .decodeToString(throwOnInvalidSequence = true))
                    require(Path.of(receipt.bridgeRemoval.path) == removedPath &&
                        receipt.bridgeRemoval.sha256 == ReleaseLocks.sha256(removedBytes) &&
                        installIntent.binding == removeIntent.binding && installIntent.action == "install" &&
                        removeIntent.action == "remove" && installIntent.binding.operation == installOp &&
                        installIntent.binding.targetGeneration == target.id &&
                        installIntent.binding.sourceGeneration == source.id &&
                        (installIntent.binding.qualifierClientInvocationId == receipt.invocationId &&
                            receipt.clientFence != null || installIntent.binding.nativeClientCapabilities == setOf("rss-mastodon") &&
                            receipt.clientFence == null) &&
                        installed.operation == installOp && installed.action == "install" &&
                        installed.intentSha256 == ReleaseLocks.sha256(installBytes) &&
                        removed.operation == removeOp && removed.action == "remove" &&
                        removed.intentSha256 == ReleaseLocks.sha256(removeBytes) &&
                        installed.beforeSha256 == TransactionalCaddy.digest(installIntent.before) &&
                        installed.afterSha256 == TransactionalCaddy.digest(installIntent.after) &&
                        removed.beforeSha256 == TransactionalCaddy.digest(removeIntent.before) &&
                        removed.afterSha256 == TransactionalCaddy.digest(removeIntent.after) &&
                        installIntent.after == removeIntent.before &&
                        installIntent.before == removeIntent.after &&
                        installed.afterSha256 == removed.beforeSha256 &&
                        installed.beforeSha256 == removed.afterSha256)
                }
                receipt.caseDirectory
            }.toSet() == started)
    }
}

internal object RestoredAggregateEvidence {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private val hex = Regex("[a-f0-9]{64}")
    private fun original(pin: ActivationInput, limit: Int = 4194304): ByteArray =
        ReleasePrivateFiles.read(Path.of(pin.path), limit).also { require(hex.matches(pin.sha256) &&
            ReleaseLocks.sha256(it) == pin.sha256) }
    fun read(pin: ActivationInput, scope: QualificationControlScope, operation: String,
        source: ReleaseGeneration, target: ReleaseGeneration, expectedOwnedUpdate: Boolean): RestoredAggregateProof {
        source.validate(); target.validate()
        val path = Path.of(pin.path)
        require(path.parent == Path.of("/mnt/media/p0-v3/restored-bridges").resolve(source.id).resolve(target.id) &&
            path.fileName.toString().matches(Regex("r-[a-f0-9]{12}\\.aggregate-v2\\.json")))
        val proof = json.decodeFromString<RestoredAggregateProof>(original(pin).decodeToString(throwOnInvalidSequence = true))
        require(proof.schemaVersion == 2 && proof.operation == operation && proof.source == source && proof.target == target &&
            scope.operation == operation && scope.generationId == target.id && scope.bundleSha256 == target.bundleSha256 &&
            proof.suiteId == scope.suiteId && proof.caseClosures.isNotEmpty() &&
            proof.caseClosures.size <= 256 && proof.caseClosures.distinctBy { it.path }.size == proof.caseClosures.size)
        val quiesce = json.decodeFromString<ListenerBridgeQuiesceResult>(original(proof.quiescence, 65536)
            .decodeToString(throwOnInvalidSequence = true))
        require(quiesce.sourceGeneration == source.id && quiesce.targetGeneration == target.id &&
            quiesce.sourceStoppedProofSha256.matches(hex))
        val isolation = json.decodeFromString<GenerationOutcome>(original(proof.finalIsolation, 1048576)
            .decodeToString(throwOnInvalidSequence = true))
        require(Path.of(proof.finalIsolation.path) == GenerationRuntime.BASE.resolve(target.id).resolve("isolate.result.json") &&
            isolation.action == "isolate" && isolation.passed && isolation.failureType == null &&
            isolation.bundleSha256 == target.bundleSha256)
        val targetBytes = ReleasePrivateFiles.read(GenerationRuntime.BASE.resolve(target.id).resolve("bundle.json"))
        require(ReleaseLocks.sha256(targetBytes) == target.bundleSha256)
        val targetBundle = json.decodeFromString<GenerationBundle>(targetBytes.decodeToString(throwOnInvalidSequence = true))
        val targetPin = QualificationCanonicalTopology.require(targetBundle, restoredTarget = true)
        // The independent raw-evidence verifier binds the ACTUAL request scope to every
        // declared case, acceptance result, original bridge pair and protected owner closure.
        RestoredCaseClosureEvidence.verify(scope, proof, targetPin)
        val sourceBytes = ReleasePrivateFiles.read(GenerationRuntime.BASE.resolve(source.id).resolve("bundle.json"))
        require(ReleaseLocks.sha256(sourceBytes) == source.bundleSha256)
        val sourceBundle = json.decodeFromString<GenerationBundle>(sourceBytes.decodeToString(throwOnInvalidSequence = true))
        QualificationCanonicalTopology.require(sourceBundle,
            allowOwnedUpdateSource = sourceBundle.ownedUpdate != null)
        require(targetBundle.recoverySourceKopia?.let { it.generation == source.id &&
            it.bundleSha256 == source.bundleSha256 } == true)
        proof.caseClosures.forEach { receiptPin ->
            val receiptPath = Path.of(receiptPin.path)
            require(receiptPath.parent == GenerationRuntime.BASE.resolve(target.id)
                .resolve("qualification-control/${proof.suiteId}/case-closures") &&
                receiptPath.fileName.toString().matches(Regex("[a-z][a-z0-9-]{0,95}\\.json")))
            val receipt = json.decodeFromString<OwnerCaseClosure>(original(receiptPin, 65536)
                .decodeToString(throwOnInvalidSequence = true))
            require(receipt.schemaVersion == 2 && receipt.phase == "RESTORE" &&
                receiptPath.fileName.toString() == "${receipt.invocationId}.json" &&
                receipt.caseDirectory == Path.of(receipt.caseIntent.path).parent.toString() &&
                Path.of(receipt.caseDirectory).parent?.toString() != null &&
                receipt.result.path == Path.of(receipt.caseDirectory).resolve("result.json").toString() &&
                receipt.context.path == Path.of(receipt.caseDirectory).resolve("context.json").toString() &&
                receipt.mode in setOf("HOST_NATIVE", "HOST_NATIVE_WITH_DENIAL_PROBE", "QCLIENT_RUNNER"))
            val intent = json.parseToJsonElement(original(receipt.caseIntent, 65536)
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
            val result = json.parseToJsonElement(original(receipt.result, 1048576)
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
            require(original(receipt.context).isNotEmpty() &&
                intent.getValue("invocationId").jsonPrimitive.content == receipt.invocationId &&
                intent.getValue("binding").jsonObject.getValue("generationId").jsonPrimitive.content == target.id &&
                intent.getValue("binding").jsonObject.getValue("phase").jsonPrimitive.content == "RESTORE" &&
                intent.getValue("contextSha256").jsonPrimitive.content == receipt.context.sha256 &&
                result.getValue("passed").jsonPrimitive.boolean && result.getValue("finished").jsonPrimitive.boolean &&
                result.getValue("exitCode").jsonPrimitive.int == 0 &&
                result.getValue("invocation").jsonObject == intent &&
                (receipt.client == null) == (receipt.clientFence == null) &&
                (receipt.ingress == null) == (receipt.bridgeRemoval == null))
            receipt.clientFence?.let { fencePin ->
                val fence = json.decodeFromString<QualificationClientFence>(original(fencePin, 65536)
                    .decodeToString(throwOnInvalidSequence = true))
                require(fence.invocationId == receipt.invocationId &&
                    fence.containerId == requireNotNull(receipt.client).containerId)
                nativeQualificationClientFence(target.id, targetBundle.members.single().spec, fence)
            }
            receipt.ingress?.let { original(it, 1048576) }
            receipt.bridgeRemoval?.let { removal ->
                val resultBytes = original(removal, 1048576)
                val removalResult = json.decodeFromString<RestoredBridgeResult>(resultBytes.decodeToString(throwOnInvalidSequence = true))
                require(removalResult.action == "remove" && removalResult.operation.matches(Regex("r-[a-f0-9]{12}")))
            }
        }
        val held = proof.heldCapture?.let { json.decodeFromString<GenerationHeldCapture>(original(it, 65536)
            .decodeToString(throwOnInvalidSequence = true)).also { value ->
            value.validate()
            require(value.access.generation == source.id && value.access.bundleSha256 == source.bundleSha256 &&
                targetBundle.recoverySourceKopia == value.snapshot)
        } }
        when (proof.sourceDisposition) {
            RestoredSourceDisposition.RESUMED -> {
                require(proof.retainedSource == null && proof.ownedUpdate == null && !expectedOwnedUpdate)
                val pinResume = requireNotNull(proof.sourceResume)
                if (held != null) {
                    val resume = json.decodeFromString<GenerationBackupOutcome>(original(pinResume, 1048576)
                        .decodeToString(throwOnInvalidSequence = true))
                    require(Path.of(pinResume.path) == GenerationRuntime.BASE.resolve(source.id)
                        .resolve("backups/${held.snapshot.id}/result.json") &&
                        resume.access == held.access && resume.passed && resume.sourceResumed &&
                        resume.snapshot == held.snapshot)
                } else {
                    val root = GenerationRuntime.BASE.resolve(source.id)
                        .resolve("qualification-direct/${proof.suiteId}")
                    val quiescenceBytes = ReleasePrivateFiles.read(root.resolve("quiesce.result.json"), 65536)
                    val routeBytes = ReleasePrivateFiles.read(root.resolve("original-route.json"), 1048576)
                    val route = json.decodeFromString<RestoredOriginalRouteAuthority>(routeBytes
                        .decodeToString(throwOnInvalidSequence = true)).also { it.recheck() }
                    val stopped = json.decodeFromString<RestoredDirectSourceQuiesce>(
                        quiescenceBytes.decodeToString(throwOnInvalidSequence = true))
                    val stopAuditBytes = ReleasePrivateFiles.read(root.resolve(
                        "quiesce-${sourceBundle.members.single().spec.name}.result.json"), 1048576)
                    val stopAudit = json.decodeFromString<RuntimeAudit>(stopAuditBytes
                        .decodeToString(throwOnInvalidSequence = true))
                    val resume = json.decodeFromString<RestoredDirectSourceResume>(original(pinResume, 65536)
                        .decodeToString(throwOnInvalidSequence = true))
                    val auditBytes = ReleasePrivateFiles.read(root.resolve("resume.audit.json"), 1048576)
                    val audits = json.decodeFromString<GenerationInspection>(auditBytes
                        .decodeToString(throwOnInvalidSequence = true))
                    require(Path.of(pinResume.path) == root.resolve("resume.result.json") &&
                        stopped.schemaVersion == 2 && stopped.source == source && stopped.target == target &&
                        stopped.suiteId == proof.suiteId &&
                        stopped.captureId == targetBundle.recoverySourceKopia?.id &&
                        stopped.originalRouteSha256 == ReleaseLocks.sha256(routeBytes) &&
                        route.source == source && route.site == sourceBundle.ownership?.contract?.site &&
                        route.approvedHosts == sourceBundle.ownership?.approvedHosts &&
                        route.upstreams.map { it.host }.toSet() == route.approvedHosts - "start.datamancy.net" &&
                        stopped.fences.keys == setOf(stopAudit.name) &&
                        stopAudit.fingerprint == sourceBundle.members.single().runtimeFingerprint &&
                        stopAudit.maintenanceId == stopped.fences.getValue(stopAudit.name) &&
                        stopAudit.statuses.all { it.state in setOf("exited", "completed") } &&
                        quiesce.sourceStoppedProofSha256 == ReleaseLocks.sha256(
                            Json.encodeToString(stopAudit.statuses).toByteArray()) &&
                        quiesce.heldCaptureSha256 == null &&
                        resume.schemaVersion == 2 && resume.suiteId == proof.suiteId &&
                        resume.source == source && resume.target == target && resume.resumed &&
                        resume.quiescenceSha256 == ReleaseLocks.sha256(quiescenceBytes) &&
                        resume.finalIsolationSha256 == proof.finalIsolation.sha256 &&
                        resume.sourceAuditSha256 == ReleaseLocks.sha256(auditBytes) &&
                        audits.id == source.id && audits.bundleSha256 == source.bundleSha256 &&
                        audits.members.isNotEmpty() && audits.members.all { audit ->
                            audit.name in stopped.fences && audit.maintenanceId == null &&
                                audit.statuses.all { it.state == "running" }
                        })
                }
            }
            RestoredSourceDisposition.RETAINED_FOR_OWNED_UPDATE -> {
                require(expectedOwnedUpdate && operation == "execute-staged" && proof.sourceResume == null && held != null)
                val update = requireNotNull(proof.ownedUpdate)
                val request = json.decodeFromString<ReleaseTransactionRequest>(original(update)
                    .decodeToString(throwOnInvalidSequence = true))
                val prepared = requireNotNull(request.updatePreparation)
                require(Path.of(update.path) == ReleaseDispatch.BASE.resolve(request.transactionId).resolve("request.json") &&
                    prepared.intent.source == source && request.snapshotId == held.snapshot.id &&
                    request.restoreTarget == target.id)
                val retained = json.decodeFromString<RestoredRetainedSource>(original(requireNotNull(proof.retainedSource), 65536)
                    .decodeToString(throwOnInvalidSequence = true))
                require(retained.schemaVersion == 2 && retained.operation == "execute-staged" &&
                    retained.source == source && retained.target == target &&
                    retained.heldCaptureSha256 == proof.heldCapture.sha256 &&
                    retained.ownedUpdateSha256 == update.sha256 && retained.originalFences == held.fences &&
                    retained.pendingDisposition == "OWNED_UPDATE_COMMIT_OR_ROLLBACK" &&
                    retained.isolatedTargetSha256 == proof.finalIsolation.sha256 &&
                    !Files.exists(GenerationRuntime.BASE.resolve(source.id)
                        .resolve("backups/${held.snapshot.id}/resume.authority.json"), NOFOLLOW_LINKS) &&
                    !Files.exists(GenerationRuntime.BASE.resolve(source.id)
                        .resolve("backups/${held.snapshot.id}/result.json"), NOFOLLOW_LINKS))
            }
        }
        return proof
    }
}
