package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import kotlin.test.*

/** Native effects and full restored-case verification are explicit unit boundaries. Real private
 * files, ownership/reference/journal/Caddy validation use temporary roots. Synthetic restored
 * receipts carry unitFixture=true and are never acceptable production qualification evidence. */
internal class ReleaseControlTestFixture : AutoCloseable {
    val root: Path = Files.createTempDirectory("release-control-unit-").also {
        Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
    }
    val json = Json { encodeDefaults = true }
    fun dir(path: Path): Path = Files.createDirectory(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
    fun pin(name: String, text: String): ActivationInput {
        val path = root.resolve(name); ReleasePrivateFiles.save(path, text.toByteArray())
        return ActivationInput(path.toString(), ReleaseLocks.sha256(text.toByteArray()))
    }
    val base = dir(root.resolve("generations"))
    val transactions = dir(root.resolve("transactions"))
    val source = "q-111111111111"
    val stagedTarget = "q-222222222222"
    val qualifiedTarget = "q-333333333333"
    val capture = "cap-111111111111"
    val qualifiedCapture = "cap-222222222222"
    val fence = "11111111-1111-1111-1111-111111111111"
    val targetHash = "f".repeat(64)
    val inventoryBytes = GenerationAssembly.readInventory(Path.of("release/downloaded-candidate-inventory.json"))
    val inventory = Json.decodeFromString<AcquiredInventory>(inventoryBytes.decodeToString())
    val inventoryPin = pin("inventory.json", inventoryBytes.decodeToString())
    val bundle: GenerationBundle
    val sourceHash: String
    val sourceRoot = dir(base.resolve(source))
    val calls = mutableListOf<String>()
    var failure: String? = null
    var interruptedAcceptance = false
    var failedAcceptance = false
    var failedRestoredVerification = false
    var importPassed = true
    var frozen = false
    var auditOverride: ((GenerationInspection) -> GenerationInspection)? = null
    val holds = mutableMapOf<String, GenerationHeldCapture>()
    val isolated = mutableSetOf<String>()
    val runtime = GenerationRuntime(base, root, { error("No native runtime allowed in unit fixture") }, { error("No host capacity observation allowed") })
    val acceptance = ReleaseAcceptance(root, AcceptanceControllerProcess { argv, _ ->
        calls += "acceptance:${argv[1]}:${Path.of(argv[4]).fileName}"
        if (interruptedAcceptance) throw InterruptedException("synthetic runner cancellation")
        RuntimeCommandResult(if (failedAcceptance) 1 else 0, "unit-only semantic runner response")
    }) { _, _ -> calls += "verify-controller" }
    private val products = pin("products.json", "{}")
    private val manifest = pin("manifest.json", "{}")
    private val acceptanceJournal = pin("acceptance.jsonl", "synthetic journal\n")
    fun invocation(name: String, generation: String, phase: String) = ReleaseAcceptanceInvocation("a".repeat(64), products, manifest,
        pin("$name.json", "{\"generationId\":\"$generation\",\"phase\":\"$phase\"}"), acceptanceJournal.path,
        "b".repeat(64), root.resolve("$name-artifacts").toString())
    private val site = CaddySiteBinding("unit", "https", "http://127.0.0.1:2019", setOf("boards.datamancy.net"))
    private fun configuration(routes: JsonArray) = buildJsonObject {
        put("apps", buildJsonObject { put("http", buildJsonObject { put("servers", buildJsonObject {
            put("https", buildJsonObject { put("routes", routes) })
        }) }) })
    }
    var configuration = configuration(JsonArray(emptyList()))
    var lostCaddyAck = false
    val caddyRoot = dir(root.resolve("caddy"))
    val caddy = TransactionalCaddy(caddyRoot, site, CaddyTransport { method, _, _, body ->
        calls += "caddy:$method"
        if (method == "GET") CaddyReply(200, configuration.toString().toByteArray(), "\"/config/ ${TransactionalCaddy.digest(configuration).take(16)}\"")
        else {
            configuration = configuration(Json.parseToJsonElement(requireNotNull(body).decodeToString()).jsonArray)
            if (lostCaddyAck) error("synthetic lost Caddy acknowledgement")
            CaddyReply(200, byteArrayOf(), null)
        }
    })
    val request: ReleaseTransactionRequest
    init {
        val plan = GenerationAssembly().plan(AssemblyRequest(id = source, candidateSha256 = "a".repeat(64),
            inventorySha256 = ReleaseLocks.sha256(inventoryBytes), selections = listOf(AssemblySelection("canonical-core")),
            diskReservationMiB = 8192, store = RuntimeStore.CANONICAL_V2), inventoryBytes)
        val graph = SiteOwnerships.inspect(plan)
        val owners = graph.processes.associate { it.process to requireNotNull(it.compiledProduct) }
        val contract = SiteOwnership(site = "unit", assemblySha256 = graph.assemblySha256,
            processes = owners.map { SiteProcessOwner(it.key, it.value) },
            state = graph.state.map { SiteStateOwner(it.volume, owners.getValue(it.writers.first()), "core") },
            inputs = graph.inputs.map { SiteInputOwner(it.input, requireNotNull(it.compiledProduct), true, it.consumers) }, routes = emptyList())
        val pins = plan.specs.map { spec ->
            val inputs = PrivateDeployment.inputNames(spec).associateWith { "b".repeat(64) }
            GenerationPin(plan.generation.members.single { it.name == spec.name }, ReleaseLocks.sha256(Json.encodeToString(spec).toByteArray()),
                inputs, PrivateDeployment.expectedFingerprint(spec, inputs), spec)
        }
        bundle = GenerationBundle(plan.generation, pins, 4096, contract.assemblySha256,
            ownership = SiteOwnerships.bind(plan, contract, site.approvedHosts))
        val bytes = json.encodeToString(bundle).toByteArray(); sourceHash = ReleaseLocks.sha256(bytes)
        ReleasePrivateFiles.save(sourceRoot.resolve("bundle.json"), bytes)
        val token = "a".repeat(64)
        val upstreams = listOf(CaddyUpstream("boards.datamancy.net", "p0v3-live-$source-canonical-core-planka:1337"))
        val ingress = ReleaseIngress(site, caddyRoot.toString(), upstreams, pin("token", token),
            TransactionalCaddy.digest(configuration), null, "r-111111111111", "r-222222222222", "r-333333333333", "r-444444444444")
        val deployment = ReleaseDeploymentBinding(source, sourceHash, "c".repeat(64),
            TransactionalCaddy.digest(caddy.revision(ingress.cutover, source, upstreams, token)))
        request = ReleaseTransactionRequest(transactionId = "unit", lockDigest = "d".repeat(64), deployment = deployment,
            inventory = inventoryPin, snapshotId = capture, restoreTarget = stagedTarget, ingress = ingress,
            publication = ReleasePublication(root.resolve("publication").toString(), "e".repeat(64)),
            staged = invocation("staged", source, "INSTALL"), realDomain = invocation("domain", source, "INSTALL"),
            restore = invocation("restore", stagedTarget, "RESTORE"),
            qualifiedRestore = ReleaseFunctionalRestore(qualifiedCapture, qualifiedTarget, invocation("qualified-restore", qualifiedTarget, "RESTORE")))
    }
    fun snapshot(cap: String) = KopiaSnapshotReceipt(id = cap, generation = source, bundleSha256 = sourceHash,
        snapshotId = if (cap == capture) "1".repeat(32) else "2".repeat(32), rootObjectId = "k" + "f".repeat(40),
        manifestSha256 = "a".repeat(64), files = 10, plaintextBytes = 4096,
        image = "example.test/kopia@sha256:" + "3".repeat(64), imageId = "4".repeat(64))
    fun outcome(action: String, hash: String = sourceHash) = GenerationOutcome(action, hash, failure != action)
    val operations = object : ReleaseRuntimeOperations {
        override fun stage(generation: String, bundle: String): GenerationOutcome { calls += "stage"; return outcome("stage") }
        override fun startRestored(inventory: AcquiredInventory, generation: String, bundle: String): GenerationOutcome {
            calls += "start-restored:$generation"
            // The runtime startup operation owns failure isolation, including partial startup.
            if (failure == "startup") isolate(generation, bundle)
            return outcome("startup", bundle)
        }
        override fun inspect(generation: String, bundle: String): GenerationInspection {
            calls += "inspect"
            val result = GenerationInspection(source, sourceHash, 4096, this@ReleaseControlTestFixture.bundle.members.map { pin ->
                RuntimeAudit(pin.member.name, pin.runtimeFingerprint, 4, if (frozen) fence else null, pin.spec.processes.map {
                    RuntimeStatus(it.id, if (frozen) "exited" else if (it.oneShot) "completed" else "running", if (frozen || it.oneShot) 0 else null)
                })
            })
            return auditOverride?.invoke(result) ?: result
        }
        override fun holdKopiaForRestore(inventory: AcquiredInventory, generation: String, bundle: String, capture: String): GenerationHeldCapture {
            calls += "hold:$capture"; check(failure != "hold")
            val held = GenerationHeldCapture(RuntimeBackupAccess(generation, capture, bundle), snapshot(capture),
                this@ReleaseControlTestFixture.bundle.members.associate { it.member.name to fence })
            holds[capture] = held; frozen = true
            val backups = sourceRoot.resolve("backups"); if (!Files.exists(backups)) dir(backups)
            val attempt = dir(backups.resolve(capture))
            ReleasePrivateFiles.save(attempt.resolve("intent.json"), json.encodeToString(held.access).toByteArray())
            return held
        }
        override fun holdKopiaForRestore(inventory: AcquiredInventory, generation: String, bundle: String, capture: String,
            reference: PendingRecoveryOperation): GenerationHeldCapture {
            val references = sourceRoot.resolve("recovery-references")
            val ledger = if (Files.exists(references)) RecoveryReferences(references)
                else RecoveryReferences.initialize(references, emptyList())
            ledger.protectPending(reference)
            val held = holdKopiaForRestore(inventory, generation, bundle, capture)
            val captures = sourceRoot.resolve("kopia-captures")
            if (!Files.exists(captures)) dir(captures)
            val captureRoot = dir(captures.resolve(capture))
            ReleasePrivateFiles.save(captureRoot.resolve("capture.result.json"), json.encodeToString(
                KopiaCaptureOutcome(capture, bundle, true, held.snapshot)).toByteArray())
            ledger.bindCaptured(reference, held.snapshot)
            ReleasePrivateFiles.save(sourceRoot.resolve("backups/$capture/held.json"), json.encodeToString(held).toByteArray())
            return held
        }
        override fun resumeHeldSourceAfterIsolation(inventory: AcquiredInventory, generation: String, bundle: String, capture: String,
            held: String, target: String, targetBundle: String): GenerationBackupOutcome {
            calls += "resume:$capture"
            assertTrue(target in isolated, "Target isolation must precede resume")
            assertEquals(holds.getValue(capture).sha256, held); assertEquals(targetHash, targetBundle)
            val passed = failure != "resume"
            val result = GenerationBackupOutcome(RuntimeBackupAccess(generation, capture, bundle), passed, snapshot(capture), passed)
            if (passed) frozen = false
            ReleasePrivateFiles.save(sourceRoot.resolve("backups/$capture/result.json"), json.encodeToString(result).toByteArray())
            return result
        }
        override fun isolate(generation: String, bundle: String): GenerationOutcome {
            calls += "isolate:$generation"; if (failure != "isolate") isolated += generation
            return outcome("isolate", bundle)
        }
        override fun reconcileBackup(generation: String, bundle: String, capture: String, reconciliation: String, prior: String): GenerationOutcome {
            calls += "reconcile-backup:$capture"; return outcome("reconcile-backup", bundle)
        }
        override fun reconcileIsolation(generation: String, bundle: String, reconciliation: String, prior: String): GenerationOutcome {
            calls += "reconcile-isolation:$generation"; return outcome("reconcile-isolation", bundle)
        }
        override fun backupKopia(inventory: AcquiredInventory, generation: String, bundle: String, capture: String): GenerationBackupOutcome {
            calls += "backup:$capture"; return GenerationBackupOutcome(RuntimeBackupAccess(generation, capture, bundle), failure != "backup", snapshot(capture), failure != "backup")
        }
    }
    fun restore(inventory: AcquiredInventory, generation: ReleaseGeneration, cap: String, target: String): GenerationOutcome {
        calls += "import:$target:$cap"; assertEquals(sourceHash, generation.bundleSha256)
        return GenerationOutcome("restore-import", targetHash, importPassed)
    }
    private val journeys = object : ReleaseRestoredJourneys {
        override fun execute(operation: String, invocation: ReleaseAcceptanceInvocation, source: ReleaseGeneration,
            target: ReleaseGeneration, acceptance: ReleaseAcceptance, isolateTarget: () -> GenerationOutcome,
            lifecycle: RestoredOwnerLifecycle): ActivationInput {
            val original = execute(operation, invocation, source, target, acceptance, isolateTarget)
            val isolationPath = base.resolve(target.id).resolve("isolate.result.json")
            val isolationBytes = ReleasePrivateFiles.read(isolationPath)
            val isolation = json.decodeFromString<GenerationOutcome>(isolationBytes.decodeToString())
            require(isolation.action == "isolate" && isolation.passed && isolation.failureType == null &&
                isolation.bundleSha256 == target.bundleSha256)
            require(lifecycle.ownedUpdate == null) { "This unit fixture does not model owned update" }
            val heldPin = requireNotNull(lifecycle.heldCapture)
            require(ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(heldPin.path))) == heldPin.sha256)
            val resumed = requireNotNull(lifecycle.resumeSource)(isolation)
            return pin("unit-restored-${target.id}-$operation.json", buildJsonObject {
                put("unitFixture", true); put("operation", operation)
                put("invocation", Json.encodeToJsonElement(invocation.input))
                put("source", Json.encodeToJsonElement(source)); put("target", Json.encodeToJsonElement(target))
                put("legacyBridge", Json.encodeToJsonElement(original)); put("held", Json.encodeToJsonElement(heldPin))
                put("sourceResume", Json.encodeToJsonElement(resumed))
                put("isolation", Json.encodeToJsonElement(ActivationInput(isolationPath.toString(), ReleaseLocks.sha256(isolationBytes))))
            }.toString())
        }
        override fun execute(operation: String, invocation: ReleaseAcceptanceInvocation, source: ReleaseGeneration,
            target: ReleaseGeneration, acceptance: ReleaseAcceptance,
            isolateTarget: () -> GenerationOutcome): ActivationInput {
            val member = base.resolve(target.id)
            if (!Files.exists(member)) dir(member)
            RestoredLifecycleDriver().settle(run = { acceptance.run(operation, invocation) },
                safety = { emptyList() }, isolate = {
                    val observed = isolateTarget()
                    if (!Files.exists(member.resolve("isolate.result.json")))
                        ReleasePrivateFiles.save(member.resolve("isolate.result.json"), json.encodeToString(observed).toByteArray())
                    observed
                }).requireForSourceDisposition()
            val evidence = root.resolve("restored-bridges")
            if (!Files.exists(evidence)) dir(evidence)
            val path = dir(evidence.resolve(target.id))
            val binding = RestoredBridgeBinding(operation = "r-111111111111", site = "unit",
                sourceGeneration = source.id, targetGeneration = target.id, targetFingerprint = "a".repeat(64),
                clientNetwork = "qualification-web", clientAddress = "10.88.0.2",
                allowedClients = setOf("unit-native-client"), server = "https",
                quiesceOperation = "r-222222222222", sourceStoppedProofSha256 = "b".repeat(64),
                targetPrivateReadinessSha256 = "c".repeat(64), originalHosts = site.approvedHosts,
                upstreams = request.ingress.upstreams, sourceCertificates = emptyMap(), sourcePrivateKeys = emptyMap(),
                certificateFiles = emptyMap(), keyFiles = emptyMap(),
                qualifierClientInvocationId = "r-333333333333", qualifierClientContainerId = "d".repeat(64),
                qualifierClientAddress = "10.88.0.3")
            val removal = RestoredBridgeResult("r-444444444444", "e".repeat(64), "remove",
                "f".repeat(64), "1".repeat(64))
            ReleasePrivateFiles.save(path.resolve("${removal.operation}.result.json"), json.encodeToString(removal).toByteArray())
            val isolationSha = ReleaseLocks.sha256(ReleasePrivateFiles.read(member.resolve("isolate.result.json")))
            val digest = ReleaseLocks.sha256(json.encodeToString(removal).toByteArray() + isolationSha.toByteArray())
            val bytes = json.encodeToString(BridgeResumeProof(binding, removal, isolationSha, digest)).toByteArray()
            val result = path.resolve("${removal.operation}.resume-proof.json")
            ReleasePrivateFiles.save(result, bytes)
            return ActivationInput(result.toString(), ReleaseLocks.sha256(bytes))
        }
    }
    private val restoredVerifier = RestoredReleaseVerifier { proof, invocation, operation, source, target, owned ->
        calls += "verify-restored:$operation:${target.id}"
        require(!failedRestoredVerification && !owned)
        val bytes = ReleasePrivateFiles.read(Path.of(proof.path))
        require(ReleaseLocks.sha256(bytes) == proof.sha256)
        val record = Json.parseToJsonElement(bytes.decodeToString()).jsonObject
        require(record.keys == setOf("unitFixture", "operation", "invocation", "source", "target", "legacyBridge", "held", "sourceResume", "isolation") &&
            record["unitFixture"] == JsonPrimitive(true) && record["operation"] == JsonPrimitive(operation) &&
            record["invocation"] == Json.encodeToJsonElement(invocation.input) &&
            record["source"] == Json.encodeToJsonElement(source) && record["target"] == Json.encodeToJsonElement(target))
        for (name in listOf("legacyBridge", "held", "sourceResume", "isolation")) {
            val original = json.decodeFromJsonElement<ActivationInput>(record.getValue(name))
            require(ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(original.path))) == original.sha256)
        }
        val binding = Json.parseToJsonElement(ReleasePrivateFiles.read(Path.of(invocation.input.path)).decodeToString()).jsonObject
        require(binding["generationId"] == JsonPrimitive(target.id) && binding["phase"] == JsonPrimitive("RESTORE"))
    }
    fun control(tx: ReleaseTransactionRequest = request): ReleaseGenerationControl = object : ReleaseGenerationControl by
        NativeReleaseControl(tx, runtime, acceptance, ::restore, operations, base, journeys, restoredVerifier) {
        override fun retireInstalledAfterCommittedSite() { calls += "retire-install-site" }
        override fun retireOwnedAfterCommittedSite() { calls += "retire-owned-references" }
        override fun retireOwnedAfterRollback() { calls += "retire-owned-rollback" }
    }
    fun dispatcher(controls: ((ReleaseTransactionRequest, Path) -> ReleaseGenerationControl)? = null,
        bridge: Boolean = true) = ReleaseDispatch(transactions,
        runtime, controls ?: { tx, _ -> control(tx) }, acceptance, ::restore,
        { _, _ -> object : ReleasePublicationControl {
            override fun pause() { calls += "pause" }
            override fun release() { calls += "release" }
        } }, { caddy }, { _, journal, _ -> object : ReleaseActiveSiteAuthorization {
            override fun verify(binding: ReleaseActivationBinding): String {
                assertEquals(Phase.ACCEPTED, TransactionJournal.verify(journal).last().phase); calls += "verify-permit"; return "f".repeat(64)
            }
            override fun consume(binding: ReleaseActivationBinding, permitSha256: String, activationJournalHead: String) {
                assertEquals(activationJournalHead, TransactionJournal.verify(journal).last().hash); calls += "consume-permit"
            }
            override fun select(binding: ReleaseActivationBinding, permitSha256: String,
                activationJournalHead: String, qualificationSnapshotId: String): String {
                assertEquals(qualifiedCapture, qualificationSnapshotId)
                assertEquals(Phase.ACTIVATION_STARTED, TransactionJournal.verify(journal).last().phase)
                calls += "select-site"; return "e".repeat(64)
            }
            override fun finalize(binding: ReleaseActivationBinding, committed: JournalRecord, selectionSha256: String) {
                assertEquals(Phase.COMMITTED, committed.phase); assertEquals("e".repeat(64), selectionSha256)
                calls += "finalize-site"
            }
        } }, operations, base, if (bridge) journeys else null)
    fun evidence() = ActivationEvidenceBinding(inventoryPin, manifest, products, products, acceptanceJournal.path, "b".repeat(64), "a".repeat(64))
    val journal: Path get() = transactions.resolve("unit/transaction.jsonl")
    override fun close() { Thread.interrupted(); Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
}
