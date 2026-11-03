package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import kotlin.test.*

/** All native effects replaced at the audited runtime/process boundary; real private files and
 * ownership/reference/journal/Caddy validation execute against this fixture's temporary directory. */
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
            ownership = SiteOwnerships.bind(plan, contract, emptySet()))
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
            calls += "start-restored:$generation"; return outcome("startup", bundle)
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
    fun control(tx: ReleaseTransactionRequest = request) = NativeReleaseControl(tx, runtime, acceptance, ::restore, operations, base)
    fun dispatcher(controls: ((ReleaseTransactionRequest, Path) -> ReleaseGenerationControl)? = null) = ReleaseDispatch(transactions,
        runtime, controls ?: { tx, _ -> control(tx) }, acceptance, ::restore,
        { _, _ -> object : ReleasePublicationControl {
            override fun pause() { calls += "pause" }
            override fun release() { calls += "release" }
        } }, { caddy }, { _, journal, _ -> object : ReleaseActivationAuthorization {
            override fun verify(binding: ReleaseActivationBinding): String {
                assertEquals(Phase.ACCEPTED, TransactionJournal.verify(journal).last().phase); calls += "verify-permit"; return "f".repeat(64)
            }
            override fun consume(binding: ReleaseActivationBinding, permitSha256: String, activationJournalHead: String) {
                assertEquals(activationJournalHead, TransactionJournal.verify(journal).last().hash); calls += "consume-permit"
            }
        } }, operations)
    fun evidence() = ActivationEvidenceBinding(inventoryPin, manifest, products, products, acceptanceJournal.path, "b".repeat(64), "a".repeat(64))
    val journal: Path get() = transactions.resolve("unit/transaction.jsonl")
    override fun close() { Thread.interrupted(); Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
}
