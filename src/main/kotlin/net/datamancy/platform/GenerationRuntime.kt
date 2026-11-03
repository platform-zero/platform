package net.datamancy.platform

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions
import com.sun.security.auth.module.UnixSystem
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable internal data class GenerationMember(val name: String, val dependencies: List<String> = emptyList())
@Serializable internal data class GenerationRequest(val schemaVersion: Int = 1, val id: String,
    val candidateSha256: String, val members: List<GenerationMember>, val diskReservationMiB: Long,
    val memoryHeadroomMiB: Long = 16384, val diskHeadroomMiB: Long = 10240,
    val purpose: String = "private-component-integration",
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val store: RuntimeStore = RuntimeStore.LEGACY,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val releaseCandidateSha256: String? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val rssPlan: GenerationRssPlan? = null)
@Serializable internal data class GenerationPin(val member: GenerationMember, val manifestSha256: String,
    val inputHashes: Map<String, String>, val runtimeFingerprint: String, val spec: PrivateDeploymentSpec)
@Serializable internal data class GenerationBundle(val request: GenerationRequest, val members: List<GenerationPin>,
    val memoryReservationMiB: Long, val assemblySha256: String? = null, val recoverySourceArchiveSha256: String? = null,
    val ownership: BoundSiteOwnership? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val recoverySourceKopia: KopiaSnapshotReceipt? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val ownedUpdate: OwnedUpdateLineage? = null)
@Serializable internal data class GenerationIntent(val action: String, val bundleSha256: String,
    val priorIntentSha256: String? = null)
@Serializable internal data class GenerationOutcome(val action: String, val bundleSha256: String,
    val passed: Boolean, val failureType: String? = null, val fences: Map<String, String> = emptyMap(),
    val priorIntentSha256: String? = null)
@Serializable internal data class GenerationCapacity(val availableMemoryMiB: Long, val usableDiskMiB: Long,
    val availableRuntimeLocks: Long = Long.MAX_VALUE)
@Serializable internal data class GenerationInspection(val id: String, val bundleSha256: String,
    val memoryReservationMiB: Long, val members: List<RuntimeAudit>, val publicActivation: Boolean = false,
    val fullStackQualification: Boolean = false)

internal interface GenerationBackend {
    fun audit(spec: PrivateDeploymentSpec, pristine: Boolean): RuntimeAudit
    fun apply(spec: PrivateDeploymentSpec): List<RuntimeStatus>
    fun isolate(spec: PrivateDeploymentSpec): String
}

/**
 * Live private-generation lifecycle, NOT the complete release transaction backend.
 * It never deletes volumes, releases historical isolation fences, enables boot units or publishes routes/outbound jobs.
 * Routine backup can release only its own freshly acquired temporary fences under an operation lease.
 */
internal class GenerationRuntime(private val base: Path, private val runtimeBase: Path,
    private val backend: (Map<String, String>) -> GenerationBackend,
    private val capacity: (RuntimeStore) -> GenerationCapacity) {
    companion object {
        val BASE: Path = Path.of("/mnt/media/p0-v3/release-generations")
        private val json = Json { ignoreUnknownKeys = false; encodeDefaults = true }
        private val id = Regex("q-[a-f0-9]{12}")
        private val hash = Regex("[a-f0-9]{64}")
        private val privateDir = PosixFilePermissions.fromString("rwx------")
        private val privateFile = PosixFilePermissions.fromString("rw-------")
        fun real() = GenerationRuntime(BASE, PrivateDeployment.BASE, { bindings -> NativeGenerationBackend(bindings) }, { store ->
            val mem = Files.readAllLines(Path.of("/proc/meminfo")).single { it.startsWith("MemAvailable:") }
                .trim().split(Regex("\\s+"))
            require(mem.size == 3 && mem[2] == "kB") { "Unknown available-memory measurement" }
            GenerationCapacity(mem[1].toLong() / 1024, Files.getFileStore(PrivateDeployment.BASE).usableSpace / 1048576,
                RuntimeLockBudget.available(PrivateRootfulCommands(store = store), store))
        })
        fun validateScope(request: GenerationRequest): List<GenerationMember> = Scope.ordered(request)
        fun request(path: Path): GenerationRequest = json.decodeFromString(privateInput(path).decodeToString(throwOnInvalidSequence = true))
        fun privateInput(path: Path): ByteArray {
            val file = path.toAbsolutePath().normalize()
            require(file.toRealPath() == file && (Files.getAttribute(file, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == UnixSystem().uid &&
                (Files.getAttribute(file, "unix:nlink", NOFOLLOW_LINKS) as Number).toInt() == 1) { "Owned single-link request required" }
            return ReleaseLocks.privateBytes(file)
        }
    }

    private fun directory(path: Path) {
        require(path.isAbsolute && path.normalize() == path && path.toRealPath() == path &&
            Files.isDirectory(path, NOFOLLOW_LINKS) && Files.getPosixFilePermissions(path) == privateDir &&
            (Files.getAttribute(path, "unix:uid") as Number).toLong() == UnixSystem().uid) { "Owned private generation directory required" }
    }
    private fun data(path: Path): ByteArray {
        require(path.toRealPath() == path && (Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == UnixSystem().uid &&
            (Files.getAttribute(path, "unix:nlink", NOFOLLOW_LINKS) as Number).toInt() == 1) { "Owned unlinked generation input required" }
        return ReleaseLocks.privateBytes(path)
    }
    private fun save(path: Path, text: String) {
        val encoded = text.toByteArray()
        require(encoded.size in 1..1048576) { "Generation record exceeds bound" }
        FileChannel.open(path, setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS), PosixFilePermissions.asFileAttribute(privateFile)).use {
            val bytes = ByteBuffer.wrap(encoded)
            while (bytes.hasRemaining()) it.write(bytes)
            it.force(true)
        }
        FileChannel.open(path.parent, READ).use { it.force(true) }
    }
    private fun <T> locked(action: () -> T): T {
        require(base.isAbsolute && base.normalize() == base && base.parent.toRealPath() == base.parent &&
            (Files.getAttribute(base.parent, "unix:uid") as Number).toLong() == UnixSystem().uid &&
            Files.getPosixFilePermissions(base.parent).none { it.name == "GROUP_WRITE" || it.name == "OTHERS_WRITE" }) {
            "Protected generation parent required"
        }
        if (!Files.exists(base, NOFOLLOW_LINKS)) Files.createDirectory(base, PosixFilePermissions.asFileAttribute(privateDir))
        directory(base)
        val lock = base.resolve("generation.lock")
        FileChannel.open(lock, setOf(CREATE, READ, WRITE, NOFOLLOW_LINKS), PosixFilePermissions.asFileAttribute(privateFile)).use { channel ->
            require(Files.getPosixFilePermissions(lock) == privateFile &&
                (Files.getAttribute(lock, "unix:uid") as Number).toLong() == UnixSystem().uid &&
                (Files.getAttribute(lock, "unix:nlink") as Number).toInt() == 1) { "Unsafe generation lock" }
            channel.lock().use { return action() }
        }
    }
    private fun ordered(request: GenerationRequest): List<GenerationMember> = validateScope(request)

    internal object Scope {
    fun ordered(request: GenerationRequest): List<GenerationMember> {
        request.rssPlan?.let { it.validate(); require(request.store == RuntimeStore.CANONICAL_V2) }
        require(request.schemaVersion == 1 && id.matches(request.id) && hash.matches(request.candidateSha256) &&
            (request.releaseCandidateSha256 == null || hash.matches(request.releaseCandidateSha256)) &&
            request.purpose == "private-component-integration" && request.members.size in 1..64 &&
            request.memoryHeadroomMiB in 16384..1048576 && request.diskHeadroomMiB in 10240..10485760 &&
            request.diskReservationMiB in 1024..10485760) { "Invalid private generation scope or capacity policy" }
        val members = request.members.associateBy { it.name }
        require(members.size == request.members.size && members.keys.all {
            it.startsWith("${request.id}-") && it.matches(Regex("q-[a-f0-9]{12}-[a-z][a-z0-9-]{0,23}")) && it.length <= 40
        }) { "Only fresh q-generation member namespaces are permitted" }
        val result = mutableListOf<GenerationMember>()
        val active = mutableSetOf<String>()
        val done = mutableSetOf<String>()
        fun visit(name: String) {
            if (name in done) return
            require(active.add(name)) { "Generation dependency cycle" }
            val member = members.getValue(name)
            require(member.dependencies.distinct().size == member.dependencies.size &&
                member.dependencies.all { it in members && it != name }) { "Invalid generation dependency" }
            member.dependencies.sorted().forEach(::visit)
            active.remove(name); done.add(name); result += member
        }
        members.keys.sorted().forEach(::visit)
        return result
    }
    }
    private fun pin(member: GenerationMember): Pair<GenerationPin, PrivateDeploymentSpec> {
        directory(runtimeBase)
        val manifest = data(runtimeBase.resolve("${member.name}.json"))
        val spec = Json.decodeFromString<PrivateDeploymentSpec>(manifest.decodeToString(throwOnInvalidSequence = true))
        require(spec.name == member.name) { "Foreign deployment manifest" }
        PrivateDeployment.validate(spec)
        val root = runtimeBase.resolve(spec.name)
        directory(root)
        val hashes = PrivateDeployment.inputNames(spec).associateWith { ReleaseLocks.sha256(data(root.resolve(it))) }
        return GenerationPin(member, ReleaseLocks.sha256(manifest), hashes, PrivateDeployment.expectedFingerprint(spec, hashes), spec) to spec
    }
    private fun reservation(specs: List<PrivateDeploymentSpec>): Long = specs.sumOf { spec ->
        spec.processes.filterNot { it.oneShot }.sumOf { it.memoryMiB.toLong() } +
            (spec.processes.filter { it.oneShot }.maxOfOrNull { it.memoryMiB } ?: 0)
    }
    private fun load(generation: String, expected: String, checkLiveInputs: Boolean = true): Pair<GenerationBundle, List<PrivateDeploymentSpec>> {
        require(id.matches(generation) && hash.matches(expected)) { "Invalid generation binding" }
        val root = base.resolve(generation); directory(root)
        val bytes = data(root.resolve("bundle.json"))
        require(ReleaseLocks.sha256(bytes) == expected) { "Generation bundle changed" }
        val bundle = json.decodeFromString<GenerationBundle>(bytes.decodeToString(throwOnInvalidSequence = true))
        if (checkLiveInputs && bundle.assemblySha256 != null) {
            val result = json.decodeFromString<AssemblyPreparationOutcome>(data(root.resolve("assembly.result.json")).decodeToString())
            require(result.passed && result.bundleSha256 == expected && result.assemblySha256 == bundle.assemblySha256 &&
                bundle.assemblySha256 == ReleaseLocks.sha256(data(root.resolve("assembly.intent.json")))) { "Incomplete or foreign assembly preparation" }
        }
        require(bundle.request.id == generation) { "Foreign generation bundle" }
        SiteOwnerships.checkSealed(bundle)
        if (checkLiveInputs) {
            val intent = root.resolve("ownership.intent.json")
            require(Files.exists(intent, NOFOLLOW_LINKS) == (bundle.ownership != null)) { "Missing or foreign ownership preparation intent" }
            bundle.ownership?.let { require(data(intent).contentEquals(json.encodeToString(it).toByteArray())) { "Ownership preparation intent changed" } }
        }
        val order = ordered(bundle.request)
        require(bundle.members.map { it.member } == order && bundle.members.all {
            it.spec.name == it.member.name && hash.matches(it.manifestSha256) &&
                PrivateDeployment.expectedFingerprint(it.spec, it.inputHashes) == it.runtimeFingerprint
        }) { "Invalid sealed member definition" }
        val specs = bundle.members.map { it.spec }
        require(specs.all { it.store == bundle.request.store }) { "Generation runtime-store binding differs" }
        require(reservation(specs) + (if (bundle.request.rssPlan != null) GenerationRssPlan.MEMORY_MIB else 0) == bundle.memoryReservationMiB &&
            bundle.request.diskReservationMiB >= specs.sumOf { it.volumes.size.toLong() * 1024 } +
                (if (bundle.request.rssPlan != null) GenerationRssPlan.DISK_MIB else 0) &&
            (!checkLiveInputs || order.map { pin(it).first } == bundle.members)) { "Generation input binding changed" }
        return bundle to specs
    }
    fun seal(request: GenerationRequest): String = locked {
        val pins = ordered(request).map(::pin)
        require(request.store == RuntimeStore.LEGACY && pins.all { it.first.spec.store == request.store }) {
            "Canonical store installation requires ownership-bound preparation"
        }
        require(request.diskReservationMiB >= pins.sumOf { it.second.volumes.size.toLong() * 1024 }) { "Disk reservation below per-volume minimum" }
        val bundle = GenerationBundle(request, pins.map { it.first }, reservation(pins.map { it.second }))
        val root = base.resolve(request.id)
        Files.createDirectory(root, PosixFilePermissions.asFileAttribute(privateDir))
        val text = json.encodeToString(bundle)
        save(root.resolve("bundle.json"), text)
        FileChannel.open(base, READ).use { it.force(true) }
        ReleaseLocks.sha256(text.toByteArray())
    }
    /** Prepares fresh synthetic inputs only. No runtime backend, unseal, provisioning or startup is invoked. */
    fun prepareAssembly(plan: AssemblyPlan): String = prepareAssembly(plan, null)
    fun prepareOwnedAssembly(plan: AssemblyPlan, contract: SiteOwnership, approvedHosts: Set<String>): String {
        val binding = SiteOwnerships.bind(plan, contract, approvedHosts) // Before registry locks/directories or credentials.
        return prepareAssembly(plan, binding)
    }
    private fun prepareAssembly(plan: AssemblyPlan, ownership: BoundSiteOwnership?): String = locked {
        val order = ordered(plan.generation)
        plan.generation.rssPlan?.let {
            require(ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(it.artifactClosure.path))) == it.artifactClosure.sha256) {
                "RSS artifact closure unavailable or changed before preparation"
            }
        }
        require(plan.specs.all { it.store == plan.generation.store } &&
            (plan.generation.store == RuntimeStore.LEGACY || ownership != null)) {
            "Canonical store installation requires matching store bindings and explicit ownership"
        }
        require(order.map { it.name } == plan.specs.map { it.name } && order.size == plan.recipes.size &&
            order == plan.summary.members.map { GenerationMember(it.name, it.dependencies) }) { "Assembly ordering mismatch" }
        require(plan.generation.diskReservationMiB >= plan.specs.sumOf { it.volumes.size.toLong() * 1024 } +
            (if (plan.generation.rssPlan != null) GenerationRssPlan.DISK_MIB else 0)) { "Insufficient controller state reservation" }
        directory(runtimeBase)
        for (member in order) require(!Files.exists(runtimeBase.resolve(member.name), NOFOLLOW_LINKS) &&
            !Files.exists(runtimeBase.resolve("${member.name}.json"), NOFOLLOW_LINKS)) { "Assembly requires fresh input namespaces; no credential regeneration" }
        val root = base.resolve(plan.generation.id)
        Files.createDirectory(root, PosixFilePermissions.asFileAttribute(privateDir))
        FileChannel.open(base, READ).use { it.force(true) }
        val text = json.encodeToString(plan.summary)
        val assemblyHash = ReleaseLocks.sha256(text.toByteArray())
        save(root.resolve("assembly.intent.json"), text)
        fun failed(error: Exception): Nothing {
            val interrupted = Thread.interrupted() || error is InterruptedException
            try { save(root.resolve("assembly.result.json"), json.encodeToString(
                AssemblyPreparationOutcome(assemblyHash, false, failureType = error.javaClass.name))) }
            finally { if (interrupted) Thread.currentThread().interrupt() }
            throw error
        }
        try {
            ownership?.let { save(root.resolve("ownership.intent.json"), json.encodeToString(it)) }
            plan.generation.rssPlan?.let { GenerationRssPlan.prepare(root) }
            val pins = order.indices.map { index ->
                val member = order[index]
                val expectedSpec = plan.summary.members[index].specSha256
                save(root.resolve("${member.name}.prepare.intent.json"), json.encodeToString(
                    AssemblyMemberIntent(assemblyHash, member.name, expectedSpec)))
                val path = plan.recipes[index].prepare(plan.inventory, runtimeBase, member.name, plan.generation.store)
                require(path == runtimeBase.resolve("${member.name}.json")) { "Recipe returned foreign input path" }
                val (actual, spec) = pin(member)
                require(spec == plan.specs[index] && actual.manifestSha256 == expectedSpec) { "Prepared recipe differs from planned definition" }
                save(root.resolve("${member.name}.prepare.result.json"), json.encodeToString(actual))
                actual
            }
            val bundle = GenerationBundle(plan.generation, pins, reservation(plan.specs) +
                (if (plan.generation.rssPlan != null) GenerationRssPlan.MEMORY_MIB else 0), assemblyHash, ownership = ownership)
            SiteOwnerships.checkSealed(bundle)
            val encoded = json.encodeToString(bundle)
            save(root.resolve("bundle.json"), encoded)
            val hash = ReleaseLocks.sha256(encoded.toByteArray())
            save(root.resolve("assembly.result.json"), json.encodeToString(AssemblyPreparationOutcome(assemblyHash, true, hash)))
            hash
        } catch (error: InterruptedException) { failed(error) }
        catch (error: Exception) { failed(error) }
    }
    private fun backend(bundle: GenerationBundle) = backend(bundle.members.associate { it.member.name to it.runtimeFingerprint })
    fun inspect(generation: String, expected: String): GenerationInspection = locked {
        val (bundle, specs) = load(generation, expected)
        val runtime = backend(bundle)
        GenerationInspection(generation, expected, bundle.memoryReservationMiB, specs.map { runtime.audit(it, false) })
    }
    private fun admit(bundle: GenerationBundle, workers: Int = 0) {
        val measured = capacity(bundle.request.store)
        RuntimeLockBudget.requireAvailable(measured.availableRuntimeLocks, bundle.members.map { it.spec }, workers)
        var reservedMemory = 0L
        var reservedDisk = 0L
        Files.list(base).use { paths ->
            val entries = paths.filter { it.fileName.toString() != "generation.lock" }.limit(4097).toList()
            require(entries.size <= 4096) { "Generation registry bound reached; no automatic evidence deletion" }
            for (path in entries) {
                require(id.matches(path.fileName.toString())) { "Unknown generation registry entry" }
                directory(path)
                val begin = path.resolve("stage.intent.json")
                if (!Files.exists(begin, NOFOLLOW_LINKS)) continue
                val intent = json.decodeFromString<GenerationIntent>(data(begin).decodeToString())
                require(intent.action in setOf("stage", "restore-import")) { "Invalid capacity reservation intent" }
                val bytes = data(path.resolve("bundle.json"))
                require(ReleaseLocks.sha256(bytes) == intent.bundleSha256) { "Reserved generation changed" }
                val existing = json.decodeFromString<GenerationBundle>(bytes.decodeToString())
                ordered(existing.request)
                require(existing.request.id == path.fileName.toString() && existing.memoryReservationMiB > 0) { "Invalid reservation" }
                // Imported startup is admitted against the existing sealed target, not charged twice.
                // The caller validates its completed import before reaching this admission boundary.
                if (existing.request.id == bundle.request.id) {
                    require(existing == bundle) { "Existing target reservation differs from sealed startup" }
                    continue
                }
                val outcomes = isolationOutcomes(path, intent.bundleSha256).filter { it.passed }
                if (outcomes.isNotEmpty()) {
                    val (retired, specs) = load(existing.request.id, intent.bundleSha256, checkLiveInputs = false)
                    val runtime = backend(retired)
                    val audits = specs.map { runtime.audit(it, false) }
                    require(outcomes.any { result -> result.fences.keys == specs.map { it.name }.toSet() && audits.all { audit ->
                        audit.maintenanceId == result.fences[audit.name] && audit.maintenanceId != null &&
                            audit.statuses.none { it.state in setOf("running", "paused", "restarting") }
                    } }) { "Isolation evidence is stale; reservation cannot be released" }
                    continue
                }
                reservedMemory = Math.addExact(reservedMemory, existing.memoryReservationMiB)
                reservedDisk = Math.addExact(reservedDisk, existing.request.diskReservationMiB)
            }
        }
        // Runtime apply is serial and topological. Do not add every completed initializer to the
        // serving peak, but keep historical sealed reservation bytes and conservative reservations
        // for other active/uncertain generations unchanged. Import still reserves startup capacity.
        val resources = GenerationCapacityPlanner.plan(bundle.members.map { it.spec }, bundle.request.diskReservationMiB)
        val phase = GenerationCapacityPlanner.phase(resources, GenerationPhase.INSTALL,
            work = GenerationResources(workers * 1024L + (if (bundle.request.rssPlan != null) GenerationRssPlan.MEMORY_MIB else 0),
                0, workers.toLong()),
            retained = GenerationResources(reservedMemory, reservedDisk, 0),
            memoryHeadroomMiB = bundle.request.memoryHeadroomMiB, diskHeadroomMiB = bundle.request.diskHeadroomMiB)
        GenerationCapacityPlanner.admit(phase, measured.availableMemoryMiB, measured.usableDiskMiB, measured.availableRuntimeLocks)
    }
    /** Imports only the compiled foundation/SQL-cache cohort into new namespaces. Leaves every target fenced and stopped. */
    fun restoreFoundation(inventory: AcquiredInventory, source: String, sourceBundle: String, captureId: String, target: String,
        custody: Path = Path.of("/mnt/media/p0-v3/generation-custody")): GenerationOutcome =
        restoreCold(inventory, source, sourceBundle, captureId, target, custody, ColdRestoreCohort.FOUNDATION)

    fun restoreApplications(inventory: AcquiredInventory, source: String, sourceBundle: String, captureId: String, target: String,
        custody: Path = Path.of("/mnt/media/p0-v3/generation-custody")): GenerationOutcome =
        restoreCold(inventory, source, sourceBundle, captureId, target, custody, ColdRestoreCohort.APPLICATIONS)

    fun restoreCanonicalCore(inventory: AcquiredInventory, source: String, sourceBundle: String, captureId: String, target: String,
        custody: Path = Path.of("/mnt/media/p0-v3/generation-custody")): GenerationOutcome =
        restoreCold(inventory, source, sourceBundle, captureId, target, custody, ColdRestoreCohort.CANONICAL_CORE)

    private fun restoreCold(inventory: AcquiredInventory, source: String, sourceBundle: String, captureId: String, target: String,
        custody: Path, cohort: ColdRestoreCohort, kopia: GenerationSnapshotStore? = null,
        targetStore: RuntimeStore = RuntimeStore.LEGACY): GenerationOutcome = locked {
        require(id.matches(target) && captureId.matches(Regex("cap-[a-f0-9]{12}")))
        val (original, _) = load(source, sourceBundle, checkLiveInputs = false)
        val captureRoot = base.resolve(source).resolve("${if (kopia == null) "captures" else "kopia-captures"}/$captureId"); directory(captureRoot)
        val archive = captureRoot.resolve("state.cap"); val key = custody.resolve(if (kopia == null) "$captureId.key" else "$source.env")
        val verified: CapsuleVerification?
        val snapshot: KopiaSnapshotReceipt?
        if (kopia == null) {
            val prior = json.decodeFromString<GenerationCaptureOutcome>(data(captureRoot.resolve("capture.result.json")).decodeToString())
            require(prior.passed && prior.id == captureId && prior.bundleSha256 == sourceBundle)
            verified = RecoveryCapsule.verify(archive, key, captureId, source, sourceBundle)
            require(verified == prior.verification) { "Capture differs from retained verification" }
            snapshot = null
        } else {
            val prior = json.decodeFromString<KopiaCaptureOutcome>(data(captureRoot.resolve("capture.result.json")).decodeToString())
            snapshot = requireNotNull(prior.snapshot)
            require(prior.passed && prior.id == captureId && prior.bundleSha256 == sourceBundle && snapshot.id == captureId &&
                snapshot.generation == source && snapshot.bundleSha256 == sourceBundle) { "Kopia capture binding mismatch" }
            KopiaGenerationStore.validate(snapshot)
            verified = null
        }
        val stateHash = verified?.archiveSha256 ?: KopiaGenerationStore.receiptHash(requireNotNull(snapshot))
        val compiled = FoundationRestore.bundle(original, inventory, target, stateHash, cohort, targetStore)
        val bundle = if (snapshot == null) compiled else compiled.copy(recoverySourceArchiveSha256 = null, recoverySourceKopia = snapshot)
        directory(runtimeBase)
        for (pin in bundle.members) require(!Files.exists(runtimeBase.resolve(pin.spec.name), NOFOLLOW_LINKS) &&
            !Files.exists(runtimeBase.resolve("${pin.spec.name}.json"), NOFOLLOW_LINKS)) { "Restore requires fresh input namespaces" }
        val runtime = backend(bundle)
        val importer = runtime as? GenerationImportBackend ?: error("Native import backend unavailable")
        admit(bundle, workers = if (kopia == null) 0 else 2)
        val root = base.resolve(target)
        Files.createDirectory(root, PosixFilePermissions.asFileAttribute(privateDir))
        FileChannel.open(base, READ).use { it.force(true) }
        val text = json.encodeToString(bundle); val expected = ReleaseLocks.sha256(text.toByteArray())
        save(root.resolve("bundle.json"), text)
        save(root.resolve("stage.intent.json"), json.encodeToString(GenerationIntent("restore-import", expected)))
        save(root.resolve("recovery.source.json"), if (snapshot == null) json.encodeToString(requireNotNull(verified)) else json.encodeToString(snapshot))
        val fences = linkedMapOf<String, String>()
        fun failed(error: Exception): GenerationOutcome {
            var interrupted = Thread.interrupted() || error is InterruptedException
            val result = GenerationOutcome("restore-import", expected, false, error.javaClass.name, fences)
            var recordingFailure: Exception? = null
            fun retain(failure: Exception) {
                interrupted = Thread.interrupted() || failure is InterruptedException || interrupted
                if (recordingFailure == null) recordingFailure = failure else recordingFailure!!.addSuppressed(failure)
            }
            try {
                try { save(root.resolve("stage.result.json"), json.encodeToString(result)) }
                catch (failure: InterruptedException) { retain(failure) }
                catch (failure: Exception) { retain(failure) }
                // Independent immutable isolation intent/outcome: a failed result write must not skip cleanup.
                // Missing/changed inputs fail closed; never regenerate credentials just to make isolation pass.
                try { isolateLocked(target, expected) }
                catch (failure: InterruptedException) { retain(failure) }
                catch (failure: Exception) { retain(failure) }
                recordingFailure?.let { it.addSuppressed(error); throw it }
                return result
            } finally { if (interrupted) Thread.currentThread().interrupt() }
        }
        try {
            val recovered = root.resolve("recovered")
            val checked = if (kopia == null) {
                RecoveryCapsule.extract(archive, key, captureId, source, sourceBundle, recovered)
                GenerationRecovery.validate(recovered, requireNotNull(verified))
            } else {
                RecoveryReferenceOperations.protect(base, requireNotNull(snapshot), "import", target)
                kopia.restore(base.resolve(source).resolve("kopia-store/repository"), key, root, snapshot, recovered)
                GenerationRecovery.validateKopia(recovered, snapshot)
            }
            require(checked.bundle == original)
            save(root.resolve("recovery.check.json"), json.encodeToString(checked.check))
            for (index in bundle.members.indices) {
                val pin = bundle.members[index]; val old = original.members[index]
                RuntimePreparation.prepare(pin.spec, runtimeBase) {
                    pin.inputHashes.mapValues { (file, _) ->
                        val bytes = data(recovered.resolve("${old.spec.name}/inputs/$file"))
                        require(ReleaseLocks.sha256(bytes) == pin.inputHashes.getValue(file))
                        bytes.decodeToString(throwOnInvalidSequence = true)
                    }
                }
                require(this.pin(pin.member).first == pin) { "Prepared restoration inputs differ from sealed definitions" }
            }
            bundle.members.forEach { runtime.audit(it.spec, true) } // All member/image audits before allocation.
            for (index in bundle.members.indices) {
                val pin = bundle.members[index]; val old = original.members[index]
                save(root.resolve("${pin.spec.name}.import.intent.json"), json.encodeToString(GenerationIntent("import-member", expected)))
                val verification = root.resolve("verify-${pin.spec.name}")
                Files.createDirectory(verification, PosixFilePermissions.asFileAttribute(privateDir))
                FileChannel.open(root, READ).use { it.force(true) }
                val inputs = pin.spec.volumes.associate { it.id to recovered.resolve("${old.spec.name}/volumes/${it.id}.tar") }
                val expectedHashes = pin.spec.volumes.associate { volume ->
                    val name = "${old.spec.name}/volumes/${volume.id}.tar"
                    volume.id to (checked.manifest.volumes.singleOrNull { it.name == name }?.sha256
                        ?: checked.manifest.files.single { it.name == name }.sha256)
                }
                fences[pin.spec.name] = importer.importCold(pin.spec, inputs, stateHash, verification, expectedHashes).id
                save(root.resolve("${pin.spec.name}.import.result.json"), json.encodeToString(runtime.audit(pin.spec, false)))
            }
            val result = GenerationOutcome("restore-import", expected, true, fences = fences)
            save(root.resolve("stage.result.json"), json.encodeToString(result))
            result
        } catch (error: InterruptedException) { failed(error); throw error }
        catch (error: Exception) { failed(error) }
    }
    /** Starts a complete, private Kopia import once. This does not confer site or promotion authority.
     * All cohort audits and capacity admission precede the first fence release. The native member
     * actuator holds its runtime lock across exact import checks, fence release and daemon startup. */
    fun startRestored(inventory: AcquiredInventory, generation: String, expected: String): GenerationOutcome = locked {
        val (bundle, specs) = backupSource(inventory, generation, expected)
        require(bundle.recoverySourceKopia != null && bundle.ownedUpdate == null &&
            specs.all { it.ingress == null && it.processes.none { p -> p.oneShot } }) {
            "Restricted restored startup requires a private initializer-free Kopia import"
        }
        val root = base.resolve(generation)
        val intent = root.resolve("restore-start.intent.json")
        require(!Files.exists(intent, NOFOLLOW_LINKS)) { "Restored startup already attempted; reconcile, never replay" }
        val imported = json.decodeFromString<GenerationOutcome>(data(root.resolve("stage.result.json")).decodeToString())
        val runtime = backend(bundle)
        val starter = runtime as? GenerationRestoreStartupBackend ?: error("Native imported startup backend unavailable")
        specs.forEach { spec ->
            val audit = runtime.audit(spec, false)
            require(audit.name == spec.name && audit.fingerprint == bundle.members.single { it.spec.name == spec.name }.runtimeFingerprint &&
                audit.maintenanceId == imported.fences.getValue(spec.name) && audit.statuses.size == spec.processes.size &&
                audit.statuses.map { it.id }.toSet() == spec.processes.map { it.id }.toSet() &&
                audit.statuses.all { it.state == "absent" && it.exitCode == null }) { "Imported target is not pristine and fenced" }
        }
        admit(bundle)
        save(intent, json.encodeToString(GenerationIntent("restore-start", expected)))
        try {
            specs.forEach { spec ->
                load(generation, expected)
                save(root.resolve("${spec.name}.restore-start.intent.json"), json.encodeToString(GenerationIntent("start-imported-member", expected)))
                val statuses = starter.startImported(spec, imported.fences.getValue(spec.name))
                require(statuses.size == spec.processes.size && spec.processes.all { process ->
                    statuses.singleOrNull { it.id == process.id }?.state == "running"
                }) { "Restored member readiness incomplete" }
                requireRunning(spec, runtime.audit(spec, false))
                save(root.resolve("${spec.name}.restore-start.result.json"), json.encodeToString(statuses))
            }
            val result = GenerationOutcome("restore-start", expected, true)
            save(root.resolve("restore-start.result.json"), json.encodeToString(result))
            result
        } catch (error: Exception) {
            var interrupted = Thread.interrupted() || error is InterruptedException
            val result = GenerationOutcome("restore-start", expected, false, error.javaClass.name)
            var recordingFailure: Exception? = null
            fun retain(failure: Exception) {
                interrupted = Thread.interrupted() || failure is InterruptedException || interrupted
                if (recordingFailure == null) recordingFailure = failure else recordingFailure!!.addSuppressed(failure)
            }
            try {
                try { save(root.resolve("restore-start.result.json"), json.encodeToString(result)) } catch (failure: Exception) { retain(failure) }
                // A missing result must not skip stop/fence of members already started.
                try { isolateLocked(generation, expected) } catch (failure: Exception) { retain(failure) }
                recordingFailure?.let { it.addSuppressed(error); throw it }
                if (interrupted) throw error
                result
            } finally { if (interrupted) Thread.currentThread().interrupt() }
        }
    }

    fun stage(generation: String, expected: String): GenerationOutcome = locked {
        val (bundle, specs) = load(generation, expected)
        require(bundle.recoverySourceArchiveSha256 == null && bundle.recoverySourceKopia == null) { "Restore generations cannot run clean-install staging" }
        require(bundle.ownedUpdate == null) { "Update generations cannot run clean-install staging" }
        val root = base.resolve(generation)
        require(!Files.exists(root.resolve("stage.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("isolate.intent.json"), NOFOLLOW_LINKS)) { "Generation already attempted; reconcile, do not replay" }
        val runtime = backend(bundle)
        // Audit every member/image before the FIRST process or resource creation.
        specs.forEach { runtime.audit(it, true) }
        admit(bundle)
        save(root.resolve("stage.intent.json"), json.encodeToString(GenerationIntent("stage", expected)))
        try {
            for (spec in specs) {
                load(generation, expected) // Immutable member manifests are also checked between effects.
                save(root.resolve("${spec.name}.stage.intent.json"), json.encodeToString(GenerationIntent("stage-member", expected)))
                val result = runtime.apply(spec)
                require(spec.processes.all { process -> result.singleOrNull { it.id == process.id }?.let {
                    if (process.oneShot) it.state in setOf("completed", "exited") && it.exitCode == 0 else it.state == "running"
                } == true }) { "Generation member not ready" }
                save(root.resolve("${spec.name}.stage.result.json"), json.encodeToString(result))
            }
            val result = GenerationOutcome("stage", expected, true)
            save(root.resolve("stage.result.json"), json.encodeToString(result))
            result
        } catch (interrupted: InterruptedException) {
            stageFailure(generation, expected, interrupted)
            throw interrupted
        } catch (failure: Exception) {
            stageFailure(generation, expected, failure)
        }
    }
    private fun stageFailure(generation: String, expected: String, failure: Exception): GenerationOutcome {
        val interrupted = Thread.interrupted() || failure is InterruptedException
        try {
            val result = GenerationOutcome("stage", expected, false, failure.javaClass.name)
            save(base.resolve(generation).resolve("stage.result.json"), json.encodeToString(result))
            // Isolation has its own intent and retained result. Never release any fence on failure.
            isolateLocked(generation, expected)
            if (interrupted) throw failure
            return result
        } finally { if (interrupted) Thread.currentThread().interrupt() }
    }
    private fun isolationOutcomes(root: Path, expected: String): List<GenerationOutcome> {
        val paths = Files.list(root).use { files -> files.filter {
            it.fileName.toString() == "isolate.result.json" ||
                (it.fileName.toString().startsWith("isolate-reconcile-") && it.fileName.toString().endsWith(".result.json"))
        }.limit(130).toList() }
        require(paths.size <= 129) { "Isolation reconciliation bound reached" }
        return paths.map { path ->
            val stem = path.fileName.toString().removeSuffix(".result.json")
            require(stem == "isolate" || stem.matches(Regex("isolate-reconcile-r-[a-f0-9]{12}"))) { "Invalid isolation record" }
            val intent = json.decodeFromString<GenerationIntent>(data(root.resolve("$stem.intent.json")).decodeToString())
            val result = json.decodeFromString<GenerationOutcome>(data(path).decodeToString())
            require(result.bundleSha256 == expected && intent.bundleSha256 == expected && result.action == intent.action &&
                result.priorIntentSha256 == intent.priorIntentSha256 &&
                if (stem == "isolate") result.action == "isolate" && intent.priorIntentSha256 == null
                else result.action == "reconcile-isolation" && intent.priorIntentSha256 ==
                    ReleaseLocks.sha256(data(root.resolve("isolate.intent.json")))) { "Foreign isolation result" }
            result
        }
    }
    private fun isolateLocked(generation: String, expected: String, reconciliationId: String? = null,
        priorIntent: String? = null, runtimeOverride: GenerationBackend? = null): GenerationOutcome {
        // Sealed definitions permit stopping other members even if a live manifest has drifted.
        // Each runtime still checks actual input fingerprints and ownership under its own lock.
        val (bundle, specs) = load(generation, expected, checkLiveInputs = false)
        val root = base.resolve(generation)
        val stem = if (reconciliationId == null) "isolate" else "isolate-reconcile-$reconciliationId"
        val action = if (reconciliationId == null) "isolate" else "reconcile-isolation"
        if (reconciliationId != null) {
            require(reconciliationId.matches(Regex("r-[a-f0-9]{12}")) && priorIntent != null && hash.matches(priorIntent)) { "Invalid reconciliation identity" }
            val original = data(root.resolve("isolate.intent.json"))
            val intent = json.decodeFromString<GenerationIntent>(original.decodeToString())
            require(ReleaseLocks.sha256(original) == priorIntent && intent.action == "isolate" &&
                intent.bundleSha256 == expected && intent.priorIntentSha256 == null) { "Isolation predecessor mismatch" }
            isolationOutcomes(root, expected) // Corrupt history cannot be bypassed with another action ID.
        }
        save(root.resolve("$stem.intent.json"), json.encodeToString(GenerationIntent(action, expected, priorIntent)))
        val runtime = runtimeOverride ?: backend(bundle)
        val fences = linkedMapOf<String, String>()
        var failure: Exception? = null
        var interrupted = false
        try {
            for (spec in specs.asReversed()) try {
                fences[spec.name] = runtime.isolate(spec)
            } catch (error: InterruptedException) {
                Thread.interrupted(); interrupted = true; failure = failure ?: error
            } catch (error: Exception) {
                interrupted = Thread.interrupted() || interrupted
                failure = failure ?: error
            }
            val result = GenerationOutcome(action, expected, failure == null, failure?.javaClass?.name, fences, priorIntent)
            save(root.resolve("$stem.result.json"), json.encodeToString(result))
            if (interrupted) throw InterruptedException("Generation isolation interrupted; outcomes retained")
            return result
        } finally { if (interrupted) Thread.currentThread().interrupt() }
    }
    fun restoreKopiaCanonicalCore(inventory: AcquiredInventory, source: String, sourceBundle: String, captureId: String, target: String,
        custody: Path = Path.of("/mnt/media/p0-v3/kopia-custody"), store: GenerationSnapshotStore? = null,
        targetStore: RuntimeStore = RuntimeStore.LEGACY): GenerationOutcome =
        restoreCold(inventory, source, sourceBundle, captureId, target, custody, ColdRestoreCohort.CANONICAL_CORE,
            store ?: KopiaGenerationStore.real(inventory, targetStore), targetStore)

    fun restoreKopiaWholeRelease(inventory: AcquiredInventory, source: String, sourceBundle: String, captureId: String, target: String,
        custody: Path = Path.of("/mnt/media/p0-v3/kopia-custody"), store: GenerationSnapshotStore? = null,
        targetStore: RuntimeStore = RuntimeStore.CANONICAL_V2): GenerationOutcome =
        restoreCold(inventory, source, sourceBundle, captureId, target, custody, ColdRestoreCohort.WHOLE_RELEASE,
            store ?: KopiaGenerationStore.real(inventory, targetStore), targetStore)

    fun retainKopia(inventory: AcquiredInventory, generation: String, expected: String, operation: String): KopiaRetentionResult = locked {
        val bundle = load(generation, expected, checkLiveInputs = false).first
        val measured = capacity(bundle.request.store)
        RuntimeLockBudget.requireAvailable(measured.availableRuntimeLocks, workers = 1)
        require(measured.availableMemoryMiB >= bundle.request.memoryHeadroomMiB + 1024 &&
            measured.usableDiskMiB >= bundle.request.diskHeadroomMiB) { "Insufficient retention worker headroom" }
        RecoveryReferenceOperations.retain(base, inventory, generation, expected, operation)
    }

    private fun backupRuntime(bundle: GenerationBundle, access: RuntimeBackupAccess): BackupGenerationBackend =
        (backend(bundle) as? BackupGenerationFactory ?: error("Routine backup backend unavailable")).forBackup(access)
    private fun requireRunning(spec: PrivateDeploymentSpec, audit: RuntimeAudit) {
        require(audit.name == spec.name && audit.maintenanceId == null && spec.processes.all { p ->
            audit.statuses.singleOrNull { it.id == p.id }?.let {
                if (p.oneShot) it.state in setOf("completed", "exited") && it.exitCode == 0 else it.state == "running"
            } == true
        }) { "Routine backup requires a fully running unfenced cohort" }
    }
    /** Activation observation only: never promotes a recovery, replays jobs or releases a maintenance/backup fence. */
    fun checkActivationSource(deployment: ReleaseDeploymentBinding, candidate: kotlinx.serialization.json.JsonObject,
        imagePins: Set<Pair<String, String>>): List<CaddyUpstream> = locked {
        deployment.validate()
        val (bundle, specs) = load(deployment.generationId, deployment.bundleSha256)
        val fields = listOf("implementationSha256", "artifactsSha256", "configurationSha256", "acceptanceSha256", "sitePolicySha256")
        require(candidate.keys == fields.toSet())
        val normalized = kotlinx.serialization.json.JsonObject(fields.associateWith { candidate.getValue(it) })
        require(bundle.request.candidateSha256 == ReleaseLocks.sha256(normalized.toString().toByteArray()) &&
            bundle.request.store == RuntimeStore.CANONICAL_V2 && bundle.recoverySourceArchiveSha256 == null && bundle.recoverySourceKopia == null &&
            bundle.ownedUpdate == null)
        require(imagePins.isNotEmpty() && specs.flatMap { it.processes }.all { (it.image to it.imageId) in imagePins }) {
            "Runtime image differs from frozen artifact closure"
        }
        val owned = requireNotNull(bundle.ownership) { "Activation requires original site ownership, not recovery lineage" }
        val capabilities = owned.assembly.members.flatMap { it.primaryCapabilities }
        require(capabilities.size == capabilities.distinct().size && capabilities.toSet() ==
            ProductSelection.bundled().products.toSet() + setOf("openbao", "keykeeper", "worklane", "tuios", "pi")) { "Complete canonical activation cohort required" }
        val root = base.resolve(bundle.request.id)
        require(!Files.exists(root.resolve("isolate.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("kopia-store/snapshot.pending.json"), NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("kopia-store/retention.pending.json"), NOFOLLOW_LINKS)) { "Retired or uncertain activation source" }
        completedCaptureSource(bundle, deployment.bundleSha256, allowRecovered = false)
        val backups = root.resolve("backups")
        if (Files.exists(backups, NOFOLLOW_LINKS)) {
            directory(backups)
            val attempts = Files.list(backups).use { it.limit(129).toList() }
            require(attempts.size <= 128)
            for (attempt in attempts) {
                directory(attempt)
                val result = json.decodeFromString<GenerationBackupOutcome>(data(attempt.resolve("result.json")).decodeToString())
                require(result.passed && result.sourceResumed && result.failureType == null && result.access.generation == bundle.request.id &&
                    result.access.bundleSha256 == deployment.bundleSha256) { "Uncertain backup blocks activation" }
            }
        }
        val runtime = backend(bundle)
        specs.forEach { spec ->
            require(!Files.exists(runtimeBase.resolve(spec.name).resolve("runtime.backup"), NOFOLLOW_LINKS)) { "Backup operation still owns source" }
            requireRunning(spec, runtime.audit(spec, false))
        }
        owned.contract.routes.map { CaddyUpstream(it.host, "p0v3-live-${it.process.replace('/', '-')}:${it.port}") }
    }

    /** Read-only eligibility for enrollment; the backup itself repeats these checks under the operation lock. */
    fun checkBackupSource(inventory: AcquiredInventory, generation: String, expected: String) = locked {
        val (bundle, specs) = backupSource(inventory, generation, expected)
        val runtime = backend(bundle)
        specs.forEach { requireRunning(it, runtime.audit(it, false)) }
    }
    /** A recovered source remains private. Its import proof is not site promotion or a functional acceptance receipt. */
    private fun completedCaptureSource(bundle: GenerationBundle, expected: String, allowRecovered: Boolean) {
        val root = base.resolve(bundle.request.id)
        val stage = json.decodeFromString<GenerationOutcome>(data(root.resolve("stage.result.json")).decodeToString())
        require(stage.passed && stage.failureType == null && stage.bundleSha256 == expected) { "Capture requires completed source staging" }
        val lineage = bundle.recoverySourceKopia
        if (lineage == null) {
            require(bundle.recoverySourceArchiveSha256 == null && stage.action == "stage") { "Capture requires a clean installation or supported Kopia recovery" }
            return
        }
        require(allowRecovered && bundle.recoverySourceArchiveSha256 == null && bundle.ownership == null && bundle.assemblySha256 == null &&
            stage.action == "restore-import" && stage.fences.keys == bundle.members.map { it.member.name }.toSet()) { "Private recovered backup authority required" }
        KopiaGenerationStore.validate(lineage)
        require(lineage.generation != bundle.request.id)
        val intent = json.decodeFromString<GenerationIntent>(data(root.resolve("stage.intent.json")).decodeToString())
        require(intent == GenerationIntent("restore-import", expected) && stage.priorIntentSha256 == null)
        require(json.decodeFromString<KopiaSnapshotReceipt>(data(root.resolve("recovery.source.json")).decodeToString()) == lineage) { "Recovery lineage changed" }
        val receiptHash = KopiaGenerationStore.receiptHash(lineage)
        val check = json.decodeFromString<GenerationRecoveryCheck>(data(root.resolve("recovery.check.json")).decodeToString())
        val parent = load(lineage.generation, lineage.bundleSha256, checkLiveInputs = false).first
        require(check.generation == lineage.generation && check.capsule == lineage.id && check.bundleSha256 == lineage.bundleSha256 &&
            check.archiveSha256.isEmpty() && check.kopiaSnapshotId == lineage.snapshotId && check.kopiaReceiptSha256 == receiptHash &&
            !check.functionalRestoreVerified && !check.runtimeImported && check.members.map { it.name } == parent.members.map { it.member.name } &&
            check.members.zip(parent.members).all { (checked, pin) -> checked.fingerprint == pin.runtimeFingerprint &&
                checked.retiredInitializers == pin.spec.processes.filter { it.oneShot }.map { it.id }.toSet() }) { "Recovered source verification differs from lineage" }
        for (pin in bundle.members) {
            require(pin.spec.processes.none { it.oneShot }) { "Recovered backup cannot regain bootstrap processes" }
            val memberIntent = json.decodeFromString<GenerationIntent>(data(root.resolve("${pin.member.name}.import.intent.json")).decodeToString())
            val memberResult = json.decodeFromString<RuntimeAudit>(data(root.resolve("${pin.member.name}.import.result.json")).decodeToString())
            require(memberIntent == GenerationIntent("import-member", expected) && memberResult.name == pin.member.name &&
                memberResult.fingerprint == pin.runtimeFingerprint && memberResult.maintenanceId == stage.fences.getValue(pin.member.name)) {
                "Incomplete or foreign member import history"
            }
            val marker = "p0v3-native-volume-import-v1\n${pin.runtimeFingerprint}\n$receiptHash\n".toByteArray()
            for (file in listOf("runtime.import.intent", "runtime.import.complete"))
                require(data(runtimeBase.resolve(pin.member.name).resolve(file)).contentEquals(marker)) { "Native imported source lineage changed" }
        }
    }
    private fun backupSource(inventory: AcquiredInventory, generation: String, expected: String): Pair<GenerationBundle, List<PrivateDeploymentSpec>> {
        val (bundle, specs) = load(generation, expected)
        require(bundle.recoverySourceArchiveSha256 == null &&
            ((bundle.ownership != null && bundle.recoverySourceKopia == null) || (bundle.ownership == null && bundle.recoverySourceKopia != null))) {
            "Routine backup requires an owned canonical installation or private Kopia recovery"
        }
        FoundationRestore.bundle(bundle, inventory, if (generation == "q-000000000000") "q-111111111111" else "q-000000000000",
            "0".repeat(64), ColdRestoreCohort.WHOLE_RELEASE)
        val generationRoot = base.resolve(generation)
        require(!Files.exists(generationRoot.resolve("isolate.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(generationRoot.resolve("kopia-store/snapshot.pending.json"), NOFOLLOW_LINKS) &&
            !Files.exists(generationRoot.resolve("kopia-store/retention.pending.json"), NOFOLLOW_LINKS)) { "Retired or uncertain source cannot be resumed by backup" }
        completedCaptureSource(bundle, expected, allowRecovered = true)
        return bundle to specs
    }
    /** New canonical source only. No permanent isolation history, unknown prior backup or bootstrap replay. */
    fun backupKopia(inventory: AcquiredInventory, generation: String, expected: String, captureId: String,
        custody: Path = Path.of("/mnt/media/p0-v3/kopia-custody"), store: GenerationSnapshotStore? = null): GenerationBackupOutcome =
        requireNotNull(coordinatedBackup(inventory, generation, expected, captureId, custody, store, hold = false).first)

    fun holdKopiaForRestore(inventory: AcquiredInventory, generation: String, expected: String, captureId: String,
        custody: Path = Path.of("/mnt/media/p0-v3/kopia-custody"), store: GenerationSnapshotStore? = null): GenerationHeldCapture =
        requireNotNull(coordinatedBackup(inventory, generation, expected, captureId, custody, store, hold = true).second) {
            "Source hold failed; retained isolation must be reconciled, never retried"
        }

    private fun coordinatedBackup(inventory: AcquiredInventory, generation: String, expected: String, captureId: String,
        custody: Path, store: GenerationSnapshotStore?, hold: Boolean): Pair<GenerationBackupOutcome?, GenerationHeldCapture?> = locked {
        val access = RuntimeBackupAccess(generation, captureId, expected); access.validate()
        val (bundle, specs) = backupSource(inventory, generation, expected)
        val generationRoot = base.resolve(generation)
        require(!Files.exists(generationRoot.resolve("kopia-captures/$captureId"), NOFOLLOW_LINKS)) { "Capture namespace already exists" }
        val runtime = backupRuntime(bundle, access)
        specs.forEach { requireRunning(it, runtime.audit(it, false)) }
        val measured = capacity(bundle.request.store)
        RuntimeLockBudget.requireAvailable(measured.availableRuntimeLocks, workers = 3)
        require(measured.availableMemoryMiB >= bundle.request.memoryHeadroomMiB + 1024 &&
            measured.usableDiskMiB >= 3 * RecoveryCapsule.MAX_TOTAL / 1048576 + bundle.request.diskHeadroomMiB + 16) { "Insufficient routine backup headroom" }
        val backups = generationRoot.resolve("backups")
        if (!Files.exists(backups, NOFOLLOW_LINKS)) {
            Files.createDirectory(backups, PosixFilePermissions.asFileAttribute(privateDir))
            FileChannel.open(generationRoot, READ).use { it.force(true) }
        }
        directory(backups)
        Files.list(backups).use { entries ->
            val prior = entries.limit(129).toList(); require(prior.size < 128) { "Backup history bound reached; no automatic evidence deletion" }
            for (path in prior) {
                directory(path); require(path.fileName.toString().matches(Regex("cap-[a-f0-9]{12}")))
                val intent = json.decodeFromString<RuntimeBackupAccess>(data(path.resolve("intent.json")).decodeToString())
                val result = json.decodeFromString<GenerationBackupOutcome>(data(path.resolve("result.json")).decodeToString())
                require(intent == RuntimeBackupAccess(generation, path.fileName.toString(), expected) && result.access == intent &&
                    result.passed && result.sourceResumed) { "Incomplete or failed backup requires reconciliation, not another operation ID" }
            }
        }
        val root = backups.resolve(captureId)
        Files.createDirectory(root, PosixFilePermissions.asFileAttribute(privateDir))
        FileChannel.open(backups, READ).use { it.force(true) }
        save(root.resolve("intent.json"), json.encodeToString(access))
        fun <T> effect(name: String, action: () -> T): T {
            save(root.resolve("$name.intent.json"), json.encodeToString(access))
            return action().also { save(root.resolve("$name.result.json"), json.encodeToString(access)) }
        }
        var snapshot: KopiaSnapshotReceipt? = null
        fun failed(error: Exception): GenerationBackupOutcome {
            var interrupted = Thread.interrupted() || error is InterruptedException
            val result = GenerationBackupOutcome(access, false, snapshot, false, error.javaClass.name)
            var recording: Exception? = null
            fun retain(e: Exception) {
                interrupted = Thread.interrupted() || e is InterruptedException || interrupted
                if (recording == null) recording = e else recording!!.addSuppressed(e)
            }
            try {
                try { save(root.resolve("result.json"), json.encodeToString(result)) }
                catch (e: InterruptedException) { retain(e) }
                catch (e: Exception) { retain(e) }
                // Independent stop/fence result, even if backup result persistence failed.
                try { isolateLocked(generation, expected, runtimeOverride = runtime) }
                catch (e: InterruptedException) { retain(e) }
                catch (e: Exception) { retain(e) }
                recording?.let { it.addSuppressed(error); throw it }
                return result
            } finally { if (interrupted) Thread.currentThread().interrupt() }
        }
        try {
            for (spec in specs) effect("claim-${spec.name}") { runtime.claim(spec) }
            val fences = linkedMapOf<String, String>()
            for (spec in specs.asReversed()) fences[spec.name] = effect("quiesce-${spec.name}") { runtime.quiesce(spec) }
            save(root.resolve("quiesced.json"), json.encodeToString(fences))
            snapshot = effect("capture") { requireNotNull(captureLocked(generation, expected, captureId, custody, store ?: KopiaGenerationStore.real(inventory, bundle.request.store), runtime, fences).kopia) }
            require(snapshot.id == captureId && snapshot.generation == generation && snapshot.bundleSha256 == expected)
            if (hold) {
                val held = GenerationHeldCapture(access, snapshot, fences).also { it.validate() }
                RecoveryReferenceOperations.protect(base, snapshot, "unknown", "held-$captureId")
                save(root.resolve("held.json"), json.encodeToString(held))
                return@locked null to held // No resumed/success outcome and no lease release while the restore target is active.
            }
            val available = capacity(bundle.request.store)
            require(available.availableMemoryMiB >= bundle.memoryReservationMiB + bundle.request.memoryHeadroomMiB &&
                available.usableDiskMiB >= bundle.request.diskHeadroomMiB) { "Insufficient safe resume capacity; source remains fenced" }
            for (spec in specs) effect("resume-${spec.name}") {
                completedCaptureSource(load(generation, expected).first, expected, allowRecovered = true)
                runtime.resume(spec, fences.getValue(spec.name))
                requireRunning(spec, runtime.audit(spec, false))
            }
            specs.forEach { requireRunning(it, runtime.audit(it, false)) }
            save(root.resolve("resume.verified.json"), json.encodeToString(access))
            for (spec in specs) effect("release-${spec.name}") { runtime.finish(spec) }
            val result = GenerationBackupOutcome(access, true, snapshot, true)
            save(root.resolve("result.json"), json.encodeToString(result))
            result to null
        } catch (e: InterruptedException) { failed(e); throw e }
        catch (e: Exception) { failed(e) to null }
    }

    /** Resume only this still-held source while the exact imported target is locked, stopped and fenced. */
    fun resumeHeldSourceAfterIsolation(inventory: AcquiredInventory, generation: String, expected: String, captureId: String,
        expectedHeldSha256: String, target: String, targetExpected: String): GenerationBackupOutcome = locked {
        val access = RuntimeBackupAccess(generation, captureId, expected).also { it.validate() }
        require(hash.matches(expectedHeldSha256) && hash.matches(targetExpected) && id.matches(target) && target != generation)
        val root = base.resolve(generation).resolve("backups/$captureId"); directory(root)
        require(!Files.exists(root.resolve("result.json"), NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("resume.authority.json"), NOFOLLOW_LINKS)) { "Held-source resume already attempted; no replay" }
        val bytes = data(root.resolve("held.json"))
        require(ReleaseLocks.sha256(bytes) == expectedHeldSha256)
        val held = json.decodeFromString<GenerationHeldCapture>(bytes.decodeToString()).also { it.validate() }
        require(held.access == access && held.sha256 == expectedHeldSha256 &&
            json.decodeFromString<RuntimeBackupAccess>(data(root.resolve("intent.json")).decodeToString()) == access)
        val capture = json.decodeFromString<KopiaCaptureOutcome>(data(base.resolve(generation)
            .resolve("kopia-captures/$captureId/capture.result.json")).decodeToString())
        require(capture.passed && capture.failureType == null && capture.id == captureId &&
            capture.bundleSha256 == expected && capture.snapshot == held.snapshot) { "Held snapshot lineage changed" }
        val (bundle, specs) = backupSource(inventory, generation, expected)
        require(held.fences.keys == specs.map { it.name }.toSet())
        val (targetBundle, targets) = load(target, targetExpected)
        require(targetBundle.recoverySourceKopia == held.snapshot && targets.none { it.name in held.fences } &&
            targets.all { spec -> spec.processes.none { it.oneShot } }) { "Exact initializer-free imported target required" }
        completedCaptureSource(targetBundle, targetExpected, allowRecovered = true)
        val targetRuntime = backend(targetBundle)
        val cold = targetRuntime as? ColdGenerationBackend ?: error("Target isolation observer unavailable")
        val observations = targets.associate { it.name to targetRuntime.audit(it, false) }
        val isolation = isolationOutcomes(base.resolve(target), targetExpected).firstOrNull { outcome ->
            outcome.passed && outcome.failureType == null && outcome.fences.keys == targets.map { it.name }.toSet() &&
                observations.all { (name, observed) -> observed.maintenanceId == outcome.fences[name] &&
                    observed.statuses.all { it.state == "exited" && it.exitCode in setOf(0, 143) } }
        } ?: error("Target isolation must be verified before source resume")
        val runtime = backupRuntime(bundle, access)
        fun frozen(index: Int): GenerationBackupOutcome {
            if (index < targets.size) return cold.withFrozen(targets[index], isolation.fences.getValue(targets[index].name)) { observed ->
                val pin = targetBundle.members[index]
                require(observed.name == pin.member.name && observed.fingerprint == pin.runtimeFingerprint &&
                    observed.fenceId == isolation.fences[observed.name] && observed.completedInitializers.isEmpty() &&
                    observed.statuses.map { it.id }.toSet() == pin.spec.processes.map { it.id }.toSet() &&
                    observed.statuses.size == pin.spec.processes.size && observed.statuses.all { it.state == "exited" && it.exitCode in setOf(0, 143) })
                frozen(index + 1)
            }
            // All target runtime locks stay held through every source resume and lease release.
            val available = capacity(bundle.request.store)
            require(available.availableMemoryMiB >= bundle.memoryReservationMiB + bundle.request.memoryHeadroomMiB &&
                available.usableDiskMiB >= bundle.request.diskHeadroomMiB) { "Insufficient safe resume capacity; source remains fenced" }
            RuntimeLockBudget.requireAvailable(available.availableRuntimeLocks, workers = 0)
            specs.forEach { spec ->
                val observed = runtime.audit(spec, false)
                require(observed.name == spec.name && observed.fingerprint == bundle.members.single { it.member.name == spec.name }.runtimeFingerprint &&
                    observed.statuses.size == spec.processes.size && observed.statuses.map { it.id }.toSet() == spec.processes.map { it.id }.toSet() &&
                    observed.maintenanceId == held.fences.getValue(spec.name) && observed.statuses.all {
                    if (spec.processes.single { p -> p.id == it.id }.oneShot) it.state in setOf("completed", "exited") && it.exitCode == 0
                    else it.state == "exited" && it.exitCode in setOf(0, 143)
                }) { "Held source changed before resume" }
            }
            save(root.resolve("resume.authority.json"), json.encodeToString(HeldSourceResumeAuthority(expectedHeldSha256, target, targetExpected, isolation.fences)))
            fun effect(name: String, action: () -> Unit) {
                if (Thread.currentThread().isInterrupted) throw InterruptedException("Held-source resume interrupted")
                save(root.resolve("$name.intent.json"), json.encodeToString(access)); action()
                save(root.resolve("$name.result.json"), json.encodeToString(access))
            }
            try {
                for (spec in specs) effect("resume-${spec.name}") {
                    completedCaptureSource(load(generation, expected).first, expected, allowRecovered = true)
                    runtime.resume(spec, held.fences.getValue(spec.name)); requireRunning(spec, runtime.audit(spec, false))
                }
                specs.forEach { requireRunning(it, runtime.audit(it, false)) }
                save(root.resolve("resume.verified.json"), json.encodeToString(access))
                for (spec in specs) effect("release-${spec.name}") { runtime.finish(spec) }
                val result = GenerationBackupOutcome(access, true, held.snapshot, true)
                save(root.resolve("result.json"), json.encodeToString(result)); return result
            } catch (failure: Exception) {
                val interrupted = Thread.interrupted() || failure is InterruptedException
                try {
                    try { save(root.resolve("result.json"), json.encodeToString(GenerationBackupOutcome(access, false, held.snapshot, false, failure.javaClass.name))) }
                    finally { isolateLocked(generation, expected, runtimeOverride = runtime) }
                    throw failure
                } finally { if (interrupted) Thread.currentThread().interrupt() }
            }
        }
        frozen(0)
    }
    /** Never resumes or re-submits a snapshot. Retains leases and original backup/capture outcomes. */
    fun reconcileBackup(generation: String, expected: String, captureId: String, reconciliationId: String, priorIntentSha256: String): GenerationOutcome = locked {
        val access = RuntimeBackupAccess(generation, captureId, expected); access.validate()
        require(reconciliationId.matches(Regex("r-[a-f0-9]{12}")) && hash.matches(priorIntentSha256))
        val root = base.resolve(generation).resolve("backups/$captureId"); directory(root)
        val original = data(root.resolve("intent.json"))
        require(ReleaseLocks.sha256(original) == priorIntentSha256 && json.decodeFromString<RuntimeBackupAccess>(original.decodeToString()) == access)
        val result = root.resolve("result.json")
        if (Files.exists(result, NOFOLLOW_LINKS)) require(!json.decodeFromString<GenerationBackupOutcome>(data(result).decodeToString()).passed) {
            "Completed backup is not interruption recovery authority"
        }
        val (bundle, _) = load(generation, expected, checkLiveInputs = false)
        save(root.resolve("reconcile-$reconciliationId.intent.json"), json.encodeToString(GenerationIntent("backup-stop-only", expected, priorIntentSha256)))
        val prior = base.resolve(generation).resolve("isolate.intent.json")
        val outcome = if (Files.exists(prior, NOFOLLOW_LINKS)) isolateLocked(generation, expected, reconciliationId,
            ReleaseLocks.sha256(data(prior)), backupRuntime(bundle, access))
        else isolateLocked(generation, expected, runtimeOverride = backupRuntime(bundle, access))
        save(root.resolve("reconcile-$reconciliationId.result.json"), json.encodeToString(outcome))
        outcome
    }

    private data class CapturedPayload(val capsule: CapsuleVerification? = null, val kopia: KopiaSnapshotReceipt? = null)
    fun capture(generation: String, expected: String, captureId: String,
        custody: Path = Path.of("/mnt/media/p0-v3/generation-custody")): GenerationCaptureOutcome = locked {
        GenerationCaptureOutcome(captureId, expected, true, captureLocked(generation, expected, captureId, custody).capsule)
    }
    fun captureKopia(inventory: AcquiredInventory, generation: String, expected: String, captureId: String,
        custody: Path = Path.of("/mnt/media/p0-v3/kopia-custody"), store: GenerationSnapshotStore? = null): KopiaCaptureOutcome = locked {
        val source = load(generation, expected).first
        require(!Files.exists(base.resolve(generation).resolve("kopia-store/snapshot.pending.json"), NOFOLLOW_LINKS)) {
            "Uncertain Kopia snapshot retained; no new capture namespace or resubmission"
        }
        // Exact supported cohort before repository initialization, custody or native worker effects.
        FoundationRestore.bundle(source, inventory, if (generation == "q-000000000000") "q-111111111111" else "q-000000000000",
            "0".repeat(64), ColdRestoreCohort.WHOLE_RELEASE)
        KopiaCaptureOutcome(captureId, expected, true, captureLocked(generation, expected, captureId, custody, store ?: KopiaGenerationStore.real(inventory, source.request.store)).kopia)
    }
    private fun captureLocked(generation: String, expected: String, captureId: String, custody: Path,
        kopia: GenerationSnapshotStore? = null, backupRuntime: BackupGenerationBackend? = null,
        backupFences: Map<String, String>? = null): CapturedPayload {
        require(captureId.matches(Regex("cap-[a-f0-9]{12}"))) { "Invalid capture identity" }
        val (bundle, specs) = load(generation, expected)
        val generationRoot = base.resolve(generation)
        require(bundle.request.rssPlan == null) { "Managed RSS capture requires controller payload custody and exclusion" }
        completedCaptureSource(bundle, expected, allowRecovered = kopia != null && backupRuntime != null)
        val runtime = backupRuntime ?: backend(bundle)
        val cold = runtime as? ColdGenerationBackend ?: error("Cold capture backend unavailable")
        val observations = specs.map { runtime.audit(it, false) }
        fun matches(fences: Map<String, String>) = fences.keys == specs.map { it.name }.toSet() && observations.all {
            it.maintenanceId != null && it.maintenanceId == fences[it.name]
        }
        val fences = if (backupRuntime == null) isolationOutcomes(generationRoot, expected).firstOrNull { it.passed && matches(it.fences) }?.fences
            ?: error("Capture requires verified generation isolation")
        else requireNotNull(backupFences).also { require(matches(it)) { "Backup fences changed before capture" } }
        val measured = capacity(bundle.request.store)
        RuntimeLockBudget.requireAvailable(measured.availableRuntimeLocks, workers = if (kopia == null) 0 else 3)
        require((kopia == null || measured.availableMemoryMiB >= 1024 + bundle.request.memoryHeadroomMiB) &&
            measured.usableDiskMiB >= (if (kopia == null) 3 else 4) * RecoveryCapsule.MAX_TOTAL / 1048576 + bundle.request.diskHeadroomMiB + 16) {
            "Insufficient capture headroom; protected data must not be evicted"
        }
        fun ensure(path: Path) {
            require(path.parent.toRealPath() == path.parent &&
                (Files.getAttribute(path.parent, "unix:uid") as Number).toLong() == UnixSystem().uid &&
                Files.getPosixFilePermissions(path.parent).none { it.name in setOf("GROUP_WRITE", "OTHERS_WRITE") }) { "Unsafe capture parent" }
            if (!Files.exists(path, NOFOLLOW_LINKS)) {
                Files.createDirectory(path, PosixFilePermissions.asFileAttribute(privateDir))
                FileChannel.open(path.parent, READ).use { it.force(true) }
            }
            directory(path)
        }
        val captures = generationRoot.resolve(if (kopia == null) "captures" else "kopia-captures"); ensure(captures); ensure(custody)
        val repository = generationRoot.resolve("kopia-store")
        if (kopia != null) ensure(repository)
        val root = captures.resolve(captureId)
        Files.createDirectory(root, PosixFilePermissions.asFileAttribute(privateDir))
        FileChannel.open(captures, READ).use { it.force(true) }
        val payloads = linkedMapOf("source/bundle.json" to generationRoot.resolve("bundle.json"))
        specs.forEach { spec ->
            payloads["${spec.name}/spec.json"] = runtimeBase.resolve("${spec.name}.json")
            PrivateDeployment.inputNames(spec).forEach { input -> payloads["${spec.name}/inputs/$input"] = runtimeBase.resolve(spec.name).resolve(input) }
            if (Files.exists(runtimeBase.resolve(spec.name).resolve("runtime.jobs"), NOFOLLOW_LINKS))
                payloads["${spec.name}/jobs.json"] = runtimeBase.resolve(spec.name).resolve("runtime.jobs")
            spec.volumes.forEach { volume -> payloads["${spec.name}/volumes/${volume.id}.tar"] = root.resolve("${spec.name}-${volume.id}.tar") }
        }
        val volumeExports = payloads.values.filter { it.parent == root }.toList()
        save(root.resolve("capture.intent.json"), json.encodeToString(GenerationCaptureIntent(captureId, generation, expected, fences, payloads.keys)))
        fun failed(error: Exception): Nothing {
            val interrupted = Thread.interrupted() || error is InterruptedException
            try { save(root.resolve("capture.result.json"), if (kopia == null)
                json.encodeToString(GenerationCaptureOutcome(captureId, expected, false, failureType = error.javaClass.name))
                else json.encodeToString(KopiaCaptureOutcome(captureId, expected, false, failureType = error.javaClass.name))) }
            finally { if (interrupted) Thread.currentThread().interrupt() }
            throw error
        }
        try {
            val frozen = mutableListOf<FrozenRuntimeObservation>()
            fun collect(index: Int): CapturedPayload {
                if (index < specs.size) return cold.withFrozen(specs[index], fences.getValue(specs[index].name)) { observed ->
                    require(observed.name == specs[index].name && observed.fingerprint == bundle.members[index].runtimeFingerprint &&
                        observed.fenceId == fences[observed.name]) { "Foreign frozen observation" }
                    frozen += observed
                    collect(index + 1)
                }
                // Every member lock remains held until all export/encryption/verification work returns.
                completedCaptureSource(bundle, expected, allowRecovered = kopia != null && backupRuntime != null)
                var exported = 0L
                for (spec in specs) for (volume in spec.volumes) {
                    require(exported < RecoveryCapsule.MAX_TOTAL) { "Capture export budget exceeded" }
                    val target = payloads.getValue("${spec.name}/volumes/${volume.id}.tar")
                    cold.exportVolume(spec, volume, target); RecoveryCapsule.guard(target, RecoveryCapsule.MAX_TOTAL); exported += Files.size(target)
                    require(exported <= RecoveryCapsule.MAX_TOTAL) { "Capture aggregate budget exceeded" }
                }
                val segments = RecoverySegments.prepare(payloads)
                val manifest = CapsuleManifest(id = captureId, generation = generation, bundleSha256 = expected,
                    members = frozen.toList(), files = RecoveryCapsule.describe(payloads), volumes = segments)
                val result = if (kopia == null) CapturedPayload(capsule = RecoveryCapsule.create(root.resolve("state.cap"), custody.resolve("$captureId.key"), manifest, payloads))
                    else CapturedPayload(kopia = kopia.snapshot(repository.resolve("repository"), custody.resolve("$generation.env"), root, manifest, payloads))
                load(generation, expected)
                return result
            }
            val verification = collect(0)
            val result = if (kopia == null) json.encodeToString(GenerationCaptureOutcome(captureId, expected, true, verification.capsule))
                else json.encodeToString(KopiaCaptureOutcome(captureId, expected, true, verification.kopia))
            // Remove only this attempt's scratch exports AFTER authenticated verification. Never source data or intents.
            (payloads.values.filter { it.parent == root } + volumeExports).distinct().forEach(Files::delete)
            save(root.resolve("capture.result.json"), result)
            verification.kopia?.let {
                RecoveryReferenceOperations.captured(base, it)
                if (backupRuntime == null) RecoveryReferenceOperations.protect(base, it, "unknown", "manual-$captureId")
            }
            return verification
        } catch (error: InterruptedException) { failed(error) }
        catch (error: Exception) { failed(error) }
    }
    fun verifyCapture(generation: String, expected: String, captureId: String,
        custody: Path = Path.of("/mnt/media/p0-v3/generation-custody")): CapsuleVerification = locked {
        require(id.matches(generation) && hash.matches(expected) && captureId.matches(Regex("cap-[a-f0-9]{12}"))) { "Invalid capture binding" }
        val root = base.resolve(generation).resolve("captures").resolve(captureId); directory(root)
        val result = json.decodeFromString<GenerationCaptureOutcome>(data(root.resolve("capture.result.json")).decodeToString())
        require(result.passed && result.id == captureId && result.bundleSha256 == expected) { "No completed capture" }
        val verified = RecoveryCapsule.verify(root.resolve("state.cap"), custody.resolve("$captureId.key"), captureId, generation, expected)
        require(verified == result.verification) { "Capture evidence changed" }
        verified
    }
    fun isolate(generation: String, expected: String): GenerationOutcome = locked { isolateLocked(generation, expected) }
    /** Stops/fences only: no accepted application write or initializer can be retried here. */
    fun reconcileIsolation(generation: String, expected: String, reconciliationId: String, priorIntent: String): GenerationOutcome = locked {
        isolateLocked(generation, expected, reconciliationId, priorIntent)
    }
}
