package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

class GenerationRecoveryTest {
    private val json = Json { encodeDefaults = true }
    private val source = "q-123456789abc"
    private val target = "q-abcdef123456"
    private val cap = "cap-123456789abc"
    private val inventory = AcquiredInventory(1, "unit-only", listOf("postgres", "valkey", "ntfy", "mariadb", "memcached", "forgejo", "planka").map {
        AcquiredImage(it, "unit", "example.test/$it:1", "example.test/$it@sha256:" + "a".repeat(64), "b".repeat(64), emptyList(), "sha256:" + "a".repeat(64), "amd64", "linux")
    })
    @Test fun `whole compiled cohort preserves state credentials networks and refuses unknown restore projections`() {
        val artifacts = Json.decodeFromString<AcquiredInventory>(Files.readString(Path.of("release/downloaded-candidate-inventory.json")))
        fun sourceBundle(recipes: List<String>): GenerationBundle {
            val pins = recipes.sorted().map { recipe ->
                val name = "$source-$recipe"
                val spec = GenerationAssembly.catalog.single { it.id == recipe }.spec(artifacts, name)
                val inputs = PrivateDeployment.inputNames(spec).associateWith { "a".repeat(64) }
                GenerationPin(GenerationMember(name), ReleaseLocks.sha256(Json.encodeToString(spec).toByteArray()), inputs,
                    PrivateDeployment.expectedFingerprint(spec, inputs), spec)
            }
            return GenerationBundle(GenerationRequest(id = source, candidateSha256 = "b".repeat(64),
                members = pins.map { it.member }, diskReservationMiB = 131072), pins,
                pins.sumOf { it.spec.processes.sumOf { p -> p.memoryMiB.toLong() } })
        }
        val original = sourceBundle(listOf("canonical-providers", "openbao", "notebook", "jupyterhub"))
        val restored = FoundationRestore.bundle(original, artifacts, target, "c".repeat(64), ColdRestoreCohort.WHOLE_RELEASE)
        assertTrue(restored.members.all { pin -> pin.spec.processes.none { it.oneShot } })
        assertEquals(original.request.candidateSha256, restored.request.releaseCandidateSha256)
        for ((before, after) in original.members.zip(restored.members)) {
            assertEquals(before.spec.volumes, after.spec.volumes)
            assertEquals(before.spec.networks, after.spec.networks)
            assertTrue(after.inputHashes.all { (name, digest) -> before.inputHashes[name] == digest })
            assertEquals(PrivateDeployment.inputNames(after.spec).toSet(), after.inputHashes.keys)
        }
        assertNull(restored.ownership)
        assertNull(restored.assemblySha256)
        for (unsupported in listOf("identity", "keykeeper", "huly"))
            assertFails { FoundationRestore.bundle(sourceBundle(listOf(unsupported)), artifacts, target, "c".repeat(64), ColdRestoreCohort.WHOLE_RELEASE) }
        val altered = original.members.first().let { it.copy(spec = it.spec.copy(networks = it.spec.networks + "unapproved")) }
        assertFails { FoundationRestore.bundle(original.copy(members = listOf(altered) + original.members.drop(1)), artifacts,
            target, "c".repeat(64), ColdRestoreCohort.WHOLE_RELEASE) }
    }

    private class Fake(val runtime: Path) : GenerationBackend, GenerationImportBackend, ColdGenerationBackend {
        var failExport = false
        var freeLocks = Long.MAX_VALUE
        var availableMemory = 1000000L
        override fun <T> withFrozen(spec: PrivateDeploymentSpec, fence: String, action: (FrozenRuntimeObservation) -> T): T {
            val jobs = RuntimeJobs(bindings.getValue(spec.name), spec.processes.filter { it.oneShot }.map { it.id }.toSet(), spec.processes.filter { it.oneShot }.map { it.id }.toSet())
            val bytes = Json.encodeToString(jobs.copy(checksum = ReleaseLocks.sha256(Json.encodeToString(jobs).toByteArray()))).toByteArray()
            val digest = if (Files.exists(runtime.resolve("${spec.name}/runtime.jobs"))) ReleaseLocks.sha256(bytes)
                else ReleaseLocks.sha256("no-initializers\n${bindings.getValue(spec.name)}\n".toByteArray())
            return action(FrozenRuntimeObservation(spec.name, bindings.getValue(spec.name), fence, digest, jobs.completed,
                spec.processes.map { RuntimeStatus(it.id, "exited", 0) }))
        }
        override fun exportVolume(spec: PrivateDeploymentSpec, volume: RuntimeVolume, output: Path) {
            check(!failExport)
            Files.createFile(output, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
            Files.write(output, VolumeTarTest.tar(VolumeTarTest.member("./", '5', ByteArray(0), uid = volume.userId, mode = 448), VolumeTarTest.member("state", uid = volume.userId)))
        }
        var bindings = emptyMap<String, String>()
        val running = mutableSetOf<String>()
        val imports = mutableListOf<String>()
        val fences = mutableMapOf<String, MaintenanceFence>()
        var fail = false
        var interrupt = false
        var isolationFailure: String? = null
        var isolationInterrupt: String? = null
        val isolated = mutableListOf<String>()
        var onImport: () -> Unit = {}
        var onStart: (PrivateDeploymentSpec) -> Unit = {}
        val started = mutableListOf<String>()
        var onBind: () -> Unit = {}
        override fun audit(spec: PrivateDeploymentSpec, pristine: Boolean) = RuntimeAudit(spec.name, bindings.getValue(spec.name),
            if (spec.name in fences || spec.name in running) 1 else 0, fences[spec.name]?.id,
            spec.processes.map { RuntimeStatus(it.id, if (spec.name in running) "running" else "absent", null) })
        override fun apply(spec: PrivateDeploymentSpec): List<RuntimeStatus> = error("Restore must never invoke clean initialization")
        override fun isolate(spec: PrivateDeploymentSpec): String {
            isolated += spec.name
            running -= spec.name
            require(Files.isDirectory(runtime.resolve(spec.name))) { "Missing prepared namespace" }
            if (spec.name == isolationInterrupt) { Thread.currentThread().interrupt(); throw InterruptedException("unit isolation interruption") }
            check(spec.name != isolationFailure) { "unit isolation failure" }
            return fences.getOrPut(spec.name) { MaintenanceFence(bindings.getValue(spec.name), java.util.UUID.randomUUID().toString(), "update") }.id
        }
        override fun importCold(spec: PrivateDeploymentSpec, archives: Map<String, Path>, sourceArchiveSha256: String, verificationRoot: Path, expectedHashes: Map<String, String>): MaintenanceFence {
            assertTrue(spec.processes.none { it.oneShot })
            assertEquals(spec.volumes.map { it.id }.toSet(), archives.keys)
            assertEquals(expectedHashes, archives.mapValues { RecoveryCapsule.fileHash(it.value) })
            imports += spec.name
            val fence = MaintenanceFence(bindings.getValue(spec.name), java.util.UUID.randomUUID().toString(), "restore")
            fences[spec.name] = fence
            onImport()
            if (interrupt) { Thread.currentThread().interrupt(); throw InterruptedException("unit interruption") }
            check(!fail) { "unit import failure" }
            for (file in listOf("runtime.import.intent", "runtime.import.complete")) {
                val path = runtime.resolve("${spec.name}/$file")
                Files.writeString(path, "p0v3-native-volume-import-v1\n${bindings.getValue(spec.name)}\n$sourceArchiveSha256\n")
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
            }
            return fence
        }
    }
    private data class Fixture(val root: Path, val engine: GenerationRuntime, val fake: Fake, val control: Path, val runtime: Path,
        val custody: Path, val bundle: GenerationBundle, val bundleSha: String, val verified: CapsuleVerification, val extracted: Path)
    private fun fixture(owned: Boolean = false, applications: Boolean = false, canonical: Boolean = false, block: (Fixture) -> Unit) {
        val root = Files.createTempDirectory("generation-recovery-unit-")
        fun dir(path: Path) = Files.createDirectory(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        fun file(path: Path, data: ByteArray): Path {
            Files.createFile(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
            Files.write(path, data); return path
        }
        val runtime = dir(root.resolve("runtime")); val control = root.resolve("control"); val custody = dir(root.resolve("custody"))
        val fake = Fake(runtime)
        val engine = GenerationRuntime(control, runtime, { bindings ->
            fake.onBind()
            // Match the real factory's per-instance immutable binding; admission also opens older retired scopes.
            object : BackupGenerationBackend, GenerationImportBackend, GenerationRestoreStartupBackend, BackupGenerationFactory {
                override fun forBackup(access: RuntimeBackupAccess): BackupGenerationBackend = this
                override fun claim(spec: PrivateDeploymentSpec) { require(spec.name in fake.running && spec.name !in fake.fences) }
                override fun quiesce(spec: PrivateDeploymentSpec): String = isolate(spec)
                override fun resume(spec: PrivateDeploymentSpec, fence: String): List<RuntimeStatus> {
                    require(fake.fences.getValue(spec.name).id == fence)
                    fake.fences.remove(spec.name); fake.running += spec.name
                    return audit(spec, false).statuses
                }
                override fun finish(spec: PrivateDeploymentSpec) { require(spec.name in fake.running && spec.name !in fake.fences) }
                override fun startImported(spec: PrivateDeploymentSpec, fence: String): List<RuntimeStatus> {
                    fake.bindings = bindings
                    require(fake.fences.getValue(spec.name).id == fence)
                    fake.started += spec.name; fake.fences.remove(spec.name); fake.running += spec.name
                    fake.onStart(spec)
                    return audit(spec, false).statuses
                }
                override fun <T> withFrozen(spec: PrivateDeploymentSpec, fence: String, action: (FrozenRuntimeObservation) -> T): T {
                    fake.bindings = bindings; return fake.withFrozen(spec, fence, action)
                }
                override fun exportVolume(spec: PrivateDeploymentSpec, volume: RuntimeVolume, output: Path) = fake.exportVolume(spec, volume, output)
                override fun audit(spec: PrivateDeploymentSpec, pristine: Boolean): RuntimeAudit {
                    fake.bindings = bindings; return fake.audit(spec, pristine)
                }
                override fun apply(spec: PrivateDeploymentSpec): List<RuntimeStatus> {
                    fake.bindings = bindings; return fake.apply(spec)
                }
                override fun isolate(spec: PrivateDeploymentSpec): String {
                    fake.bindings = bindings; return fake.isolate(spec)
                }
                override fun importCold(spec: PrivateDeploymentSpec, archives: Map<String, Path>, sourceArchiveSha256: String,
                    verificationRoot: Path, expectedHashes: Map<String, String>): MaintenanceFence {
                    fake.bindings = bindings; return fake.importCold(spec, archives, sourceArchiveSha256, verificationRoot, expectedHashes)
                }
            }
        }, { GenerationCapacity(fake.availableMemory, 1000000, fake.freeLocks) })
        try {
            val bytes = json.encodeToString(inventory).toByteArray()
            val request = AssemblyRequest(id = source, candidateSha256 = "a".repeat(64), inventorySha256 = ReleaseLocks.sha256(bytes),
                selections = listOf(AssemblySelection("foundation"), AssemblySelection("sql-cache", listOf("foundation"))) +
                    if (applications) listOf(AssemblySelection("forgejo", listOf("foundation")), AssemblySelection("planka", listOf("foundation"))) else emptyList(),
                diskReservationMiB = 8192)
            val selected = if (canonical) request.copy(selections = listOf(AssemblySelection("canonical-core"),
                AssemblySelection("sql-cache", listOf("canonical-core")), AssemblySelection("forgejo", listOf("canonical-core")))) else request
            val registry = GenerationAssembly.catalog.map { recipe -> if (recipe.id != "canonical-core") recipe else recipe.copy(prepare = { inv, base, name, store ->
                RuntimePreparation.prepare(CanonicalCoreRuntime.spec(inv, name).copy(store = store), base) { CanonicalCoreRuntime.inputs({
                    mapOf("ca.pem" to "unit-ca", "web.pem" to "unit-cert", "web-key.pem" to "unit-key")
                }) }
            }) }
            val plan = GenerationAssembly(registry).plan(selected, bytes)
            val hash = if (!owned) engine.prepareAssembly(plan) else {
                val graph = SiteOwnerships.inspect(plan)
                val owners = graph.processes.associate { it.process to requireNotNull(it.compiledProduct) }
                val contract = SiteOwnership(site = "owned-recovery-unit", assemblySha256 = graph.assemblySha256,
                    processes = owners.map { SiteProcessOwner(it.key, it.value) },
                    state = graph.state.map { SiteStateOwner(it.volume, owners.getValue(it.writers.first()), "cohort") },
                    inputs = graph.inputs.map { SiteInputOwner(it.input, requireNotNull(it.compiledProduct), true, it.consumers) },
                    routes = listOf(SiteRouteOwner("ntfy.example.org", "ntfy", "$source-${if (canonical) "canonical-core" else "foundation"}/ntfy", 8080)))
                engine.prepareOwnedAssembly(plan, contract, setOf("ntfy.example.org"))
            }
            val bundlePath = control.resolve("$source/bundle.json")
            val bundle = json.decodeFromString<GenerationBundle>(Files.readString(bundlePath))
            val payloads = linkedMapOf("source/bundle.json" to bundlePath)
            val observations = bundle.members.map { pin ->
                val name = pin.spec.name
                payloads["$name/spec.json"] = runtime.resolve("$name.json")
                pin.inputHashes.keys.forEach { payloads["$name/inputs/$it"] = runtime.resolve("$name/$it") }
                val initialized = pin.spec.processes.filter { it.oneShot }.map { it.id }.toSet()
                val job = RuntimeJobs(pin.runtimeFingerprint, initialized, initialized)
                val checksum = ReleaseLocks.sha256(Json.encodeToString(job).toByteArray())
                val jobBytes = Json.encodeToString(job.copy(checksum = checksum)).toByteArray()
                payloads["$name/jobs.json"] = file(root.resolve("$name-jobs"), jobBytes)
                pin.spec.volumes.forEach { volume ->
                    payloads["$name/volumes/${volume.id}.tar"] = file(root.resolve("$name-${volume.id}.tar"),
                        VolumeTarTest.tar(VolumeTarTest.member("./", '5', ByteArray(0), uid = volume.userId, mode = 448), VolumeTarTest.member("state", uid = volume.userId)))
                }
                FrozenRuntimeObservation(name, pin.runtimeFingerprint, "unit-fence", ReleaseLocks.sha256(jobBytes), initialized,
                    pin.spec.processes.map { RuntimeStatus(it.id, if (it.oneShot) "completed" else "exited", 0) })
            }
            val captures = dir(control.resolve("$source/captures")); val capture = dir(captures.resolve(cap))
            val manifest = CapsuleManifest(id = cap, generation = source, bundleSha256 = hash, members = observations, files = RecoveryCapsule.describe(payloads))
            val verified = RecoveryCapsule.create(capture.resolve("state.cap"), custody.resolve("$cap.key"), manifest, payloads)
            file(capture.resolve("capture.result.json"), json.encodeToString(GenerationCaptureOutcome(cap, hash, true, verified)).toByteArray())
            val extracted = root.resolve("extracted")
            RecoveryCapsule.extract(capture.resolve("state.cap"), custody.resolve("$cap.key"), cap, source, hash, extracted) { Long.MAX_VALUE }
            block(Fixture(root, engine, fake, control, runtime, custody, bundle, hash, verified, extracted))
        } finally { Thread.interrupted(); Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `Kopia capture and restore bind native snapshot identity without fabricating capsule authentication`() = fixture(owned = true, canonical = true) { f ->
        fun privateWrite(path: Path, bytes: ByteArray) {
            Files.createFile(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))); Files.write(path, bytes)
        }
        fun privateDirectory(path: Path) { Files.createDirectory(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))) }
        fun copyTree(from: Path, to: Path) {
            privateDirectory(to)
            Files.walk(from).use { paths -> paths.filter { it != from }.forEach { path ->
                val dest = to.resolve(from.relativize(path))
                if (Files.isDirectory(path)) privateDirectory(dest) else privateWrite(dest, Files.readAllBytes(path))
            } }
        }
        f.bundle.members.forEach { pin ->
            Files.copy(f.extracted.resolve("${pin.spec.name}/jobs.json"), f.runtime.resolve("${pin.spec.name}/runtime.jobs"))
        }
        val generationRoot = f.control.resolve(source)
        privateWrite(generationRoot.resolve("stage.intent.json"), json.encodeToString(GenerationIntent("stage", f.bundleSha)).toByteArray())
        privateWrite(generationRoot.resolve("stage.result.json"), json.encodeToString(GenerationOutcome("stage", f.bundleSha, true)).toByteArray())
        val store = object : GenerationSnapshotStore {
            override fun snapshot(repository: Path, custody: Path, operation: Path, manifest: CapsuleManifest, payloads: Map<String, Path>): KopiaSnapshotReceipt {
                val plain = f.root.resolve("unit-snapshot-${manifest.id}")
                privateDirectory(plain)
                for ((name, path) in payloads) {
                    var parent = plain
                    for (part in name.split('/').dropLast(1)) {
                        parent = parent.resolve(part); if (!Files.exists(parent)) privateDirectory(parent)
                    }
                    privateWrite(plain.resolve(name), Files.readAllBytes(path))
                }
                privateWrite(plain.resolve("manifest.json"), json.encodeToString(manifest).toByteArray())
                return KopiaSnapshotReceipt(id = manifest.id, generation = manifest.generation, bundleSha256 = manifest.bundleSha256, snapshotId = "a".repeat(32),
                    rootObjectId = "k" + "b".repeat(40), manifestSha256 = RecoveryCapsule.fileHash(plain.resolve("manifest.json")),
                    files = manifest.files.size, plaintextBytes = manifest.files.sumOf { it.bytes }, image = "example.test/kopia@sha256:" + "a".repeat(64), imageId = "c".repeat(64))
            }
            override fun restore(repository: Path, custody: Path, operation: Path, receipt: KopiaSnapshotReceipt, destination: Path) = copyTree(f.root.resolve("unit-snapshot-${receipt.id}"), destination)
        }
        assertFails { f.engine.captureKopia(inventory, source, f.bundleSha, cap, f.custody, store) }
        f.engine.isolate(source, f.bundleSha)
        val captured = f.engine.captureKopia(inventory, source, f.bundleSha, cap, f.custody, store)
        val snapshot = assertNotNull(captured.snapshot)
        assertTrue(captured.passed)
        assertFalse(Files.exists(generationRoot.resolve("kopia-captures/$cap/state.cap")))
        assertFails { f.engine.captureKopia(inventory, source, f.bundleSha, cap, f.custody, store) }
        assertTrue(f.engine.restoreKopiaCanonicalCore(inventory, source, f.bundleSha, cap, target, f.custody, store, RuntimeStore.CANONICAL_V2).passed)
        val result = json.decodeFromString<GenerationBundle>(Files.readString(f.control.resolve("$target/bundle.json")))
        assertEquals(RuntimeStore.CANONICAL_V2, result.request.store)
        assertEquals(f.bundle.request.candidateSha256, result.request.releaseCandidateSha256)
        assertTrue(result.members.all { it.spec.store == result.request.store })
        assertEquals(snapshot, result.recoverySourceKopia)
        assertNull(result.recoverySourceArchiveSha256)
        assertNull(result.ownership)
        val checked = GenerationRecovery.validateKopia(f.control.resolve("$target/recovered"), snapshot)
        assertEquals(snapshot.snapshotId, checked.check.kopiaSnapshotId)
        assertEquals("", checked.check.archiveSha256)
        assertFalse(checked.check.functionalRestoreVerified)
        assertEquals(3, f.fake.imports.size)
        assertFails { f.engine.stage(target, ReleaseLocks.sha256(Files.readAllBytes(f.control.resolve("$target/bundle.json")))) }
        assertFails { f.engine.restoreKopiaCanonicalCore(inventory, source, f.bundleSha, cap, target, f.custody, store) }
        val recoveredHash = RecoveryCapsule.fileHash(f.control.resolve("$target/bundle.json"))
        assertFails { f.engine.checkBackupSource(inventory, target, recoveredHash) } // Import fences are not backup/resume authority.
        val first = result.members.first().member.name
        f.fake.running += first
        assertFails { f.engine.startRestored(inventory, target, recoveredHash) }
        f.fake.running -= first
        assertFalse(Files.exists(f.control.resolve("$target/restore-start.intent.json")))
        f.fake.freeLocks = 0
        assertFails { f.engine.startRestored(inventory, target, recoveredHash) }
        f.fake.freeLocks = Long.MAX_VALUE
        assertFalse(Files.exists(f.control.resolve("$target/restore-start.intent.json")))
        f.fake.availableMemory = result.memoryReservationMiB + result.request.memoryHeadroomMiB
        assertTrue(f.engine.startRestored(inventory, target, recoveredHash).passed)
        f.fake.availableMemory = 1000000L
        assertEquals(result.members.map { it.member.name }, f.fake.started)
        assertFails { f.engine.startRestored(inventory, target, recoveredHash) }
        f.engine.checkBackupSource(inventory, target, recoveredHash)
        // Missing or foreign import lineage is refused before any new backup/capture namespace.
        for (path in listOf(f.control.resolve("$target/recovery.source.json"), f.control.resolve("$target/recovery.check.json"),
            f.control.resolve("$target/${result.members.first().member.name}.import.result.json"),
            f.runtime.resolve("${result.members.first().member.name}/runtime.import.complete"))) {
            val original = Files.readAllBytes(path)
            Files.writeString(path, "{}")
            assertFails { f.engine.backupKopia(inventory, target, recoveredHash, "cap-222222222222", f.custody, store) }
            assertFalse(Files.exists(f.control.resolve("$target/backups")))
            Files.write(path, original)
        }
        val cap2 = "cap-222222222222"
        val renewed = f.engine.backupKopia(inventory, target, recoveredHash, cap2, f.custody, store)
        assertTrue(renewed.passed && renewed.sourceResumed)
        assertEquals(target, renewed.snapshot!!.generation)
        assertEquals(recoveredHash, renewed.snapshot.bundleSha256)
        assertNull(result.ownership)
        assertFails { f.engine.stage(target, recoveredHash) }
        val newer = "q-222222222222"
        f.engine.isolate(target, recoveredHash)
        assertFails { f.engine.checkBackupSource(inventory, target, recoveredHash) }
        f.fake.freeLocks = 0
        assertFails { f.engine.restoreKopiaCanonicalCore(inventory, target, recoveredHash, cap2, newer, f.custody, store) }
        assertFalse(Files.exists(f.control.resolve(newer)))
        assertFalse(Files.exists(f.runtime.resolve("$newer-canonical-core")))
        f.fake.freeLocks = Long.MAX_VALUE
        assertTrue(f.engine.restoreKopiaCanonicalCore(inventory, target, recoveredHash, cap2, newer, f.custody, store, RuntimeStore.CANONICAL_V2).passed)
        val chained = json.decodeFromString<GenerationBundle>(Files.readString(f.control.resolve("$newer/bundle.json")))
        assertEquals(RuntimeStore.CANONICAL_V2, chained.request.store)
        assertEquals(result.request.releaseCandidateSha256, chained.request.releaseCandidateSha256)
        assertTrue(chained.members.all { it.spec.store == RuntimeStore.CANONICAL_V2 })
        assertFails { FoundationRestore.bundle(result.copy(request = result.request.copy(store = RuntimeStore.LEGACY)),
            inventory, newer, "b".repeat(64), ColdRestoreCohort.CANONICAL_CORE) }
        assertNull(chained.ownership); assertNull(chained.assemblySha256); assertEquals(renewed.snapshot, chained.recoverySourceKopia)
        assertTrue(chained.members.all { it.spec.processes.none { process -> process.oneShot } })
        assertTrue(chained.members.all { it.inputHashes.keys.none { name -> name.endsWith("bootstrap.env") || name == "postgres-admin.env" } })
        val tampered = result.copy(members = result.members.map { pin ->
            pin.copy(spec = pin.spec.copy(processes = pin.spec.processes.map { it.copy(memoryMiB = it.memoryMiB + 1) }))
        })
        assertFails { FoundationRestore.bundle(tampered, inventory, newer, "b".repeat(64), ColdRestoreCohort.CANONICAL_CORE) }
        // Each failure uses a distinct fresh import, never a new action ID on an uncertain target.
        for ((index, mode) in listOf("failure", "interrupt", "result-collision").withIndex()) {
            val failedTarget = "q-99999999999$index"
            val imported = f.engine.restoreKopiaCanonicalCore(inventory, source, f.bundleSha, cap, failedTarget,
                f.custody, store, RuntimeStore.CANONICAL_V2)
            assertTrue(imported.passed)
            f.fake.onStart = {
                if (mode == "result-collision") ReleasePrivateFiles.save(
                    f.control.resolve("$failedTarget/restore-start.result.json"), "retained-collision".toByteArray())
                if (mode == "interrupt") throw InterruptedException("synthetic startup interruption")
                error("synthetic partial startup")
            }
            try {
                if (mode == "failure") assertFalse(f.engine.startRestored(inventory, failedTarget, imported.bundleSha256).passed)
                else assertFails { f.engine.startRestored(inventory, failedTarget, imported.bundleSha256) }
                assertEquals(mode == "interrupt", Thread.currentThread().isInterrupted)
            } finally { Thread.interrupted() }
            assertTrue(Files.exists(f.control.resolve("$failedTarget/isolate.result.json")))
            assertTrue(f.fake.running.none { it.startsWith(failedTarget) })
            assertFails { f.engine.startRestored(inventory, failedTarget, imported.bundleSha256) }
            if (mode == "result-collision") assertEquals("retained-collision",
                Files.readString(f.control.resolve("$failedTarget/restore-start.result.json")))
        }
        f.fake.onStart = {}
        f.fake.failExport = true
        assertFails { f.engine.captureKopia(inventory, source, f.bundleSha, "cap-111111111111", f.custody, store) }
        val failed = json.decodeFromString<KopiaCaptureOutcome>(Files.readString(generationRoot.resolve("kopia-captures/cap-111111111111/capture.result.json")))
        assertFalse(failed.passed)
        assertNull(failed.snapshot)
    }
    @Test fun `application cohort imports exact daemons without bootstrap files or inherited site authority`() = fixture(owned = true, applications = true) { f ->
        assertFails { f.engine.restoreFoundation(inventory, source, f.bundleSha, cap, target, f.custody) }
        assertFalse(Files.exists(f.control.resolve(target)))
        val forgejo = f.bundle.members.single { it.spec.name.endsWith("-forgejo") }
        val changed = forgejo.copy(spec = forgejo.spec.copy(processes = forgejo.spec.processes.map {
            if (it.id == "forgejo") it.copy(command = listOf("migrate")) else it
        }))
        assertFails { FoundationRestore.bundle(f.bundle.copy(ownership = null, members = f.bundle.members.map {
            if (it == forgejo) changed else it
        }), inventory, target, f.verified.archiveSha256, ColdRestoreCohort.APPLICATIONS) }
        val extraInput = forgejo.copy(inputHashes = forgejo.inputHashes + ("extra.env" to "a".repeat(64)))
        assertFails { FoundationRestore.bundle(f.bundle.copy(ownership = null, members = f.bundle.members.map {
            if (it == forgejo) extraInput else it
        }), inventory, target, f.verified.archiveSha256, ColdRestoreCohort.APPLICATIONS) }
        assertTrue(f.engine.restoreApplications(inventory, source, f.bundleSha, cap, target, f.custody).passed)
        val restored = json.decodeFromString<GenerationBundle>(Files.readString(f.control.resolve("$target/bundle.json")))
        assertEquals(4, f.fake.imports.size)
        assertEquals(8, restored.members.sumOf { it.spec.processes.size })
        assertTrue(restored.members.all { p -> p.spec.processes.none { it.oneShot } })
        assertNull(restored.ownership)
        val planka = restored.members.single { it.spec.name.endsWith("-planka") }
        assertEquals(listOf("postgres"), planka.spec.processes.single { it.id == "planka" }.dependencies)
        assertEquals("postgres.env", planka.spec.processes.single { it.id == "postgres" }.environmentFile)
        assertFalse("database-init.env" in planka.inputHashes)
        assertTrue(Files.exists(f.control.resolve("$target/recovered/$source-planka/inputs/database-init.env")))
        restored.members.forEach { pin ->
            val old = f.bundle.members.single { it.spec.name.removePrefix(source) == pin.spec.name.removePrefix(target) }
            pin.inputHashes.forEach { (file, hash) -> assertEquals(old.inputHashes.getValue(file), hash) }
        }
        assertFails { f.engine.restoreApplications(inventory, source, f.bundleSha, cap, target, f.custody) }
    }
    @Test fun `application import failure isolates the entire attempted and unattempted cohort`() = fixture(applications = true) { f ->
        f.fake.fail = true
        assertFalse(f.engine.restoreApplications(inventory, source, f.bundleSha, cap, target, f.custody).passed)
        assertEquals(4, f.fake.isolated.size)
        assertEquals(1, f.fake.imports.size)
    }
    @Test fun `wrong application cohort is rejected before target preparation`() = fixture { f ->
        assertFails { f.engine.restoreApplications(inventory, source, f.bundleSha, cap, target, f.custody) }
        assertFalse(Files.exists(f.control.resolve(target)))
        assertTrue(f.fake.imports.isEmpty())
    }
    @Test fun `authenticated owned source retains provenance without granting restored target its route authority`() = fixture(owned = true) { f ->
        val sourceBinding = requireNotNull(f.bundle.ownership)
        val recovered = GenerationRecovery.validate(f.extracted, f.verified)
        assertEquals(sourceBinding, recovered.bundle.ownership)
        val result = f.engine.restoreFoundation(inventory, source, f.bundleSha, cap, target, f.custody)
        assertTrue(result.passed)
        val imported = json.decodeFromString<GenerationBundle>(Files.readString(f.control.resolve("$target/bundle.json")))
        assertNull(imported.ownership)
        assertEquals(f.verified.archiveSha256, imported.recoverySourceArchiveSha256)
        assertEquals(sourceBinding, json.decodeFromString<GenerationBundle>(Files.readString(f.control.resolve("$target/recovered/source/bundle.json"))).ownership)
        assertEquals(2, f.fake.imports.size)
    }
    @Test fun `valid capsule authentication cannot authorize inconsistent source ownership`() = fixture(owned = true) { f ->
        val binding = requireNotNull(f.bundle.ownership)
        val bad = f.bundle.copy(ownership = binding.copy(approvedHosts = emptySet()))
        val bytes = json.encodeToString(bad).toByteArray()
        val file = Files.createFile(f.root.resolve("invalid-owned-bundle"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        Files.write(file, bytes)
        val original = json.decodeFromString<CapsuleManifest>(Files.readString(f.extracted.resolve("manifest.json")))
        val payloads = original.files.associate { it.name to if (it.name == "source/bundle.json") file else f.extracted.resolve(it.name) }
        val capId = "cap-abcdefabcdef"
        val manifest = original.copy(id = capId, bundleSha256 = ReleaseLocks.sha256(bytes), files = RecoveryCapsule.describe(payloads))
        val capsuleRoot = Files.createDirectory(f.root.resolve("invalid-owned-capsule"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val archive = capsuleRoot.resolve("state.cap"); val key = f.custody.resolve("invalid-owned.key")
        val verified = RecoveryCapsule.create(archive, key, manifest, payloads)
        val extracted = f.root.resolve("invalid-owned-extracted")
        RecoveryCapsule.extract(archive, key, capId, source, manifest.bundleSha256, extracted) { Long.MAX_VALUE }
        assertTrue(verified.authenticated)
        assertFailsWith<IllegalArgumentException> { GenerationRecovery.validate(extracted, verified) }
        assertTrue(f.fake.imports.isEmpty())
    }
    @Test fun `recovered source binds exact bundle configurations ledgers and all volume roots`() = fixture { f ->
        val recovered = GenerationRecovery.validate(f.extracted, f.verified)
        assertEquals(f.bundle, recovered.bundle)
        assertEquals(2, recovered.check.members.size)
        assertEquals(4, recovered.check.members.sumOf { it.volumeEntries.size })
        assertFalse(recovered.check.runtimeImported)
        assertFalse(recovered.check.functionalRestoreVerified)
        val targetBundle = FoundationRestore.bundle(f.bundle, inventory, target, f.verified.archiveSha256)
        assertTrue(targetBundle.members.all { it.spec.processes.none { p -> p.oneShot } })
        assertEquals(5, targetBundle.members.sumOf { it.spec.processes.size })
        assertEquals("postgres.env", targetBundle.members.first().spec.processes.first { it.id == "postgres" }.environmentFile)
        assertFails { FoundationRestore.bundle(f.bundle, inventory, source, f.verified.archiveSha256) }
        val changed = f.bundle.members.first().let { it.copy(spec = it.spec.copy(processes = it.spec.processes.map { p -> p.copy(memoryMiB = 64) })) }
        assertFails { FoundationRestore.bundle(f.bundle.copy(members = listOf(changed) + f.bundle.members.drop(1)), inventory, target, f.verified.archiveSha256) }
        assertFails { FoundationRestore.bundle(f.bundle.copy(members = f.bundle.members.take(1)), inventory, target, f.verified.archiveSha256) }
    }
    @Test fun `changed plaintext extras symlinks and foreign observations fail before any import`() = fixture { f ->
        assertFails { GenerationRecovery.validate(f.extracted, f.verified.copy(manifestSha256 = "0".repeat(64))) }
        val path = f.extracted.resolve("${source}-foundation/inputs/postgres.env")
        val before = Files.readAllBytes(path)
        Files.writeString(path, "CHANGED=1\n")
        assertFails { GenerationRecovery.validate(f.extracted, f.verified) }
        Files.write(path, before)
        val extra = f.extracted.resolve("extra")
        Files.createSymbolicLink(extra, path)
        assertFails { GenerationRecovery.validate(f.extracted, f.verified) }
        Files.delete(extra)
        Files.createFile(extra, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))); Files.writeString(extra, "unexpected")
        assertFails { GenerationRecovery.validate(f.extracted, f.verified) }
        assertTrue(f.fake.imports.isEmpty())
    }
    @Test fun `restore imports all members once with copied credentials and leaves fresh scopes fenced`() = fixture { f ->
        val result = f.engine.restoreFoundation(inventory, source, f.bundleSha, cap, target, f.custody)
        assertTrue(result.passed)
        assertEquals("restore-import", result.action)
        assertEquals(2, result.fences.size)
        assertEquals(listOf("$target-foundation", "$target-sql-cache"), f.fake.imports)
        assertFails { f.engine.restoreFoundation(inventory, source, f.bundleSha, cap, target, f.custody) }
        assertFails { f.engine.stage(target, result.bundleSha256) }
        assertContentEquals(Files.readAllBytes(f.runtime.resolve("$source-foundation/postgres.env")), Files.readAllBytes(f.runtime.resolve("$target-foundation/postgres.env")))
        assertFalse(Files.exists(f.runtime.resolve("$target-foundation/runtime.jobs")))
        assertTrue(f.engine.isolate(target, result.bundleSha256).passed)
    }
    @Test fun `failed or interrupted import retains reservation and cannot replay`() = fixture { f ->
        f.fake.fail = true
        val result = f.engine.restoreFoundation(inventory, source, f.bundleSha, cap, target, f.custody)
        assertFalse(result.passed)
        assertTrue(Files.exists(f.control.resolve("$target/stage.intent.json")))
        assertFails { f.engine.restoreFoundation(inventory, source, f.bundleSha, cap, target, f.custody) }
        assertEquals(1, f.fake.imports.size)
        assertEquals(listOf("$target-sql-cache", "$target-foundation"), f.fake.isolated)
        val isolated = json.decodeFromString<GenerationOutcome>(Files.readString(f.control.resolve("$target/isolate.result.json")))
        assertTrue(isolated.passed)
        assertEquals(2, isolated.fences.size)
        f.fake.fail = false; f.fake.interrupt = true
        assertFailsWith<InterruptedException> { f.engine.restoreFoundation(inventory, source, f.bundleSha, cap, "q-aaaaaaaaaaaa", f.custody) }
        assertTrue(Thread.interrupted())
        assertTrue(Files.exists(f.control.resolve("q-aaaaaaaaaaaa/stage.result.json")))
        assertTrue(json.decodeFromString<GenerationOutcome>(Files.readString(f.control.resolve("q-aaaaaaaaaaaa/isolate.result.json"))).passed)
    }
    @Test fun `failure outcome collision cannot skip controller-owned isolation`() = fixture { f ->
        f.fake.fail = true
        f.fake.onImport = { Files.createDirectory(f.control.resolve("$target/stage.result.json")) }
        assertFails { f.engine.restoreFoundation(inventory, source, f.bundleSha, cap, target, f.custody) }
        assertTrue(Files.isDirectory(f.control.resolve("$target/stage.result.json")))
        val result = json.decodeFromString<GenerationOutcome>(Files.readString(f.control.resolve("$target/isolate.result.json")))
        assertTrue(result.passed)
        assertEquals(2, result.fences.size)
        assertEquals(1, f.fake.imports.size)
    }
    @Test fun `failed isolation is retained and reconciles without replaying import`() = fixture { f ->
        f.fake.fail = true; f.fake.isolationFailure = "$target-sql-cache"
        val result = f.engine.restoreFoundation(inventory, source, f.bundleSha, cap, target, f.custody)
        assertFalse(result.passed)
        val root = f.control.resolve(target)
        val original = Files.readAllBytes(root.resolve("isolate.result.json"))
        assertFalse(json.decodeFromString<GenerationOutcome>(original.decodeToString()).passed)
        assertEquals(listOf("$target-sql-cache", "$target-foundation"), f.fake.isolated)
        f.fake.isolationFailure = null
        val predecessor = ReleaseLocks.sha256(Files.readAllBytes(root.resolve("isolate.intent.json")))
        val reconciled = f.engine.reconcileIsolation(target, result.bundleSha256, "r-123456789abc", predecessor)
        assertTrue(reconciled.passed)
        assertContentEquals(original, Files.readAllBytes(root.resolve("isolate.result.json")))
        assertEquals(1, f.fake.imports.size)
    }
    @Test fun `isolation interruption persists outcome and restores interrupt flag`() = fixture { f ->
        f.fake.fail = true; f.fake.isolationInterrupt = "$target-sql-cache"
        assertFailsWith<InterruptedException> { f.engine.restoreFoundation(inventory, source, f.bundleSha, cap, target, f.custody) }
        assertTrue(Thread.interrupted())
        assertFalse(json.decodeFromString<GenerationOutcome>(Files.readString(f.control.resolve("$target/isolate.result.json"))).passed)
        assertTrue(f.fake.fences.containsKey("$target-foundation"))
    }
    @Test fun `preparation failure never regenerates inputs to invent a successful isolation`() = fixture { f ->
        f.fake.onBind = {
            f.fake.onBind = {}
            Files.write(f.control.resolve("$source/captures/$cap/state.cap"), byteArrayOf(0)) // Isolated unit corruption after first verification only.
        }
        val result = f.engine.restoreFoundation(inventory, source, f.bundleSha, cap, target, f.custody)
        assertFalse(result.passed)
        assertTrue(f.fake.imports.isEmpty())
        assertFalse(Files.exists(f.runtime.resolve("$target-foundation")))
        val isolation = json.decodeFromString<GenerationOutcome>(Files.readString(f.control.resolve("$target/isolate.result.json")))
        assertFalse(isolation.passed)
        assertTrue(isolation.fences.isEmpty())
    }
}
