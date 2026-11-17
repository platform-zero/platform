package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.UUID
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

class GenerationBackupTest {
    @Test fun `nested recovery deadline cannot reset an outer operation budget`() {
        assertFails { RecoveryDeadline.remainingMillis() }
        assertFails { RecoveryDeadline.within(RecoveryDeadline.MAX_MILLIS + 1) { } }
        RecoveryDeadline.within(5000) {
            val outer = RecoveryDeadline.remainingMillis()
            assertTrue(outer in 1..5000)
            RecoveryDeadline.within(RecoveryDeadline.MAX_MILLIS) {
                assertTrue(RecoveryDeadline.remainingMillis() <= outer)
                assertTrue(RecoveryDeadline.observedUtcDeadline().isAfter(java.time.Instant.now()))
            }
            RecoveryDeadline.within(750) {
                assertTrue(RecoveryDeadline.remainingMillis() <= 750)
                assertFails { RecoveryDeadline.remainingSeconds() }
            }
            assertTrue(RecoveryDeadline.remainingMillis() <= outer)
        }
        assertNull(RecoveryDeadline.remainingSecondsIfBound())
    }
    private val json = Json { encodeDefaults = true }
    private val generation = "q-abcdef123456"
    private val cap = "cap-abcdef123456"
    private val inventory = AcquiredInventory(1, "unit-only", listOf("postgres", "valkey", "ntfy", "mariadb", "memcached", "forgejo", "planka").map {
        AcquiredImage(it, "unit", "unit", "example.test/$it@sha256:" + "a".repeat(64), "b".repeat(64), emptyList(), "sha256:" + "a".repeat(64), "amd64", "linux")
    })
    private class Fake(val root: Path) : BackupGenerationBackend, BackupGenerationFactory {
        val calls = mutableListOf<String>()
        val running = mutableSetOf<String>()
        val initialized = mutableSetOf<String>()
        val leases = mutableSetOf<String>()
        val fences = mutableMapOf<String, String>()
        var bindings = emptyMap<String, String>()
        var fault: String? = null
        var fatal = false
        var interrupt = false
        var frozen = 0
        var freeLocks = Long.MAX_VALUE
        private fun event(phase: String, spec: PrivateDeploymentSpec) {
            calls += "$phase:${spec.name}"
            if (phase == fault) {
                if (fatal) throw AssertionError("unit simulated controller death")
                if (interrupt) { Thread.currentThread().interrupt(); throw InterruptedException("unit interruption") }
                error("unit $phase failure")
            }
        }
        override fun forBackup(access: RuntimeBackupAccess): BackupGenerationBackend = this
        override fun audit(spec: PrivateDeploymentSpec, pristine: Boolean): RuntimeAudit {
            if (pristine) require(spec.name !in initialized)
            return RuntimeAudit(spec.name, bindings.getValue(spec.name), if (spec.name in initialized) 1 else 0, fences[spec.name],
                spec.processes.map { RuntimeStatus(it.id, if (it.oneShot) "completed" else if (spec.name in running) "running" else "exited", 0) })
        }
        override fun apply(spec: PrivateDeploymentSpec): List<RuntimeStatus> {
            initialized += spec.name; running += spec.name
            val ids = spec.processes.filter { it.oneShot }.map { it.id }.toSet()
            val jobs = RuntimeJobs(bindings.getValue(spec.name), ids, ids)
            val bytes = Json.encodeToString(jobs.copy(checksum = ReleaseLocks.sha256(Json.encodeToString(jobs).toByteArray())))
            val path = root.resolve("${spec.name}/runtime.jobs")
            Files.createFile(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))); Files.writeString(path, bytes)
            return audit(spec, false).statuses
        }
        override fun claim(spec: PrivateDeploymentSpec) { require(spec.name in running && spec.name !in fences); leases += spec.name; event("claim", spec) }
        override fun quiesce(spec: PrivateDeploymentSpec): String {
            require(spec.name in leases); running -= spec.name
            val fence = fences.getOrPut(spec.name) { UUID.randomUUID().toString() }; event("quiesce", spec); return fence
        }
        override fun resume(spec: PrivateDeploymentSpec, fence: String): List<RuntimeStatus> {
            require(spec.name in leases && fences[spec.name] == fence)
            fences.remove(spec.name); running += spec.name; event("resume", spec); return audit(spec, false).statuses
        }
        override fun finish(spec: PrivateDeploymentSpec) { require(spec.name in running); leases.remove(spec.name); event("finish", spec) }
        override fun isolate(spec: PrivateDeploymentSpec): String {
            running -= spec.name; event("isolate", spec); return fences.getOrPut(spec.name) { UUID.randomUUID().toString() }
        }
        override fun <T> withFrozen(spec: PrivateDeploymentSpec, fence: String, action: (FrozenRuntimeObservation) -> T): T {
            require(spec.name in leases && fences[spec.name] == fence && spec.name !in running)
            frozen++
            try { return action(FrozenRuntimeObservation(spec.name, bindings.getValue(spec.name), fence,
                RecoveryCapsule.fileHash(root.resolve("${spec.name}/runtime.jobs")), spec.processes.filter { it.oneShot }.map { it.id }.toSet(),
                spec.processes.map { RuntimeStatus(it.id, "exited", 0) })) }
            finally { frozen-- }
        }
        override fun exportVolume(spec: PrivateDeploymentSpec, volume: RuntimeVolume, output: Path) {
            assertEquals(3, frozen); event("export", spec)
            Files.createFile(output, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
            Files.write(output, VolumeTarTest.tar(VolumeTarTest.member("./", '5', ByteArray(0), uid = volume.userId, mode = 448)))
        }
    }
    private data class Fixture(val root: Path, val control: Path, val engine: GenerationRuntime, val fake: Fake, val hash: String,
        val store: GenerationSnapshotStore, val custody: Path, val afterSnapshot: MutableList<() -> Unit>)
    private fun fixture(block: (Fixture) -> Unit) {
        val root = Files.createTempDirectory("routine-backup-unit-")
        val runtime = Files.createDirectory(root.resolve("runtime"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val control = root.resolve("control"); val fake = Fake(runtime)
        var memory = 1000000L
        val after = mutableListOf<() -> Unit>()
        val engine = GenerationRuntime(control, runtime, { fake.bindings = it; fake }, { GenerationCapacity(memory, 1000000, fake.freeLocks) })
        try {
            val bytes = json.encodeToString(inventory).toByteArray()
            val request = AssemblyRequest(id = generation, candidateSha256 = "c".repeat(64), inventorySha256 = ReleaseLocks.sha256(bytes),
                selections = listOf(AssemblySelection("canonical-core"), AssemblySelection("sql-cache", listOf("canonical-core")),
                    AssemblySelection("forgejo", listOf("canonical-core"))), diskReservationMiB = 8192)
            val recipes = GenerationAssembly.catalog.map { recipe -> if (recipe.id != "canonical-core") recipe else recipe.copy(prepare = { inv, base, name, store ->
                RuntimePreparation.prepare(CanonicalCoreRuntime.spec(inv, name).copy(store = store), base) { CanonicalCoreRuntime.inputs({
                    mapOf("ca.pem" to "unit-ca", "web.pem" to "unit-cert", "web-key.pem" to "unit-key") }) }
            }) }
            val plan = GenerationAssembly(recipes).plan(request, bytes)
            val graph = SiteOwnerships.inspect(plan)
            val owners = graph.processes.associate { it.process to it.compiledProduct!! }
            val contract = SiteOwnership(site = "unit", assemblySha256 = graph.assemblySha256,
                processes = owners.map { SiteProcessOwner(it.key, it.value) },
                state = graph.state.map { SiteStateOwner(it.volume, owners.getValue(it.writers.first()), "cohort") },
                inputs = graph.inputs.map { SiteInputOwner(it.input, it.compiledProduct!!, true, it.consumers) }, routes = emptyList())
            val hash = engine.prepareOwnedAssembly(plan, contract, emptySet()); engine.stage(generation, hash)
            val store = object : GenerationSnapshotStore {
                override fun snapshot(repository: Path, custody: Path, operation: Path, manifest: CapsuleManifest, payloads: Map<String, Path>): KopiaSnapshotReceipt {
                    assertTrue(fake.running.isEmpty()); assertEquals(3, fake.leases.size); assertEquals(3, fake.frozen)
                    if (fake.fault == "capacity") memory = 16384
                    after.forEach { it() }
                    return KopiaSnapshotReceipt(id = manifest.id, generation = generation, bundleSha256 = hash,
                        snapshotId = ReleaseLocks.sha256("unit-native-snapshot:${manifest.id}".toByteArray()).take(32),
                        rootObjectId = "k" + ReleaseLocks.sha256("unit-native-root:${manifest.id}".toByteArray()).take(40), manifestSha256 = ReleaseLocks.sha256(json.encodeToString(manifest).toByteArray()),
                        files = manifest.files.size, plaintextBytes = manifest.files.sumOf { it.bytes }, image = "example.test/kopia@sha256:" + "a".repeat(64), imageId = "b".repeat(64))
                }
                override fun restore(repository: Path, custody: Path, operation: Path, receipt: KopiaSnapshotReceipt, destination: Path) = error("Not a functional restore test")
            }
            block(Fixture(root, control, engine, fake, hash, store, root.resolve("custody"), after))
        } finally { Thread.interrupted(); Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    private fun backup(f: Fixture, id: String = cap) = f.engine.backupKopia(inventory, generation, f.hash, id, f.custody, f.store)
    @Test fun `routine backup fences captures and resumes in dependency order without permanent retirement`() = fixture { f ->
        f.engine.checkBackupSource(inventory, generation, f.hash)
        f.fake.freeLocks = 0
        assertFails { backup(f) }
        assertFalse(Files.exists(f.control.resolve("$generation/backups")))
        assertTrue(f.fake.leases.isEmpty())
        f.fake.freeLocks = Long.MAX_VALUE
        val result = backup(f)
        assertTrue(result.passed && result.sourceResumed)
        assertEquals(3, f.fake.running.size); assertTrue(f.fake.fences.isEmpty() && f.fake.leases.isEmpty())
        assertFalse(Files.exists(f.control.resolve("$generation/isolate.intent.json")))
        assertEquals(listOf("sql-cache", "forgejo", "canonical-core"), f.fake.calls.filter { it.startsWith("quiesce:") }.map { it.substringAfter("$generation-") })
        assertEquals(listOf("canonical-core", "forgejo", "sql-cache"), f.fake.calls.filter { it.startsWith("resume:") }.map { it.substringAfter("$generation-") })
        assertFails { backup(f) }
        val next = backup(f, "cap-111111111111")
        assertTrue(next.passed)
        assertNotEquals(result.snapshot!!.snapshotId, next.snapshot!!.snapshotId)
        assertNotEquals(result.snapshot.rootObjectId, next.snapshot.rootObjectId)
        val intent = f.control.resolve("$generation/backups/$cap/intent.json")
        assertFails { f.engine.reconcileBackup(generation, f.hash, cap, "r-abcdef123456", RecoveryCapsule.fileHash(intent)) }
    }
    @Test fun `claim freeze capture capacity resume and release failures isolate all members and forbid another ID`() {
        for (fault in listOf("claim", "quiesce", "export", "capacity", "resume", "finish")) fixture { f ->
            f.fake.fault = fault
            val result = backup(f)
            assertFalse(result.passed || result.sourceResumed)
            assertTrue(f.fake.running.isEmpty()); assertEquals(3, f.fake.fences.size)
            assertFails { backup(f, "cap-111111111111") }
            assertEquals(3, f.fake.calls.count { it.startsWith("isolate:") })
            assertFails { f.engine.checkBackupSource(inventory, generation, f.hash) }
        }
    }
    @Test fun `process death leaves unknown outcome and linked reconciliation never resumes or resubmits`() = fixture { f ->
        f.fake.fault = "quiesce"; f.fake.fatal = true
        assertFailsWith<AssertionError> { backup(f) }
        val root = f.control.resolve("$generation/backups/$cap")
        assertFalse(Files.exists(root.resolve("result.json")))
        assertFails { backup(f, "cap-111111111111") }
        val intentHash = RecoveryCapsule.fileHash(root.resolve("intent.json"))
        assertFails { f.engine.reconcileBackup(generation, f.hash, cap, "r-abcdef123456", "f".repeat(64)) }
        f.fake.fault = null
        assertTrue(f.engine.reconcileBackup(generation, f.hash, cap, "r-abcdef123456", intentHash).passed)
        assertTrue(f.fake.running.isEmpty()); assertEquals(3, f.fake.fences.size); assertEquals(3, f.fake.leases.size)
        assertFalse(Files.exists(root.resolve("result.json")))
        assertTrue(f.fake.calls.none { it.startsWith("resume:") })
    }
    @Test fun `interruption and result persistence failure do not skip source isolation`() {
        fixture { f ->
            f.fake.fault = "resume"; f.fake.interrupt = true
            assertFailsWith<InterruptedException> { backup(f) }
            assertTrue(Thread.interrupted()); assertTrue(f.fake.running.isEmpty()); assertEquals(3, f.fake.fences.size)
        }
        fixture { f ->
            f.afterSnapshot += {
                Files.createDirectory(f.control.resolve("$generation/backups/$cap/result.json"))
                error("unit result persistence fault")
            }
            assertFails { backup(f) }
            assertTrue(f.fake.running.isEmpty()); assertEquals(3, f.fake.fences.size)
        }
    }
}
