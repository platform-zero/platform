package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.UUID
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

class GenerationHeldCaptureTest {
    private val json = Json { encodeDefaults = true }
    private val source = "q-abcdef123456"
    private val target = "q-111111111111"
    private val cap = "cap-abcdef123456"
    private val inventory = AcquiredInventory(1, "unit-only", listOf("postgres", "valkey", "ntfy", "mariadb", "memcached", "forgejo", "planka").map {
        AcquiredImage(it, "unit", "unit", "example.test/$it@sha256:" + "a".repeat(64), "b".repeat(64), emptyList(), "sha256:" + "a".repeat(64), "amd64", "linux")
    })
    private class Fake(val root: Path) : BackupGenerationBackend, BackupGenerationFactory {
        val running = mutableSetOf<String>(); val initialized = mutableSetOf<String>(); val leases = mutableSetOf<String>()
        val fences = mutableMapOf<String, String>(); val bindings = mutableMapOf<String, String>(); val calls = mutableListOf<String>()
        var frozen = 0; var targetFrozen = 0; var fault: String? = null; var interrupt = false; var memory = 1000000L
        override fun forBackup(access: RuntimeBackupAccess) = this
        override fun audit(spec: PrivateDeploymentSpec, pristine: Boolean): RuntimeAudit {
            if (pristine) require(spec.name !in initialized)
            return RuntimeAudit(spec.name, bindings.getValue(spec.name), if (spec.name in initialized) 1 else 0, fences[spec.name],
                spec.processes.map { RuntimeStatus(it.id, if (it.oneShot) "completed" else if (spec.name in running) "running" else "exited", 0) })
        }
        fun jobs(spec: PrivateDeploymentSpec) {
            val ids = spec.processes.filter { it.oneShot }.map { it.id }.toSet()
            val jobs = RuntimeJobs(bindings.getValue(spec.name), ids, ids)
            ReleasePrivateFiles.save(root.resolve("${spec.name}/runtime.jobs"), Json.encodeToString(jobs.copy(checksum =
                ReleaseLocks.sha256(Json.encodeToString(jobs).toByteArray()))).toByteArray())
        }
        override fun apply(spec: PrivateDeploymentSpec): List<RuntimeStatus> {
            initialized += spec.name; running += spec.name; jobs(spec); return audit(spec, false).statuses
        }
        override fun claim(spec: PrivateDeploymentSpec) { require(spec.name in running && spec.name !in fences); leases += spec.name; calls += "claim" }
        override fun quiesce(spec: PrivateDeploymentSpec): String {
            require(spec.name in leases); running -= spec.name
            return fences.getOrPut(spec.name) { UUID.randomUUID().toString() }
        }
        override fun resume(spec: PrivateDeploymentSpec, fence: String): List<RuntimeStatus> {
            assertEquals(3, targetFrozen, "Target locks must remain held throughout source resume")
            require(spec.name in leases && fences[spec.name] == fence)
            calls += "resume"; running += spec.name; fences.remove(spec.name)
            if (fault == "resume") {
                if (interrupt) { Thread.currentThread().interrupt(); throw InterruptedException("unit interruption") }
                error("unit resume fault")
            }
            return audit(spec, false).statuses
        }
        override fun finish(spec: PrivateDeploymentSpec) { assertEquals(3, targetFrozen); calls += "finish"; leases.remove(spec.name) }
        override fun isolate(spec: PrivateDeploymentSpec): String {
            running -= spec.name; calls += "isolate"; return fences.getOrPut(spec.name) { UUID.randomUUID().toString() }
        }
        override fun <T> withFrozen(spec: PrivateDeploymentSpec, fence: String, action: (FrozenRuntimeObservation) -> T): T {
            val isTarget = spec.name.startsWith("q-111111111111-")
            require((isTarget || spec.name in leases) && fences[spec.name] == fence && spec.name !in running)
            frozen++; if (isTarget) targetFrozen++
            try { return action(FrozenRuntimeObservation(spec.name, bindings.getValue(spec.name), fence,
                RecoveryCapsule.fileHash(root.resolve("${spec.name}/runtime.jobs")), spec.processes.filter { it.oneShot }.map { it.id }.toSet(),
                spec.processes.map { RuntimeStatus(it.id, "exited", 0) })) }
            finally { frozen--; if (isTarget) targetFrozen-- }
        }
        override fun exportVolume(spec: PrivateDeploymentSpec, volume: RuntimeVolume, output: Path) {
            assertEquals(3, frozen)
            ReleasePrivateFiles.save(output, VolumeTarTest.tar(VolumeTarTest.member("./", '5', ByteArray(0), uid = volume.userId, mode = 448)))
        }
    }
    private data class Fixture(val root: Path, val runtime: Path, val control: Path, val engine: GenerationRuntime,
        val fake: Fake, val hash: String, val store: GenerationSnapshotStore)
    private fun fixture(action: (Fixture) -> Unit) {
        val root = Files.createTempDirectory("held-source-unit-")
        val runtime = Files.createDirectory(root.resolve("runtime"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val control = root.resolve("control"); val fake = Fake(runtime)
        val engine = GenerationRuntime(control, runtime, { fake.bindings.putAll(it); fake }, { GenerationCapacity(fake.memory, 1000000) })
        try {
            val bytes = json.encodeToString(inventory).toByteArray()
            val request = AssemblyRequest(id = source, candidateSha256 = "c".repeat(64), inventorySha256 = ReleaseLocks.sha256(bytes),
                selections = listOf(AssemblySelection("canonical-core"), AssemblySelection("sql-cache", listOf("canonical-core")),
                    AssemblySelection("forgejo", listOf("canonical-core"))), diskReservationMiB = 8192)
            val recipes = GenerationAssembly.catalog.map { recipe -> if (recipe.id != "canonical-core") recipe else recipe.copy(prepare = { inv, base, name, store ->
                RuntimePreparation.prepare(CanonicalCoreRuntime.spec(inv, name).copy(store = store), base) {
                    CanonicalCoreRuntime.inputs({ mapOf("ca.pem" to "unit-ca", "web.pem" to "unit-cert", "web-key.pem" to "unit-key") })
                }
            }) }
            val plan = GenerationAssembly(recipes).plan(request, bytes); val graph = SiteOwnerships.inspect(plan)
            val owners = graph.processes.associate { it.process to it.compiledProduct!! }
            val contract = SiteOwnership(site = "unit", assemblySha256 = graph.assemblySha256,
                processes = owners.map { SiteProcessOwner(it.key, it.value) },
                state = graph.state.map { SiteStateOwner(it.volume, owners.getValue(it.writers.first()), "cohort") },
                inputs = graph.inputs.map { SiteInputOwner(it.input, it.compiledProduct!!, true, it.consumers) }, routes = emptyList())
            val hash = engine.prepareOwnedAssembly(plan, contract, emptySet()); engine.stage(source, hash)
            val store = object : GenerationSnapshotStore {
                override fun snapshot(repository: Path, custody: Path, operation: Path, manifest: CapsuleManifest, payloads: Map<String, Path>): KopiaSnapshotReceipt {
                    assertTrue(fake.running.isEmpty()); assertEquals(3, fake.leases.size); assertEquals(3, fake.frozen)
                    return KopiaSnapshotReceipt(id = manifest.id, generation = source, bundleSha256 = hash, snapshotId = "a".repeat(32),
                        rootObjectId = "k" + "b".repeat(40), manifestSha256 = ReleaseLocks.sha256(json.encodeToString(manifest).toByteArray()),
                        files = manifest.files.size, plaintextBytes = manifest.files.sumOf { it.bytes }, image = "example.test/kopia@sha256:" + "a".repeat(64), imageId = "b".repeat(64))
                }
                override fun restore(repository: Path, custody: Path, operation: Path, receipt: KopiaSnapshotReceipt, destination: Path) = error("No native restore in this unit fixture")
            }
            action(Fixture(root, runtime, control, engine, fake, hash, store))
        } finally { Thread.interrupted(); Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    private fun hold(f: Fixture) = f.engine.holdKopiaForRestore(inventory, source, f.hash, cap, f.root.resolve("custody"), f.store)
    private fun target(f: Fixture, held: GenerationHeldCapture): String {
        val original = json.decodeFromString<GenerationBundle>(Files.readString(f.control.resolve("$source/bundle.json")))
        val receiptHash = KopiaGenerationStore.receiptHash(held.snapshot)
        val bundle = FoundationRestore.bundle(original, inventory, target, receiptHash, ColdRestoreCohort.CANONICAL_CORE)
            .copy(recoverySourceArchiveSha256 = null, recoverySourceKopia = held.snapshot)
        val dir = Files.createDirectory(f.control.resolve(target), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        fun save(name: String, text: String) = ReleasePrivateFiles.save(dir.resolve(name), text.toByteArray())
        val text = json.encodeToString(bundle); val hash = ReleaseLocks.sha256(text.toByteArray())
        save("bundle.json", text)
        for ((pin, old) in bundle.members.zip(original.members)) {
            RuntimePreparation.prepare(pin.spec, f.runtime) { pin.inputHashes.mapValues { (file, _) -> Files.readString(f.runtime.resolve("${old.member.name}/$file")) } }
            f.fake.bindings[pin.member.name] = pin.runtimeFingerprint; f.fake.initialized += pin.member.name; f.fake.jobs(pin.spec)
            f.fake.fences[pin.member.name] = UUID.randomUUID().toString()
            save("${pin.member.name}.import.intent.json", json.encodeToString(GenerationIntent("import-member", hash)))
            save("${pin.member.name}.import.result.json", json.encodeToString(f.fake.audit(pin.spec, false)))
            val marker = "p0v3-native-volume-import-v1\n${pin.runtimeFingerprint}\n$receiptHash\n".toByteArray()
            for (name in listOf("runtime.import.intent", "runtime.import.complete")) ReleasePrivateFiles.save(f.runtime.resolve("${pin.member.name}/$name"), marker)
        }
        save("stage.intent.json", json.encodeToString(GenerationIntent("restore-import", hash)))
        save("stage.result.json", json.encodeToString(GenerationOutcome("restore-import", hash, true,
            fences = bundle.members.associate { it.member.name to f.fake.fences.getValue(it.member.name) })))
        save("recovery.source.json", json.encodeToString(held.snapshot))
        save("recovery.check.json", json.encodeToString(GenerationRecoveryCheck(source, cap, f.hash, "", original.members.map {
            RecoveryMemberCheck(it.member.name, it.runtimeFingerprint, it.spec.processes.filter { p -> p.oneShot }.map { p -> p.id }.toSet(), emptyMap())
        }, kopiaSnapshotId = held.snapshot.snapshotId, kopiaReceiptSha256 = receiptHash)))
        return hash
    }
    private fun resume(f: Fixture, held: GenerationHeldCapture, targetHash: String) =
        f.engine.resumeHeldSourceAfterIsolation(inventory, source, f.hash, cap, held.sha256, target, targetHash)

    @Test fun `hold never resumes and exact imported target is frozen across source release`() = fixture { f ->
        val held = hold(f); held.validate()
        assertTrue(f.fake.running.isEmpty()); assertEquals(3, f.fake.leases.size)
        assertFalse(Files.exists(f.control.resolve("$source/backups/$cap/result.json")))
        assertEquals(held.sha256, RecoveryCapsule.fileHash(f.control.resolve("$source/backups/$cap/held.json")))
        assertFails { hold(f) }
        val targetHash = target(f, held)
        assertFails { resume(f, held, targetHash) } // No verified target isolation record yet.
        assertTrue(f.engine.isolate(target, targetHash).passed)
        val result = resume(f, held, targetHash)
        assertTrue(result.passed && result.sourceResumed); assertEquals(held.snapshot, result.snapshot)
        assertEquals(3, f.fake.running.size); assertTrue(f.fake.running.all { it.startsWith(source) }); assertTrue(f.fake.leases.isEmpty())
        assertEquals(3, f.fake.calls.count { it == "resume" }); assertEquals(0, f.fake.targetFrozen)
        assertFails { resume(f, held, targetHash) }
    }

    @Test fun `drift capacity and unproven isolation leave held source stopped`() {
        for (fault in listOf("target-running", "target-import", "capacity", "source-fence", "receipt")) fixture { f ->
            val held = hold(f); val targetHash = target(f, held); f.engine.isolate(target, targetHash)
            when (fault) {
                "target-running" -> f.fake.running += "$target-canonical-core"
                "target-import" -> Files.delete(f.runtime.resolve("$target-canonical-core/runtime.import.complete"))
                "capacity" -> f.fake.memory = 16384
                "source-fence" -> f.fake.fences["$source-canonical-core"] = UUID.randomUUID().toString()
                else -> Files.writeString(f.control.resolve("$source/backups/$cap/held.json"), "changed")
            }
            assertFails(fault) { resume(f, held, targetHash) }
            assertEquals(0, f.fake.calls.count { it == "resume" }); assertEquals(3, f.fake.leases.size)
            assertFalse(Files.exists(f.control.resolve("$source/backups/$cap/resume.authority.json")))
        }
    }

    @Test fun `partial and interrupted resume are fenced and never replayed`() {
        for (interrupt in listOf(false, true)) fixture { f ->
            val held = hold(f); val targetHash = target(f, held); f.engine.isolate(target, targetHash)
            f.fake.fault = "resume"; f.fake.interrupt = interrupt
            assertFails { resume(f, held, targetHash) }
            if (interrupt) assertTrue(Thread.interrupted())
            assertTrue(f.fake.running.isEmpty()); assertEquals(3, f.fake.leases.size)
            assertEquals(1, f.fake.calls.count { it == "resume" })
            assertTrue(Files.exists(f.control.resolve("$source/backups/$cap/resume.authority.json")))
            f.fake.fault = null
            assertFails { resume(f, held, targetHash) }
            assertEquals(1, f.fake.calls.count { it == "resume" })
        }
    }

    @Test fun `retention uncertainty prevents quiescing a healthy source`() = fixture { f ->
        val dir = Files.createDirectory(f.control.resolve("$source/kopia-store"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.save(dir.resolve("retention.pending.json"), "unknown".toByteArray())
        assertFails { hold(f) }; assertTrue(f.fake.leases.isEmpty()); assertEquals(3, f.fake.running.size)
    }
}
