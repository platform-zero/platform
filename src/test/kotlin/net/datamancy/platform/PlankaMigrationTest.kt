package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

class PlankaMigrationTest {
    private val inventory = Json.decodeFromString<AcquiredInventory>(GenerationAssembly.readInventory(
        Path.of("release/downloaded-candidate-inventory.json")).decodeToString())
    private fun temporary(block: (Path) -> Unit) {
        val root = Files.createTempDirectory("planka-migration-unit-")
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        try { block(root) } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    private fun pin(root: Path, name: String, bytes: ByteArray): ActivationInput {
        val file = root.resolve(name); ReleasePrivateFiles.save(file, bytes)
        return ActivationInput(file.toString(), ReleaseLocks.sha256(bytes))
    }
    private fun request(root: Path): PlankaMigrationRequest {
        val original = CanonicalCoreRuntime.spec(inventory, "q-111111111111-core").copy(store = RuntimeStore.CANONICAL_V2)
        val ids = original.processes.filterNot { it.oneShot }.map { it.id }.toSet()
        val restored = original.copy(processes = original.processes.filterNot { it.oneShot }.map {
            it.copy(dependencies = it.dependencies.filter(ids::contains))
        }, databaseAccess = original.databaseAccess.filter { it.consumer in ids })
        val image = restored.processes.single { it.id == "planka" }
        return PlankaMigrationRequest(operation = "r-111111111111", transition = PlankaVersionTransition("2.2.0", "2.2.1"),
            generation = "q-111111111111", bundleSha256 = "a".repeat(64), snapshotId = "cap-111111111111",
            manifest = pin(root, "manifest.json", Json.encodeToString(restored).toByteArray()),
            migrationEnvironment = pin(root, "migration.env", "DATABASE_URL=postgresql://planka_migrate:synthetic@postgres:5432/planka?sslmode=verify-full\n".toByteArray()),
            image = ActivationImagePin(image.image, image.imageId), fenceId = "11111111-1111-1111-1111-111111111111")
    }
    @Test fun `migration runs only Knex no bootstrap and retires scoped principal`() = temporary { root ->
        val req = request(root); val calls = mutableListOf<List<String>>(); var observed = 0
        val migration = PlankaMigration(root, RuntimeCommands { args ->
            calls += args; RuntimeCommandResult(0, if (args.last().startsWith("SELECT")) "f\n" else "")
        }) { spec, fence -> assertEquals(req.fenceId, fence); assertTrue(spec.processes.none { it.oneShot }); observed++ }
        val result = migration.migrate(req)
        assertTrue(result.passed && result.migrationRoleRetired); assertEquals(1, observed)
        assertTrue(calls.first().last().contains("LOGIN"))
        val worker = calls.single { it.first() == "run" }
        assertTrue("--pull=never" in worker && "--read-only" in worker && "--cap-drop=ALL" in worker)
        assertTrue(worker.last().contains("knex.migrate.latest()")); assertFalse(worker.last().contains("seed.run"))
        assertFalse(worker.last().contains("db/init.js"))
        assertTrue(calls[calls.lastIndex - 1].last().contains("NOLOGIN"))
        assertFails { migration.migrate(req) }; assertEquals(4, calls.size)
    }
    @Test fun `migration failures retain original pending identity and revoke role`() {
        for (failure in listOf("run", "interrupt", "retire", "interrupt-retire", "interrupt-flag")) temporary { root ->
            val req = request(root); val calls = mutableListOf<List<String>>()
            val migration = PlankaMigration(root, RuntimeCommands { args ->
                calls += args
                if (args.first() == "run" && failure == "interrupt") throw InterruptedException("unit")
                if (args.first() == "run" && failure == "interrupt-flag") Thread.currentThread().interrupt()
                if (args.last().contains("NOLOGIN") && failure == "interrupt-retire") {
                    Thread.currentThread().interrupt(); throw InterruptedException("unit retirement")
                }
                RuntimeCommandResult(if (args.first() == "run" && failure == "run" || args.last().contains("NOLOGIN") && failure == "retire") 1 else 0,
                    if (args.last().startsWith("SELECT")) "f" else "")
            }) { _, _ -> }
            try {
                if (failure.startsWith("interrupt")) {
                    assertFailsWith<InterruptedException> { migration.migrate(req) }; assertTrue(Thread.currentThread().isInterrupted)
                } else assertFalse(migration.migrate(req).passed)
                assertTrue(calls.any { it.last().contains("NOLOGIN") })
                assertTrue(Files.exists(root.resolve("pending.json")))
                assertTrue(Files.exists(root.resolve("${req.operation}.result.json")))
            } finally { Thread.interrupted() }
        }
    }
    @Test fun `unsupported versions image substitution and input tampering have no effects`() = temporary { root ->
        val req = request(root); var calls = 0
        val migration = PlankaMigration(root, RuntimeCommands { calls++; error("must not execute") }) { _, _ -> }
        for (invalid in listOf(req.copy(transition = PlankaVersionTransition("2.1.0", "2.2.1")),
            req.copy(transition = PlankaVersionTransition("2.2.1", "2.2.0")), req.copy(image = req.image.copy(imageId = "b".repeat(64))),
            req.copy(manifest = req.manifest.copy(sha256 = "c".repeat(64))), req.copy(snapshotId = "foreign"))) {
            assertFails { migration.migrate(invalid) }
        }
        assertEquals(0, calls); assertFalse(Files.exists(root.resolve("pending.json")))
        assertFails { PlankaMigration.requireRollbackSafe(Phase.ACTIVATION_STARTED, "2.2.1", "2.2.1") }
        assertFails { PlankaMigration.requireRollbackSafe(Phase.COMMITTED, "2.2.1", "2.2.1") }
        assertFails { PlankaMigration.requireRollbackSafe(Phase.RECOVERY_REQUIRED, "2.2.1", "2.2.1") }
        assertFails { PlankaMigration.requireRollbackSafe(Phase.ACCEPTED, "2.2.1", "2.2.0") }
        PlankaMigration.requireRollbackSafe(Phase.ACCEPTED, "2.2.1", "2.2.1")
    }
    @Test fun `cold restored standalone app cannot recreate administrator or lose provider order`() {
        val spec = PlankaRuntime.spec(inventory)
        val restored = PlankaRuntime.coldRestoreSpec(spec)
        assertEquals(setOf("postgres", "planka"), restored.processes.map { it.id }.toSet())
        assertTrue(restored.processes.none { it.oneShot })
        assertEquals(listOf("postgres"), restored.processes.single { it.id == "planka" }.dependencies)
        assertEquals(listOf("app.js", "--prod"), restored.processes.single { it.id == "planka" }.command)
        assertEquals(spec.volumes, restored.volumes)
        assertFails { PlankaRuntime.coldRestoreSpec(restored) }
        assertFails { PlankaRuntime.coldRestoreSpec(spec.copy(processes = spec.processes.map {
            if (it.id == "planka") it.copy(command = listOf("db/init.js")) else it
        })) }
    }
}
