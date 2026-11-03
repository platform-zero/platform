package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.time.Instant
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

class GenerationBackupScheduleTest {
    private val q = "q-abcdef123456"
    private val hash = "a".repeat(64)
    private val json = Json { encodeDefaults = true }
    private fun write(path: Path, text: String) {
        Files.writeString(path, text); Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
    }
    private class State {
        var at = Instant.parse("2026-01-02T02:59:59Z")
        var checks = 0
        var callbacks = 0
        var fail: (() -> Unit)? = null
        var checkFail = false
        var controllerFail = false
        var badOutcome = false
    }
    private data class Fixture(val base: Path, val root: Path, val engine: GenerationBackupSchedule, val state: State, val enrollment: BackupScheduleEnrollment)
    private fun fixture(block: (Fixture) -> Unit) {
        val base = Files.createTempDirectory("backup-schedule-unit-")
        Files.createDirectory(base.resolve(q), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val state = State()
        val engine = GenerationBackupSchedule(base, { state.at }, { _, _, _ -> state.checks++; check(!state.checkFail) },
            { _, generation, bundle, capture ->
                state.callbacks++; state.fail?.invoke()
                result(generation, bundle, capture).let { if (state.badOutcome) it.copy(sourceResumed = false) else it }
            }, { check(!state.controllerFail) })
        try {
            val enrollment = engine.enroll(json.encodeToString(AcquiredInventory(1, "unit", emptyList())).toByteArray(), q, hash, hash, UnixSystem().uid.toInt())
            block(Fixture(base, base.resolve("$q/backup-schedule"), engine, state, enrollment))
        } finally { Thread.interrupted(); Files.walk(base).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    private fun result(generation: String, bundle: String, capture: String) = GenerationBackupOutcome(RuntimeBackupAccess(generation, capture, bundle), true,
        KopiaSnapshotReceipt(id = capture, generation = generation, bundleSha256 = bundle, snapshotId = "b".repeat(32), rootObjectId = "k" + "b".repeat(32),
            manifestSha256 = hash, files = 1, plaintextBytes = 10, image = "example.test/kopia@sha256:$hash", imageId = hash), true)
    private fun tick(f: Fixture) = f.engine.tick(q, f.enrollment.bindingSha256)
    @Test fun `initial due run deduplicates and catches up only latest UTC slot`() = fixture { f ->
        assertEquals(1, f.state.checks)
        val first = tick(f); assertEquals("completed", first.status); assertEquals("2026-01-01", first.slot!!.day)
        assertEquals("already-completed", tick(f).status); assertEquals(1, f.state.callbacks)
        f.state.at = Instant.parse("2026-01-02T03:00:00Z")
        assertEquals("2026-01-02", tick(f).slot!!.day)
        f.state.at = Instant.parse("2026-01-20T12:00:00Z")
        assertEquals("2026-01-20", tick(f).slot!!.day); assertEquals(3, f.state.callbacks)
        assertEquals(3L, Files.list(f.root.resolve("slots")).use { it.count() })
        assertEquals(first.slot, GenerationBackupSchedule.slot(f.enrollment.bindingSha256, "2026-01-01"))
        assertFalse(Files.exists(f.root.resolve("failure.alert")))
    }
    @Test fun `enrollment is single use and pins full immutable inventory`() = fixture { f ->
        val bytes = Files.readAllBytes(f.root.resolve("inventory.json"))
        assertFails { f.engine.enroll(bytes, q, hash, hash, UnixSystem().uid.toInt()) }
        assertFails { f.engine.enroll(bytes, q, hash, hash, 0) }
        assertFails { f.engine.enroll(bytes, "foreign", hash, hash, UnixSystem().uid.toInt()) }
        assertFails { f.engine.enroll(bytes, q, hash, "invalid", UnixSystem().uid.toInt()) }
        assertFails { f.engine.enroll(byteArrayOf(), q, hash, hash, UnixSystem().uid.toInt()) }
        f.state.checkFail = true
        assertFails { f.engine.enroll(bytes, "q-111111111111", hash, hash, UnixSystem().uid.toInt()) }
        assertFalse(Files.exists(f.base.resolve("q-111111111111")))
        Files.writeString(f.root.resolve("inventory.json"), "\n", java.nio.file.StandardOpenOption.APPEND)
        assertFails { tick(f) }; assertEquals(0, f.state.callbacks)
    }
    @Test fun `unknown controller loss prevents alternate day resubmission`() = fixture { f ->
        f.state.fail = { throw AssertionError("unit simulated lost acknowledgement") }
        assertFailsWith<AssertionError> { tick(f) }
        val intent = f.root.resolve("slots/2026-01-01/intent.json"); val original = Files.readAllBytes(intent)
        assertFalse(Files.exists(intent.parent.resolve("result.json")))
        f.state.fail = null; f.state.at = f.state.at.plusSeconds(864000)
        assertFails { tick(f) }; assertEquals(1, f.state.callbacks)
        assertTrue(Files.exists(f.root.resolve("failure.alert")))
        assertContentEquals(original, Files.readAllBytes(intent))
        assertEquals(1L, Files.list(f.root.resolve("slots")).use { it.count() })
        assertFails { tick(f) }
    }
    @Test fun `caught failure incomplete resume and interruption retain outcome and alert`() {
        for (fault in listOf("throw", "resume", "interrupt")) fixture { f ->
            if (fault == "resume") f.state.badOutcome = true
            else f.state.fail = { if (fault == "interrupt") throw InterruptedException("unit") else error("unit") }
            assertFails { tick(f) }
            if (fault == "interrupt") assertTrue(Thread.interrupted())
            assertTrue(Files.exists(f.root.resolve("slots/2026-01-01/result.json")))
            assertTrue(Files.exists(f.root.resolve("failure.alert")))
            f.state.at = f.state.at.plusSeconds(86400); assertFails { tick(f) }; assertEquals(1, f.state.callbacks)
        }
    }
    @Test fun `failure result persistence does not skip independent alert`() = fixture { f ->
        f.state.fail = { Files.createDirectory(f.root.resolve("slots/2026-01-01/result.json")); error("unit persistence failure") }
        assertFails { tick(f) }; assertTrue(Files.exists(f.root.resolve("failure.alert")))
        assertTrue(Files.isDirectory(f.root.resolve("slots/2026-01-01/result.json")))
        assertFails { tick(f) }; assertEquals(1, f.state.callbacks)
    }
    @Test fun `clock rollback cannot authorize another slot`() = fixture { f ->
        f.state.at = f.state.at.minusSeconds(1); assertFails { tick(f) }
        f.state.at = Instant.parse("2026-01-03T03:00:00Z"); tick(f)
        f.state.at = Instant.parse("2026-01-02T03:00:00Z"); assertFails { tick(f) }
        assertEquals(1, f.state.callbacks)
    }
    @Test fun `suspension and failure alert are idempotent irreversible barriers without effects`() = fixture { f ->
        val expected = f.enrollment.bindingSha256
        f.engine.signalFailure(q, expected); f.engine.signalFailure(q, expected)
        assertFails { tick(f) }
        f.engine.suspend(q, expected); f.engine.suspend(q, expected)
        assertEquals("suspended", tick(f).status); assertEquals(0, f.state.callbacks)
        write(f.root.resolve("suspended"), "foreign")
        assertFails { tick(f) }; assertFails { f.engine.suspend(q, expected) }
        write(f.root.resolve("failure.alert"), "foreign")
        assertFails { f.engine.signalFailure(q, expected) }
    }
    @Test fun `binding artifact lock and incomplete enrollment fail before backup effects`() {
        for (fault in listOf("hash", "owner", "enrolled", "controller", "lock")) fixture { f ->
            when (fault) {
                "hash" -> assertFails { f.engine.tick(q, "b".repeat(64)) }
                "owner" -> {
                    val changed = f.enrollment.binding.copy(userId = 1)
                    write(f.root.resolve("binding.json"), json.encodeToString(changed)); assertFails { tick(f) }
                }
                "enrolled" -> { Files.delete(f.root.resolve("enrolled.json")); assertFails { tick(f) } }
                "controller" -> { f.state.controllerFail = true; assertFails { tick(f) } }
                "lock" -> {
                    Files.createSymbolicLink(f.root.resolve("schedule.lock"), f.root.resolve("binding.json")); assertFails { tick(f) }
                }
            }
            assertEquals(0, f.state.callbacks)
        }
    }
    @Test fun `corrupt prior result or operation identity cannot be bypassed by a later day`() {
        for (fault in listOf("result", "intent", "name")) fixture { f ->
            tick(f); val path = f.root.resolve("slots/2026-01-01")
            when (fault) {
                "result" -> write(path.resolve("result.json"), "{}")
                "intent" -> write(path.resolve("intent.json"), json.encodeToString(GenerationBackupSchedule.slot("b".repeat(64), "2026-01-01")))
                "name" -> Files.move(path, path.resolveSibling("2026-13-01"))
            }
            f.state.at = f.state.at.plusSeconds(86400)
            assertFails { tick(f) }; assertEquals(1, f.state.callbacks)
        }
    }
    @Test fun `bounded history blocks rather than deleting retained records`() = fixture { f ->
        tick(f)
        for (n in 1..128) Files.createDirectory(f.root.resolve("slots/extra-$n"))
        assertFails { tick(f) }; assertEquals(1, f.state.callbacks)
        assertEquals(129L, Files.list(f.root.resolve("slots")).use { it.count() })
    }
    @Test fun `rendered units bind controller and generation and invoke coordinated operations only`() = fixture { f ->
        val units = f.engine.units(q, f.enrollment.bindingSha256)
        assertEquals(3, units.size)
        val timer = units.getValue("p0v3-backup-$q.timer")
        assertTrue(timer.contains("OnCalendar=*-*-* 03:00:00 UTC")); assertTrue(timer.contains("OnActiveSec=5s")); assertTrue(timer.contains("Persistent=true"))
        val service = units.getValue("p0v3-backup-$q.service")
        assertTrue(service.contains("OnFailure=p0v3-backup-$q-alert.service")); assertTrue(service.contains("KillMode=process"))
        assertTrue(service.contains("release backup-schedule-tick $q ${f.enrollment.bindingSha256}"))
        assertTrue(service.contains("/releases/$hash/bin/p0-v3-platform")); assertTrue(service.contains("Restart=no"))
        assertFalse(service.contains("snapshot create")); assertFalse(service.contains("ExecStop="))
        assertFails { BackupScheduleUnits.render(f.enrollment.binding, "invalid") }
        assertFails { GenerationBackupSchedule.validate(f.enrollment.binding.copy(schemaVersion = 2)) }
    }
}
