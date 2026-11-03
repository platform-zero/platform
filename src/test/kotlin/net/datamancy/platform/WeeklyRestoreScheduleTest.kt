package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.time.Instant
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.test.*

class WeeklyRestoreScheduleTest {
    private val q = "q-abcdef123456"
    private val hash = "a".repeat(64)
    private val json = Json { encodeDefaults = true }
    private fun receipt() = KopiaSnapshotReceipt(id = "cap-111111111111", generation = q, bundleSha256 = hash,
        snapshotId = "b".repeat(32), rootObjectId = "k" + "b".repeat(32), manifestSha256 = hash, files = 1,
        plaintextBytes = 10, image = "example.test/kopia@sha256:$hash", imageId = hash)
    private class State {
        var at = Instant.parse("2026-01-04T04:00:00Z")
        var nanos = 0L
        val effects = mutableListOf<String>()
        var fail: String? = null
        var timeout: String? = null
        var mismatch = false
        var invalidOutcome: String? = null
        var controllerFails = false
        var hook: ((String) -> Unit)? = null
    }
    private fun fixture(block: (WeeklyRestoreSchedule, State, String, Path) -> Unit) {
        val base = Files.createTempDirectory("weekly-unit-")
        val mode = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
        Files.createDirectory(base.resolve(q), mode)
        val refs = RecoveryReferences.initialize(base.resolve("$q/recovery-references"), emptyList())
        val state = State()
        val inventory = json.encodeToString(AcquiredInventory(1, "unit", emptyList())).toByteArray()
        val assertions = setOf("fixture:historical-readback")
        val plan = json.encodeToString(WeeklyFunctionalPlan(candidate = buildJsonObject {
            for (key in listOf("implementationSha256", "artifactsSha256", "configurationSha256", "acceptanceSha256", "sitePolicySha256")) put(key, hash)
        }, cases = listOf(WeeklyFunctionalCase("fixture", "forgejo", "native", "restore", "native",
            "/unit/adapter.py", hash, setOf("historical-readback"), buildJsonObject {}, buildJsonObject { put("fixture", "original") })))).toByteArray()
        val engine = WeeklyRestoreSchedule(base, { state.at }, { check(!state.controllerFails) }, { _, _, _ -> }, { _, slot, _, _ ->
            object : WeeklyRestoreBackend {
                private fun effect(name: String) {
                    state.effects += name
                    state.hook?.invoke(name)
                    if (state.timeout == name) state.at = state.at.plusSeconds(WeeklyRestoreSchedule.BUDGET_SECONDS)
                    if (state.fail == name) throw InterruptedException("unit loss at $name")
                }
                override fun holdSource(): GenerationHeldCapture {
                    effect("hold")
                    val snapshotId = ReleaseLocks.sha256(slot.operation.toByteArray()).take(32)
                    return GenerationHeldCapture(RuntimeBackupAccess(q, slot.operation, hash),
                        receipt().copy(id = slot.operation, snapshotId = snapshotId, rootObjectId = "k$snapshotId"),
                        if (state.invalidOutcome == "held") emptyMap() else mapOf("$q-core" to "11111111-1111-1111-1111-111111111111"))
                }
                override fun restore(snapshot: KopiaSnapshotReceipt): GenerationOutcome { effect("restore"); return GenerationOutcome("restore-import", hash, state.invalidOutcome != "import") }
                override fun startTarget(imported: GenerationOutcome) = effect("start")
                override fun verify(snapshot: KopiaSnapshotReceipt, imported: GenerationOutcome, deadline: Instant): WeeklyFunctionalResult {
                    effect("verify"); return WeeklyFunctionalResult(slot.operation, slot.target, hash, snapshot.snapshotId,
                        if (state.mismatch) emptySet() else assertions, true)
                }
                override fun isolateTarget(imported: GenerationOutcome): GenerationOutcome {
                    effect("isolate"); return GenerationOutcome("isolate", hash, state.invalidOutcome != "isolation", fences = mapOf("${slot.target}-core" to "22222222-2222-2222-2222-222222222222"))
                }
                override fun verifyTargetIsolation(isolation: GenerationOutcome) = effect("observe")
                override fun resumeSource(fences: Map<String, String>) = effect("resume")
            }
        }, { refs }, { _, generation, _, operation -> refs.withProtection { protection ->
            state.effects += "retention"; state.hook?.invoke("retention")
            KopiaRetentionResult(KopiaRetentionPlan(id = operation, generation = generation, referenceHeadSha256 = protection.referenceHeadSha256,
                beforeSha256 = hash, retain = protection.receipts.map { it.snapshotId }.sorted(), delete = emptyList()), hash)
        } }, { state.nanos })
        val binding = WeeklyRestoreBinding(BackupScheduleBinding(generation = q, bundleSha256 = hash, inventorySha256 = ReleaseLocks.sha256(inventory),
            controllerSha256 = hash, userId = UnixSystem().uid.toInt(), enrolledAt = state.at.toString()), ReleaseLocks.sha256(plan), assertions)
        try { block(engine, state, engine.enroll(inventory, binding, plan), base.resolve("$q/weekly-restore")) }
        finally { Thread.interrupted(); Files.walk(base).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `UTC Sunday boundary and bounded latest catchup`() {
        assertEquals("2025-12-28", WeeklyRestoreSchedule.sunday(Instant.parse("2026-01-04T03:59:59Z")))
        assertEquals("2026-01-04", WeeklyRestoreSchedule.sunday(Instant.parse("2026-01-04T04:00:00Z")))
        fixture { engine, state, expected, root ->
            assertEquals("completed", engine.tick(q, expected).status)
            assertEquals(listOf("hold", "restore", "start", "verify", "isolate", "observe", "resume"), state.effects)
            assertEquals("already-completed", engine.tick(q, expected).status)
            state.at = Instant.parse("2026-03-30T12:00:00Z")
            assertEquals("2026-03-29", engine.tick(q, expected).slot!!.sunday)
            assertEquals(2L, Files.list(root.resolve("slots")).use { it.count() })
        }
    }
    @Test fun `failed or timed out verification and isolation never resume or retry`() {
        for (fault in listOf("hold", "restore", "start", "verify", "isolate", "observe")) fixture { engine, state, expected, root ->
            state.fail = fault
            assertFails { engine.tick(q, expected) }; assertTrue(Thread.interrupted())
            assertFalse("resume" in state.effects); assertTrue(Files.exists(root.resolve("failure.alert")))
            state.fail = null; state.at = state.at.plusSeconds(604800)
            val before = state.effects.toList(); assertFails { engine.tick(q, expected) }; assertEquals(before, state.effects)
        }
        fixture { engine, state, expected, _ ->
            state.timeout = "observe"; assertFails { engine.tick(q, expected) }; assertFalse("resume" in state.effects)
        }
    }
    @Test fun `functional assertions are exact not merely successful exit`() = fixture { engine, state, expected, _ ->
        state.mismatch = true; assertFails { engine.tick(q, expected) }; assertFalse("resume" in state.effects)
    }
    @Test fun `unknown completed record cannot be bypassed by a later Sunday`() = fixture { engine, state, expected, root ->
        engine.tick(q, expected)
        Files.delete(root.resolve("slots/2026-01-04/result.json"))
        state.at = state.at.plusSeconds(604800)
        val before = state.effects.toList(); assertFails { engine.tick(q, expected) }; assertEquals(before, state.effects)
    }
    @Test fun `monotonic deadline rollback and interrupt flag forbid source resume`() {
        for (fault in listOf("monotonic", "rollback", "interrupt")) fixture { engine, state, expected, root ->
            state.hook = { phase -> if (phase == "observe") when (fault) {
                "monotonic" -> state.nanos = WeeklyRestoreSchedule.BUDGET_SECONDS * 1_000_000_000L
                "rollback" -> state.at = state.at.minusSeconds(1)
                "interrupt" -> Thread.currentThread().interrupt()
                else -> error("Unknown unit fault")
            } }
            assertFails { engine.tick(q, expected) }
            assertFalse("resume" in state.effects)
            assertEquals(fault == "interrupt", Thread.interrupted())
            assertTrue(Files.exists(root.resolve("failure.alert")))
            val before = state.effects.toList(); state.hook = null
            assertFails { engine.tick(q, expected) }; assertEquals(before, state.effects)
        }
    }
    @Test fun `failed held import or isolation outcome is not successful process completion`() {
        for (fault in listOf("held", "import", "isolation")) fixture { engine, state, expected, root ->
            state.invalidOutcome = fault
            assertFails { engine.tick(q, expected) }
            assertFalse("resume" in state.effects)
            assertTrue(Files.exists(root.resolve("slots/2026-01-04/failure.json")))
            assertTrue(Files.exists(root.resolve("failure.alert")))
        }
    }
    @Test fun `independent alert survives outcome persistence failures and native retention remains single use`() {
        for (fault in listOf("failure-record", "result-record", "retention")) fixture { engine, state, expected, root ->
            if (fault == "retention") {
                engine.tick(q, expected); state.at = state.at.plusSeconds(604800); state.effects.clear()
            }
            val date = WeeklyRestoreSchedule.sunday(state.at)
            state.hook = { phase ->
                if (fault == "failure-record" && phase == "verify") {
                    Files.createDirectory(root.resolve("slots/$date/failure.json")); error("unit failed persistence")
                }
                if (fault == "result-record" && phase == "resume") Files.createDirectory(root.resolve("slots/$date/result.json"))
                if (fault == "retention" && phase == "retention") error("unit lost native retention acknowledgement")
            }
            assertFails { engine.tick(q, expected) }
            assertTrue(Files.exists(root.resolve("failure.alert")))
            if (fault == "failure-record") assertFalse("resume" in state.effects)
            if (fault == "retention") assertTrue(Files.exists(root.parent.resolve("recovery-references/retention.pending")))
            val before = state.effects.toList(); state.hook = null; state.at = state.at.plusSeconds(604800)
            assertFails { engine.tick(q, expected) }; assertEquals(before, state.effects)
        }
    }
    @Test fun `changed inventory controller binding or retained markers fails before effects`() {
        for (fault in listOf("inventory", "controller", "binding", "owner-mode", "enrolled", "suspended", "alert")) fixture { engine, state, expected, root ->
            when (fault) {
                "inventory" -> Files.writeString(root.resolve("inventory.json"), "{}")
                "controller" -> state.controllerFails = true
                "binding" -> Files.writeString(root.resolve("binding.json"), "{}")
                "owner-mode" -> Files.setPosixFilePermissions(root.resolve("binding.json"), PosixFilePermissions.fromString("rw-r--r--"))
                "enrolled" -> Files.delete(root.resolve("enrolled"))
                "suspended" -> { engine.suspend(q, expected); Files.writeString(root.resolve("suspended"), "foreign") }
                "alert" -> { engine.signalFailure(q, expected); Files.writeString(root.resolve("failure.alert"), "foreign") }
            }
            assertFails { engine.tick(q, expected) }; assertTrue(state.effects.isEmpty())
            if (fault == "suspended") assertFails { engine.suspend(q, expected) }
            if (fault == "alert") assertFails { engine.signalFailure(q, expected) }
        }
    }
    @Test fun `foreign prior identities clock rollback and history exhaustion never create another target`() {
        for (fault in listOf("intent", "future", "history", "result-binding")) fixture { engine, state, expected, root ->
            engine.tick(q, expected); val attempt = root.resolve("slots/2026-01-04")
            when (fault) {
                "intent" -> Files.writeString(attempt.resolve("intent.json"), json.encodeToString(WeeklyRestoreSchedule.slot("b".repeat(64), "2026-01-04")))
                "future" -> Files.move(attempt, attempt.resolveSibling("2026-02-01"))
                "history" -> for (n in 1..128) Files.createDirectory(root.resolve("slots/extra-$n"))
                "result-binding" -> {
                    val result = json.decodeFromString<WeeklyRestoreResult>(Files.readString(attempt.resolve("result.json")))
                    Files.writeString(attempt.resolve("result.json"), json.encodeToString(result.copy(snapshot = result.snapshot.copy(bundleSha256 = "b".repeat(64)))))
                }
            }
            state.at = state.at.plusSeconds(604800)
            val before = state.effects.toList(); assertFails { engine.tick(q, expected) }; assertEquals(before, state.effects)
        }
    }
    @Test fun `enrollment refuses reuse changed plan stale binding and wrong owner without effects`() = fixture { engine, state, _, root ->
        val binding = json.decodeFromString<WeeklyRestoreBinding>(Files.readString(root.resolve("binding.json")))
        val inventory = Files.readAllBytes(root.resolve("inventory.json")); val plan = Files.readAllBytes(root.resolve("functional-plan.json"))
        assertFails { engine.enroll(inventory, binding, plan) }
        assertFails { engine.enroll(inventory, binding, plan + byteArrayOf(10)) }
        assertFails { engine.enroll(inventory, binding.copy(source = binding.source.copy(userId = 0)), plan) }
        assertFails { engine.enroll(inventory, binding.copy(source = binding.source.copy(enrolledAt = state.at.minusSeconds(120).toString())), plan) }
        assertFails { engine.enroll(inventory, binding.copy(requiredAssertions = setOf("other:assertion")), plan) }
        assertTrue(state.effects.isEmpty())
    }
    @Test fun `clock rollback suspension and rendered eight hour units`() = fixture { engine, state, expected, _ ->
        val units = engine.units(q, expected)
        assertTrue(units.getValue("p0v3-weekly-restore-$q.timer").contains("OnCalendar=Sun *-*-* 04:00:00 UTC"))
        val service = units.getValue("p0v3-weekly-restore-$q.service")
        assertTrue(service.contains("TimeoutStartSec=28800")); assertTrue(service.contains("Restart=no")); assertFalse(service.contains("ExecStop="))
        state.at = state.at.minusSeconds(1); assertFails { engine.tick(q, expected) }
        engine.signalFailure(q, expected); engine.signalFailure(q, expected)
        engine.suspend(q, expected); engine.suspend(q, expected)
        assertEquals("suspended", engine.tick(q, expected).status); assertTrue(state.effects.isEmpty())
    }
}
