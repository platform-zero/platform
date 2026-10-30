package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SandboxBackupScheduleTest {
    @Test fun `loopback functional checker demands health publish cached read and approved probes`() {
        var healthCalls = 0
        val messages = mutableMapOf<Int, MutableSet<String>>()
        val checker = LoopbackTopicCheck { port, path, body ->
            when (path) {
                "v1/health" -> {
                    healthCalls++
                    if (healthCalls == 1) error("not ready yet")
                    "{\"healthy\":true}"
                }
                else -> if (body != null) {
                    messages.getOrPut(port) { mutableSetOf() }.add(body)
                    "{\"message\":\"$body\"}"
                } else {
                    messages.getOrPut(port) { mutableSetOf() }.joinToString("\n") { "{\"message\":\"$it\"}" }
                }
            }
        }
        checker.publishAndRead(18486, "p0v3-schedule-h1", "before-h1")
        assertTrue(healthCalls >= 2)
        assertFailsWith<IllegalStateException> { checker.assertCached(18487, "p0v3-schedule-h1", "before-h1") }
        messages.getOrPut(18487) { mutableSetOf() }.add("before-h1") // restored cache simulation
        checker.assertCached(18487, "p0v3-schedule-h1", "before-h1")
        checker.publishAndRead(18487, "p0v3-schedule-h1", "after-h1")
        assertFailsWith<IllegalArgumentException> { checker.publishAndRead(443, "p0v3-schedule-h1", "after-h1") }
        assertFailsWith<IllegalArgumentException> { checker.publishAndRead(18486, "../escape", "before-h1") }
        assertFailsWith<IllegalArgumentException> { checker.assertCached(18486, "p0v3-schedule-h1", "secret") }
    }
    private fun sha(path: Path) = MessageDigest.getInstance("SHA-256")
        .digest(Files.readAllBytes(path)).joinToString("") { "%02x".format(it) }
    private fun clean(root: Path) = Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }

    private class Fake(val root: Path) {
        val events = mutableListOf<String>()
        var ntfyRunning = true
        var restoredWrite = false
        var failPgBackup = false
        var failNtfySnapshot = false
        var badPgHash = false
        var failRestoredRow = false
        fun ntfy(): NtfyBackupOps = NtfyBackupOps(
            { events += "ntfy-prepare" },
            { check(ntfyRunning); events += "ntfy-require-running" },
            { check(ntfyRunning); ntfyRunning = false; events += "ntfy-stop" },
            { id ->
                check(!ntfyRunning); events += "ntfy-snapshot-$id"
                if (failNtfySnapshot) error("simulated SQLite backup failure")
                val dir = root.resolve("ntfy-fixture/$id")
                Files.createDirectories(dir)
                val cache = dir.resolve("cache.db")
                Files.writeString(cache, "cache-$id")
                Files.writeString(dir.resolve(".manifest"), "${hash(cache)} cache.db\n")
            },
            { ntfyRunning = true; events += "ntfy-start" },
            { id -> events += "ntfy-restore-$id" },
            { id -> events += "ntfy-remove-$id" }
        )
        fun postgres(): PostgresBackupOps = PostgresBackupOps(
            { events += "pg-prepare" },
            { events += "pg-write" },
            { id -> events += "pg-query-${id ?: "primary"}";
                if (id != null && failRestoredRow) "missing"
                else if (id != null && restoredWrite) "1:first\n2:restored" else "1:first" },
            { id ->
                events += "pg-backup-$id"
                if (failPgBackup) error("simulated pg_dump failure")
                val dir = root.resolve("postgres-fixture/$id")
                Files.createDirectories(dir)
                val dump = dir.resolve("backup.dump")
                Files.writeString(dump, "dump-$id")
                Files.writeString(dir.resolve(".sha256"), "${if (badPgHash) "bad" else hash(dump)}  backup.dump\n")
            },
            { id -> restoredWrite = false; events += "pg-restore-$id" },
            { id -> restoredWrite = true; events += "pg-write-restored-$id" },
            { id -> events += "pg-remove-$id" }
        )
        private fun hash(path: Path) = MessageDigest.getInstance("SHA-256")
            .digest(Files.readAllBytes(path)).joinToString("") { "%02x".format(it) }
        fun topic(): TopicCheck = object : TopicCheck {
            override fun publishAndRead(port: Int, topic: String, message: String) {
                events += "publish-$port-$message"
            }
            override fun assertCached(port: Int, topic: String, message: String) {
                check(events.contains("publish-18486-$message")); events += "cached-$port-$message"
            }
        }
    }

    @Test fun `due slots are deterministic idempotent and verify both isolated restores`() {
        val root = Files.createTempDirectory("p0v3-schedule-")
        try {
            val fake = Fake(root)
            var now = Instant.ofEpochSecond(3600)
            val schedule = SandboxBackupSchedule(root, fake.ntfy(), fake.postgres(), fake.topic(), { now })
            assertTrue(schedule.runDue())
            assertFalse(schedule.runDue())
            assertTrue(fake.ntfyRunning)
            assertTrue(fake.events.indexOf("ntfy-stop") < fake.events.indexOf("ntfy-snapshot-h1"))
            assertTrue(fake.events.indexOf("ntfy-snapshot-h1") < fake.events.indexOf("ntfy-start"))
            assertTrue(fake.events.indexOf("ntfy-start") < fake.events.indexOf("pg-backup-h1"))
            assertTrue(fake.events.contains("cached-18486-before-h1"))
            assertTrue(fake.events.contains("cached-18487-before-h1"))
            assertTrue(fake.events.contains("publish-18487-after-h1"))
            assertTrue(fake.events.containsAll(listOf("pg-write-restored-h1", "pg-remove-h1", "ntfy-remove-h1")))
            assertEquals("h1\nntfy=${sha(root.resolve("ntfy-fixture/h1/cache.db"))}\npostgres=${sha(root.resolve("postgres-fixture/h1/backup.dump"))}\n",
                Files.readString(root.resolve("sandbox-schedule/h1.ok")))
            now = Instant.ofEpochSecond(7200)
            assertTrue(schedule.runDue())
            assertTrue(Files.isRegularFile(root.resolve("sandbox-schedule/h2.ok")))
            assertTrue(Files.isRegularFile(root.resolve("sandbox-schedule/h1.ok"))) // no retention deletion
        } finally { clean(root) }
    }

    @Test fun `bounded runner waits for due time and executes exactly twice`() {
        val root = Files.createTempDirectory("p0v3-schedule-")
        try {
            val fake = Fake(root)
            var now = Instant.ofEpochSecond(3600)
            val schedule = SandboxBackupSchedule(root, fake.ntfy(), fake.postgres(), fake.topic(), { now },
                pause = { now = now.plusSeconds(3600) })
            assertEquals(2, schedule.runBounded(maxWaitSeconds = 2))
            assertEquals(2, fake.events.count { it.startsWith("ntfy-snapshot-") })
            assertFailsWith<IllegalArgumentException> { schedule.runBounded(3) }
        } finally { clean(root) }
    }

    @Test fun `partial postgres failure leaves marker and backup with ntfy restarted but prevents future slot`() {
        val root = Files.createTempDirectory("p0v3-schedule-")
        try {
            val fake = Fake(root).also { it.failPgBackup = true }
            var now = Instant.ofEpochSecond(3600)
            val schedule = SandboxBackupSchedule(root, fake.ntfy(), fake.postgres(), fake.topic(), { now })
            assertFailsWith<IllegalStateException> { schedule.runDue() }
            assertTrue(fake.ntfyRunning)
            assertTrue(Files.isRegularFile(root.resolve("sandbox-schedule/h1.started")))
            assertTrue(Files.isRegularFile(root.resolve("ntfy-fixture/h1/cache.db")))
            assertFalse(Files.exists(root.resolve("sandbox-schedule/h1.ok")))
            now = Instant.ofEpochSecond(7200)
            assertFailsWith<IllegalArgumentException> { schedule.runDue() }
            assertFalse(Files.exists(root.resolve("postgres-fixture/h2")))
        } finally { clean(root) }
    }

    @Test fun `SQLite snapshot failure restarts primary and blocks slot`() {
        val root = Files.createTempDirectory("p0v3-schedule-")
        try {
            val fake = Fake(root).also { it.failNtfySnapshot = true }
            val schedule = SandboxBackupSchedule(root, fake.ntfy(), fake.postgres(), fake.topic(), { Instant.ofEpochSecond(3600) })
            assertFailsWith<IllegalStateException> { schedule.runDue() }
            assertTrue(fake.ntfyRunning)
            assertTrue(fake.events.contains("ntfy-start"))
            assertFalse(fake.events.any { it.startsWith("pg-backup-") })
            assertTrue(Files.isRegularFile(root.resolve("sandbox-schedule/h1.started")))
        } finally { clean(root) }
    }

    @Test fun `corrupted dump hash blocks both restores without deleting backup`() {
        val root = Files.createTempDirectory("p0v3-schedule-")
        try {
            val fake = Fake(root).also { it.badPgHash = true }
            val schedule = SandboxBackupSchedule(root, fake.ntfy(), fake.postgres(), fake.topic(), { Instant.ofEpochSecond(3600) })
            assertFailsWith<IllegalArgumentException> { schedule.runDue() }
            assertTrue(fake.ntfyRunning)
            assertTrue(Files.isRegularFile(root.resolve("postgres-fixture/h1/backup.dump")))
            assertTrue(Files.isRegularFile(root.resolve("sandbox-schedule/h1.started")))
            assertFalse(fake.events.any { it.startsWith("ntfy-restore-") || it.startsWith("pg-restore-") })
        } finally { clean(root) }
    }

    @Test fun `failed functional SQL restore removes only its isolated containers`() {
        val root = Files.createTempDirectory("p0v3-schedule-")
        try {
            val fake = Fake(root).also { it.failRestoredRow = true }
            val schedule = SandboxBackupSchedule(root, fake.ntfy(), fake.postgres(), fake.topic(), { Instant.ofEpochSecond(3600) })
            assertFailsWith<IllegalStateException> { schedule.runDue() }
            assertTrue(fake.events.containsAll(listOf("pg-remove-h1", "ntfy-remove-h1")))
            assertTrue(Files.isRegularFile(root.resolve("sandbox-schedule/h1.started")))
            assertTrue(Files.isRegularFile(root.resolve("ntfy-fixture/h1/cache.db")))
            assertTrue(Files.isRegularFile(root.resolve("postgres-fixture/h1/backup.dump")))
        } finally { clean(root) }
    }

    @Test fun `unowned schedule and backup roots fail closed`() {
        val root = Files.createTempDirectory("p0v3-schedule-")
        try {
            val fake = Fake(root)
            val schedule = SandboxBackupSchedule(root, fake.ntfy(), fake.postgres(), fake.topic(), { Instant.ofEpochSecond(3600) })
            Files.writeString(root.resolve("unrelated"), "leave alone")
            assertTrue(schedule.runDue()) // unrelated backup children are not read or deleted
            assertEquals("leave alone", Files.readString(root.resolve("unrelated")))
            Files.writeString(root.resolve("sandbox-schedule/foreign"), "do not touch")
            assertFailsWith<IllegalArgumentException> { schedule.runDue() }
            assertEquals("do not touch", Files.readString(root.resolve("sandbox-schedule/foreign")))
            assertFailsWith<IllegalArgumentException> {
                SandboxBackupSchedule(Path.of("/etc"), fake.ntfy(), fake.postgres(), fake.topic()).runDue()
            }
        } finally { clean(root) }
    }
}
