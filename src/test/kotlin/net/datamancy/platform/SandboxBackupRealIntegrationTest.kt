package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import org.junit.jupiter.api.Assumptions.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Explicit opt-in; no daemon, timer, account changes, image pulls or production mounts. */
class SandboxBackupRealIntegrationTest {
    @Test fun `two timed sandbox slots verify ntfy and postgres independent functional restores`() {
        assumeTrue(System.getenv("P0V3_SANDBOX_BACKUP_INTEGRATION") == "1", "Requires reviewed v3 roots and preloaded official digests")
        val n = NtfySandbox.real()
        val p = PostgresSandbox.real()
        val backup = Path.of("/mnt/media/p0-v3/backup")
        val scheduleDir = backup.resolve("sandbox-schedule")
        val previous = if (Files.isDirectory(scheduleDir, NOFOLLOW_LINKS)) Files.list(scheduleDir).use { entries ->
            entries.map { it.fileName.toString() }.filter { it.endsWith(".ok") }.toList().toSet()
        } else emptySet()
        var nInstalled = false
        var pInstalled = false
        try {
            n.prepare()
            p.prepare()
            n.install()
            nInstalled = true
            p.install()
            pInstalled = true
            val runner = SandboxBackupSchedule.real(periodSeconds = 3)
            assertEquals(2, runner.runBounded(maxRuns = 2, maxWaitSeconds = 120))
            val fresh = Files.list(scheduleDir).use { entries -> entries.map { it.fileName.toString() }
                .filter { it.endsWith(".ok") && it !in previous }.toList().sorted() }
            assertEquals(2, fresh.size)
            fresh.forEach { file ->
                val id = file.removeSuffix(".ok")
                val receipt = Files.readString(scheduleDir.resolve(file))
                assertTrue(receipt.startsWith("$id\nntfy="))
                assertTrue(receipt.contains("\npostgres="))
                assertTrue(Files.isRegularFile(backup.resolve("ntfy-fixture/$id/.manifest"), NOFOLLOW_LINKS))
                assertTrue(Files.isRegularFile(backup.resolve("postgres-fixture/$id/.sha256"), NOFOLLOW_LINKS))
                LoopbackTopicCheck().assertCached(18486, "p0v3-schedule-$id", "before-$id")
            }
            assertEquals("1:first", p.query())
        } finally {
            if (pInstalled) runCatching { p.remove() }
            if (nInstalled) runCatching { n.remove() }
            // Preserve all backups, restored data, fixture credentials and images for inspection.
        }
    }
}
