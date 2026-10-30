package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import org.junit.jupiter.api.Assumptions.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Deliberately opt-in: performs real side effects only inside the dedicated PostgreSQL v3 sandbox. */
class PostgresRealIntegrationTest {
    @Test fun `official digest SQL consistent dump isolated restore and two reinstalls`() {
        assumeTrue(System.getenv("P0V3_POSTGRES_SANDBOX_INTEGRATION") == "1", "Requires reviewed roots and preloaded pinned image")
        val id = "it" + System.nanoTime().toString(36).replace('-', 'x').takeLast(14)
        val db = PostgresSandbox.real()
        db.prepare()
        try {
            db.install()
            db.writeFixture()
            assertEquals("1:first", db.query())
            db.backup(id)
            val dir = Path.of("/mnt/media/p0-v3/backup/postgres-fixture/$id")
            val dump = dir.resolve("backup.dump")
            assertTrue(Files.size(dump) > 0)
            val hash = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(dump))
                .joinToString("") { "%02x".format(it) }
            assertEquals("$hash  backup.dump\n", Files.readString(dir.resolve(".sha256")))
            db.restore(id)
            assertEquals("1:first", db.query(id))
            db.writeRestored(id)
            assertEquals("1:first\n2:restored", db.query(id))
            assertEquals("1:first", db.query()) // restored target cannot mutate primary
            db.removeRestore(id)
            db.remove()
            repeat(2) {
                db.install()
                assertEquals("1:first", db.query())
                db.writeFixture()
                db.stop()
                db.remove()
            }
        } finally {
            runCatching { db.removeRestore(id) }
            runCatching { db.remove() }
            // Never remove data, fake credential, images or backups automatically.
        }
    }
}
