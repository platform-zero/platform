package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PostgresSandboxTest {
    private class Fake : ProbeCommands {
        val existing = mutableSetOf<String>()
        val running = mutableSetOf<String>()
        val calls = mutableListOf<List<String>>()
        override fun invoke(arguments: List<String>): String {
            calls.add(arguments)
            val filter = arguments.find { it.startsWith("name=^") }?.removePrefix("name=^")?.removeSuffix("$")
            return when (arguments.first()) {
                "image" -> ""
                "ps" -> if (filter in (if ("-a" in arguments) existing else running)) filter!! else ""
                "create" -> { existing.add(arguments[arguments.indexOf("--name") + 1]); "created" }
                "start" -> { running.add(arguments[1]); "started" }
                "stop" -> { running.remove(arguments.last()); "stopped" }
                "rm" -> { existing.remove(arguments.last()); "removed" }
                "cp" -> { Files.writeString(Path.of(arguments.last()), "PGDMP-fake-test-only"); "copied" }
                "exec" -> if ("SELECT 1" in arguments) "1" else if ("-tA" in arguments) "1:first" else "ok"
                else -> error("Unexpected Podman action")
            }
        }
    }
    private fun cleanup(vararg paths: Path) = paths.forEach { root ->
        Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
    }

    @Test fun `private fake credential pg_dump restore and two reinstalls never use other stores`() {
        val base = Files.createTempDirectory("p0v3-pg-")
        val backup = Files.createTempDirectory("p0v3-pg-backup-")
        val fake = Fake()
        val sandbox = PostgresSandbox(base, backup, { fake }, {})
        try {
            sandbox.prepare()
            val secret = base.resolve("postgres-fixture/secrets/fake-password")
            assertEquals(setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE), Files.getPosixFilePermissions(secret))
            assertEquals(64L, Files.size(secret))
            sandbox.install()
            assertFailsWith<IllegalArgumentException> { sandbox.install() }
            val create = fake.calls.first { it.first() == "create" }
            assertTrue("--publish=127.0.0.1:15432:5432/tcp" in create && "--pull=never" in create)
            assertTrue("--env=POSTGRES_PASSWORD_FILE=/run/secrets/p0v3-password" in create)
            assertTrue(create.any { it.endsWith("/run/secrets/p0v3-password:ro") })
            assertFalse(fake.calls.flatten().any { Files.readString(secret) in it })
            sandbox.writeFixture()
            assertEquals("1:first", sandbox.query())
            sandbox.backup("first")
            val archive = backup.resolve("postgres-fixture/first")
            assertTrue(Files.readString(archive.resolve(".sha256")).contains("backup.dump"))
            assertFailsWith<IllegalArgumentException> { sandbox.backup("first") }
            sandbox.restore("first")
            assertTrue(fake.calls.any { "--publish=127.0.0.1:15433:5432/tcp" in it })
            assertTrue(fake.calls.any { it.first() == "exec" && "pg_restore" in it })
            sandbox.writeRestored("first")
            assertEquals("1:first", sandbox.query("first"))
            Files.writeString(archive.resolve("backup.dump"), "corrupted")
            assertFailsWith<IllegalArgumentException> { sandbox.restore("first") }
            sandbox.removeRestore("first")
            sandbox.remove()
            repeat(2) { sandbox.install(); sandbox.writeFixture(); sandbox.stop(); sandbox.remove() }
            assertTrue(fake.existing.isEmpty())
            assertTrue(Files.isRegularFile(archive.resolve("backup.dump")))
        } finally { cleanup(base, backup) }
    }

    @Test fun `backup hash and namespace guards reject tampering without touching unrelated data`() {
        val base = Files.createTempDirectory("p0v3-pg-")
        val backup = Files.createTempDirectory("p0v3-pg-backup-")
        val outside = Files.createTempFile("p0v3-unrelated-", ".txt")
        val sandbox = PostgresSandbox(base, backup, { Fake() })
        try {
            Files.writeString(outside, "untouched")
            sandbox.prepare()
            assertFailsWith<IllegalArgumentException> { sandbox.backup("../escape") }
            assertFailsWith<IllegalArgumentException> { sandbox.restore("missing") }
            Files.setPosixFilePermissions(backup, setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE, PosixFilePermission.GROUP_READ))
            assertFailsWith<IllegalArgumentException> { sandbox.install() }
            Files.setPosixFilePermissions(backup, setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE))
            Files.delete(base.resolve("postgres-fixture/secrets/fake-password"))
            Files.createSymbolicLink(base.resolve("postgres-fixture/secrets/fake-password"), outside)
            assertFailsWith<IllegalArgumentException> { sandbox.install() }
            assertEquals("untouched", Files.readString(outside))
            assertFailsWith<IllegalArgumentException> { PostgresSandbox(Path.of("/etc"), backup, { Fake() }).prepare() }
        } finally { cleanup(base, backup); Files.delete(outside) }
    }
}
