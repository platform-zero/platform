package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NtfySandboxTest {
    private class Fake : ProbeCommands {
        val existing = mutableSetOf<String>()
        val running = mutableSetOf<String>()
        val calls = mutableListOf<List<String>>()
        override fun invoke(arguments: List<String>): String {
            calls.add(arguments)
            val name = arguments.find { it.startsWith("name=^") }?.removePrefix("name=^")?.removeSuffix("$")
            return when (arguments.first()) {
                "ps" -> if (name in (if ("-a" in arguments) existing else running)) name!! else ""
                "image" -> ""
                "create" -> { existing.add(arguments[arguments.indexOf("--name") + 1]); "created" }
                "start" -> { running.add(arguments[1]); "started" }
                "stop" -> { running.remove(arguments.last()); "stopped" }
                "rm" -> { existing.remove(arguments.last()); "removed" }
                else -> error("Unexpected Podman action")
            }
        }
    }
    private fun cleanup(vararg roots: Path) = roots.forEach { root ->
        Files.walk(root).use { entries -> entries.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
    }

    @Test fun `stop sqlite snapshot isolated restoration and namespace-only teardown`() {
        val sandbox = Files.createTempDirectory("p0v3-ntfy-")
        val backup = Files.createTempDirectory("p0v3-ntfy-backup-")
        val fake = Fake()
        val service = NtfySandbox(sandbox, backup) { fake }
        try {
            service.prepare()
            service.install()
            assertFailsWith<IllegalArgumentException> { service.install() }
            assertTrue(fake.calls.any { "--publish=127.0.0.1:18486:8080/tcp" in it && "--pull=never" in it &&
                "--read-only" in it && NtfySandbox.IMAGE in it })
            val data = sandbox.resolve("ntfy-fixture/data/cache.db")
            Files.writeString(data, "published-before")
            assertFailsWith<IllegalArgumentException> { service.snapshot("first") } // running SQLite
            service.stop()
            service.snapshot("first")
            service.start()
            assertTrue(fake.running.contains("p0v3-sandbox-ntfy-fixture"))
            assertTrue(Files.isRegularFile(backup.resolve("ntfy-fixture/first/.manifest")))
            Files.writeString(data, "mutated-after")
            service.restore("first")
            assertEquals("published-before", Files.readString(sandbox.resolve("ntfy-fixture/restores/first/cache.db")))
            assertEquals("mutated-after", Files.readString(data))
            assertTrue(fake.calls.any { "--publish=127.0.0.1:18487:8080/tcp" in it })
            assertFailsWith<IllegalArgumentException> { service.restore("first") }
            service.removeRestore("first")
            service.remove()
            assertTrue(fake.existing.isEmpty())
            assertTrue(Files.exists(backup.resolve("ntfy-fixture/first/cache.db"))) // remove never deletes backup
        } finally { cleanup(sandbox, backup) }
    }

    @Test fun `reject corrupted backup unsafe input symlink and foreign backup scope`() {
        val sandbox = Files.createTempDirectory("p0v3-ntfy-")
        val backup = Files.createTempDirectory("p0v3-ntfy-backup-")
        val outside = Files.createTempFile("p0v3-unrelated-", ".db")
        val fake = Fake()
        val service = NtfySandbox(sandbox, backup) { fake }
        try {
            Files.writeString(outside, "untouched")
            service.prepare()
            val data = sandbox.resolve("ntfy-fixture/data/cache.db")
            Files.writeString(data, "before")
            assertFailsWith<IllegalArgumentException> { service.snapshot("../sibling") }
            service.snapshot("first")
            Files.writeString(backup.resolve("ntfy-fixture/first/cache.db"), "corrupt")
            assertFailsWith<IllegalArgumentException> { service.restore("first") }
            assertFalse(Files.exists(sandbox.resolve("ntfy-fixture/restores/first")))
            Files.createSymbolicLink(sandbox.resolve("ntfy-fixture/data/cache.db-wal"), outside)
            assertFailsWith<IllegalArgumentException> { service.snapshot("second") }
            assertEquals("untouched", Files.readString(outside))
            Files.writeString(backup.resolve("unrelated"), "leave alone")
            assertEquals("leave alone", Files.readString(backup.resolve("unrelated")))
        } finally { cleanup(sandbox, backup); Files.delete(outside) }
    }

    @Test fun `require private reviewed roots`() {
        val sandbox = Files.createTempDirectory("p0v3-ntfy-")
        val backup = Files.createTempDirectory("p0v3-ntfy-backup-")
        try {
            val service = NtfySandbox(sandbox, backup) { Fake() }
            Files.setPosixFilePermissions(backup, setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE, PosixFilePermission.GROUP_READ))
            assertFailsWith<IllegalArgumentException> { service.prepare() }
            Files.setPosixFilePermissions(backup, setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE))
            service.prepare()
            assertFailsWith<IllegalArgumentException> { NtfySandbox(Path.of("/etc"), backup) { Fake() }.prepare() }
        } finally { cleanup(sandbox, backup) }
    }
}
