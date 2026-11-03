package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

class SogoMailRecoveryTest {
    private val inventory = AcquiredInventory(1, "candidate", listOf("postgres", "sogo", "memcached").map {
        val pin = "example.org/$it@sha256:" + "a".repeat(64)
        AcquiredImage(it, "upstream", "example.org/$it:1", pin, "b".repeat(64), emptyList(), pin.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `three cold volume guards replace destructive initialization`() {
        val source = SogoMailRuntime.spec(inventory, "source")
        val target = SogoMailRecovery.spec(source, inventory, "smrestore-unit", "a".repeat(64))
        assertEquals(source.volumes, target.volumes)
        assertEquals(SingleUserRestore.inputNames(source), SingleUserRestore.inputNames(target))
        for (id in listOf("database-init", "mail-init", "home-restore-check")) {
            val guard = target.processes.single { it.id == id }
            assertTrue(guard.oneShot)
            assertContains(guard.command.last(), "test ! -L")
            assertContains(guard.command.last(), ".restore-in-progress")
            assertContains(guard.command.last(), "stat -c %s")
            assertContains(guard.command.last(), "a".repeat(64))
            assertFalse(guard.command.last().contains("initdb"))
        }
        val sql = target.processes.single { it.id == "accounts-init" }
        assertEquals("/bin/sh", sql.entrypoint)
        assertContains(sql.command.last(), "PGUSER=sogo")
        assertContains(sql.command.last(), "SELECT")
        assertFalse(sql.command.last().contains("setup.sql"))
        assertContains(target.processes.single { it.id == "sogod" }.dependencies, "home-restore-check")
        for (id in listOf("database", "cache", "mail", "groupware")) assertEquals(source.processes.single { it.id == id }, target.processes.single { it.id == id })
        assertFails { SogoMailRecovery.spec(source, inventory, "source", "a".repeat(64)) }
        assertFails { SogoMailRecovery.spec(source, inventory, "smrestore-unit", "bad") }
        assertFails { SogoMailRecovery.spec(source.copy(processes = source.processes.drop(1)), inventory, "smrestore-unit", "a".repeat(64)) }
        assertFails { SogoMailRecovery.spec(source, inventory, "../escape", "a".repeat(64)) }
    }
    @Test fun `recovered input preparation rejects replacement and symlinks`() {
        val root = Files.createTempDirectory("sogo-mail-recovery-unit")
        fun private(path: Path, text: String) { Files.writeString(path, text); Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------")) }
        try {
            val recovered = Files.createDirectory(root.resolve("recovered"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            val base = Files.createDirectory(root.resolve("deployments"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            val source = SogoMailRuntime.spec(inventory, "source")
            private(recovered.resolve("source-spec.json"), Json.encodeToString(source))
            SogoMailRuntime.inputs { host -> mapOf("ca.pem" to "$host-ca", "web.pem" to "$host-cert", "web-key.pem" to "$host-key") }.forEach { (name, content) -> private(recovered.resolve(name), content) }
            val path = SogoMailRecovery.prepare(inventory, recovered, "smrestore-unit", base)
            assertEquals(path, SogoMailRecovery.prepare(inventory, recovered, "smrestore-unit", base))
            private(recovered.resolve("mail-ca.pem"), "changed")
            assertFails { SogoMailRecovery.prepare(inventory, recovered, "smrestore-unit", base) }
            assertFails { SogoMailRecovery.prepare(inventory, Path.of("relative"), "smrestore-other", base) }
            val link = root.resolve("link"); Files.createSymbolicLink(link, recovered)
            assertFails { SogoMailRecovery.prepare(inventory, link, "smrestore-other", base) }
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}
