package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class IdentitySandboxTest {
    private class Fake : ProbeCommands {
        val calls = mutableListOf<List<String>>()
        val existing = mutableSetOf<String>()
        val running = mutableSetOf<String>()
        val networks = mutableSetOf<String>()
        var failDump = false
        override fun invoke(arguments: List<String>): String {
            calls += arguments
            val name = arguments.find { it.startsWith("name=^") }?.removePrefix("name=^")?.removeSuffix("$")
            return when (arguments.first()) {
                "ps" -> if (name in (if ("-a" in arguments) existing else running)) name!! else ""
                "image" -> ""
                "network" -> when (arguments[1]) {
                    "create" -> { networks.add(arguments.last()); "" }
                    "rm" -> { networks.remove(arguments.last()); "" }
                    "ls" -> networks.joinToString("\n")
                    else -> error("Unexpected network operation")
                }
                "create" -> { existing.add(arguments[arguments.indexOf("--name") + 1]); "created" }
                "start" -> { running.add(arguments[1]); "started" }
                "stop" -> { running.remove(arguments.last()); "stopped" }
                "rm" -> { existing.remove(arguments.last()); "removed" }
                "exec" -> {
                    if ("SELECT 1" in arguments) "1"
                    else { if (failDump && "pg_dump" in arguments) error("simulated pg_dump failure"); "" }
                }
                "cp" -> {
                    if (arguments[1].contains(":")) Files.writeString(Path.of(arguments.last()), "PGDMP-fake-only")
                    ""
                }
                else -> error("Unexpected private Podman operation")
            }
        }
    }
    private fun clean(vararg roots: Path) = roots.forEach { root ->
        Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
    }

    @Test fun `new private namespace creates distinct fake subjects and backs up config plus database`() {
        val base = Files.createTempDirectory("p0v3-identity-")
        val backups = Files.createTempDirectory("p0v3-identity-backup-")
        val fake = Fake()
        val service = IdentitySandbox(base, backups, { fake }, {})
        try {
            service.prepare()
            val secrets = base.resolve("identity-fixture/secrets")
            val networkConfig = base.resolve("identity-fixture/network-config")
            assertEquals(setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE),
                Files.getPosixFilePermissions(networkConfig))
            assertTrue("--network-config-dir=$networkConfig" in RootlessPodman(base.resolve("identity-fixture"), networkConfig).argumentsPrefix())
            Files.writeString(networkConfig.resolve("netavark.lock"), "")
            service.prepare() // Podman's scoped lock file is expected and never a shared-home definition
            assertEquals(setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
                Files.getPosixFilePermissions(secrets.resolve("realm.json")))
            assertTrue(Files.readString(secrets.resolve("realm.json")).contains(IdentitySandbox.HUMAN_SUB))
            assertTrue(Files.readString(secrets.resolve("realm.json")).contains(IdentitySandbox.AGENT_SUB))
            assertTrue(Files.readString(secrets.resolve("realm.json")).contains("\"directAccessGrantsEnabled\":true"))
            assertTrue(Files.readString(secrets.resolve("realm.json")).contains("\"standardFlowEnabled\":false"))
            assertTrue(service.fakePassword("sandbox-human") != service.fakePassword("sandbox-agent"))
            assertFailsWith<IllegalArgumentException> { service.fakePassword("gerald") }
            service.install()
            assertFailsWith<IllegalArgumentException> { service.install() }
            assertEquals(setOf("p0v3-identity-net"), fake.networks)
            val keycloakCreate = fake.calls.single { it.first() == "create" && IdentitySandbox.KEYCLOAK in it }
            assertTrue("--publish=127.0.0.1:18580:8080/tcp" in keycloakCreate)
            assertTrue(keycloakCreate.any { it.startsWith("--env-file=") })
            assertTrue(fake.calls.flatten().none { service.fakePassword("sandbox-human") in it ||
                service.fakePassword("sandbox-agent") in it })
            assertTrue(fake.calls.none { it.any { arg -> arg.startsWith("--publish") && "5432" in arg } })
            service.backup("first")
            val archive = backups.resolve("identity-fixture/first")
            assertTrue(Files.isRegularFile(archive.resolve("backup.dump")))
            assertTrue(Files.readString(archive.resolve(".sha256")).contains("realm.json"))
            assertTrue(Files.readString(archive.resolve(".sha256")).contains("keycloak.env"))
            assertTrue(Files.readString(archive.resolve(".sha256")).contains("pg-password"))
            assertTrue(fake.running.contains("p0v3-identity-kc")) // restarted after stopped backup
            Files.writeString(archive.resolve("backup.dump"), "tampered")
            assertFailsWith<IllegalArgumentException> { service.restore("first") }
            assertFalse(Files.exists(base.resolve("identity-fixture/restores/first")))
            Files.writeString(archive.resolve("backup.dump"), "PGDMP-fake-only")
            service.restore("first")
            assertTrue(fake.networks.contains("p0v3-identity-net-first"))
            assertTrue(fake.calls.any { it.first() == "exec" && "pg_restore" in it })
            assertTrue(fake.calls.any { "--publish=127.0.0.1:18581:8080/tcp" in it })
            service.removeRestore("first")
            service.remove()
            assertTrue(fake.existing.isEmpty() && fake.networks.isEmpty())
            assertTrue(Files.isRegularFile(archive.resolve("backup.dump"))) // no retention deletion
        } finally { clean(base, backups) }
    }

    @Test fun `partial failure preserves backup and restarts only fake keycloak`() {
        val base = Files.createTempDirectory("p0v3-identity-")
        val backups = Files.createTempDirectory("p0v3-identity-backup-")
        val fake = Fake().also { it.failDump = true }
        val service = IdentitySandbox(base, backups, { fake }, {})
        try {
            service.prepare(); service.install()
            assertFailsWith<IllegalStateException> { service.backup("partial") }
            assertTrue(fake.running.contains("p0v3-identity-kc"))
            assertFalse(Files.exists(backups.resolve("identity-fixture/partial")))
            assertTrue(Files.list(backups.resolve("identity-fixture")).use { it.anyMatch { p -> p.fileName.toString().startsWith(".pending-") } })
            assertFailsWith<IllegalArgumentException> { service.backup("../escape") }
            service.remove()
        } finally { clean(base, backups) }
    }

    @Test fun `reject tampered backup symlinked input and unrelated roots`() {
        val base = Files.createTempDirectory("p0v3-identity-")
        val backups = Files.createTempDirectory("p0v3-identity-backup-")
        val outside = Files.createTempFile("p0v3-untouched-", ".txt")
        val service = IdentitySandbox(base, backups, { Fake() }, {})
        try {
            Files.writeString(outside, "untouched")
            service.prepare()
            Files.delete(base.resolve("identity-fixture/secrets/realm.json"))
            Files.createSymbolicLink(base.resolve("identity-fixture/secrets/realm.json"), outside)
            assertFailsWith<IllegalArgumentException> { service.install() }
            assertEquals("untouched", Files.readString(outside))
            assertFailsWith<IllegalArgumentException> { IdentitySandbox(Path.of("/etc"), backups, { Fake() }).prepare() }
            val networkConfig = base.resolve("identity-fixture/network-config")
            Files.setPosixFilePermissions(networkConfig, setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE, PosixFilePermission.GROUP_READ))
            assertFailsWith<IllegalArgumentException> {
                RootlessPodman(base.resolve("identity-fixture"), networkConfig).argumentsPrefix()
            }
        } finally { clean(base, backups); Files.delete(outside) }
    }
}
