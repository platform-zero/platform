package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*

class FireflyRuntimeTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("postgres", "valkey", "ntfy", "firefly-iii").map {
        AcquiredImage(it, "upstream", "example.org/app:1", image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `financial recovery binds supported recipe recovered keys and skips data mutations`() {
        val source = FireflyRuntime.spec(inventory, "source")
        val restored = FireflyRecovery.spec(source, inventory, "restored", "a".repeat(64))
        assertEquals(source.volumes, restored.volumes)
        val checks = restored.processes.filter { it.id in setOf("firefly-files-init", "firefly-migrate") }
        assertTrue(checks.all { it.command.joinToString(" ").contains(".p0v3-restore-complete") })
        assertTrue(checks.none { it.command.joinToString(" ").let { command -> "cp -R" in command || "artisan" in command } })
        assertContains(checks.last().command.last(), "SELECT count(*) FROM users")
        assertFails { FireflyRecovery.spec(source, inventory, "source", "a".repeat(64)) }
        assertFails { FireflyRecovery.spec(source, inventory, "restored", "bad") }
        assertFails { FireflyRecovery.spec(source.copy(processes = source.processes.dropLast(1)), inventory, "restored", "a".repeat(64)) }
        val base = Files.createTempDirectory("finance-recovery-unit-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try {
            val manifest = FireflyRuntime.prepare(inventory, base, "source")
            val recovered = Files.createDirectory(base.resolve("recovered"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            Files.copy(manifest, recovered.resolve("source-spec.json"))
            SingleUserRestore.inputNames(source).forEach { Files.copy(base.resolve("source").resolve(it), recovered.resolve(it)) }
            val path = FireflyRecovery.prepare(inventory, recovered, "restored", base)
            assertEquals(path, FireflyRecovery.prepare(inventory, recovered, "restored", base))
            assertContentEquals(Files.readAllBytes(base.resolve("source/firefly.env")), Files.readAllBytes(base.resolve("restored/firefly.env")))
            Files.writeString(recovered.resolve("firefly.env"), "CHANGED=forbidden\n")
            assertFails { FireflyRecovery.prepare(inventory, recovered, "restored", base) }
            assertFails { FireflyRecovery.prepare(inventory, java.nio.file.Path.of("relative"), "restored", base) }
        } finally { Files.walk(base).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `financial application has dedicated database and non-root split web processes`() {
        val spec = FireflyRuntime.spec(inventory)
        assertEquals(setOf("postgres-init", "postgres", "firefly-db-init", "firefly-files-init", "firefly-migrate", "php", "firefly"), PrivateDeployment.validate(spec).map { it.id }.toSet())
        val web = spec.processes.single { it.id == "firefly" }
        assertNull(web.environmentFile)
        assertTrue(web.volumes.isEmpty())
        assertEquals(33, web.userId)
        assertTrue(spec.processes.all { it.capabilities.isEmpty() })
        assertTrue(spec.processes.single { it.id == "firefly-migrate" }.oneShot)
        val inputs = FireflyRuntime.inputs()
        assertEquals((spec.processes.mapNotNull { it.environmentFile } + spec.processes.flatMap { it.files.map { f -> f.file } }).toSet(), inputs.keys)
        assertContains(inputs.getValue("firefly.env"), "APP_ENV=production")
        assertContains(inputs.getValue("firefly.env"), "DB_CONNECTION=pgsql")
        assertContains(inputs.getValue("firefly.env"), "MAIL_MAILER=array")
        assertContains(inputs.getValue("nginx.conf"), "location = /index.php")
        assertFalse(inputs.getValue("firefly.env").contains("APP_DEBUG=true"))
        assertNotEquals(inputs.getValue("firefly.env"), FireflyRuntime.inputs().getValue("firefly.env"))
        assertFails { FireflyRuntime.spec(inventory.copy(images = inventory.images.filterNot { it.product == "firefly-iii" })) }
        assertFails { FireflyRuntime.spec(inventory.copy(images = inventory.images.map { if (it.product == "firefly-iii") it.copy(os = "other") else it })) }
        val base = Files.createTempDirectory("firefly-unit-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try {
            val path = FireflyRuntime.prepare(inventory, base)
            val env = Files.readString(base.resolve("firefly/firefly.env"))
            assertEquals(spec, PrivateDeployment.read(path))
            assertEquals(path, FireflyRuntime.prepare(inventory, base))
            assertEquals(env, Files.readString(base.resolve("firefly/firefly.env")))
        } finally { Files.walk(base).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}
