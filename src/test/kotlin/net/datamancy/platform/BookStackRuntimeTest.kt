package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*

class BookStackRuntimeTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("mariadb", "memcached", "bookstack").map {
        AcquiredImage(it, "upstream", "example.org/app:1", image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `v2 wiki uses original OIDC owner and shared MariaDB rather than copying provider authority`() : Unit {
        val fresh = BookStackRuntime.releaseFragment(inventory, "canonical-release-v2")
        assertEquals("bookstack", fresh.product)
        assertEquals(setOf("bookstack-data"), fresh.providerNetworks.getValue("mariadb"))
        assertEquals(setOf("bookstack-web"), fresh.webNetworks)
        assertFalse(fresh.spec.processes.any { it.id in setOf("mariadb", "memcached") })
        assertEquals(setOf("bookstack_migrate", "bookstack_runtime"), fresh.spec.databaseAccess.map { it.principal }.toSet())
        val cold = BookStackRuntime.releaseColdFragment(fresh)
        assertEquals(fresh.spec.volumes, cold.spec.volumes)
        assertEquals(setOf("bookstack-php", "bookstack"), cold.spec.processes.map { it.id }.toSet())
        assertTrue(cold.spec.processes.none { it.environmentFile == "bookstack-migration.env" })
        assertEquals(listOf("mariadb"), cold.spec.processes.single { it.id == "bookstack-php" }.dependencies)
        val inputs = BookStackRuntime.releaseInputs(CanonicalMariaCredentialPair("2".repeat(64), "1".repeat(64)),
            "base64:" + "A".repeat(43) + "=", "123e4567-e89b-12d3-a456-426614174000",
            "3".repeat(64), "4".repeat(64))
        assertEquals(PrivateDeployment.inputNames(fresh.spec).toSet() - setOf("mariadb-ca.pem"), inputs.keys)
        assertContains(inputs.getValue("bookstack-runtime.env"), "AUTH_METHOD=oidc")
        // Pinned BookStack v26.09.2 app/Config/database.php reads MYSQL_ATTR_SSL_CA,
        // not DB_SSL_CA or the invented DB_SSL_VERIFY_CERT switch.
        for (file in listOf("bookstack-runtime.env", "bookstack-migration.env")) {
            assertContains(inputs.getValue(file), "MYSQL_ATTR_SSL_CA=/run/secrets/mariadb-ca.pem")
            assertFalse(inputs.getValue(file).contains("DB_SSL_CA="))
        }
        assertContains(inputs.getValue("bookstack-admin.php"), "'--external-auth-id'")
        assertFalse(inputs.getValue("bookstack-runtime.env").contains("P0V3_INITIAL_ADMIN_PASSWORD"))
        assertFails { BookStackRuntime.releaseColdFragment(cold) }
    }

    @Test fun `private wiki uses dedicated database and replaces default administrator before serving`() {
        val spec = BookStackRuntime.spec(inventory)
        assertEquals(6, PrivateDeployment.validate(spec).size)
        assertEquals(listOf("mariadb", "php", "bookstack"), spec.processes.filterNot { it.oneShot }.map { it.id })
        assertContains(spec.processes.first().command.last(), "CREATE DATABASE bookstack")
        val web = spec.processes.last()
        assertNull(web.environmentFile)
        assertEquals(listOf(RuntimeMount("uploads", "/config/www/uploads")), web.volumes)
        assertEquals("/login", web.readinessHttpPath)
        assertTrue(spec.processes.all { it.capabilities.isEmpty() })
        val inputs = BookStackRuntime.inputs()
        assertEquals(SingleUserRestore.inputNames(spec), inputs.keys)
        assertContains(inputs.getValue("admin.php"), "'--initial' => true")
        assertContains(inputs.getValue("admin.php"), "admin@admin.com")
        assertContains(inputs.getValue("bookstack.env"), "MAIL_DRIVER=array")
        assertFalse(inputs.getValue("bookstack.env").contains("P0V3_FIXTURE_PASSWORD"))
        assertContains(inputs.getValue("nginx.conf"), "/app/www/public/index.php")
        assertNotEquals(inputs, BookStackRuntime.inputs())
        assertFails { BookStackRuntime.spec(inventory.copy(images = inventory.images.filterNot { it.product == "bookstack" })) }
        assertFails { BookStackRuntime.spec(inventory.copy(images = inventory.images.map { if (it.product == "bookstack") it.copy(os = "other") else it })) }
        val base = Files.createTempDirectory("bookstack-unit-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try {
            val path = BookStackRuntime.prepare(inventory, base)
            val before = Files.readAllBytes(base.resolve("bookstack/admin.env"))
            assertEquals(spec, PrivateDeployment.read(path))
            assertEquals(path, BookStackRuntime.prepare(inventory, base))
            assertContentEquals(before, Files.readAllBytes(base.resolve("bookstack/admin.env")))
        } finally { Files.walk(base).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}
