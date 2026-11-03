package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*

class BookStackRuntimeTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("mariadb", "memcached", "bookstack").map {
        AcquiredImage(it, "upstream", "example.org/app:1", image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")
    })
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
