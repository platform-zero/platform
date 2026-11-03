package net.datamancy.platform

import kotlin.test.*

class OfficeRuntimeTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("seafile", "mariadb", "valkey").map {
        AcquiredImage(it, "upstream", "example.org/app:1", image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `office is isolated authenticated and uses immutable generated assets`() {
        val spec = OfficeRuntime.spec(inventory)
        assertEquals(7, spec.processes.count { !it.oneShot })
        assertEquals(11, PrivateDeployment.validate(spec).size)
        assertTrue(spec.processes.all { it.capabilities.isEmpty() && it.apparmorProfile == "p0v3-private-v1" })
        val files = OfficeRuntime.inputs { host -> mapOf("ca.pem" to "CA-$host", "web.pem" to "leaf-$host", "web-key.pem" to "key-$host") }
        assertEquals(SingleUserRestore.inputNames(spec), files.keys)
        assertContains(files.getValue("office.json"), "\"rejectUnauthorized\":true")
        assertContains(files.getValue("office.json"), "\"allowMetaIPAddress\":false")
        assertContains(files.getValue("office.json"), "\"address\":\"*\",\"allowed\":false")
        assertContains(files.getValue("office.json"), "\"retries\":0")
        assertContains(files.getValue("seahub-settings.py"), "OfficeCallbackGuard")
        assertContains(files.getValue("seahub-settings.py"), "VERIFY_ONLYOFFICE_CERTIFICATE=True")
        assertContains(files.getValue("office-nginx.conf"), "secure_link_md5")
        assertContains(files.getValue("office-nginx.conf"), "ssl_protocols TLSv1.2 TLSv1.3")
        assertFalse("verysecretstring" in files.getValue("office.json"))
        assertFalse(spec.processes.single { it.id == "docservice" }.files.any { it.file in setOf("office-db.env", "users.json") })
        assertContains(spec.processes.single { it.id == "office-state-init" }.command.last(), "test -z")
        assertFalse(spec.processes.any { it.id in setOf("broker", "postgres", "converter") })
        assertFails { OfficeRuntime.spec(inventory.copy(images = inventory.images.dropLast(1))) }
        assertFails { OfficeRuntime.spec(inventory.copy(images = inventory.images.map { it.copy(os = "other") })) }
        assertFails { OfficeRuntime.spec(inventory, "../bad") }
        assertFails { SeafileRecovery.spec(spec, inventory, "other", "a".repeat(64)) }
    }
}
