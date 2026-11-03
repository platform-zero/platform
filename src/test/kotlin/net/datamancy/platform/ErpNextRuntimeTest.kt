package net.datamancy.platform

import kotlin.test.*
import kotlinx.serialization.json.*

class ErpNextRuntimeTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("erpnext", "mariadb", "valkey").map {
        AcquiredImage(it, "upstream", "example.org/app:1", image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `native site installation retires its database privilege and isolates credentials`() {
        val spec = ErpNextRuntime.spec(inventory)
        assertEquals(12, PrivateDeployment.validate(spec).size)
        assertEquals(8, spec.processes.count { !it.oneShot })
        assertTrue(spec.processes.all { it.userId != 0 && it.capabilities.isEmpty() && it.apparmorProfile == "p0v3-private-v1" })
        val files = ErpNextRuntime.inputs { mapOf("ca.pem" to "ca", "web.pem" to "cert", "web-key.pem" to "key") }
        assertEquals(SingleUserRestore.inputNames(spec), files.keys)
        assertTrue(spec.processes.filterNot { it.oneShot }.none { it.environmentFile in setOf("bootstrap.env", "installer.env") })
        assertContains(spec.processes.single { it.id == "installer-retire" }.command.last(), "DROP USER")
        assertContains(files.getValue("site-init.py"), "force=False")
        assertContains(files.getValue("site-init.py"), "Existing or interrupted site retained")
        assertContains(files.getValue("site-init.py"), "if not __debug__:")
        assertContains(files.getValue("queue.conf"), "appendonly yes")
        assertContains(files.getValue("cache.conf"), "appendonly no")
        val common = Json.parseToJsonElement(files.getValue("common-site.json")).jsonObject
        assertEquals(false, common.getValue("server_script_enabled").jsonPrimitive.boolean)
        assertEquals(1, common.getValue("pause_scheduler").jsonPrimitive.int)
        assertEquals("backend", common.getValue("webserver_host").jsonPrimitive.content)
        assertEquals(8000, common.getValue("webserver_port").jsonPrimitive.int)
        assertContains(files.getValue("nginx.conf"), "default ${'$'}http_origin;")
        assertContains(files.getValue("nginx.conf"), "proxy_set_header Origin ${'$'}erp_origin;")
        assertFalse("proxy_set_header Origin https:" in files.getValue("nginx.conf"))
        assertTrue(spec.processes.filter { it.id in setOf("worker", "scheduler", "websocket") }.all { it.command.first() == "/run/secrets/process-init.py" })
        assertTrue(common.getValue("redis_queue").jsonPrimitive.content.startsWith("redis://:"))
        assertFails { ErpNextRuntime.spec(inventory.copy(images = inventory.images.drop(1))) }
        assertFails { ErpNextRuntime.spec(inventory.copy(images = inventory.images.map { it.copy(os = "other") })) }
        assertFails { ErpNextRuntime.spec(inventory, "../bad") }
    }
}
