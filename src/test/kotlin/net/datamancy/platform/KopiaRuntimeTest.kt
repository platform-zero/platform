package net.datamancy.platform

import kotlin.test.*

class KopiaRuntimeTest {
    private val pin = "example.org/kopia@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf(AcquiredImage("kopia", "upstream", "example.org/kopia:1", pin, "b".repeat(64), emptyList(), pin.substringAfter('@'), "amd64", "linux")))
    @Test fun `native encrypted repository initialization stays separate from serving`() {
        val spec = KopiaRuntime.spec(inventory)
        assertEquals(listOf("repository-init", "backup"), PrivateDeployment.validate(spec).map { it.id })
        assertTrue(spec.processes.first().oneShot)
        assertContains(spec.processes.first().command.last(), "test -z")
        val daemon = spec.processes.last()
        assertFalse(daemon.oneShot)
        assertContains(daemon.command, "--no-enable-actions")
        assertContains(daemon.command, "--no-grpc")
        assertContains(daemon.command, "--no-check-for-updates")
        assertFalse(daemon.command.contains("--insecure"))
        assertTrue(spec.processes.all { it.userId == 1000 && it.capabilities.isEmpty() })
        var n = 0
        val inputs = KopiaRuntime.inputs({ mapOf("ca.pem" to "unit", "web.pem" to "unit", "web-key.pem" to "unit") }, { (++n).toString().repeat(64) })
        assertEquals(SingleUserRestore.inputNames(spec), inputs.keys)
        assertFalse(inputs.getValue("repository.env").contains("SERVER_PASSWORD"))
        assertContains(inputs.getValue("server.env"), "KOPIA_SERVER_USERNAME=fixture-admin")
        assertContains(inputs.getValue("fixture.txt"), "synthetic")
        assertFails { KopiaRuntime.inputs({ emptyMap() }, { "a".repeat(64) }) }
        assertFails { KopiaRuntime.inputs({ emptyMap() }, { (++n).toString().repeat(64) }) }
        assertFails { KopiaRuntime.spec(inventory.copy(images = emptyList())) }
        assertFails { KopiaRuntime.spec(inventory.copy(images = inventory.images.map { it.copy(os = "other") })) }
        assertFails { KopiaRuntime.spec(inventory, "../escape") }
    }
}
