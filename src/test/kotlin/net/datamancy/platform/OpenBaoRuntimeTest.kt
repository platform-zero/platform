package net.datamancy.platform

import kotlin.test.*

class OpenBaoRuntimeTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf(
        AcquiredImage("openbao", "upstream", "example.org/app:1", image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")))
    @Test fun `private backend persists encrypted state without embedding root or unseal credentials`() {
        val spec = OpenBaoRuntime.spec(inventory)
        assertEquals(spec, OpenBaoRuntime.coldRestoreSpec(spec))
        assertFailsWith<IllegalArgumentException> { OpenBaoRuntime.coldRestoreSpec(spec.copy(processes = spec.processes.map { it.copy(oneShot = true) })) }
        assertFailsWith<IllegalArgumentException> { OpenBaoRuntime.coldRestoreSpec(spec.copy(processes = spec.processes.map { it.copy(command = listOf("server", "-dev")) })) }
        val process = PrivateDeployment.validate(spec).single()
        assertEquals(1000, process.userId)
        assertTrue(process.capabilities.isEmpty())
        assertFalse(process.oneShot)
        assertEquals(listOf(RuntimeVolume("data", 1000)), spec.volumes)
        val inputs = OpenBaoRuntime.inputs { mapOf("ca.pem" to "ca", "web.pem" to "cert", "web-key.pem" to "key") }
        assertEquals(SingleUserRestore.inputNames(spec), inputs.keys)
        assertContains(inputs.getValue("bao.hcl"), "tls_min_version = \"tls12\"")
        assertContains(inputs.getValue("bao.hcl"), "storage \"raft\"")
        assertContains(inputs.getValue("bao.env"), "BAO_CACERT=/run/secrets/ca.pem")
        assertFalse(inputs.values.any { "root_token" in it || "unseal" in it || "dev-root-token" in it })
        assertContains(process.readiness.last(), "code -eq 2") // Explicit sealed API availability, not operational health.
        assertContains(process.readiness.last(), "code -eq 1") // Fresh uninitialized first-install can be explicitly initialized later.
        assertContains(process.readiness.last(), "initialized")
        assertContains(process.readiness.last(), "sealed")
        assertFails { OpenBaoRuntime.spec(inventory.copy(images = emptyList())) }
        assertFails { OpenBaoRuntime.spec(inventory.copy(images = inventory.images.map { it.copy(os = "windows") })) }
    }
}
