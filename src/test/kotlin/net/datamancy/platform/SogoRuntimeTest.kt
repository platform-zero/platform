package net.datamancy.platform

import kotlin.test.*

class SogoRuntimeTest {
    private val inventory = AcquiredInventory(1, "candidate", listOf("postgres", "sogo", "memcached").map {
        val pin = "example.org/$it@sha256:" + "a".repeat(64)
        AcquiredImage(it, "upstream", "example.org/$it:1", pin, "b".repeat(64), emptyList(), pin.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `native groupware retires initializer and separates TLS database and web credentials`() {
        val spec = SogoRuntime.spec(inventory)
        val inputs = SogoRuntime.inputs { host -> mapOf("ca.pem" to "$host-ca", "web.pem" to "$host-web", "web-key.pem" to "$host-key") }
        assertEquals(SingleUserRestore.inputNames(spec), inputs.keys)
        assertEquals(4, spec.processes.count { !it.oneShot })
        assertEquals(setOf("database-init", "accounts-init"), spec.processes.filter { it.oneShot }.map { it.id }.toSet())
        assertTrue(spec.processes.all { it.userId > 0 && it.capabilities.isEmpty() && it.apparmorProfile == "p0v3-private-v1" })
        assertEquals(setOf("database", "home"), spec.volumes.map { it.id }.toSet())
        assertFalse(spec.processes.filterNot { it.oneShot }.any { it.environmentFile == "bootstrap.env" })
        assertContains(inputs.getValue("setup.sql"), "gen_salt('bf',12)")
        assertContains(inputs.getValue("setup.sql"), "PASSWORD NULL NOLOGIN")
        assertContains(inputs.getValue("setup.sql"), "GRANT SELECT ON users TO sogo")
        assertContains(inputs.getValue("sogo.env"), "PGSSLMODE=verify-full")
        assertContains(inputs.getValue("bootstrap.env"), "PGSSLMODE=verify-full")
        assertContains(inputs.getValue("sogo.conf"), "SOGoTrustProxyAuthentication = NO")
        assertContains(inputs.getValue("sogo.conf"), "SOGoXSRFValidationEnabled = YES")
        assertContains(inputs.getValue("sogo.conf"), "SOGoAppointmentSendEMailNotifications = NO")
        assertContains(inputs.getValue("sogo.conf"), "127.0.0.1:9")
        assertContains(inputs.getValue("apache.conf"), "RequestHeader unset x-webobjects-remote-user")
        assertContains(inputs.getValue("apache.conf"), "[R=503,L]")
        assertContains(inputs.getValue("apache.conf"), "[R=421,L]")
        assertContains(inputs.getValue("apache.conf"), "HTTP:Origin")
        assertEquals("database-ca", inputs.getValue("db-ca.pem"))
        assertEquals("groupware-ca", inputs.getValue("ca.pem"))
        val credentials = inputs.getValue("bootstrap.env").lineSequence().filter { "PASSWORD=" in it }.map { it.substringAfter('=') }.toList()
        assertEquals(5, credentials.size)
        assertEquals(5, credentials.toSet().size)
        assertTrue(credentials.all { Regex("[a-f0-9]{64}").matches(it) })
        assertFails { SogoRuntime.spec(inventory, "../foreign") }
        assertFails { SogoRuntime.spec(inventory.copy(images = emptyList())) }
        assertFails { SogoRuntime.spec(inventory.copy(images = inventory.images.map { it.copy(architecture = "arm64") })) }
    }
}
