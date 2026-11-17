package net.datamancy.platform

import kotlin.test.*

class SogoRuntimeTest {
    @Test fun `canonical groupware shares one PostgreSQL Memcached and mail backend without login reset`() : Unit {
        val acquired = kotlinx.serialization.json.Json.decodeFromString<AcquiredInventory>(
            GenerationAssembly.readInventory(java.nio.file.Path.of("release/downloaded-candidate-inventory.json")).decodeToString())
        val base = CanonicalCoreRuntime.releaseProvidersSpec(acquired).copy(store = RuntimeStore.CANONICAL_V2)
        val fresh = SogoRuntime.canonicalFragment(acquired, base)
        assertEquals("sogo", fresh.product)
        assertEquals(mapOf("postgres" to setOf("sogo-data"), "memcached" to setOf("sogo-cache")),
            fresh.providerNetworks)
        assertEquals(setOf("sogo-web"), fresh.webNetworks)
        assertEquals(listOf("home"), fresh.spec.volumes.map { it.id })
        assertFalse(fresh.spec.processes.any { it.id in setOf("postgres", "memcached", "mail", "caddy", "database", "cache") })
        assertEquals(listOf("sogo-db-init", "memcached", "mail"),
            fresh.spec.processes.single { it.id == "sogod" }.dependencies)
        val cold = SogoRuntime.canonicalColdFragment(acquired, base, fresh)
        assertEquals(fresh.spec.volumes, cold.spec.volumes)
        assertEquals(fresh.spec.databaseAccess, cold.spec.databaseAccess)
        assertTrue(cold.spec.processes.none { it.oneShot })
        assertFails { SogoRuntime.canonicalColdFragment(acquired, base,
            fresh.copy(spec = fresh.spec.copy(volumes = emptyList()))) }
        val users = mapOf("alice" to "a".repeat(64), "bob" to "b".repeat(64), "outsider" to "c".repeat(64))
        val inputs = SogoRuntime.canonicalInputs(users, "d".repeat(64),
            mapOf("postgres-ca.pem" to "original-ca", "postgres.pem" to "original-cert",
                "postgres-key.pem" to "original-key"),
            pki = { mapOf("ca.pem" to "group-ca", "web.pem" to "group-cert", "web-key.pem" to "group-key") })
        assertEquals(fresh.spec.processes.flatMap { p ->
            listOfNotNull(p.environmentFile) + p.files.map { it.file }
        }.toSet() - setOf("postgres-ca.pem", "mail-ca.pem"), inputs.keys)
        assertContains(inputs.getValue("sogo.conf"), "@postgres:5432")
        val dbSecret = Regex("(?m)^SOGO_DB_PASSWORD=([a-f0-9]{64})$")
            .find(inputs.getValue("sogo.env"))?.groupValues?.get(1)
        assertNotNull(dbSecret)
        assertContains(inputs.getValue("sogo.conf"), "sogo:$dbSecret@postgres:5432")
        assertContains(inputs.getValue("sogo.conf"), "memcached:11211")
        assertContains(inputs.getValue("sogo.conf"), "groupware.datamancy.net")
        assertContains(inputs.getValue("sogo-apache.conf"), "groupware.datamancy.net")
        assertFalse(inputs.any { (file, _) -> file in setOf("db.pem", "db-key.pem", "db-ca.pem", "setup.sql", "bootstrap.env") })
    }
    private val inventory = AcquiredInventory(1, "candidate", listOf("postgres", "sogo", "memcached").map {
        val pin = "example.org/$it@sha256:" + "a".repeat(64)
        AcquiredImage(it, "upstream", "example.org/$it:1", pin, "b".repeat(64), emptyList(), pin.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `native groupware retires initializer and separates TLS database and web credentials`() : Unit {
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
