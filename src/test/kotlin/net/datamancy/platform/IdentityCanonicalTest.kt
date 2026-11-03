package net.datamancy.platform

import kotlinx.serialization.json.*
import kotlin.test.*

class IdentityCanonicalTest {
    private val postgres = RuntimeProcess("postgres", "example.org/postgres@sha256:" + "a".repeat(64), "b".repeat(64), 999,
        networks = listOf("db-admin", "keycloak-data"),
        readiness = listOf("pg_isready", "-U", "postgres", "-d", "postgres"))
    private val pki = { mapOf("ca.pem" to "ca", "web.pem" to "certificate", "web-key.pem" to "private-key") }

    @Test fun `canonical identity uses shared verified database and no daemon bootstrap authority`() {
        val processes = IdentityRuntime.canonicalProcesses(postgres)
        val spec = PrivateDeploymentSpec(name = "identity-unit", volumes = emptyList(), processes = listOf(postgres) + processes,
            networks = listOf("db-admin", "keycloak-data", "identity-web"))
        PrivateDeployment.validate(spec)
        assertTrue(spec.processes.filterNot { it.oneShot }.all {
            it.readiness.isNotEmpty() xor (it.readinessHttpPort != null)
        })
        val keycloak = processes.single { it.id == "keycloak" }
        assertEquals(listOf("/bin/bash", "-ec"), keycloak.readiness.take(2))
        assertContains(keycloak.readiness.last(), "/health/ready")
        assertNull(keycloak.readinessHttpPort)
        for (invalid in listOf(keycloak.copy(readiness = emptyList()), keycloak.copy(readinessHttpPort = 9000))) {
            assertFailsWith<IllegalArgumentException> {
                PrivateDeployment.validate(spec.copy(processes = spec.processes.map { if (it.id == "keycloak") invalid else it }))
            }
        }
        var counter = 1
        val inputs = IdentityRuntime.canonicalInputs("0".repeat(64), pki, { (counter++).toString().repeat(64) })
        assertEquals(PrivateDeployment.inputNames(spec).toSet(), inputs.keys + "postgres-ca.pem")
        assertEquals(3, processes.count { it.oneShot })
        val daemon = processes.single { it.id == "keycloak" }
        assertFalse(daemon.command.any { "import-realm" in it })
        assertTrue(daemon.command.any { "migration-strategy=validate" in it })
        assertEquals("identity-runtime.env", daemon.environmentFile)
        val env = inputs.getValue("identity-runtime.env")
        assertContains(env, "sslmode=verify-full")
        assertContains(env, "KC_HTTP_ENABLED=false")
        assertFalse(env.contains("BOOTSTRAP"))
        assertFalse(env.contains("1".repeat(64))) // Migration password never reaches daemon.
        assertFalse(env.contains("3".repeat(64))) // Temporary owner password never reaches daemon.
        assertContains(processes.single { it.id == "identity-db-finalize" }.command.last(), "ALTER ROLE keycloak_migrate NOLOGIN")
        val realm = Json.parseToJsonElement(inputs.getValue("identity-realm.json")).jsonObject
        assertEquals(false, realm.getValue("registrationAllowed").jsonPrimitive.boolean)
        assertEquals(setOf("UPDATE_PASSWORD", "CONFIGURE_TOTP"), realm.getValue("users").jsonArray.single().jsonObject
            .getValue("requiredActions").jsonArray.map { it.jsonPrimitive.content }.toSet())
    }

    @Test fun `canonical restore retires only known identity jobs and rejects unsafe daemon drift`() {
        val processes = listOf(postgres) + IdentityRuntime.canonicalProcesses(postgres)
        val restored = IdentityRuntime.canonicalColdRestoreProcesses(processes)
        assertEquals(listOf("postgres", "keycloak"), restored.map { it.id })
        assertEquals(listOf("postgres"), restored.single { it.id == "keycloak" }.dependencies)
        assertTrue(restored.none { it.oneShot })
        assertEquals(processes.single { it.id == "keycloak" }.readiness, restored.single { it.id == "keycloak" }.readiness)
        PrivateDeployment.validate(PrivateDeploymentSpec(name = "identity-restored-unit", volumes = emptyList(),
            processes = restored, networks = listOf("db-admin", "keycloak-data", "identity-web")))
        assertFailsWith<IllegalArgumentException> { IdentityRuntime.canonicalColdRestoreProcesses(processes.filterNot { it.id == "identity-realm-init" }) }
        assertFailsWith<IllegalArgumentException> { IdentityRuntime.canonicalColdRestoreProcesses(processes.map {
            if (it.id == "keycloak") it.copy(environmentFile = "keycloak.env") else it
        }) }
        assertFailsWith<IllegalArgumentException> { IdentityRuntime.canonicalColdRestoreProcesses(processes.map {
            if (it.id == "keycloak") it.copy(command = it.command + "--import-realm") else it
        }) }
        assertFailsWith<IllegalArgumentException> { IdentityRuntime.canonicalInputs("x", pki) }
        assertFailsWith<IllegalArgumentException> { IdentityRuntime.canonicalInputs("0".repeat(64), pki, { "0".repeat(64) }) }
    }
}
