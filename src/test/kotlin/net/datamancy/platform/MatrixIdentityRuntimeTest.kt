package net.datamancy.platform

import kotlin.test.*
import kotlinx.serialization.json.*

class MatrixIdentityRuntimeTest {
    @Test fun `selected MAS verifies graph Keycloak ingress issuer`() {
        val fragment = PackagedGraphFragment.loadPendingV3("private-matrix-authentication-service", 3, 9)
        val mas = fragment.definition.processes.single { it.id == "mas" }
        assertEquals(listOf("identity-web"), fragment.definition.providerNetworks["keycloak"])
        assertTrue("identity-web" in mas.networks)
        assertTrue(mas.files.any { it.file == "identity-ca.pem" &&
            it.target == "/run/secrets/identity-ca.pem" })
        assertTrue(fragment.definition.processes.filter { it.id in setOf("mas-config-init", "mas-migrate") }
            .all { p -> p.files.any { it.file == "identity-ca.pem" } })
        val secrets = List(5) { index -> ("a"[0] + index).toString().repeat(64) }
        val inputs = MatrixIdentityRuntime.canonicalInputs(secrets[0], secrets[1], secrets[2],
            "-----BEGIN PRIVATE KEY-----\n" + "A".repeat(1600) + "\n-----END PRIVATE KEY-----\n",
            secrets[3], secrets[4])
        assertContains(inputs.getValue("mas-runtime.env"), "SSL_CERT_FILE=/run/secrets/identity-ca.pem")
        assertContains(inputs.getValue("mas.yaml"), "issuer: https://auth.datamancy.net/realms/p0v3")
    }
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("postgres", "valkey", "ntfy", "synapse", "matrix-authentication-service", "element").map {
        AcquiredImage(it, "upstream", "example.org/app:1", image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `delegated Matrix identity uses distinct origins durable migrations and closed local passwords`() : Unit {
        val spec = MatrixIdentityRuntime.spec(inventory)
        assertEquals(13, PrivateDeployment.validate(spec).size)
        assertEquals(6, spec.processes.count { !it.oneShot })
        assertTrue(spec.processes.all { it.capabilities.isEmpty() && it.apparmorProfile == "p0v3-private-v1" })
        val inputs = MatrixIdentityRuntime.inputs { host -> mapOf("ca.pem" to "$host-ca", "web.pem" to "$host-cert", "web-key.pem" to "$host-key") }
        assertEquals(SingleUserRestore.inputNames(spec), inputs.keys)
        assertContains(inputs.getValue("trusted-ca.pem"), "identity-ca")
        assertContains(inputs.getValue("mas.yaml"), "pkce_method: always")
        assertContains(inputs.getValue("mas.yaml"), "on_conflict: fail")
        assertContains(inputs.getValue("mas.yaml"), "passwords:\n  enabled: false")
        assertContains(inputs.getValue("mas.yaml"), "literals: [owner, reader]")
        assertContains(inputs.getValue("homeserver.yaml"), "matrix_authentication_service:")
        assertFalse("registration_shared_secret" in inputs.getValue("homeserver.yaml"))
        assertContains(inputs.getValue("mas-signing.pem"), "BEGIN PRIVATE KEY")
        assertContains(inputs.getValue("mas.yaml"), "https://element:8443/?no_universal_links=true")
        val element = Json.parseToJsonElement(inputs.getValue("element.json")).jsonObject
        assertEquals(MatrixIdentityRuntime.ELEMENT_CLIENT, element.getValue("oidc_static_clients").jsonObject
            .getValue("https://auth:8443/").jsonObject.getValue("client_id").jsonPrimitive.content)
        assertEquals(false, element.getValue("enable_client_well_known_lookups").jsonPrimitive.boolean)
        val realm = Json.parseToJsonElement(inputs.getValue("realm.json")).jsonObject
        assertEquals("all", realm.getValue("sslRequired").jsonPrimitive.content)
        val client = realm.getValue("clients").jsonArray.single().jsonObject
        assertEquals("false", client.getValue("directAccessGrantsEnabled").jsonPrimitive.content)
        assertEquals("S256", client.getValue("attributes").jsonObject.getValue("pkce.code.challenge.method").jsonPrimitive.content)
        assertTrue(realm.getValue("users").jsonArray.take(2).all { it.jsonObject.getValue("requiredActions").jsonArray.size == 2 })
        assertEquals(listOf("-c", "/run/secrets/mas.yaml", "server", "--no-migrate", "--no-sync"), spec.processes.single { it.id == "auth" }.command)
        assertFails { MatrixIdentityRuntime.spec(inventory.copy(images = inventory.images.filter { it.product != "matrix-authentication-service" })) }
        assertFails { MatrixIdentityRuntime.spec(inventory.copy(images = inventory.images.map { it.copy(os = "other") })) }
    }
}
