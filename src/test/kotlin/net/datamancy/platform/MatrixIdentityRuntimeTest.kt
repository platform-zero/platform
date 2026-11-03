package net.datamancy.platform

import kotlin.test.*
import kotlinx.serialization.json.*

class MatrixIdentityRuntimeTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("postgres", "valkey", "ntfy", "synapse", "matrix-authentication-service", "element").map {
        AcquiredImage(it, "upstream", "example.org/app:1", image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `delegated Matrix identity uses distinct origins durable migrations and closed local passwords`() {
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
