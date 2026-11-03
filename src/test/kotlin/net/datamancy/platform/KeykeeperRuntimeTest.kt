package net.datamancy.platform

import kotlinx.serialization.json.*
import kotlin.test.*

class KeykeeperRuntimeTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("postgres", "valkey", "ntfy", "openbao").map {
        AcquiredImage(it, "upstream", "example.org/app:1", image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `native TLS identity and vault have scoped protected inputs and no automatic unseal`() {
        val spec = KeykeeperRuntime.spec(inventory)
        assertEquals(4, spec.processes.count { !it.oneShot })
        assertEquals(7, PrivateDeployment.validate(spec).size)
        val files = KeykeeperRuntime.inputs { host -> mapOf("ca.pem" to "CA-$host", "web.pem" to "CERT-$host", "web-key.pem" to "KEY-$host") }
        assertEquals(SingleUserRestore.inputNames(spec), files.keys)
        assertTrue(spec.processes.all { it.capabilities.isEmpty() && it.apparmorProfile == "p0v3-private-v1" })
        val keeper = spec.processes.single { it.id == "keeper" }
        assertEquals(listOf("serve", "--oidc"), keeper.command)
        assertEquals(setOf("keeper-web.pem", "keeper-web-key.pem"), keeper.files.map { it.file }.toSet())
        assertFalse(spec.processes.any { p -> p.command.any { "unseal" in it || "operator init" in it } })
        assertContains(spec.processes.single { it.id == "trust-init" }.command.last(), "test -z")
        assertContains(files.getValue("keycloak.env"), "KC_HTTP_ENABLED=false")
        assertContains(files.getValue("keeper.env"), "KEYKEEPER_PUBLIC_ORIGIN=https://keeper:8443")
        val realm = Json.parseToJsonElement(files.getValue("realm.json")).jsonObject
        assertEquals("all", realm.getValue("sslRequired").jsonPrimitive.content)
        val clients = realm.getValue("clients").jsonArray.map { it.jsonObject }
        assertTrue(clients.all { !it.getValue("directAccessGrantsEnabled").jsonPrimitive.boolean })
        val human = clients.single { it.getValue("clientId").jsonPrimitive.content == "keykeeper-human" }
        assertEquals(listOf("https://keeper:8443/auth/callback"), human.getValue("redirectUris").jsonArray.map { it.jsonPrimitive.content })
        assertFalse(human.getValue("serviceAccountsEnabled").jsonPrimitive.boolean)
        val audiences = human.getValue("protocolMappers").jsonArray.map { it.jsonObject }.filter { it.getValue("protocolMapper").jsonPrimitive.content == "oidc-audience-mapper" }.map { it.getValue("config").jsonObject }
        assertEquals(2, audiences.size) // One mapper chooses client OR custom audience, not both.
        assertEquals("keykeeper", audiences.single { "included.custom.audience" in it }.getValue("included.custom.audience").jsonPrimitive.content)
        assertEquals("keykeeper-introspection", audiences.single { "included.client.audience" in it }.getValue("included.client.audience").jsonPrimitive.content)
        val agent = realm.getValue("users").jsonArray.map { it.jsonObject }.single { it["serviceAccountClientId"]?.jsonPrimitive?.content == "keykeeper-agent" }
        assertContains(files.getValue("keeper.env"), "KEYKEEPER_OIDC_AGENT_SUBJECTS=${agent.getValue("id").jsonPrimitive.content}\n")
        assertFails { KeykeeperRuntime.spec(inventory, "../bad") }
        assertFails { KeykeeperRuntime.spec(inventory.copy(images = inventory.images.dropLast(1))) }
    }
}
