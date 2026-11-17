package net.datamancy.platform

import kotlinx.serialization.json.*
import kotlin.test.*

class KeykeeperRuntimeTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("postgres", "valkey", "ntfy", "openbao").map {
        AcquiredImage(it, "upstream", "example.org/app:1", image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `providerless keeper uses actual providers and retains trust on cold restore`() {
        val keycloak = IdentityRuntime.canonicalProcesses(RuntimeProcess("postgres", image, "b".repeat(64), 999)).last()
        val bao = OpenBaoRuntime.spec(inventory).processes.single()
        val members = KeykeeperRuntime.canonicalProcesses(keycloak, bao)
        assertEquals(listOf("keeper-trust-init", "keeper"), members.map { it.id })
        val trust = members.first().command.last()
        assertContains(trust, "-srckeystore /opt/java/openjdk/lib/security/cacerts")
        assertContains(trust, "-destkeystore /trust/trust.p12")
        assertContains(trust, "p0v3-")
        assertFalse(trust.contains("-cacerts -delete") || trust.contains("/etc/ssl/certs/java/cacerts -import"))
        assertEquals(setOf("keycloak", "bao", "keeper-trust-init"), members.last().dependencies.toSet())
        val restored = KeykeeperRuntime.canonicalColdRestoreProcesses(members)
        assertEquals(listOf("keeper"), restored.map { it.id })
        assertEquals(listOf("keycloak", "bao"), restored.single().dependencies)
        assertEquals(members.last().volumes, restored.single().volumes)
        val revised = KeykeeperRuntime.canonicalColdRestoreProcesses(members, "keeper-revision.env")
        assertEquals("keeper-revision.env", revised.single().environmentFile)
        assertFailsWith<IllegalArgumentException> {
            KeykeeperRuntime.canonicalColdRestoreProcesses(members, "keeper-bootstrap.env")
        }
        assertFalse(restored.single().command.any { it.contains("init") || it.contains("unseal") })
        assertFailsWith<IllegalArgumentException> {
            KeykeeperRuntime.canonicalColdRestoreProcesses(members.map {
                if (it.id == "keeper") it.copy(environmentFile = "bootstrap.env") else it
            })
        }
        val clientsJson = KeykeeperRuntime.canonicalClients("agent-secret", "introspection-secret", "q-111111111111")
        val clients = clientsJson.map { it.jsonObject }
        val serviceAccount = KeykeeperRuntime.canonicalServiceAccount("11111111-1111-4111-8111-111111111111")
        val laneAccount = KeykeeperRuntime.canonicalManagedLaneServiceAccount("22222222-2222-4222-8222-222222222222")
        val laneClient = KeykeeperRuntime.canonicalManagedLaneClient("lane-agent-secret", "q-111111111111")
        val readerClient = KeykeeperRuntime.canonicalManagedLaneReaderClient("host-only-reader-secret", "q-111111111111")
        val readerAccount = KeykeeperRuntime.canonicalManagedLaneReaderServiceAccount("33333333-3333-4333-8333-333333333333")
        assertEquals(listOf("view-users"), readerAccount.getValue("clientRoles").jsonObject
            .getValue("realm-management").jsonArray.map { it.jsonPrimitive.content })
        assertFalse(readerClient.getValue("publicClient").jsonPrimitive.boolean)
        assertFalse(readerClient.getValue("fullScopeAllowed").jsonPrimitive.boolean)
        assertTrue(readerClient.getValue("protocolMappers").jsonArray.map { it.jsonObject }.none {
            it.getValue("config").jsonObject["included.custom.audience"]?.jsonPrimitive?.content in
                setOf("keykeeper", "managed-lanes")
        })
        assertTrue(laneClient.getValue("protocolMappers").jsonArray.map { it.jsonObject }.any {
            it.getValue("name").jsonPrimitive.content == "managed-lane-audience" &&
                it.getValue("config").jsonObject.getValue("included.custom.audience").jsonPrimitive.content == "managed-lanes"
        })
        val agentMappers = laneClient.getValue("protocolMappers").jsonArray.map { it.jsonObject }
        for (mapper in listOf("managed-lane-audience", "managed-lane-principal-type", "keykeeper-generation")) {
            val configuration = agentMappers.single { it.getValue("name").jsonPrimitive.content == mapper }
                .getValue("config").jsonObject
            assertEquals("true", configuration.getValue("introspection.token.claim").jsonPrimitive.content)
        }
        assertFalse(laneClient.getValue("directAccessGrantsEnabled").jsonPrimitive.boolean)
        assertTrue(laneAccount.getValue("id").jsonPrimitive.content != readerAccount.getValue("id").jsonPrimitive.content)
        assertFalse(laneClient.getValue("standardFlowEnabled").jsonPrimitive.boolean)
        assertTrue(clientsJson.first().jsonObject.getValue("protocolMappers").jsonArray.map { it.jsonObject }.any {
            it.getValue("name").jsonPrimitive.content == "managed-lane-audience"
        })
        assertTrue((clients.filter { it.getValue("clientId").jsonPrimitive.content != "keykeeper-introspection" } + laneClient)
            .all { client -> client.getValue("protocolMappers").jsonArray.map { it.jsonObject }.any {
                it.getValue("name").jsonPrimitive.content == "keykeeper-introspection-audience" &&
                    it.getValue("config").jsonObject.getValue("included.client.audience").jsonPrimitive.content ==
                    "keykeeper-introspection"
            } })
        var counter = 1
        val imported = IdentityRuntime.canonicalInputs("0".repeat(64),
            { mapOf("ca.pem" to "ca", "web.pem" to "web", "web-key.pem" to "key") },
            { (counter++).toString().repeat(64) },
            JsonArray(clientsJson + laneClient + readerClient + IdentityRuntime.canonicalOperatorClient("q-111111111111")),
            JsonArray(listOf(serviceAccount, laneAccount, readerAccount)))
        val importedRealm = Json.parseToJsonElement(imported.getValue("identity-realm.json")).jsonObject
        val importedUsers = importedRealm.getValue("users").jsonArray
        assertEquals(listOf(serviceAccount, laneAccount, readerAccount), importedUsers.takeLast(3))
        val mappings = importedRealm.getValue("clientScopeMappings").jsonObject
        assertEquals(setOf("identity-controller", "managed-lane-reader"), mappings.keys)
        assertEquals(listOf("view-users"), mappings.getValue("managed-lane-reader").jsonArray.single().jsonObject
            .getValue("roles").jsonArray.map { it.jsonPrimitive.content })
        var credentialCalls = 0
        val forgedReader = JsonObject(readerAccount.toMutableMap().apply {
            put("clientRoles", buildJsonObject { put("realm-management", buildJsonArray { add("manage-users") }) })
        })
        assertFailsWith<IllegalArgumentException> {
            IdentityRuntime.canonicalInputs("0".repeat(64), { error("TLS was prepared before full role validation") },
                { credentialCalls++; "a".repeat(64) }, JsonArray(clientsJson + laneClient + readerClient),
                JsonArray(listOf(serviceAccount, laneAccount, forgedReader)))
        }
        assertEquals(0, credentialCalls)
        val forgedAgent = JsonObject(laneClient.toMutableMap().apply {
            put("protocolMappers", buildJsonArray { laneClient.getValue("protocolMappers").jsonArray.forEach { mapper ->
                if (mapper.jsonObject.getValue("name").jsonPrimitive.content == "managed-lane-principal-type")
                    add(JsonObject(mapper.jsonObject.toMutableMap().apply {
                        put("config", JsonObject(mapper.jsonObject.getValue("config").jsonObject.toMutableMap().apply {
                            put("claim.value", JsonPrimitive("HUMAN"))
                        }))
                    }))
                else add(mapper)
            } })
        })
        assertFailsWith<IllegalArgumentException> {
            IdentityRuntime.canonicalInputs("0".repeat(64), { error("TLS prepared before agent issuer validation") },
                { credentialCalls++; "a".repeat(64) }, JsonArray(clientsJson + forgedAgent + readerClient),
                JsonArray(listOf(serviceAccount, laneAccount, readerAccount)))
        }
        assertEquals(0, credentialCalls)
        assertFailsWith<IllegalArgumentException> { KeykeeperRuntime.canonicalServiceAccount("foreign-subject") }
        assertEquals(setOf("keykeeper-human", "keykeeper-agent", "keykeeper-introspection"),
            clients.map { it.getValue("clientId").jsonPrimitive.content }.toSet())
        assertTrue(clients.all { it.getValue("directAccessGrantsEnabled").jsonPrimitive.boolean.not() })
        assertTrue(clients.filter { it.getValue("clientId").jsonPrimitive.content != "keykeeper-introspection" }.all {
            it.getValue("protocolMappers").jsonArray.map { mapper -> mapper.jsonObject }.any { mapper ->
                mapper.getValue("name").jsonPrimitive.content == "keykeeper-generation" &&
                    mapper.getValue("config").jsonObject.getValue("claim.value").jsonPrimitive.content == "q-111111111111"
            }
        })
        val inputs = KeykeeperRuntime.canonicalInputs("scoped-token", "introspection-secret", setOf("11111111-1111-4111-8111-111111111111"),
            "q-111111111111", mapOf("ca.pem" to "ca", "web.pem" to "web", "web-key.pem" to "key"), "identity-ca", "bao-ca")
        assertEquals(setOf("keeper.env", "identity-ca.pem", "bao-ca.pem", "keeper-ca.pem", "keeper-web.pem", "keeper-web-key.pem"), inputs.keys)
        assertFalse(inputs.getValue("keeper.env").contains("UNSEAL") || inputs.getValue("keeper.env").contains("ROOT_TOKEN"))
        assertContains(inputs.getValue("keeper.env"), "KEYKEEPER_GENERATION_ID=q-111111111111")
        assertContains(inputs.getValue("keeper.env"), "KEYKEEPER_OIDC_ISSUER=https://auth.datamancy.net/realms/p0v3")
        assertContains(inputs.getValue("keeper.env"), "KEYKEEPER_PUBLIC_ORIGIN=https://keykeeper.datamancy.net")
        assertContains(inputs.getValue("keeper.env"), "KEYKEEPER_PROBE_ORIGIN=https://keeper:8443")
        assertFailsWith<IllegalArgumentException> {
            KeykeeperRuntime.canonicalInputs("scoped-token", "introspection-secret", setOf("invented"),
                "q-111111111111", mapOf("ca.pem" to "ca", "web.pem" to "web", "web-key.pem" to "key"), "identity-ca", "bao-ca")
        }
    }

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
