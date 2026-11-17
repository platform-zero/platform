package net.datamancy.platform

import kotlinx.serialization.json.*
import kotlin.test.*

class IdentityCanonicalTest {
    private val postgres = RuntimeProcess("postgres", "example.org/postgres@sha256:" + "a".repeat(64), "b".repeat(64), 999,
        networks = listOf("db-admin", "keycloak-data"),
        readiness = listOf("pg_isready", "-U", "postgres", "-d", "postgres"))
    private val pki = { mapOf("ca.pem" to "ca", "web.pem" to "certificate", "web-key.pem" to "private-key") }

    @Test fun `original outsider human UUID is separate and receives no realm management role`(): Unit {
        var count = 1
        val owner = "11111111-1111-4111-8111-111111111111"
        val outsider = "22222222-2222-4222-8222-222222222222"
        val original = IdentityRuntime.canonicalInputs("0".repeat(64), pki,
            { (count++).toString().repeat(64) }, originalOwnerId = owner, originalOutsiderId = outsider)
        val users = Json.parseToJsonElement(original.getValue("identity-realm.json")).jsonObject
            .getValue("users").jsonArray.map { it.jsonObject }
        assertEquals(listOf(owner, outsider), users.map { it.getValue("id").jsonPrimitive.content })
        assertEquals("owner", users[0].getValue("username").jsonPrimitive.content)
        assertEquals("outsider", users[1].getValue("username").jsonPrimitive.content)
        assertNull(users[1]["clientRoles"])
        assertTrue(users[1].getValue("credentials").jsonArray.single().jsonObject
            .getValue("temporary").jsonPrimitive.boolean)
        assertFails { IdentityRuntime.canonicalInputs("0".repeat(64), pki,
            originalOwnerId = owner, originalOutsiderId = owner) }
        assertFails { IdentityRuntime.canonicalInputs("0".repeat(64), pki,
            originalOwnerId = owner) }
    }

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
        assertNull(realm["defaultRequiredActions"])
        assertEquals(setOf("UPDATE_PASSWORD", "CONFIGURE_TOTP"), realm.getValue("requiredActions")
            .jsonArray.map { action ->
                val provider = action.jsonObject
                assertEquals(provider.getValue("alias"), provider.getValue("providerId"))
                assertTrue(provider.getValue("enabled").jsonPrimitive.boolean)
                assertTrue(provider.getValue("defaultAction").jsonPrimitive.boolean)
                provider.getValue("alias").jsonPrimitive.content
            }.toSet())
        val owner = realm.getValue("users").jsonArray.single().jsonObject
        assertEquals(setOf("UPDATE_PASSWORD", "CONFIGURE_TOTP"), owner
            .getValue("requiredActions").jsonArray.map { it.jsonPrimitive.content }.toSet())
        val roles = owner.getValue("clientRoles").jsonObject
        assertEquals(setOf("realm-management"), roles.keys)
        assertTrue("manage-realm" in roles.getValue("realm-management").jsonArray.map { it.jsonPrimitive.content })
    }

    @Test fun `managed broker checks signed generation bearer against live realm and native enabled account`() {
        val issuer = ManagedLaneIdentityAuthority.ISSUER
        val subject = "11111111-1111-4111-8111-111111111111"
        val pair = java.security.KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val public = pair.public as java.security.interfaces.RSAPublicKey
        fun b64(bytes: ByteArray) = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        fun unsigned(value: java.math.BigInteger) = value.toByteArray().let { if (it[0] == 0.toByte()) it.drop(1).toByteArray() else it }
        val keys = buildJsonObject { put("keys", buildJsonArray { add(buildJsonObject {
            put("kid", "test-kid"); put("kty", "RSA"); put("alg", "RS256"); put("use", "sig")
            put("n", b64(unsigned(public.modulus))); put("e", b64(unsigned(public.publicExponent)))
        }) }) }.toString()
        val now = 1_900_000_000L
        val claims = buildJsonObject {
            put("iss", issuer); put("sub", subject); put("azp", "managed-human")
            put("aud", ManagedLaneIdentityAuthority.AUDIENCE); put("keykeeper_principal_type", "HUMAN")
            put("p0v3_generation", "q-111111111111"); put("jti", "original-jti")
            put("iat", now - 20); put("exp", now + 300)
        }
        fun token(claims: JsonObject): String {
            val header = buildJsonObject { put("alg", "RS256"); put("kid", "test-kid"); put("typ", "JWT") }
            val prefix = b64(header.toString().toByteArray()) + "." + b64(claims.toString().toByteArray())
            val signer = java.security.Signature.getInstance("SHA256withRSA").apply {
                initSign(pair.private); update(prefix.toByteArray(Charsets.US_ASCII))
            }
            return prefix + "." + b64(signer.sign())
        }
        var active = true; var enabled = true; var generationActive = true
        var head = "a".repeat(64)
        val transport = object : IdentityNativeTransport {
            override fun jwks() = keys
            override fun introspect(bearer: String) = buildJsonObject {
                put("active", active); put("sub", subject); put("iss", issuer)
                put("azp", "managed-human"); put("jti", "original-jti")
            }
            override fun user(subject: String, adminBearer: String) = buildJsonObject {
                require(adminBearer == "host-only-admin-token"); put("id", subject); put("enabled", enabled)
            }
        }
        val ledger = object : IdentityGenerationLedger {
            override fun revisionHead(generation: String) = head
            override fun generationActive(generation: String) = generationActive
        }
        val authority = ManagedLaneIdentityAuthority(transport, ledger, { "host-only-admin-token" },
            setOf(subject), mapOf("managed-human" to "HUMAN"), { now })
        val signed = token(claims)
        fun hash(value: String) = java.security.MessageDigest.getInstance("SHA-256").digest(value.toByteArray())
            .joinToString("") { "%02x".format(it) }
        val grant = ManagedLaneGrant(subject, issuer, "q-111111111111", "lane-1", "session", "openai", "gpt-6-sol",
            now + 100, head, hash(signed))
        assertTrue(authority.authorizeBearer(signed, grant, now))
        active = false; assertFalse(authority.authorizeBearer(signed, grant, now)); active = true
        enabled = false; assertFalse(authority.authorizeBearer(signed, grant, now)); enabled = true
        generationActive = false; assertFalse(authority.authorizeBearer(signed, grant, now)); generationActive = true
        head = "b".repeat(64); assertFalse(authority.authorizeBearer(signed, grant, now)); head = grant.revisionSha256
        assertFalse(authority.authorizeBearer(signed, grant.copy(tokenHash = hash("foreign-bearer")), now))
        val foreign = token(JsonObject(claims.toMutableMap().apply {
            put("p0v3_generation", JsonPrimitive("q-222222222222"))
        }))
        assertFalse(authority.authorizeBearer(foreign, grant.copy(tokenHash = hash(foreign)), now))
    }

    @Test fun `native managed agent grant demands exact original subject generation and audience`(): Unit {
        val subject = "11111111-1111-4111-8111-111111111111"
        val generation = "q-111111111111"
        val observed = buildJsonObject {
            put("active", true); put("iss", ManagedLaneIdentityAuthority.ISSUER)
            put("azp", "managed-lane-agent"); put("sub", subject)
            put("p0v3_generation", generation); put("keykeeper_principal_type", "AGENT")
            put("aud", buildJsonArray { add("managed-lanes"); add("keykeeper-introspection") })
        }
        assertTrue(nativeAgentIntrospectionMatches(observed, generation, subject))
        for ((key, changed) in mapOf(
            "active" to JsonPrimitive(false), "iss" to JsonPrimitive("https://foreign.invalid/realms/p0v3"),
            "azp" to JsonPrimitive("managed-lane-reader"), "sub" to JsonPrimitive("22222222-2222-4222-8222-222222222222"),
            "p0v3_generation" to JsonPrimitive("q-222222222222"),
            "keykeeper_principal_type" to JsonPrimitive("HUMAN"), "aud" to JsonPrimitive("keykeeper"))) {
            assertFalse(nativeAgentIntrospectionMatches(JsonObject(observed.toMutableMap().apply { put(key, changed) }),
                generation, subject), "Unexpected native agent authority for modified $key")
        }
        val privileged = JsonObject(observed.toMutableMap().apply {
            put("resource_access", buildJsonObject { put("realm-management", buildJsonObject {
                put("roles", buildJsonArray { add("manage-users") })
            }) })
        })
        assertFalse(nativeAgentIntrospectionMatches(privileged, generation, subject))
        assertFalse(nativeAgentIntrospectionMatches(observed, generation, "22222222-2222-4222-8222-222222222222"))
    }

    @Test fun `managed reader has a bounded host only lease and rejects foreign native credentials`() {
        var now = 1_900_000_000L
        var minted = 0
        val subject = "11111111-1111-4111-8111-111111111111"
        val supplier = NativeReaderTokenIssuer { generation, originalSubject, secret ->
            assertEquals("q-111111111111", generation)
            assertEquals(subject, originalSubject)
            assertEquals("host-only-private-secret", secret)
            minted++
            "native-reader-bearer-" + minted.toString().repeat(24)
        }
        val reader = ManagedLaneNativeReader(supplier, "q-111111111111", subject,
            { "host-only-private-secret" }, { now })
        val first = reader.bearer()
        assertEquals(first, reader.bearer())
        assertEquals(1, minted)
        now += 60
        assertNotEquals(first, reader.bearer())
        assertEquals(2, minted)
        assertFailsWith<IllegalArgumentException> {
            ManagedLaneNativeReader(supplier, "q-222222222222", "invented-subject", { "private" }, { now })
        }
        val denied = ManagedLaneNativeReader(NativeReaderTokenIssuer { _, _, _ -> error("native denied") },
            "q-222222222222", subject, { "host-only-private-secret" }, { now })
        assertFailsWith<IllegalStateException> { denied.bearer() }
    }

    @Test fun `operator PKCE uses three explicit controller scopes and a generation mapper`() {
        val operator = IdentityRuntime.canonicalOperatorClient("q-111111111111")
        assertEquals("identity-controller", operator.getValue("clientId").jsonPrimitive.content)
        assertTrue(operator.getValue("publicClient").jsonPrimitive.boolean)
        assertFalse(operator.getValue("fullScopeAllowed").jsonPrimitive.boolean) // exact native role-scope mapping, not broad roles
        assertFalse(operator.getValue("directAccessGrantsEnabled").jsonPrimitive.boolean)
        assertFalse(operator.getValue("serviceAccountsEnabled").jsonPrimitive.boolean)
        assertEquals("S256", operator.getValue("attributes").jsonObject.getValue("pkce.code.challenge.method").jsonPrimitive.content)
        assertEquals(listOf("https://start.datamancy.net/identity/operator/callback"),
            operator.getValue("redirectUris").jsonArray.map { it.jsonPrimitive.content })
        assertEquals(setOf("identity:manage", "bao:recover", "credentials:rotate"),
            operator.getValue("defaultClientScopes").jsonArray.map { it.jsonPrimitive.content }
                .filter { ':' in it }.toSet())
        val mappers = operator.getValue("protocolMappers").jsonArray.map { it.jsonObject }
        val claim = mappers.single { it.getValue("name").jsonPrimitive.content == "identity-generation" }
            .getValue("config").jsonObject
        assertEquals("q-111111111111", claim.getValue("claim.value").jsonPrimitive.content)
        assertEquals("keykeeper-introspection", mappers.single {
            it.getValue("name").jsonPrimitive.content == "keykeeper-introspection-audience"
        }.getValue("config").jsonObject.getValue("included.client.audience").jsonPrimitive.content)
        var counter = 1
        val inputs = IdentityRuntime.canonicalInputs("0".repeat(64), pki,
            { (counter++).toString().repeat(64) }, JsonArray(listOf(operator)))
        val realm = Json.parseToJsonElement(inputs.getValue("identity-realm.json")).jsonObject
        val scopes = realm.getValue("clientScopes").jsonArray.map { it.jsonObject }
        assertEquals(setOf("identity:manage", "bao:recover", "credentials:rotate"),
            scopes.map { it.getValue("name").jsonPrimitive.content }.toSet())
        assertEquals("controller", scopes.single { it.getValue("name").jsonPrimitive.content == "identity:manage" }
            .getValue("protocolMappers").jsonArray.single().jsonObject.getValue("config").jsonObject
            .getValue("included.custom.audience").jsonPrimitive.content)
        val nativeOperatorRoles = realm.getValue("clientScopeMappings").jsonObject
            .getValue("identity-controller").jsonArray.single().jsonObject
        assertEquals("realm-management", nativeOperatorRoles.getValue("client").jsonPrimitive.content)
        assertEquals(setOf("manage-users", "view-users", "manage-clients", "view-clients", "manage-realm"),
            nativeOperatorRoles.getValue("roles").jsonArray.map { it.jsonPrimitive.content }.toSet())
        assertEquals(nativeOperatorRoles.getValue("roles"), realm.getValue("users").jsonArray.first().jsonObject
            .getValue("clientRoles").jsonObject.getValue("realm-management"))
        assertFailsWith<IllegalArgumentException> { IdentityRuntime.canonicalOperatorClient("foreign") }
        var credentialCalls = 0
        val forged = JsonObject(operator.toMutableMap().apply { put("directAccessGrantsEnabled", JsonPrimitive(true)) })
        assertFailsWith<IllegalArgumentException> {
            IdentityRuntime.canonicalInputs("0".repeat(64), pki, { credentialCalls++; "a".repeat(64) },
                JsonArray(listOf(forged)))
        }
        assertEquals(0, credentialCalls)
    }

    @Test fun `original restore service authority is generation scoped and never aliases human or reader`() {
        val generation = "q-abcdef012345"
        val owner = "11111111-1111-4111-8111-111111111111"
        val outsider = "22222222-2222-4222-8222-222222222222"
        val subject = "33333333-3333-4333-8333-333333333333"
        val secret = "a".repeat(64)
        val controller = IdentityRuntime.canonicalRestoreControllerClient(secret, generation)
        val account = IdentityRuntime.canonicalRestoreControllerServiceAccount(subject)
        assertEquals("managed-restore-controller", controller.getValue("clientId").jsonPrimitive.content)
        for (flag in listOf("standardFlowEnabled", "directAccessGrantsEnabled", "fullScopeAllowed", "publicClient"))
            assertFalse(controller.getValue(flag).jsonPrimitive.boolean)
        assertTrue(controller.getValue("serviceAccountsEnabled").jsonPrimitive.boolean)
        assertEquals(listOf("roles"), controller.getValue("defaultClientScopes").jsonArray.map { it.jsonPrimitive.content })
        assertEquals(generation, controller.getValue("protocolMappers").jsonArray.single {
            it.jsonObject.getValue("name").jsonPrimitive.content == "original-restore-generation"
        }.jsonObject.getValue("config").jsonObject.getValue("claim.value").jsonPrimitive.content)
        val roles = listOf("view-users", "view-clients", "manage-clients", "manage-realm")
        assertEquals(roles, account.getValue("clientRoles").jsonObject.getValue("realm-management")
            .jsonArray.map { it.jsonPrimitive.content })
        fun realm(client: JsonObject = controller, actor: JsonObject = account): JsonObject {
            var counter = 1
            val input = IdentityRuntime.canonicalInputs("0".repeat(64), pki,
                { (counter++).toString(16).padStart(64, '0') },
                JsonArray(listOf(IdentityRuntime.canonicalOperatorClient(generation), client)),
                JsonArray(listOf(actor)), originalOwnerId = owner, originalOutsiderId = outsider)
            return Json.parseToJsonElement(input.getValue("identity-realm.json")).jsonObject
        }
        val original = realm()
        assertEquals(roles, original.getValue("clientScopeMappings").jsonObject
            .getValue("managed-restore-controller").jsonArray.single().jsonObject.getValue("roles")
            .jsonArray.map { it.jsonPrimitive.content })
        assertEquals(subject, original.getValue("users").jsonArray.last().jsonObject.getValue("id").jsonPrimitive.content)
        assertFailsWith<IllegalArgumentException> { IdentityRuntime.canonicalRestoreControllerClient("bad", generation) }
        assertFailsWith<IllegalArgumentException> { IdentityRuntime.canonicalRestoreControllerClient(secret, "foreign") }
        assertFailsWith<IllegalArgumentException> { IdentityRuntime.canonicalRestoreControllerServiceAccount("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA") }
        assertFailsWith<IllegalArgumentException> { realm(actor = IdentityRuntime.canonicalRestoreControllerServiceAccount(owner)) }
        assertFailsWith<IllegalArgumentException> {
            realm(client = JsonObject(controller.toMutableMap().apply { put("fullScopeAllowed", JsonPrimitive(true)) }))
        }
        assertFailsWith<IllegalArgumentException> {
            realm(actor = JsonObject(account.toMutableMap().apply {
                put("clientRoles", buildJsonObject { put("realm-management", buildJsonArray { add("realm-admin") }) })
            }))
        }
    }

    @Test fun `consumer adoption preserves original account subject and credential revision`() {
        fun binding(generation: String, account: String = "original-uid", revision: String = "a".repeat(64)) =
            IdentityConsumerBinding(generation, "https://auth.datamancy.net/realms/p0v3", "keykeeper", "keykeeper-human",
                "original-sub", account, revision)
        val source = binding("q-111111111111")
        val target = binding("q-222222222222")
        val evidence = IdentityAdoptionEvidence(source, target, "original-uid", "original-uid",
            source.credentialRevisionSha256, target.credentialRevisionSha256)
        val readback = IdentityNativeObservation(target.issuer, target.subject, target.nativeAccountId,
            target.credentialRevisionSha256, "c".repeat(64), true)
        IdentityConsumerAuthorization.requireAdoption(evidence, target.generation) { readback }
        assertFailsWith<IllegalArgumentException> {
            IdentityConsumerAuthorization.requireAdoption(evidence.copy(target = binding(target.generation, "reprovisioned")),
                target.generation) { readback }
        }
        assertFailsWith<IllegalArgumentException> {
            IdentityConsumerAuthorization.requireAdoption(evidence.copy(target = binding(target.generation, revision = "b".repeat(64))),
                target.generation) { readback }
        }
        assertFailsWith<IllegalArgumentException> {
            IdentityConsumerAuthorization.requireAdoption(evidence, target.generation) { readback.copy(isolationReceiptSha256 = "") }
        }
        assertFailsWith<IllegalArgumentException> {
            IdentityConsumerAuthorization.requireAdoption(evidence, target.generation) { readback.copy(introspectionActive = false) }
        }
        assertFailsWith<IllegalArgumentException> {
            IdentityConsumerAuthorization.requireAdoption(evidence, target.generation) { readback.copy(subject = "replacement") }
        }
        assertFailsWith<IllegalArgumentException> {
            IdentityConsumerAuthorization.requireAdoption(evidence, source.generation) { readback }
        }
        assertTrue(IdentityConsumerAuthorization.authorize(target, target.issuer, target.audience, target.clientId,
            target.subject, target.generation, target.credentialRevisionSha256) { true })
        for (invalid in listOf(source.generation, "q-333333333333")) {
            assertFalse(IdentityConsumerAuthorization.authorize(target, target.issuer, target.audience, target.clientId,
                target.subject, invalid, target.credentialRevisionSha256) { true })
        }
        assertFalse(IdentityConsumerAuthorization.authorize(target, target.issuer, target.audience, target.clientId,
            target.subject, target.generation, target.credentialRevisionSha256) { false })
        assertFalse(IdentityConsumerAuthorization.authorize(target, target.issuer, target.audience, target.clientId,
            target.subject, target.generation, target.credentialRevisionSha256) { error("revoked") })
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
        var credentialCalls = 0
        assertFailsWith<IllegalArgumentException> {
            IdentityRuntime.canonicalInputs("0".repeat(64), pki, { credentialCalls++; "a".repeat(64) },
                serviceAccounts = JsonArray(listOf(buildJsonObject {
                    put("id", "11111111-1111-4111-8111-111111111111")
                    put("serviceAccountClientId", "undeclared")
                })))
        }
        assertEquals(0, credentialCalls)
        assertFailsWith<IllegalArgumentException> { IdentityRuntime.canonicalInputs("x", pki) }
        assertFailsWith<IllegalArgumentException> { IdentityRuntime.canonicalInputs("0".repeat(64), pki, { "0".repeat(64) }) }
    }
}
