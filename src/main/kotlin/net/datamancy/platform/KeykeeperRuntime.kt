package net.datamancy.platform

import java.nio.file.Path
import java.util.UUID
import kotlinx.serialization.json.*

/** Isolated native OIDC + scoped OpenBao fixture. Bao is never automatically initialized or unsealed. */
internal object KeykeeperRuntime {
    const val IMAGE = "localhost/p0v3-keykeeper@sha256:b8f1a1fca2877f5bae467fb7b70ca21ef6c014925ef728e333b9ca504b92904d"
    const val IMAGE_ID = "29b7ef3937f29f039cc74038be1044ba44027d1341340f7c5d2ab02fefa41299"
    fun spec(inventory: AcquiredInventory, name: String = "keykeeper-identity"): PrivateDeploymentSpec {
        val identity = IdentityRuntime.spec(inventory, name)
        val bao = OpenBaoRuntime.spec(inventory, name)
        val processes = identity.processes.map { p -> if (p.id == "keycloak") p.copy(id = "identity",
            files = p.files + listOf("identity-web.pem", "identity-web-key.pem").map { RuntimeFile(it, "/run/secrets/$it") }) else p } + bao.processes + listOf(
            RuntimeProcess("trust-init", IMAGE, IMAGE_ID, 65532, oneShot = true, entrypoint = "/bin/sh", apparmorProfile = "p0v3-private-v1",
                files = listOf("ca.pem", "identity-ca.pem", "keeper-ca.pem").map { RuntimeFile(it, "/run/secrets/$it") },
                volumes = listOf(RuntimeMount("trust", "/trust")), command = listOf("-ec", """
                    test -z "${'$'}(ls -A /trust)"; umask 077
                    for name in ca identity-ca keeper-ca; do
                      /opt/java/openjdk/bin/keytool -importcert -noprompt -alias "${'$'}name" -file "/run/secrets/${'$'}name.pem" -keystore /trust/trust.p12 -storetype PKCS12 -storepass changeit
                    done
                    sync
                """.trimIndent())),
            RuntimeProcess("keeper", IMAGE, IMAGE_ID, 65532, dependencies = listOf("identity", "bao", "trust-init"),
                command = listOf("serve", "--oidc"), environmentFile = "keeper.env", memoryMiB = 512, apparmorProfile = "p0v3-private-v1",
                files = listOf("keeper-web.pem", "keeper-web-key.pem").map { RuntimeFile(it, "/run/secrets/$it") },
                volumes = listOf(RuntimeMount("trust", "/trust")), readiness = listOf("/opt/keykeeper/bin/p0-v3-keykeeper", "probe"))
        )
        return PrivateDeploymentSpec(name = name, volumes = identity.volumes + bao.volumes + RuntimeVolume("trust", 65532), processes = processes)
            .also { PrivateDeployment.validate(it) }
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "keykeeper-identity", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }
    fun inputs(pki: (String) -> Map<String, String> = { PrivateWebPki.generate(it) }): Map<String, String> {
        val files = (IdentityRuntime.inputs() + OpenBaoRuntime.inputs { pki("bao") }).toMutableMap()
        for (host in listOf("identity", "keeper")) pki(host).forEach { (key, value) -> files["$host-$key"] = value }
        files["keycloak.env"] = files.getValue("keycloak.env").replace("KC_HTTP_ENABLED=true", "KC_HTTP_ENABLED=false")
            .replace("KC_HOSTNAME=http://keycloak:8080", "KC_HOSTNAME=https://identity:8443") +
            "KC_HTTPS_PORT=8443\nKC_HTTPS_CERTIFICATE_FILE=/run/secrets/identity-web.pem\nKC_HTTPS_CERTIFICATE_KEY_FILE=/run/secrets/identity-web-key.pem\nKC_HTTP_MANAGEMENT_SCHEME=http\n"
        val realm = Json.parseToJsonElement(files.getValue("realm.json")).jsonObject.toMutableMap()
        realm["sslRequired"] = JsonPrimitive("all"); realm["accessTokenLifespan"] = JsonPrimitive(300)
        val owner = realm.getValue("users").jsonArray.single().jsonObject.toMutableMap().apply {
            put("id", JsonPrimitive(UUID.randomUUID().toString())); put("email", JsonPrimitive("owner@localhost.invalid"))
            put("emailVerified", JsonPrimitive(true)); put("firstName", JsonPrimitive("Synthetic")); put("lastName", JsonPrimitive("Owner"))
        }
        val outsider = owner.toMutableMap().apply {
            put("id", JsonPrimitive(UUID.randomUUID().toString())); put("username", JsonPrimitive("outsider"))
            put("email", JsonPrimitive("outsider@localhost.invalid")); put("lastName", JsonPrimitive("Outsider"))
            put("credentials", buildJsonArray { add(buildJsonObject { put("type", "password"); put("temporary", true); put("value", RuntimePreparation.password()) }) })
        }
        val agentId = UUID.randomUUID().toString(); val agentSecret = RuntimePreparation.password()
        val rogueId = UUID.randomUUID().toString(); val rogueSecret = RuntimePreparation.password()
        val introspectionSecret = RuntimePreparation.password()
        realm["users"] = buildJsonArray {
            add(JsonObject(owner)); add(JsonObject(outsider))
            for ((client, id) in listOf("keykeeper-agent" to agentId, "keykeeper-rogue" to rogueId)) add(buildJsonObject {
                put("id", id); put("username", "service-account-$client"); put("enabled", true); put("serviceAccountClientId", client)
            })
        }
        fun client(name: String, kind: String?, secret: String? = null): JsonObject = buildJsonObject {
            val human = name == "keykeeper-human"
            put("clientId", name); put("enabled", true); put("protocol", "openid-connect"); put("publicClient", human)
            put("standardFlowEnabled", human); put("directAccessGrantsEnabled", false); put("serviceAccountsEnabled", !human && kind != null)
            put("fullScopeAllowed", false); if (secret != null) put("secret", secret)
            put("redirectUris", buildJsonArray { if (human) add("https://keeper:8443/auth/callback") })
            put("webOrigins", buildJsonArray { if (human) add("https://keeper:8443") })
            put("attributes", buildJsonObject { put("pkce.code.challenge.method", "S256"); put("oauth2.device.authorization.grant.enabled", "false") })
            put("protocolMappers", buildJsonArray { if (kind != null) {
                add(buildJsonObject {
                    put("name", "keykeeper-audience"); put("protocol", "openid-connect"); put("protocolMapper", "oidc-audience-mapper")
                    put("config", buildJsonObject { put("included.custom.audience", "keykeeper"); put("access.token.claim", "true"); put("id.token.claim", "false"); put("introspection.token.claim", "true") })
                })
                add(buildJsonObject {
                    put("name", "keykeeper-introspection-audience"); put("protocol", "openid-connect"); put("protocolMapper", "oidc-audience-mapper")
                    put("config", buildJsonObject { put("included.client.audience", "keykeeper-introspection"); put("access.token.claim", "true"); put("id.token.claim", "false"); put("introspection.token.claim", "true") })
                })
                add(buildJsonObject {
                    put("name", "keykeeper-kind"); put("protocol", "openid-connect"); put("protocolMapper", "oidc-hardcoded-claim-mapper")
                    put("config", buildJsonObject { put("claim.name", "keykeeper_principal_type"); put("claim.value", kind); put("jsonType.label", "String"); put("access.token.claim", "true"); put("id.token.claim", "false"); put("introspection.token.claim", "true") })
                })
            } })
        }
        realm["clients"] = buildJsonArray {
            add(client("keykeeper-human", "HUMAN")); add(client("keykeeper-agent", "AGENT", agentSecret))
            add(client("keykeeper-rogue", "AGENT", rogueSecret)); add(client("keykeeper-introspection", null, introspectionSecret))
        }
        files["realm.json"] = JsonObject(realm).toString()
        files["keeper.env"] = "KEYKEEPER_OIDC_ISSUER=https://identity:8443/realms/p0v3\nKEYKEEPER_OIDC_AUDIENCE=keykeeper\nKEYKEEPER_OIDC_HUMAN_CLIENT=keykeeper-human\nKEYKEEPER_OIDC_AGENT_CLIENT=keykeeper-agent\nKEYKEEPER_OIDC_AGENT_SUBJECTS=$agentId\nKEYKEEPER_OIDC_INTROSPECTION_CLIENT=keykeeper-introspection\nKEYKEEPER_OIDC_INTROSPECTION_SECRET=$introspectionSecret\nKEYKEEPER_BAO_URL=https://bao:8200\nKEYKEEPER_BAO_MOUNT=keykeeper\nKEYKEEPER_BAO_TOKEN=${RuntimePreparation.password()}\nKEYKEEPER_BAO_REMOTE_HTTPS=true\nKEYKEEPER_PORT=8443\nKEYKEEPER_PUBLIC_ORIGIN=https://keeper:8443\nKEYKEEPER_TLS_CERTIFICATE=/run/secrets/keeper-web.pem\nKEYKEEPER_TLS_PRIVATE_KEY=/run/secrets/keeper-web-key.pem\nKEYKEEPER_URL=https://keeper:8443\nKEYKEEPER_REMOTE_HTTPS=true\nJAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStore=/trust/trust.p12 -Djavax.net.ssl.trustStorePassword=changeit\nHOME=/tmp\n"
        return files
    }
}
