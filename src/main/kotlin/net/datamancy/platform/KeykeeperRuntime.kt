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
    /** Provider-less Keykeeper: exactly one externally owned Keycloak and Bao, with no recreated realm/raft data.
     * Trust is a durable, private generation member state; its installer never runs on cold restore.
     */
    fun canonicalProcesses(keycloak: RuntimeProcess, bao: RuntimeProcess): List<RuntimeProcess> {
        require(keycloak.id == "keycloak" && !keycloak.oneShot && keycloak.environmentFile == "identity-runtime.env")
        require(bao.id == "bao" && !bao.oneShot && bao.command == listOf("server", "-config=/run/secrets/bao.hcl"))
        return listOf(
            RuntimeProcess("keeper-trust-init", IMAGE, IMAGE_ID, 65532, oneShot = true, entrypoint = "/bin/sh",
                files = listOf("identity-ca.pem", "bao-ca.pem", "keeper-ca.pem").map { RuntimeFile(it, "/run/secrets/$it") },
                volumes = listOf(RuntimeMount("trust", "/trust")), apparmorProfile = "p0v3-private-v1",
                command = listOf("-ec", """
                    test -z "${'$'}(ls -A /trust)"; umask 077
                    # The image digest pins its installed public WebPKI CA set. Copy those
                    # trust anchors into this generation-local keystore BEFORE appending
                    # the three private service CAs; never change JVM/global trust.
                    test -s /opt/java/openjdk/lib/security/cacerts
                    /opt/java/openjdk/bin/keytool -importkeystore -noprompt \
                      -srckeystore /opt/java/openjdk/lib/security/cacerts -srcstorepass changeit \
                      -destkeystore /trust/trust.p12 -deststoretype PKCS12 -deststorepass changeit
                    for name in identity bao keeper; do
                      /opt/java/openjdk/bin/keytool -importcert -noprompt -alias "p0v3-${'$'}name" -file "/run/secrets/${'$'}name-ca.pem" -keystore /trust/trust.p12 -storetype PKCS12 -storepass changeit
                    done
                    sync
                """.trimIndent())),
            RuntimeProcess("keeper", IMAGE, IMAGE_ID, 65532, dependencies = listOf(keycloak.id, bao.id, "keeper-trust-init"),
                command = listOf("serve", "--oidc"), environmentFile = "keeper.env", memoryMiB = 512,
                files = listOf("keeper-web.pem", "keeper-web-key.pem").map { RuntimeFile(it, "/run/secrets/$it") },
                volumes = listOf(RuntimeMount("trust", "/trust")), networks = listOf("identity-web", "bao-web", "keeper-web"),
                readiness = listOf("/opt/keykeeper/bin/p0-v3-keykeeper", "probe"), apparmorProfile = "p0v3-private-v1")
        )
    }

    fun canonicalColdRestoreProcesses(processes: List<RuntimeProcess>, revisionFile: String? = null): List<RuntimeProcess> {
        require(revisionFile == null || revisionFile == "keeper-revision.env") {
            "Restored Keykeeper must use the append-only target-generation credential revision" }
        val init = processes.single { it.id == "keeper-trust-init" }
        val keeper = processes.single { it.id == "keeper" }
        require(init.oneShot && init.volumes == listOf(RuntimeMount("trust", "/trust")) &&
            keeper.volumes == listOf(RuntimeMount("trust", "/trust")) && !keeper.oneShot &&
            keeper.command == listOf("serve", "--oidc") && keeper.environmentFile == "keeper.env" &&
            keeper.dependencies.toSet() == setOf("keycloak", "bao", "keeper-trust-init"))
        return processes.filterNot { it.id == init.id }.map {
            if (it.id == "keeper") it.copy(dependencies = listOf("keycloak", "bao"),
                environmentFile = revisionFile ?: it.environmentFile) else it
        }
    }

    /** Exact OIDC clients contributed to the one canonical Keycloak realm before initial import.
     * The service-account sub is read from Keycloak after import, never manufactured from a fixture UUID.
     */
    fun canonicalClients(agentSecret: String, introspectionSecret: String, generation: String,
        keeperOrigin: String = "https://keykeeper.datamancy.net"): JsonArray {
        require(generation.matches(Regex("q-[a-f0-9]{12}")))
        require(agentSecret.isNotBlank() && introspectionSecret.isNotBlank() && agentSecret != introspectionSecret)
        require(keeperOrigin == "https://keykeeper.datamancy.net")
        fun client(id: String, kind: String?, secret: String? = null) = buildJsonObject {
            val human = id == "keykeeper-human"
            put("clientId", id); put("enabled", true); put("protocol", "openid-connect")
            put("publicClient", human); put("standardFlowEnabled", human)
            put("directAccessGrantsEnabled", false); put("serviceAccountsEnabled", id == "keykeeper-agent")
            put("fullScopeAllowed", false)
            if (secret != null) put("secret", secret)
            put("redirectUris", buildJsonArray { if (human) add("$keeperOrigin/auth/callback") })
            put("webOrigins", buildJsonArray { if (human) add(keeperOrigin) })
            put("attributes", buildJsonObject { put("pkce.code.challenge.method", "S256") })
            put("protocolMappers", buildJsonArray { if (kind != null) {
                add(buildJsonObject {
                    put("name", "keykeeper-audience"); put("protocol", "openid-connect"); put("protocolMapper", "oidc-audience-mapper")
                    put("config", buildJsonObject { put("included.custom.audience", "keykeeper"); put("access.token.claim", "true") })
                })
                add(buildJsonObject {
                    put("name", "keykeeper-introspection-audience"); put("protocol", "openid-connect")
                    put("protocolMapper", "oidc-audience-mapper")
                    put("config", buildJsonObject {
                        put("included.client.audience", "keykeeper-introspection")
                        put("access.token.claim", "true"); put("introspection.token.claim", "true")
                    })
                })
                if (human) add(buildJsonObject {
                    put("name", "managed-lane-audience"); put("protocol", "openid-connect"); put("protocolMapper", "oidc-audience-mapper")
                    put("config", buildJsonObject {
                        put("included.custom.audience", "managed-lanes"); put("access.token.claim", "true")
                    })
                })
                add(buildJsonObject {
                    put("name", "keykeeper-principal-type"); put("protocol", "openid-connect"); put("protocolMapper", "oidc-hardcoded-claim-mapper")
                    put("config", buildJsonObject {
                        put("claim.name", "keykeeper_principal_type"); put("claim.value", kind)
                        put("jsonType.label", "String"); put("access.token.claim", "true")
                    })
                })
                add(buildJsonObject {
                    put("name", "keykeeper-generation"); put("protocol", "openid-connect"); put("protocolMapper", "oidc-hardcoded-claim-mapper")
                    put("config", buildJsonObject {
                        put("claim.name", "p0v3_generation"); put("claim.value", generation)
                        put("jsonType.label", "String"); put("access.token.claim", "true")
                    })
                })
            } })
        }
        return buildJsonArray {
            add(client("keykeeper-human", "HUMAN")); add(client("keykeeper-agent", "AGENT", agentSecret))
            add(client("keykeeper-introspection", null, introspectionSecret))
        }
    }

    /** A separate confidential service account for managed lanes; it cannot mint a Keykeeper
     * audience token. Human browser authorization uses the same registered Keykeeper PKCE
     * client, with a second explicitly signed managed-lanes audience and a broker-bound grant.
     */
    fun canonicalManagedLaneClient(secret: String, generation: String): JsonObject {
        require(secret.isNotBlank() && generation.matches(Regex("q-[a-f0-9]{12}")))
        return buildJsonObject {
            put("clientId", "managed-lane-agent"); put("enabled", true); put("protocol", "openid-connect")
            put("publicClient", false); put("secret", secret); put("standardFlowEnabled", false)
            put("directAccessGrantsEnabled", false); put("serviceAccountsEnabled", true); put("fullScopeAllowed", false)
            put("redirectUris", buildJsonArray { }); put("webOrigins", buildJsonArray { })
            put("protocolMappers", buildJsonArray {
                add(buildJsonObject {
                    put("name", "managed-lane-audience"); put("protocol", "openid-connect"); put("protocolMapper", "oidc-audience-mapper")
                    put("config", buildJsonObject { put("included.custom.audience", "managed-lanes"); put("access.token.claim", "true")
                        put("introspection.token.claim", "true") })
                })
                add(buildJsonObject {
                    put("name", "keykeeper-introspection-audience"); put("protocol", "openid-connect")
                    put("protocolMapper", "oidc-audience-mapper")
                    put("config", buildJsonObject {
                        put("included.client.audience", "keykeeper-introspection")
                        put("access.token.claim", "true"); put("introspection.token.claim", "true")
                    })
                })
                add(buildJsonObject {
                    put("name", "managed-lane-principal-type"); put("protocol", "openid-connect"); put("protocolMapper", "oidc-hardcoded-claim-mapper")
                    put("config", buildJsonObject {
                        put("claim.name", "keykeeper_principal_type"); put("claim.value", "AGENT")
                        put("jsonType.label", "String"); put("access.token.claim", "true")
                        put("introspection.token.claim", "true")
                    })
                })
                add(buildJsonObject {
                    put("name", "keykeeper-generation"); put("protocol", "openid-connect"); put("protocolMapper", "oidc-hardcoded-claim-mapper")
                    put("config", buildJsonObject {
                        put("claim.name", "p0v3_generation"); put("claim.value", generation)
                        put("jsonType.label", "String"); put("access.token.claim", "true")
                        put("introspection.token.claim", "true")
                    })
                })
            })
        }
    }

    /** Broker-side confidential native reader only. It has no Keykeeper/managed-lanes
     * audience, no browser/agent grant, and one realm-management VIEW role for enabled
     * original Keycloak subject readback on every broker request and idle tick.
     */
    fun canonicalManagedLaneReaderClient(secret: String, generation: String): JsonObject {
        require(secret.isNotBlank() && generation.matches(Regex("q-[a-f0-9]{12}")))
        return buildJsonObject {
            put("clientId", "managed-lane-reader"); put("enabled", true); put("protocol", "openid-connect")
            put("publicClient", false); put("secret", secret); put("standardFlowEnabled", false)
            put("directAccessGrantsEnabled", false); put("serviceAccountsEnabled", true)
            put("fullScopeAllowed", false)
            put("redirectUris", buildJsonArray { }); put("webOrigins", buildJsonArray { })
            put("defaultClientScopes", buildJsonArray { add("roles") })
            put("protocolMappers", buildJsonArray {
                add(buildJsonObject {
                    put("name", "native-realm-management-audience"); put("protocol", "openid-connect")
                    put("protocolMapper", "oidc-audience-mapper")
                    put("config", buildJsonObject {
                        put("included.client.audience", "realm-management")
                        put("access.token.claim", "true"); put("introspection.token.claim", "true")
                    })
                })
                add(buildJsonObject {
                    put("name", "keykeeper-generation"); put("protocol", "openid-connect")
                    put("protocolMapper", "oidc-hardcoded-claim-mapper")
                    put("config", buildJsonObject {
                        put("claim.name", "p0v3_generation"); put("claim.value", generation)
                        put("jsonType.label", "String"); put("access.token.claim", "true")
                        put("introspection.token.claim", "true")
                    })
                })
            })
        }
    }

    fun canonicalManagedLaneReaderServiceAccount(subject: String): JsonObject {
        require(runCatching { UUID.fromString(subject).toString() }.getOrNull() == subject)
        return buildJsonObject {
            put("id", subject); put("username", "service-account-managed-lane-reader")
            put("enabled", true); put("serviceAccountClientId", "managed-lane-reader")
            put("clientRoles", buildJsonObject { put("realm-management", buildJsonArray { add("view-users") }) })
        }
    }

    fun canonicalManagedLaneServiceAccount(subject: String): JsonObject {
        require(runCatching { UUID.fromString(subject).toString() }.getOrNull() == subject)
        return buildJsonObject {
            put("id", subject); put("username", "service-account-managed-lane-agent"); put("enabled", true)
            put("serviceAccountClientId", "managed-lane-agent")
        }
    }

    /** Identity is assigned ONCE in the sealed realm import and then read back from Keycloak;
     * no restored generation calls this initializer or allocates a replacement principal.
     */
    fun canonicalServiceAccount(subject: String): JsonObject {
        require(runCatching { UUID.fromString(subject).toString() }.getOrNull() == subject)
        return buildJsonObject {
            put("id", subject); put("username", "service-account-keykeeper-agent"); put("enabled", true)
            put("serviceAccountClientId", "keykeeper-agent")
        }
    }

    /** No Bao root, recovery unseal, bootstrap password or fabricated token is ever generated here.
     * The caller must have provisioned a scoped, generation-bound Bao policy and verified its lease.
     */
    fun canonicalInputs(baoToken: String, introspectionSecret: String, agentSubjects: Set<String>, generation: String,
        keeperPki: Map<String, String>, identityCa: String, baoCa: String): Map<String, String> {
        require(generation.matches(Regex("q-[a-f0-9]{12}")))
        require(baoToken.isNotBlank() && introspectionSecret.isNotBlank() &&
            agentSubjects.isNotEmpty() && agentSubjects.all { runCatching { UUID.fromString(it).toString() }.getOrNull() == it })
        require(keeperPki.keys == setOf("ca.pem", "web.pem", "web-key.pem"))
        val environment = "KEYKEEPER_GENERATION_ID=$generation\nKEYKEEPER_OIDC_ISSUER=https://auth.datamancy.net/realms/p0v3\n" +
            "KEYKEEPER_OIDC_AUDIENCE=keykeeper\nKEYKEEPER_OIDC_HUMAN_CLIENT=keykeeper-human\n" +
            "KEYKEEPER_OIDC_AGENT_CLIENT=keykeeper-agent\nKEYKEEPER_OIDC_AGENT_SUBJECTS=${agentSubjects.sorted().joinToString(",")}\n" +
            "KEYKEEPER_OIDC_INTROSPECTION_CLIENT=keykeeper-introspection\n" +
            "KEYKEEPER_OIDC_INTROSPECTION_SECRET=$introspectionSecret\n" +
            "KEYKEEPER_BAO_URL=https://bao:8200\nKEYKEEPER_BAO_MOUNT=keykeeper\n" +
            "KEYKEEPER_BAO_TOKEN=$baoToken\nKEYKEEPER_BAO_REMOTE_HTTPS=true\n" +
            "KEYKEEPER_PORT=8443\nKEYKEEPER_PUBLIC_ORIGIN=https://keykeeper.datamancy.net\n" +
            "KEYKEEPER_PROBE_ORIGIN=https://keeper:8443\n" +
            "KEYKEEPER_TLS_CERTIFICATE=/run/secrets/keeper-web.pem\n" +
            "KEYKEEPER_TLS_PRIVATE_KEY=/run/secrets/keeper-web-key.pem\n" +
            "KEYKEEPER_URL=https://keykeeper.datamancy.net\nKEYKEEPER_REMOTE_HTTPS=true\n" +
            "JAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStore=/trust/trust.p12 -Djavax.net.ssl.trustStorePassword=changeit\nHOME=/tmp\n"
        return mapOf("keeper.env" to environment, "identity-ca.pem" to identityCa, "bao-ca.pem" to baoCa,
            "keeper-ca.pem" to keeperPki.getValue("ca.pem"), "keeper-web.pem" to keeperPki.getValue("web.pem"),
            "keeper-web-key.pem" to keeperPki.getValue("web-key.pem"))
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
