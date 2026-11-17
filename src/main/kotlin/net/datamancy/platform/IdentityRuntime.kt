package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.json.*

/** Persistent private Keycloak deployment, not public identity activation. */
internal object IdentityRuntime {
    private const val IMAGE = "localhost/p0v3-keycloak@sha256:ff264e6231948cf3b879dc3d08f89cbdd0dbef24c044ef1c4dcd71f571b77c1e"
    private const val IMAGE_ID = "345177fdf5102c9a0b017e1ef0eb409a0020c74ee4feaca82b1389758de041e1"
    fun spec(inventory: AcquiredInventory, name: String = "identity"): PrivateDeploymentSpec {
        val foundation = FoundationRuntime.spec(inventory, name)
        val pg = foundation.processes.single { it.id == "postgres" }
        return PrivateDeploymentSpec(name = name, volumes = foundation.volumes.filter { it.id == "postgres" },
            processes = foundation.processes.filter { it.id in setOf("postgres-init", "postgres") } + listOf(
                RuntimeProcess("identity-db-init", pg.image, pg.imageId, 999, dependencies = listOf("postgres"),
                    entrypoint = "/bin/sh", environmentFile = "database-init.env", oneShot = true,
                    apparmorProfile = "p0v3-private-v1", command = listOf("-ec", """
                        export PGPASSWORD="${'$'}POSTGRES_PASSWORD"
                        psql -X -h postgres -U postgres -v ON_ERROR_STOP=1 <<SQL
                        CREATE ROLE keycloak LOGIN PASSWORD '${'$'}KEYCLOAK_PASSWORD';
                        CREATE DATABASE keycloak OWNER keycloak;
                        SQL
                    """.trimIndent())),
                RuntimeProcess("keycloak", IMAGE, IMAGE_ID, 1000, groupId = 0, dependencies = listOf("identity-db-init"),
                    command = listOf("start", "--optimized", "--import-realm"), environmentFile = "keycloak.env",
                    files = listOf(RuntimeFile("realm.json", "/opt/keycloak/data/import/realm.json")),
                    tmpfs = listOf("/tmp", "/opt/keycloak/data"), memoryMiB = 1024, apparmorProfile = "p0v3-private-v1",
                    readiness = listOf("/bin/bash", "-ec", "exec 3<>/dev/tcp/127.0.0.1/9000; printf 'GET /health/ready HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n' >&3; read -r -t 3 line <&3; [[ \"${'$'}line\" == *' 200 '* ]]"))
            )).also { PrivateDeployment.validate(it) }
    }
    fun inputs(): Map<String, String> {
            val postgresPassword = RuntimePreparation.password()
            val applicationPassword = RuntimePreparation.password()
            val bootstrapPassword = RuntimePreparation.password()
            val initialPassword = RuntimePreparation.password()
            val realm = buildJsonObject {
                put("realm", "p0v3"); put("enabled", true); put("sslRequired", "none"); put("registrationAllowed", false)
                put("users", buildJsonArray { add(buildJsonObject {
                    put("username", "owner"); put("enabled", true)
                    put("requiredActions", buildJsonArray { add("UPDATE_PASSWORD"); add("CONFIGURE_TOTP") })
                    put("credentials", buildJsonArray { add(buildJsonObject {
                        put("type", "password"); put("value", initialPassword); put("temporary", true)
                    }) })
                }) })
            }
            return mapOf(
                "postgres.env" to "POSTGRES_PASSWORD=$postgresPassword\n",
                "database-init.env" to "POSTGRES_PASSWORD=$postgresPassword\nKEYCLOAK_PASSWORD=$applicationPassword\n",
                "keycloak.env" to "KC_DB=postgres\nKC_DB_URL=jdbc:postgresql://postgres:5432/keycloak\nKC_DB_USERNAME=keycloak\nKC_DB_PASSWORD=$applicationPassword\nKC_HTTP_ENABLED=true\nKC_HOSTNAME=http://keycloak:8080\nKC_BOOTSTRAP_ADMIN_USERNAME=p0v3-bootstrap\nKC_BOOTSTRAP_ADMIN_PASSWORD=$bootstrapPassword\n",
                "realm.json" to realm.toString())
    }
    /** Provider-less canonical projection. Caller owns postgres and the three named networks.
     * Offline realm import owns migrations; serving Keycloak cannot run DDL or regain bootstrap inputs. */
    fun canonicalProcesses(postgres: RuntimeProcess): List<RuntimeProcess> {
        fun sql(id: String, dependencies: List<String>, command: String) = RuntimeProcess(id, postgres.image, postgres.imageId,
            postgres.userId, groupId = postgres.groupId, dependencies = dependencies, entrypoint = "/bin/sh",
            command = listOf("-ec", command), environmentFile = "identity-db-admin.env", oneShot = true,
            files = listOf(RuntimeFile("postgres-ca.pem", "/run/secrets/postgres-ca.pem")),
            networks = listOf("db-admin"), apparmorProfile = "p0v3-private-v1")
        return listOf(
            sql("identity-db-init", listOf(postgres.id), """
                psql -X -v ON_ERROR_STOP=1 <<SQL
                CREATE ROLE keycloak_migrate LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '${'$'}KEYCLOAK_MIGRATION_PASSWORD';
                CREATE ROLE keycloak LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '${'$'}KEYCLOAK_PASSWORD';
                CREATE DATABASE keycloak OWNER keycloak_migrate;
                REVOKE ALL ON DATABASE keycloak FROM PUBLIC;
                GRANT CONNECT ON DATABASE keycloak TO keycloak;
                SQL
            """.trimIndent()),
            RuntimeProcess("identity-realm-init", IMAGE, IMAGE_ID, 1000, groupId = 0, dependencies = listOf("identity-db-init"),
                command = listOf("import", "--optimized", "--file=/run/secrets/identity-realm.json"), oneShot = true,
                environmentFile = "identity-migration.env", memoryMiB = 1024, networks = listOf("keycloak-data"),
                files = listOf(RuntimeFile("identity-realm.json", "/run/secrets/identity-realm.json"),
                    RuntimeFile("postgres-ca.pem", "/run/secrets/postgres-ca.pem")),
                tmpfs = listOf("/tmp", "/opt/keycloak/data"), apparmorProfile = "p0v3-private-v1"),
            sql("identity-db-finalize", listOf("identity-realm-init"), """
                psql -X -d keycloak -v ON_ERROR_STOP=1 <<'SQL'
                REVOKE CREATE ON SCHEMA public FROM PUBLIC;
                GRANT USAGE ON SCHEMA public TO keycloak;
                GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO keycloak;
                GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO keycloak;
                ALTER ROLE keycloak_migrate NOLOGIN;
                SQL
            """.trimIndent()),
            RuntimeProcess("keycloak", IMAGE, IMAGE_ID, 1000, groupId = 0, dependencies = listOf("identity-db-finalize"),
                command = listOf("start", "--optimized", "--spi-connections-jpa--quarkus--migration-strategy=validate"),
                environmentFile = "identity-runtime.env", memoryMiB = 1024, networks = listOf("keycloak-data", "identity-web"),
                files = listOf("identity-web.pem", "identity-web-key.pem", "identity-ca.pem", "postgres-ca.pem").map { RuntimeFile(it, "/run/secrets/$it") },
                tmpfs = listOf("/tmp", "/opt/keycloak/data"), apparmorProfile = "p0v3-private-v1",
                readiness = listOf("/bin/bash", "-ec", "exec 3<>/dev/tcp/127.0.0.1/9000; printf 'GET /health/ready HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n' >&3; read -r -t 3 line <&3; [[ \"${'$'}line\" == *' 200 '* ]]"))
        )
    }

    /** Composable projection; other products' jobs are intentionally left for their owning projections. */
    fun canonicalColdRestoreProcesses(processes: List<RuntimeProcess>): List<RuntimeProcess> {
        val retired = setOf("identity-db-init", "identity-realm-init", "identity-db-finalize")
        require(processes.filter { it.id in retired }.map { it.id }.toSet() == retired &&
            processes.filter { it.id in retired }.all { it.oneShot })
        val daemon = processes.single { it.id == "keycloak" }
        require(!daemon.oneShot && daemon.environmentFile == "identity-runtime.env" &&
            daemon.command == listOf("start", "--optimized", "--spi-connections-jpa--quarkus--migration-strategy=validate") &&
            daemon.files.map { it.file }.toSet() == setOf("identity-web.pem", "identity-web-key.pem", "identity-ca.pem", "postgres-ca.pem"))
        return processes.filterNot { it.id in retired }.map { process ->
            if (process.id == "keycloak") process.copy(dependencies = listOf("postgres"))
            else process.copy(dependencies = process.dependencies.filterNot { it in retired })
        }
    }

    /** Separate human PKCE operator client. The callback is a fixed same-site page, not an
     * arbitrary local redirect or a direct-password grant; only the original native owner UUID
     * may subsequently pass IdentityAuthority's subject+generation+scope readback.
     */
    fun canonicalOperatorClient(generation: String): JsonObject {
        require(generation.matches(Regex("q-[a-f0-9]{12}")))
        return buildJsonObject {
            put("clientId", "identity-controller"); put("enabled", true); put("protocol", "openid-connect")
            put("publicClient", true); put("standardFlowEnabled", true)
            put("directAccessGrantsEnabled", false); put("serviceAccountsEnabled", false)
            // Realm clientScopeMappings below expose only the original owner's assigned
            // p0v3 realm-management roles; no master-realm or full-scope token is granted.
            put("fullScopeAllowed", false)
            put("redirectUris", buildJsonArray { add("https://start.datamancy.net/identity/operator/callback") })
            put("webOrigins", buildJsonArray { add("https://start.datamancy.net") })
            put("attributes", buildJsonObject { put("pkce.code.challenge.method", "S256") })
            put("defaultClientScopes", buildJsonArray {
                for (name in listOf("profile", "email", "roles", "web-origins",
                    "identity:manage", "bao:recover", "credentials:rotate")) add(name)
            })
            put("protocolMappers", buildJsonArray {
                add(buildJsonObject {
                    put("name", "keykeeper-introspection-audience"); put("protocol", "openid-connect")
                    put("protocolMapper", "oidc-audience-mapper")
                    put("config", buildJsonObject {
                        put("included.client.audience", "keykeeper-introspection")
                        put("access.token.claim", "true"); put("introspection.token.claim", "true")
                    })
                })
                add(buildJsonObject {
                    put("name", "identity-generation"); put("protocol", "openid-connect")
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

    /** ORIGINAL imported issuer authority for cold RESTORE only. Core mints the
     * original 256-bit secret once in protected full-generation inputs. A target
     * never imports this as a new realm nor signs a token locally: its inherited
     * client credentials are exchanged against the imported, pinned target issuer.
     * manage-realm is limited to the selected realm's all-session notBefore revocation.
     */
    fun canonicalRestoreControllerClient(secret: String, generation: String): JsonObject {
        require(secret.matches(Regex("[a-f0-9]{64}")) && generation.matches(Regex("q-[a-f0-9]{12}")))
        return buildJsonObject {
            put("clientId", "managed-restore-controller"); put("enabled", true)
            put("protocol", "openid-connect"); put("publicClient", false); put("secret", secret)
            put("standardFlowEnabled", false); put("directAccessGrantsEnabled", false)
            put("serviceAccountsEnabled", true); put("fullScopeAllowed", false)
            put("redirectUris", buildJsonArray {}); put("webOrigins", buildJsonArray {})
            put("defaultClientScopes", buildJsonArray { add("roles") })
            put("protocolMappers", buildJsonArray {
                add(buildJsonObject {
                    put("name", "restore-native-realm-management-audience")
                    put("protocol", "openid-connect"); put("protocolMapper", "oidc-audience-mapper")
                    put("config", buildJsonObject {
                        put("included.client.audience", "realm-management")
                        put("access.token.claim", "true"); put("introspection.token.claim", "true")
                    })
                })
                add(buildJsonObject {
                    put("name", "original-restore-generation")
                    put("protocol", "openid-connect"); put("protocolMapper", "oidc-hardcoded-claim-mapper")
                    put("config", buildJsonObject {
                        put("claim.name", "p0v3_generation"); put("claim.value", generation)
                        put("jsonType.label", "String"); put("access.token.claim", "true")
                        put("introspection.token.claim", "true")
                    })
                })
            })
        }
    }

    fun canonicalRestoreControllerServiceAccount(subject: String): JsonObject {
        require(runCatching { java.util.UUID.fromString(subject).toString() }.getOrNull() == subject)
        return buildJsonObject {
            put("id", subject); put("username", "service-account-managed-restore-controller")
            put("enabled", true); put("serviceAccountClientId", "managed-restore-controller")
            put("clientRoles", buildJsonObject { put("realm-management", buildJsonArray {
                listOf("view-users", "view-clients", "manage-clients", "manage-realm").forEach { add(it) }
            }) })
        }
    }

    fun canonicalInputs(postgresAdminPassword: String, pki: () -> Map<String, String> = { PrivateWebPki.generate("keycloak") },
        password: () -> String = RuntimePreparation::password, clients: JsonArray = JsonArray(emptyList()),
        serviceAccounts: JsonArray = JsonArray(emptyList()), issuerOrigin: String = "https://auth.datamancy.net",
        originalOwnerId: String? = null, originalOutsiderId: String? = null,
        originalMemberships: Map<String, Set<String>>? = null,
        originalAppNonMemberId: String? = null): Map<String, String> {
        require((originalOwnerId == null && originalOutsiderId == null) ||
            (originalOwnerId != null && originalOutsiderId != null && originalOwnerId != originalOutsiderId &&
                listOf(originalOwnerId, originalOutsiderId).all {
                    runCatching { java.util.UUID.fromString(it).toString() == it }.getOrDefault(false)
                } && serviceAccounts.none { it.jsonObject["id"]?.jsonPrimitive?.content in setOf(originalOwnerId, originalOutsiderId) })) {
            "Original human owner/outsider UUIDs must be distinct from each other and service accounts" }
        require(originalAppNonMemberId == null || originalMemberships != null &&
            serviceAccounts.none { it.jsonObject["id"]?.jsonPrimitive?.content == originalAppNonMemberId })
        if (originalMemberships != null) require(originalOwnerId != null && originalOutsiderId != null &&
            originalMemberships.keys == setOfNotNull(originalOwnerId, originalOutsiderId, originalAppNonMemberId) &&
            (originalAppNonMemberId == null || (originalAppNonMemberId != originalOwnerId &&
                originalAppNonMemberId != originalOutsiderId &&
                runCatching { java.util.UUID.fromString(originalAppNonMemberId).toString() == originalAppNonMemberId }
                    .getOrDefault(false) && originalMemberships[originalOutsiderId].orEmpty().isEmpty() &&
                originalMemberships[originalAppNonMemberId] == setOf("users"))) &&
            originalMemberships.values.all { it.all { group -> group in
                setOf("admins", "operators", "users", "developers", "agents") } }) {
            "Never generate protected Keycloak grants from new subjects or undeclared groups"
        }
        require(issuerOrigin == "https://auth.datamancy.net") { "Canonical issuer is the exact approved public hostname" }
        val clientIds = clients.map { it.jsonObject["clientId"]?.jsonPrimitive?.content }
        require(clientIds.size == clientIds.distinct().size && clientIds.none { it.isNullOrBlank() })
        val operator = clients.firstOrNull { it.jsonObject["clientId"]?.jsonPrimitive?.content == "identity-controller" }
        if (operator != null) {
            val mapper = operator.jsonObject["protocolMappers"]?.jsonArray?.singleOrNull {
                it.jsonObject["name"]?.jsonPrimitive?.content == "identity-generation" }?.jsonObject
            val claim = mapper?.get("config")?.jsonObject?.get("claim.value")?.jsonPrimitive?.content
            require(claim != null && claim.matches(Regex("q-[a-f0-9]{12}")) &&
                operator.jsonObject == canonicalOperatorClient(claim)) {
                "The operator client, its generation and native PKCE scopes must be fixed before credentials" }
        }
        val agent = clients.firstOrNull { it.jsonObject["clientId"]?.jsonPrimitive?.content == "managed-lane-agent" }
        if (agent != null) {
            val obj = agent.jsonObject
            val generation = obj["protocolMappers"]?.jsonArray?.singleOrNull {
                it.jsonObject["name"]?.jsonPrimitive?.content == "keykeeper-generation" }?.jsonObject
                ?.get("config")?.jsonObject?.get("claim.value")?.jsonPrimitive?.content
            val secret = obj["secret"]?.jsonPrimitive?.content
            require(generation != null && generation.matches(Regex("q-[a-f0-9]{12}")) &&
                secret != null && obj == KeykeeperRuntime.canonicalManagedLaneClient(secret, generation)) {
                "Native agent issuer, managed-lanes audience and introspection generation must be exact" }
            val account = serviceAccounts.singleOrNull {
                it.jsonObject["serviceAccountClientId"]?.jsonPrimitive?.content == "managed-lane-agent" }?.jsonObject
            val subject = account?.get("id")?.jsonPrimitive?.content
            require(subject != null && account == KeykeeperRuntime.canonicalManagedLaneServiceAccount(subject)) {
                "Native managed-lane agent must retain one distinct original Keycloak service account UUID" }
        }
        val reader = clients.firstOrNull { it.jsonObject["clientId"]?.jsonPrimitive?.content == "managed-lane-reader" }
        if (reader != null) {
            val obj = reader.jsonObject
            val generation = obj["protocolMappers"]?.jsonArray?.singleOrNull {
                it.jsonObject["name"]?.jsonPrimitive?.content == "keykeeper-generation" }?.jsonObject
                ?.get("config")?.jsonObject?.get("claim.value")?.jsonPrimitive?.content
            val secret = obj["secret"]?.jsonPrimitive?.content
            require(generation != null && generation.matches(Regex("q-[a-f0-9]{12}")) &&
                secret != null && obj == KeykeeperRuntime.canonicalManagedLaneReaderClient(secret, generation)) {
                "Native view-users reader must be a fixed generation-bound confidential client" }
            val account = serviceAccounts.singleOrNull {
                it.jsonObject["serviceAccountClientId"]?.jsonPrimitive?.content == "managed-lane-reader" }
                ?.jsonObject
            val subject = account?.get("id")?.jsonPrimitive?.content
            require(subject != null && account == KeykeeperRuntime.canonicalManagedLaneReaderServiceAccount(subject)) {
                "Native view-users reader must retain a separately pinned UUID and one role" }
        }
        val restore = clients.firstOrNull { it.jsonObject["clientId"]?.jsonPrimitive?.content == "managed-restore-controller" }
        if (restore != null) {
            val obj = restore.jsonObject
            val generation = obj["protocolMappers"]?.jsonArray?.singleOrNull {
                it.jsonObject["name"]?.jsonPrimitive?.content == "original-restore-generation" }?.jsonObject
                ?.get("config")?.jsonObject?.get("claim.value")?.jsonPrimitive?.content
            val secret = obj["secret"]?.jsonPrimitive?.content
            require(originalOwnerId != null && originalOutsiderId != null && generation != null &&
                generation.matches(Regex("q-[a-f0-9]{12}")) && secret != null &&
                obj == canonicalRestoreControllerClient(secret, generation) &&
                clients.filter { it.jsonObject["clientId"]?.jsonPrimitive?.content in
                    setOf("managed-lane-agent", "managed-lane-reader", "identity-controller") }
                    .all { client -> client.jsonObject["protocolMappers"]?.jsonArray?.any { mapper ->
                        mapper.jsonObject["config"]?.jsonObject?.get("claim.value")?.jsonPrimitive?.content == generation
                    } == true } &&
                clients.none { it !== restore && it.jsonObject["secret"]?.jsonPrimitive?.content == secret }) {
                "Original restore authority must be one sealed distinct scoped generation client" }
            val account = serviceAccounts.singleOrNull {
                it.jsonObject["serviceAccountClientId"]?.jsonPrimitive?.content == "managed-restore-controller" }?.jsonObject
            val subject = account?.get("id")?.jsonPrimitive?.content
            require(subject != null && account == canonicalRestoreControllerServiceAccount(subject) &&
                subject !in setOfNotNull(originalOwnerId, originalOutsiderId, originalAppNonMemberId)) {
                "Original restore principal needs a separate pinned UUID and only four native realm roles" }
        }
        require(serviceAccounts.all { it is JsonObject && it["id"]?.jsonPrimitive?.content?.let { id ->
            runCatching { java.util.UUID.fromString(id).toString() }.getOrNull() == id
        } == true && it["serviceAccountClientId"]?.jsonPrimitive?.content in clientIds } &&
            serviceAccounts.map { it.jsonObject["id"]?.jsonPrimitive?.content }.distinct().size == serviceAccounts.size) {
            "Service-account identities must be bound to distinct declared clients" }
        val migration = password(); val runtime = password(); val initial = password()
        val outsiderInitial = if (originalOutsiderId != null) password() else null
        val appNonMemberInitial = if (originalAppNonMemberId != null) password() else null
        val secrets = listOfNotNull(postgresAdminPassword, migration, runtime, initial, outsiderInitial, appNonMemberInitial)
        require(secrets.all { it.matches(Regex("[a-f0-9]{64}")) } && secrets.toSet().size == secrets.size &&
            (restore == null || restore.jsonObject.getValue("secret").jsonPrimitive.content !in secrets))
        val tls = pki()
        require(tls.keys == setOf("ca.pem", "web.pem", "web-key.pem"))
        val adminRoles = listOf("manage-users", "view-users", "manage-clients", "view-clients", "manage-realm")
        val realm = buildJsonObject {
            put("realm", "p0v3"); put("enabled", true); put("sslRequired", "all"); put("registrationAllowed", false)
            // Admin-issued required-action links are bounded to one 30-minute
            // enrollment/recovery window. This is NOT a password expiry claim.
            put("actionTokenGeneratedByAdminLifespan", 1800)
            put("actionTokenGeneratedByUserLifespan", 1800)
            put("accessCodeLifespanUserAction", 1800)
            put("loginWithEmailAllowed", false); put("duplicateEmailsAllowed", false)
            put("resetPasswordAllowed", false); put("bruteForceProtected", true); put("accessTokenLifespan", 300)
            put("ssoSessionIdleTimeout", 900); put("ssoSessionMaxLifespan", 3600)
            // Keycloak 26.8 RealmRepresentation accepts requiredActions provider
            // representations, not the unsupported defaultRequiredActions field.
            // Keep the existing per-user requiredActions as a separate guard.
            put("requiredActions", buildJsonArray {
                listOf("UPDATE_PASSWORD", "CONFIGURE_TOTP").forEach { alias ->
                    add(buildJsonObject {
                        put("alias", alias); put("providerId", alias)
                        put("enabled", true); put("defaultAction", true)
                    })
                }
            })
            put("otpPolicyType", "totp"); put("otpPolicyAlgorithm", "HmacSHA256"); put("otpPolicyDigits", 6)
            put("otpPolicyPeriod", 30); put("otpPolicyLookAheadWindow", 1)
            if ("identity-controller" in clientIds || "managed-lane-reader" in clientIds ||
                "managed-restore-controller" in clientIds) {
                put("clientScopeMappings", buildJsonObject {
                    if ("identity-controller" in clientIds) put("identity-controller", buildJsonArray { add(buildJsonObject {
                        put("client", "realm-management")
                        put("roles", buildJsonArray { adminRoles.forEach { add(it) } })
                    }) })
                    if ("managed-lane-reader" in clientIds) put("managed-lane-reader", buildJsonArray { add(buildJsonObject {
                        put("client", "realm-management")
                        put("roles", buildJsonArray { add("view-users") })
                    }) })
                    if ("managed-restore-controller" in clientIds) put("managed-restore-controller", buildJsonArray {
                        add(buildJsonObject {
                            put("client", "realm-management")
                            put("roles", buildJsonArray {
                                listOf("view-users", "view-clients", "manage-clients", "manage-realm").forEach { add(it) }
                            })
                        })
                    })
                })
            }
            if ("identity-controller" in clientIds || "p0v3-edge" in clientIds) {
                put("clientScopes", buildJsonArray {
                    if ("p0v3-edge" in clientIds) add(buildJsonObject {
                        put("name", "groups"); put("protocol", "openid-connect")
                        put("attributes", buildJsonObject {
                            put("include.in.token.scope", "true")
                            put("display.on.consent.screen", "false")
                        })
                        put("protocolMappers", buildJsonArray { add(buildJsonObject {
                            put("name", "groups"); put("protocol", "openid-connect")
                            put("protocolMapper", "oidc-group-membership-mapper")
                            put("config", buildJsonObject {
                                put("full.path", "false"); put("id.token.claim", "true")
                                put("access.token.claim", "true"); put("userinfo.token.claim", "true")
                                put("claim.name", "groups"); put("jsonType.label", "String")
                                put("multivalued", "true")
                            })
                        }) })
                    })
                    for (name in if ("identity-controller" in clientIds)
                        listOf("identity:manage", "bao:recover", "credentials:rotate") else emptyList()) {
                        add(buildJsonObject {
                            put("name", name); put("protocol", "openid-connect")
                            put("attributes", buildJsonObject {
                                put("include.in.token.scope", "true")
                                put("display.on.consent.screen", "false")
                            })
                            if (name == "identity:manage") put("protocolMappers", buildJsonArray { add(buildJsonObject {
                                put("name", "controller-audience"); put("protocol", "openid-connect")
                                put("protocolMapper", "oidc-audience-mapper")
                                put("config", buildJsonObject {
                                    put("included.custom.audience", "controller")
                                    put("access.token.claim", "true"); put("introspection.token.claim", "true")
                                })
                            }) })
                        })
                    }
                })
            }
            // OLD Caddy's group allowlists and the pinned Keycloak runtime scope
            // refer to these exact names. Declaring the groups grants nobody
            // membership; historical grants require authenticated import.
            if ("p0v3-edge" in clientIds) put("groups", buildJsonArray {
                for (name in listOf("admins", "operators", "users", "developers", "agents"))
                    add(buildJsonObject { put("name", name) })
            })
            put("clients", clients)
            put("users", buildJsonArray { add(buildJsonObject {
                put("id", originalOwnerId ?: java.util.UUID.randomUUID().toString()); put("username", "owner"); put("enabled", true)
                originalOwnerId?.let { originalMemberships?.get(it) }?.let { names -> put("groups", buildJsonArray {
                    names.sorted().forEach { add(it) }
                }) }
                // Realm-scoped administration, never master-realm/root authority. Required actions precede token issuance.
                put("clientRoles", buildJsonObject { put("realm-management", buildJsonArray {
                    adminRoles.forEach { add(it) } // `manage-realm` needed only for scoped all-session cold revocation.
                }) })
                put("requiredActions", buildJsonArray { add("UPDATE_PASSWORD"); add("CONFIGURE_TOTP") })
                put("credentials", buildJsonArray { add(buildJsonObject {
                    put("type", "password"); put("temporary", true); put("value", initial)
                }) })
            }); if (originalOutsiderId != null) add(buildJsonObject {
                put("id", originalOutsiderId); put("username", "outsider"); put("enabled", true)
                originalMemberships?.get(originalOutsiderId)?.let { names -> put("groups", buildJsonArray {
                    names.sorted().forEach { add(it) }
                }) }
                put("requiredActions", buildJsonArray { add("UPDATE_PASSWORD"); add("CONFIGURE_TOTP") })
                put("credentials", buildJsonArray { add(buildJsonObject {
                    put("type", "password"); put("temporary", true); put("value", outsiderInitial!!)
                }) })
            }); if (originalAppNonMemberId != null) add(buildJsonObject {
                put("id", originalAppNonMemberId); put("username", "app-nonmember"); put("enabled", true)
                put("groups", buildJsonArray { add("users") })
                put("requiredActions", buildJsonArray { add("UPDATE_PASSWORD"); add("CONFIGURE_TOTP") })
                put("credentials", buildJsonArray { add(buildJsonObject {
                    put("type", "password"); put("temporary", true); put("value", appNonMemberInitial!!)
                }) })
            }); addAll(serviceAccounts) })
        }
        val database = "KC_DB=postgres\nKC_DB_URL=jdbc:postgresql://postgres:5432/keycloak?sslmode=verify-full&sslrootcert=/run/secrets/postgres-ca.pem\n"
        return mapOf(
            "identity-db-admin.env" to "PGHOST=postgres\nPGUSER=postgres\nPGDATABASE=postgres\nPGPASSWORD=$postgresAdminPassword\nPGSSLMODE=verify-full\nPGSSLROOTCERT=/run/secrets/postgres-ca.pem\nKEYCLOAK_MIGRATION_PASSWORD=$migration\nKEYCLOAK_PASSWORD=$runtime\n",
            "identity-migration.env" to database + "KC_DB_USERNAME=keycloak_migrate\nKC_DB_PASSWORD=$migration\n",
            "identity-runtime.env" to database + "KC_DB_USERNAME=keycloak\nKC_DB_PASSWORD=$runtime\nKC_HTTP_ENABLED=false\nKC_HOSTNAME=$issuerOrigin\nKC_HTTPS_PORT=8443\nKC_HTTPS_CERTIFICATE_FILE=/run/secrets/identity-web.pem\nKC_HTTPS_CERTIFICATE_KEY_FILE=/run/secrets/identity-web-key.pem\nKC_HTTP_MANAGEMENT_SCHEME=http\n",
            "identity-realm.json" to realm.toString(), "identity-ca.pem" to tls.getValue("ca.pem"),
            "identity-web.pem" to tls.getValue("web.pem"), "identity-web-key.pem" to tls.getValue("web-key.pem")
        )
    }

    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "identity", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base, ::inputs)
}

/** Application-owned principal mapping, never inferred from a username, display name or email.
 * A recovered application must read the original external subject and native account ID back;
 * provisioning a new account or accepting a token for another generation is not adoption.
 */
internal data class IdentityConsumerBinding(val generation: String, val issuer: String, val audience: String,
    val clientId: String, val subject: String, val nativeAccountId: String, val credentialRevisionSha256: String) {
    init {
        require(generation.matches(Regex("q-[a-f0-9]{12}")))
        require(issuer.startsWith("https://") && java.net.URI(issuer).let { uri ->
            uri.host != null && uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null &&
                uri.path.matches(Regex("/realms/[a-zA-Z0-9_-]+"))
        })
        require(audience.isNotBlank() && clientId.isNotBlank() && subject.isNotBlank() && nativeAccountId.isNotBlank())
        require(credentialRevisionSha256.matches(Regex("[a-f0-9]{64}")))
    }
}

internal data class IdentityAdoptionEvidence(val source: IdentityConsumerBinding, val target: IdentityConsumerBinding,
    val sourceAccountReadback: String, val targetAccountReadback: String, val sourceRevisionHead: String,
    val targetRevisionHead: String)

/** Produced by a native, isolated consumer readback; never inferred from a caller completion flag. */
internal data class IdentityNativeObservation(val issuer: String, val subject: String, val nativeAccountId: String,
    val revisionSha256: String, val isolationReceiptSha256: String, val introspectionActive: Boolean)

internal object IdentityConsumerAuthorization {
    /** The revision head is read at the moment of capture and again after isolated import.
     * No caller-supplied success flag can substitute for observed token introspection or native readback.
     */
    fun requireAdoption(evidence: IdentityAdoptionEvidence, generation: String,
        observation: (IdentityConsumerBinding) -> IdentityNativeObservation) {
        require(evidence.source.generation != evidence.target.generation && evidence.target.generation == generation)
        require(evidence.source.issuer == evidence.target.issuer && evidence.source.audience == evidence.target.audience &&
            evidence.source.clientId == evidence.target.clientId && evidence.source.subject == evidence.target.subject &&
            evidence.source.nativeAccountId == evidence.target.nativeAccountId) { "Reprovisioned principal is not recovered authority" }
        require(evidence.sourceAccountReadback == evidence.source.nativeAccountId &&
            evidence.targetAccountReadback == evidence.source.nativeAccountId) { "Original native account was not recovered" }
        require(evidence.sourceRevisionHead == evidence.source.credentialRevisionSha256 &&
            evidence.targetRevisionHead == evidence.target.credentialRevisionSha256 &&
            evidence.sourceRevisionHead == evidence.targetRevisionHead) { "Credential revision adoption is incomplete" }
        val observed = observation(evidence.target)
        require(observed.issuer == evidence.target.issuer && observed.subject == evidence.target.subject &&
            observed.nativeAccountId == evidence.target.nativeAccountId &&
            observed.revisionSha256 == evidence.targetRevisionHead && observed.introspectionActive &&
            observed.isolationReceiptSha256.matches(Regex("[a-f0-9]{64}"))) {
            "Identity authorization must be read back in an isolated target" }
    }

    /** Reject a disabled or logged-out identity on each use, including each broker stream tick.
     * introspect must be a pinned realm call (no cached successful result).
     */
    fun authorize(binding: IdentityConsumerBinding, issuer: String, audience: String, clientId: String,
        subject: String, generation: String, revisionHead: String, introspect: () -> Boolean): Boolean =
        binding.generation == generation && binding.issuer == issuer && binding.audience == audience &&
            binding.clientId == clientId && binding.subject == subject &&
            binding.credentialRevisionSha256 == revisionHead && runCatching { introspect() }.getOrDefault(false)
}

/** Generation status and credential head MUST come from controller-owned durable records,
 * not the broker's own memory or a caller success flag. Read again for every request/tick.
 */
internal interface IdentityGenerationLedger {
    fun revisionHead(generation: String): String
    fun generationActive(generation: String): Boolean
}

/** Live pinned Keycloak observations. Real transport below uses HTTPS for both frontchannel
 * issuer and the network-private admin account readback; no admin path exposed publicly.
 */
internal interface IdentityNativeTransport {
    fun jwks(): String
    fun introspect(bearer: String): JsonObject
    fun user(subject: String, adminBearer: String): JsonObject
}

/** Native identity authority for A06's fixed OpenAI lane broker. This is not an opaque
 * caller-asserted identity: RSA signatures, pinned issuer/audience/generation, Keycloak
 * introspection and user.enabled are all observed freshly for EACH call and idle tick.
 */
internal class ManagedLaneIdentityAuthority(private val transport: IdentityNativeTransport,
    private val ledger: IdentityGenerationLedger, private val adminBearer: () -> String,
    private val allowedSubjects: Set<String>, private val clients: Map<String, String>,
    private val now: () -> Long = { java.time.Instant.now().epochSecond }) : ManagedLaneAuthority {
    companion object {
        const val ISSUER = "https://auth.datamancy.net/realms/p0v3"
        const val AUDIENCE = "managed-lanes"
        private val sha = Regex("[a-f0-9]{64}")
        private val identifier = Regex("[A-Za-z0-9_-]{1,128}")
        private fun text(objectValue: JsonObject, key: String): String = objectValue.getValue(key).jsonPrimitive.also {
            require(it.isString)
        }.content
        private fun seconds(objectValue: JsonObject, key: String): Long = objectValue.getValue(key).jsonPrimitive.let {
            require(!it.isString && it.content.matches(Regex("[0-9]+")))
            it.content.toLong()
        }
        private fun uuid(value: String): Boolean =
            runCatching { java.util.UUID.fromString(value).toString() }.getOrNull() == value
    }
    init {
        require(allowedSubjects.isNotEmpty() && allowedSubjects.all { uuid(it) })
        require(clients.isNotEmpty() && clients.keys.all { identifier.matches(it) } &&
            clients.values.all { it in setOf("HUMAN", "AGENT") })
    }
    override fun revisionHead(generation: String): String = ledger.revisionHead(generation)
    override fun generationActive(generation: String): Boolean = ledger.generationActive(generation)

    override fun authorizeBearer(bearer: String, expected: ManagedLaneGrant, nowEpochSeconds: Long): Boolean = try {
        require(nowEpochSeconds <= now() + 1 && nowEpochSeconds >= now() - 1 && bearer.length in 24..8192 &&
            expected.issuer == ISSUER && expected.provider == "openai" && expected.model == "gpt-6-sol" &&
            expected.generation.matches(Regex("q-[a-f0-9]{12}")) &&
            expected.subject in allowedSubjects && expected.expiresAtEpochSeconds > nowEpochSeconds &&
            sha.matches(expected.revisionSha256) && sha.matches(expected.tokenHash))
        val presented = java.security.MessageDigest.getInstance("SHA-256").digest(bearer.toByteArray(Charsets.UTF_8))
        val pinned = expected.tokenHash.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        require(java.security.MessageDigest.isEqual(presented, pinned) && ledger.generationActive(expected.generation) &&
            ledger.revisionHead(expected.generation) == expected.revisionSha256)
        val parts = bearer.split('.')
        require(parts.size == 3 && parts.all { it.length in 1..8192 })
        fun decode(component: String): ByteArray {
            require(component.matches(Regex("[A-Za-z0-9_-]+")))
            return java.util.Base64.getUrlDecoder().decode(component)
        }
        val header = Json.parseToJsonElement(decode(parts[0]).decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(header.keys == setOf("alg", "typ", "kid") && text(header, "alg") == "RS256" &&
            text(header, "typ") in setOf("JWT", "at+jwt"))
        val kid = text(header, "kid")
        require(identifier.matches(kid))
        val document = transport.jwks()
        require(document.length <= 131072)
        val keys = Json.parseToJsonElement(document).jsonObject.getValue("keys").jsonArray.map { it.jsonObject }
        require(keys.size in 1..64 && keys.map { text(it, "kid") }.distinct().size == keys.size)
        val key = keys.single { text(it, "kid") == kid }
        require(text(key, "kty") == "RSA" && text(key, "alg") == "RS256" && text(key, "use") == "sig")
        val modulus = java.math.BigInteger(1, decode(text(key, "n")))
        val exponent = java.math.BigInteger(1, decode(text(key, "e")))
        require(modulus.bitLength() in 2048..4096 && exponent == java.math.BigInteger.valueOf(65537))
        val publicKey = java.security.KeyFactory.getInstance("RSA")
            .generatePublic(java.security.spec.RSAPublicKeySpec(modulus, exponent))
        val signature = java.security.Signature.getInstance("SHA256withRSA")
        signature.initVerify(publicKey)
        signature.update("${parts[0]}.${parts[1]}".toByteArray(Charsets.US_ASCII))
        require(signature.verify(decode(parts[2])))
        val claims = Json.parseToJsonElement(decode(parts[1]).decodeToString(throwOnInvalidSequence = true)).jsonObject
        val audience = claims.getValue("aud")
        require(text(claims, "iss") == ISSUER &&
            (if (audience is JsonArray) audience.any { it is JsonPrimitive && it.isString && it.content == AUDIENCE }
             else audience is JsonPrimitive && audience.isString && audience.content == AUDIENCE) &&
            text(claims, "sub") == expected.subject && text(claims, "p0v3_generation") == expected.generation &&
            text(claims, "azp") in clients.keys &&
            text(claims, "keykeeper_principal_type") == clients.getValue(text(claims, "azp")))
        val jti = text(claims, "jti")
        val issued = seconds(claims, "iat")
        val expires = seconds(claims, "exp")
        val notBefore = claims["nbf"]?.let { seconds(claims, "nbf") } ?: issued
        require(identifier.matches(jti) && issued <= nowEpochSeconds && notBefore <= nowEpochSeconds &&
            nowEpochSeconds < expires && expires - issued in 1..3600)
        val observed = transport.introspect(bearer)
        require(observed["active"]?.jsonPrimitive?.booleanOrNull == true &&
            observed["sub"]?.jsonPrimitive?.content == expected.subject &&
            observed["iss"]?.jsonPrimitive?.content == ISSUER &&
            observed["azp"]?.jsonPrimitive?.content == text(claims, "azp") &&
            (observed["jti"] == null || observed["jti"]?.jsonPrimitive?.content == jti))
        val native = transport.user(expected.subject, adminBearer())
        require(native["id"]?.jsonPrimitive?.content == expected.subject &&
            native["enabled"]?.jsonPrimitive?.booleanOrNull == true)
        // Re-read the ledger after network calls: a concurrent disable/retirement must win.
        require(ledger.generationActive(expected.generation) && ledger.revisionHead(expected.generation) == expected.revisionSha256)
        true
    } catch (_: Exception) { false }
}

internal fun interface NativeReaderTokenIssuer {
    fun mint(generation: String, subject: String, secret: String): String
}

/** A short bounded host-only reader-token cache. Native Keycloak still checks its actual
 * view-users permission and the original target user's enabled flag on EVERY broker tick;
 * a retired generation is rejected by the durable controller ledger, not this cache.
 */
internal class ManagedLaneNativeReader(private val issuer: NativeReaderTokenIssuer,
    private val generation: String, private val originalReaderSubject: String,
    private val hostOnlySecret: () -> String,
    private val now: () -> Long = { java.time.Instant.now().epochSecond }) {
    private var cached: Pair<String, Long>? = null
    init {
        require(generation.matches(Regex("q-[a-f0-9]{12}")) &&
            runCatching { java.util.UUID.fromString(originalReaderSubject).toString() }.getOrNull() == originalReaderSubject)
    }
    @Synchronized fun bearer(): String {
        val current = now()
        cached?.let { (token, expiry) -> if (current < expiry) return token }
        val token = issuer.mint(generation, originalReaderSubject, hostOnlySecret())
        require(token.length in 24..8192)
        // Keycloak issued a <=300s access token; discard locally after 60s to avoid
        // stale authority, and let a native 401/403 deny the current request immediately.
        cached = token to (current + 60)
        return token
    }
}

/** Separate HTTPS verification for Keycloak's public issuer and private admin endpoint.
 * CA+leaf pinned per endpoint, default JVM hostname verification, no redirects or global trust mutation.
 */
internal fun nativeAgentIntrospectionMatches(observed: JsonObject, generation: String, subject: String): Boolean = try {
    val audiences = observed["aud"]?.let { audience ->
        if (audience is JsonArray) audience.map { it.jsonPrimitive.content }.toSet()
        else setOf(audience.jsonPrimitive.content)
    } ?: emptySet()
    val roles = observed["resource_access"]?.jsonObject?.get("realm-management")?.jsonObject
        ?.get("roles")?.jsonArray?.map { it.jsonPrimitive.content }?.toSet() ?: emptySet()
    observed["active"]?.jsonPrimitive?.booleanOrNull == true &&
        observed["iss"]?.jsonPrimitive?.content == ManagedLaneIdentityAuthority.ISSUER &&
        observed["azp"]?.jsonPrimitive?.content == "managed-lane-agent" &&
        observed["sub"]?.jsonPrimitive?.content == subject &&
        observed["p0v3_generation"]?.jsonPrimitive?.content == generation &&
        observed["keykeeper_principal_type"]?.jsonPrimitive?.content == "AGENT" &&
        "managed-lanes" in audiences && "keykeeper" !in audiences &&
        roles.none { it in setOf("view-users", "manage-users", "manage-clients", "manage-realm", "realm-admin") }
} catch (_: Exception) { false }

internal class PinnedLaneIdentityTransport(private val publicCa: Path, private val publicLeafSha256: String,
    private val privateCa: Path, private val privateLeafSha256: String,
    private val introspectionClient: String, private val introspectionSecret: () -> String,
    private val privateAddresses: Map<String,String> = emptyMap()) : IdentityNativeTransport,
    NativeReaderTokenIssuer {
    override fun mint(generation: String, subject: String, secret: String): String =
        readerBearer(generation, subject, secret)
    private fun ssl(ca: Path, host: String): javax.net.ssl.SSLSocketFactory {
        require(Files.isRegularFile(ca, java.nio.file.LinkOption.NOFOLLOW_LINKS) &&
            Files.getPosixFilePermissions(ca) == java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"))
        val factory = java.security.cert.CertificateFactory.getInstance("X.509")
        val cert = Files.newInputStream(ca).use { factory.generateCertificate(it) }
        val store = java.security.KeyStore.getInstance("PKCS12")
        store.load(null, null)
        store.setCertificateEntry("ca", cert)
        val managers = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm())
        managers.init(store)
        val trusted=javax.net.ssl.SSLContext.getInstance("TLS").apply { init(null, managers.trustManagers, null) }.socketFactory
        require(privateAddresses.keys.all { it in setOf("auth.datamancy.net","keycloak") })
        return privateAddresses[host]?.let { PrivatePinnedSocketFactory(trusted,host,it) } ?: trusted
    }
    private fun call(origin: String, ca: Path, pin: String, method: String, path: String,
        body: String? = null, header: Pair<String, String>? = null): String {
        require(pin.matches(Regex("[a-f0-9]{64}")) && method in setOf("GET", "POST") &&
            path.startsWith("/") && !path.startsWith("//") && !path.contains('?'))
        val endpoint = java.net.URI(origin + path)
        require(endpoint.scheme == "https" && endpoint.rawUserInfo == null && endpoint.rawQuery == null && endpoint.rawFragment == null)
        val connection = endpoint.toURL().openConnection() as javax.net.ssl.HttpsURLConnection
        try {
            connection.sslSocketFactory = ssl(ca,endpoint.host)
            connection.connectTimeout = 250
            connection.readTimeout = 250
            connection.instanceFollowRedirects = false
            connection.requestMethod = method
            if (header != null) connection.setRequestProperty(header.first, header.second)
            if (body != null) {
                require(body.length <= 16_384)
                connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
                connection.doOutput = true
            }
            connection.connect()
            val leaf = java.security.MessageDigest.getInstance("SHA-256").digest(connection.serverCertificates.first().encoded)
            val pinned = pin.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            require(java.security.MessageDigest.isEqual(leaf, pinned))
            if (body != null) connection.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            require(connection.responseCode == 200)
            return connection.inputStream.use { stream ->
                val bytes = stream.readNBytes(131073)
                require(bytes.size <= 131072)
                bytes.decodeToString(throwOnInvalidSequence = true)
            }
        } finally { connection.disconnect() }
    }
    /** Host-only least-privileged service account, never a broker upstream credential or
     * daemon env. Keycloak's native role-scope mapping confines this token to view-users;
     * every caller/tick still makes a fresh native user.enabled GET with that bearer.
     */
    fun readerBearer(generation: String, subject: String, secret: String): String {
        require(generation.matches(Regex("q-[a-f0-9]{12}")) &&
            runCatching { java.util.UUID.fromString(subject).toString() }.getOrNull() == subject &&
            secret.length in 16..4096 && !secret.contains('\n') && !secret.contains('\r'))
        val authorization = java.util.Base64.getEncoder().encodeToString(
            "managed-lane-reader:$secret".toByteArray(Charsets.UTF_8))
        val body = call("https://auth.datamancy.net", publicCa, publicLeafSha256, "POST",
            "/realms/p0v3/protocol/openid-connect/token", "grant_type=client_credentials",
            "Authorization" to "Basic $authorization")
        val grant = Json.parseToJsonElement(body).jsonObject
        val expiresIn = grant["expires_in"]?.jsonPrimitive?.intOrNull
        require(grant["token_type"]?.jsonPrimitive?.content == "Bearer" &&
            expiresIn != null && expiresIn in 1..300)
        val token = grant.getValue("access_token").jsonPrimitive.content
        require(token.length in 24..8192)
        val observed = introspect(token)
        val audiences = observed["aud"]?.let {
            if (it is JsonArray) it.map { value -> value.jsonPrimitive.content }.toSet()
            else setOf(it.jsonPrimitive.content)
        } ?: emptySet()
        val roles = observed["resource_access"]?.jsonObject?.get("realm-management")?.jsonObject
            ?.get("roles")?.jsonArray?.map { it.jsonPrimitive.content }?.toSet() ?: emptySet()
        require(observed["active"]?.jsonPrimitive?.booleanOrNull == true &&
            observed["iss"]?.jsonPrimitive?.content == ManagedLaneIdentityAuthority.ISSUER &&
            observed["azp"]?.jsonPrimitive?.content == "managed-lane-reader" &&
            observed["sub"]?.jsonPrimitive?.content == subject &&
            observed["p0v3_generation"]?.jsonPrimitive?.content == generation &&
            "realm-management" in audiences && "view-users" in roles &&
            roles.none { it in setOf("manage-users", "manage-clients", "manage-realm", "realm-admin") }) {
            "Only the original generation-bound native view-users reader may inspect principals" }
        return token
    }

    /** Native confidential Keycloak grant for the ORIGINAL managed-lane-agent UUID.
     * Only the supervised host broker may hold the client secret or call this method;
     * the lane receives a bounded bearer through A15's protected one-use UNIX exchange.
     * This is token issuance, NOT a durable grant-head update or permission to replay.
     */
    fun agentBearer(generation: String, subject: String, secret: String): String {
        require(generation.matches(Regex("q-[a-f0-9]{12}")) &&
            runCatching { java.util.UUID.fromString(subject).toString() }.getOrNull() == subject &&
            secret.length in 16..4096 && !secret.contains('\n') && !secret.contains('\r'))
        val authorization = java.util.Base64.getEncoder().encodeToString(
            "managed-lane-agent:$secret".toByteArray(Charsets.UTF_8))
        val body = call("https://auth.datamancy.net", publicCa, publicLeafSha256, "POST",
            "/realms/p0v3/protocol/openid-connect/token", "grant_type=client_credentials",
            "Authorization" to "Basic $authorization")
        val grant = Json.parseToJsonElement(body).jsonObject
        val expiresIn = grant["expires_in"]?.jsonPrimitive?.intOrNull
        require(grant["token_type"]?.jsonPrimitive?.content == "Bearer" &&
            expiresIn != null && expiresIn in 1..300)
        val token = grant.getValue("access_token").jsonPrimitive.content
        require(token.length in 24..8192 && nativeAgentIntrospectionMatches(introspect(token), generation, subject)) {
            "Native generation-bound managed-lane agent grant not observed"
        }
        return token
    }

    override fun jwks(): String = call("https://auth.datamancy.net", publicCa, publicLeafSha256, "GET",
        "/realms/p0v3/protocol/openid-connect/certs")
    override fun introspect(bearer: String): JsonObject {
        val authorization = java.util.Base64.getEncoder().encodeToString(
            "$introspectionClient:${introspectionSecret()}".toByteArray(Charsets.UTF_8))
        val form = "token=" + java.net.URLEncoder.encode(bearer, Charsets.UTF_8) + "&token_type_hint=access_token"
        return Json.parseToJsonElement(call("https://auth.datamancy.net", publicCa, publicLeafSha256, "POST",
            "/realms/p0v3/protocol/openid-connect/token/introspect", form,
            "Authorization" to "Basic $authorization")).jsonObject
    }
    override fun user(subject: String, adminBearer: String): JsonObject {
        require(runCatching { java.util.UUID.fromString(subject).toString() }.getOrNull() == subject &&
            adminBearer.length in 24..8192 && !adminBearer.contains('\n'))
        return Json.parseToJsonElement(call("https://keycloak:8443", privateCa, privateLeafSha256, "GET",
            "/admin/realms/p0v3/users/$subject", header = "Authorization" to "Bearer $adminBearer")).jsonObject
    }
}
