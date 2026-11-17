package net.datamancy.platform

import java.nio.file.Path
import java.security.KeyPairGenerator
import java.util.Base64
import java.util.UUID
import kotlinx.serialization.json.*

/** Separate private MAS/Keycloak/Synapse fixture; never migrates the existing Matrix deployment. */
internal object MatrixIdentityRuntime {
    const val PROVIDER = "01HFVBY12TMNTYTBV8W921M5FA"
    const val CLIENT = "01J00000000000000000000000"
    const val ELEMENT_CLIENT = "01J00000000000000000000001"
    fun spec(inventory: AcquiredInventory, name: String = "matrix-identity"): PrivateDeploymentSpec {
        val identity = IdentityRuntime.spec(inventory, name)
        val synapse = SynapseRuntime.spec(inventory, name)
        val pg = identity.processes.single { it.id == "postgres" }
        fun image(id: String) = inventory.images.single { it.product == id }.also { require(it.os == "linux" && it.architecture == "amd64") }
        val mas = image("matrix-authentication-service"); val nginx = image("element")
        fun web(id: String, dependencies: List<String>, config: String, extra: List<RuntimeFile> = emptyList()) =
            RuntimeProcess(id, nginx.pinnedImage, nginx.imageId, 101, dependencies = dependencies, entrypoint = "/usr/sbin/nginx",
                command = listOf("-c", "/run/secrets/$config", "-g", "daemon off;"),
                files = listOf(config, "$id-web.pem", "$id-web-key.pem").map { RuntimeFile(it, "/run/secrets/$it") } + extra,
                memoryMiB = 256, apparmorProfile = "p0v3-private-v1", readinessHttpPort = 8080, readinessHttpPath = "/healthz")
        val auth = RuntimeProcess("auth", mas.pinnedImage, mas.imageId, 65532, entrypoint = "/usr/local/bin/mas-cli",
            command = listOf("-c", "/run/secrets/mas.yaml", "server", "--no-migrate", "--no-sync"), environmentFile = "mas.env",
            files = listOf("mas.yaml", "mas-signing.pem", "auth-web.pem", "auth-web-key.pem", "trusted-ca.pem").map { RuntimeFile(it, "/run/secrets/$it") },
            memoryMiB = 768, apparmorProfile = "p0v3-private-v1", readinessHttpPort = 8080, readinessHttpPath = "/health")
        return PrivateDeploymentSpec(name = name, volumes = identity.volumes + synapse.volumes.filter { it.id != "postgres" },
            processes = identity.processes + synapse.processes.filter { it.id !in setOf("postgres-init", "postgres") }.map { p ->
                if (p.id == "synapse-db-init") p.copy(environmentFile = "matrix-database.env") else p
            } + listOf(
                web("identity", listOf("keycloak"), "identity-nginx.conf"),
                RuntimeProcess("mas-db-init", pg.image, pg.imageId, 999, dependencies = listOf("postgres"), entrypoint = "/bin/sh",
                    environmentFile = "mas-database.env", oneShot = true, apparmorProfile = "p0v3-private-v1", command = listOf("-ec", """
                        export PGPASSWORD="${'$'}POSTGRES_PASSWORD"
                        psql -X -h postgres -U postgres -v ON_ERROR_STOP=1 <<SQL
                        CREATE ROLE mas LOGIN PASSWORD '${'$'}MAS_PASSWORD';
                        CREATE DATABASE mas OWNER mas;
                        SQL
                    """.trimIndent())),
                auth.copy(id = "mas-migrate", dependencies = listOf("mas-db-init"), oneShot = true, readinessHttpPort = null,
                    command = listOf("-c", "/run/secrets/mas.yaml", "database", "migrate")),
                auth.copy(id = "mas-config-init", dependencies = listOf("mas-migrate"), oneShot = true, readinessHttpPort = null,
                    command = listOf("-c", "/run/secrets/mas.yaml", "config", "sync")),
                auth.copy(dependencies = listOf("mas-config-init", "identity", "synapse")),
                web("element", listOf("auth", "synapse"), "element-nginx.conf", listOf(RuntimeFile("element.json", "/run/secrets/element.json")))
            )).also { PrivateDeployment.validate(it) }
    }
    /** Exactly one MAS application and SQL schema against the shared canonical PostgreSQL
     * and Keycloak. No identity realm/user, PostgreSQL or Caddy provider is duplicated.
     */
    fun canonicalFragment(inventory: AcquiredInventory, base: PrivateDeploymentSpec): CanonicalProviderFragment {
        require(base.store == RuntimeStore.CANONICAL_V2 && base.processes.any { it.id == "keycloak" && !it.oneShot })
        val postgres = base.processes.single { it.id == "postgres" && !it.oneShot }
        val image = inventory.images.single { it.product == "matrix-authentication-service" }.also {
            require(it.os == "linux" && it.architecture == "amd64")
        }
        val admin = RuntimeProcess("mas-db-init", postgres.image, postgres.imageId, 999,
            dependencies = listOf("postgres"), entrypoint = "/bin/sh", oneShot = true,
            environmentFile = "mas-db-admin.env", files = listOf(RuntimeFile("postgres-ca.pem", "/run/secrets/postgres-ca.pem")),
            networks = listOf("db-admin", "mas-data"), apparmorProfile = "p0v3-private-v1", command = listOf("-ec", """
                export PGPASSWORD="${'$'}POSTGRES_PASSWORD"
                psql -X -h postgres -U postgres -v ON_ERROR_STOP=1 <<SQL
                CREATE ROLE mas LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '${'$'}MAS_PASSWORD';
                CREATE DATABASE mas OWNER mas;
                REVOKE ALL ON DATABASE mas FROM PUBLIC;
                SQL
            """.trimIndent()))
        val files = listOf(RuntimeFile("mas.yaml", "/run/secrets/mas.yaml"),
            RuntimeFile("mas-signing.pem", "/run/secrets/mas-signing.pem"),
            RuntimeFile("postgres-ca.pem", "/run/secrets/postgres-ca.pem"))
        fun process(id: String, command: List<String>, oneShot: Boolean, dependencies: List<String>) =
            RuntimeProcess(id, image.pinnedImage, image.imageId, 65532,
                dependencies = dependencies, entrypoint = "/usr/local/bin/mas-cli", command = command,
                environmentFile = "mas-runtime.env", files = files,
                networks = if (oneShot) listOf("mas-data", "mas-web") else listOf("mas-data", "mas-web", "identity-web"),
                oneShot = oneShot, memoryMiB = 768, apparmorProfile = "p0v3-private-v1",
                readinessHttpPort = if (oneShot) null else 8080, readinessHttpPath = "/health")
        val migration = process("mas-migrate", listOf("-c", "/run/secrets/mas.yaml", "database", "migrate"), true,
            listOf("mas-db-init"))
        val sync = process("mas-config-init", listOf("-c", "/run/secrets/mas.yaml", "config", "sync"), true,
            listOf("mas-migrate", "keycloak", "caddy", "synapse"))
        val daemon = process("mas", listOf("-c", "/run/secrets/mas.yaml", "server", "--no-migrate", "--no-sync"), false,
            listOf("mas-config-init", "synapse", "keycloak", "caddy"))
        val partial = PrivateDeploymentSpec(name = base.name, store = base.store,
            volumes = emptyList(), processes = listOf(admin, migration, sync, daemon),
            networks = listOf("mas-data", "mas-web", "identity-web"), databaseAccess = listOf(
                RuntimeDatabaseAccess("mas", "postgres", "postgres", "mas", "mas", "mas-runtime.env", "mas-data"),
                RuntimeDatabaseAccess("mas-migrate", "postgres", "postgres", "mas", "mas", "mas-runtime.env", "mas-data"),
                RuntimeDatabaseAccess("mas-config-init", "postgres", "postgres", "mas", "mas", "mas-runtime.env", "mas-data")))
        return CanonicalProviderFragment("matrix-authentication-service", partial,
            providerNetworks = mapOf("postgres" to setOf("mas-data")), webNetworks = setOf("mas-web"),
            identityWebConsumers = setOf(CanonicalIdentityWebConsumer.MAS))
    }

    fun canonicalColdFragment(inventory: AcquiredInventory, base: PrivateDeploymentSpec,
        original: CanonicalProviderFragment): CanonicalProviderFragment {
        val fresh = canonicalFragment(inventory, base)
        require(original == fresh && fresh.spec.processes.filter { it.oneShot }.map { it.id }.toSet() ==
            setOf("mas-db-init", "mas-migrate", "mas-config-init")) {
            "MAS source schema/client/signing key must be the original compiled cohort"
        }
        val daemon = fresh.spec.processes.single { it.id == "mas" }
        return fresh.copy(spec = fresh.spec.copy(processes = listOf(daemon.copy(
            dependencies = daemon.dependencies.filterNot { it in setOf("mas-db-init", "mas-migrate", "mas-config-init") })),
            databaseAccess = fresh.spec.databaseAccess.filter { it.consumer == "mas" }))
    }

    fun canonicalUpstreamClient(clientSecret: String) = buildJsonObject {
        require(clientSecret.matches(Regex("[a-f0-9]{64}")))
        put("clientId", "matrix-mas"); put("enabled", true); put("protocol", "openid-connect")
        put("publicClient", false); put("secret", clientSecret); put("standardFlowEnabled", true)
        put("directAccessGrantsEnabled", false); put("serviceAccountsEnabled", false)
        put("redirectUris", buildJsonArray { add("https://matrix-auth.datamancy.net/upstream/callback/$PROVIDER") })
        put("webOrigins", buildJsonArray { add("https://matrix-auth.datamancy.net") })
        put("attributes", buildJsonObject { put("pkce.code.challenge.method", "S256") })
    }

    /** The caller passes ONE credential pair both to this original MAS config and the
     * A05 canonical Keycloak client before either input map is persisted.
     */
    fun canonicalInputs(postgresAdminPassword: String, masPassword: String,
        upstreamClientSecret: String, signingKey: String, encryptionSecret: String,
        matrixSharedSecret: String): Map<String, String> {
        require(listOf(postgresAdminPassword, masPassword, upstreamClientSecret, encryptionSecret, matrixSharedSecret).all {
            it.matches(Regex("[a-f0-9]{64}"))
        } && listOf(postgresAdminPassword, masPassword, upstreamClientSecret, encryptionSecret, matrixSharedSecret).distinct().size == 5 &&
            signingKey.startsWith("-----BEGIN PRIVATE KEY-----\n") && signingKey.endsWith("-----END PRIVATE KEY-----\n") &&
            signingKey.length in 1600..8192)
        return mapOf(
            "mas-db-admin.env" to "PGHOST=postgres\nPGUSER=postgres\nPGDATABASE=postgres\nPOSTGRES_PASSWORD=$postgresAdminPassword\nPGSSLMODE=verify-full\nPGSSLROOTCERT=/run/secrets/postgres-ca.pem\nMAS_PASSWORD=$masPassword\n",
            // The selected r9 Keycloak issuer has a generation-issued ingress leaf,
            // not public ACME. MAS verifies that exact issuer through its own CA mount.
            "mas-runtime.env" to "RUST_LOG=mas=warn\nSSL_CERT_FILE=/run/secrets/identity-ca.pem\n",
            "mas-signing.pem" to signingKey,
            "mas.yaml" to """
                http:
                  public_base: https://matrix-auth.datamancy.net/
                  listeners:
                    - name: internal
                      resources:
                        - name: discovery
                        - name: human
                        - name: oauth
                        - name: compat
                        - name: graphql
                        - name: assets
                          path: /usr/local/share/mas-cli/assets/
                        - name: health
                      binds:
                        - address: '0.0.0.0:8080'
                database:
                  uri: postgresql://mas:$masPassword@postgres:5432/mas?sslmode=verify-full&sslrootcert=/run/secrets/postgres-ca.pem
                  max_connections: 10
                matrix:
                  kind: synapse
                  homeserver: matrix.datamancy.net
                  endpoint: http://synapse:8008
                  secret: '$matrixSharedSecret'
                secrets:
                  encryption: '$encryptionSecret'
                  keys:
                    - kid: original-mas-rsa
                      key_file: /run/secrets/mas-signing.pem
                passwords:
                  enabled: false
                clients:
                  - client_id: $ELEMENT_CLIENT
                    client_auth_method: none
                    redirect_uris: ['https://chat.datamancy.net/', 'https://chat.datamancy.net/?no_universal_links=true']
                upstream_oauth2:
                  providers:
                    - id: $PROVIDER
                      human_name: Original Keycloak
                      issuer: https://auth.datamancy.net/realms/p0v3
                      client_id: matrix-mas
                      client_secret: '$upstreamClientSecret'
                      token_endpoint_auth_method: client_secret_basic
                      scope: 'openid profile email'
                      pkce_method: always
                      discovery_mode: oidc
                      claims_imports:
                        subject:
                          template: '{{ user.sub }}'
                        skip_confirmation: true
                        localpart:
                          action: require
                          template: '{{ user.preferred_username }}'
                          on_conflict: fail
                        displayname:
                          action: force
                        email:
                          action: ignore
                policy:
                  data:
                    registration:
                      allowed_usernames:
                        literals: [owner, reader]
            """.trimIndent() + "\n")
    }

    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "matrix-identity", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }

    fun inputs(pki: (String) -> Map<String, String> = { PrivateWebPki.generate(it) }): Map<String, String> {
        val identity = IdentityRuntime.inputs().toMutableMap()
        val matrix = SynapseRuntime.inputs("https://element:8443/").toMutableMap()
        val postgres = identity.getValue("postgres.env").lineSequence().first().substringAfter('=')
        val matrixPassword = matrix.getValue("database-init.env").lineSequence().first { it.startsWith("SYNAPSE_PASSWORD=") }.substringAfter('=')
        val masPassword = RuntimePreparation.password(); val upstreamSecret = RuntimePreparation.password(); val shared = RuntimePreparation.password()
        val realm = Json.parseToJsonElement(identity.getValue("realm.json")).jsonObject.toMutableMap()
        val owner = realm.getValue("users").jsonArray.single().jsonObject.toMutableMap().apply {
            put("id", JsonPrimitive(UUID.randomUUID().toString())); put("firstName", JsonPrimitive("Private")); put("lastName", JsonPrimitive("Owner"))
            put("email", JsonPrimitive("owner@localhost.invalid")); put("emailVerified", JsonPrimitive(true))
        }
        fun user(username: String, required: Boolean) = buildJsonObject {
            put("id", UUID.randomUUID().toString()); put("username", username); put("enabled", true)
            put("firstName", "Private"); put("lastName", username); put("email", "$username@localhost.invalid"); put("emailVerified", true)
            put("requiredActions", buildJsonArray { if (required) { add("UPDATE_PASSWORD"); add("CONFIGURE_TOTP") } })
            put("credentials", buildJsonArray { add(buildJsonObject { put("type", "password"); put("value", RuntimePreparation.password()); put("temporary", required) }) })
        }
        realm["users"] = buildJsonArray { add(JsonObject(owner)); add(user("reader", true)); add(user("outsider", false)) }
        realm["sslRequired"] = JsonPrimitive("all")
        realm["clients"] = buildJsonArray { add(buildJsonObject {
            put("clientId", "mas"); put("enabled", true); put("protocol", "openid-connect"); put("publicClient", false); put("secret", upstreamSecret)
            put("standardFlowEnabled", true); put("directAccessGrantsEnabled", false); put("serviceAccountsEnabled", false)
            put("redirectUris", buildJsonArray { add("https://auth:8443/upstream/callback/$PROVIDER") })
            put("webOrigins", buildJsonArray { add("https://auth:8443") })
            put("attributes", buildJsonObject { put("pkce.code.challenge.method", "S256") })
        }) }
        identity["realm.json"] = JsonObject(realm).toString()
        identity["keycloak.env"] = identity.getValue("keycloak.env").replace("KC_HOSTNAME=http://keycloak:8080", "KC_HOSTNAME=https://identity:8443") + "KC_PROXY_HEADERS=xforwarded\n"
        matrix.remove("postgres.env"); matrix.remove("database-init.env")
        matrix["matrix-database.env"] = "POSTGRES_PASSWORD=$postgres\nSYNAPSE_PASSWORD=$matrixPassword\n"
        matrix["synapse.env"] = "TZ=UTC\n"
        matrix["homeserver.yaml"] = matrix.getValue("homeserver.yaml").lineSequence().filterNot {
            it.startsWith("registration_shared_secret:") || it.startsWith("macaroon_secret_key:") || it.startsWith("form_secret:")
        }.joinToString("\n") + "\nmatrix_authentication_service:\n  enabled: true\n  endpoint: http://auth:8080/\n  secret: '$shared'\n"
        val certificates = listOf("identity", "auth", "element").associateWith(pki)
        val files = certificates.flatMap { (host, values) -> listOf("web.pem", "web-key.pem").map { "$host-$it" to values.getValue(it) } }.toMap()
        val signer = KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }.generateKeyPair().private
        return identity + matrix + files + mapOf(
            "trusted-ca.pem" to certificates.values.joinToString("\n") { it.getValue("ca.pem") },
            "mas-signing.pem" to "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder(64, byteArrayOf(10)).encodeToString(signer.encoded) + "\n-----END PRIVATE KEY-----\n",
            "mas.env" to "SSL_CERT_FILE=/run/secrets/trusted-ca.pem\n",
            "mas-database.env" to "POSTGRES_PASSWORD=$postgres\nMAS_PASSWORD=$masPassword\n",
            "mas.yaml" to """
                http:
                  public_base: https://auth:8443/
                  listeners:
                    - name: internal
                      resources:
                        - name: discovery
                        - name: oauth
                        - name: compat
                        - name: health
                      binds:
                        - address: '0.0.0.0:8080'
                    - name: private-tls
                      resources:
                        - name: discovery
                        - name: human
                        - name: oauth
                        - name: compat
                        - name: graphql
                        - name: assets
                          path: /usr/local/share/mas-cli/assets/
                      binds:
                        - address: '0.0.0.0:8443'
                      tls:
                        certificate_file: /run/secrets/auth-web.pem
                        key_file: /run/secrets/auth-web-key.pem
                database:
                  uri: postgresql://mas:$masPassword@postgres:5432/mas?sslmode=disable
                  max_connections: 10
                matrix:
                  kind: synapse
                  homeserver: matrix.private.invalid
                  endpoint: http://synapse:8008
                  secret: '$shared'
                secrets:
                  encryption: '${RuntimePreparation.password()}'
                  keys:
                    - kid: p0v3-mas-rsa
                      key_file: /run/secrets/mas-signing.pem
                passwords:
                  enabled: false
                clients:
                  - client_id: $CLIENT
                    client_auth_method: none
                    redirect_uris: ['https://element:8443/fixture-callback']
                  - client_id: $ELEMENT_CLIENT
                    client_auth_method: none
                    redirect_uris: ['https://element:8443/', 'https://element:8443/?no_universal_links=true']
                upstream_oauth2:
                  providers:
                    - id: $PROVIDER
                      human_name: Private Keycloak
                      issuer: https://identity:8443/realms/p0v3
                      client_id: mas
                      client_secret: '$upstreamSecret'
                      token_endpoint_auth_method: client_secret_basic
                      scope: 'openid profile email'
                      pkce_method: always
                      discovery_mode: oidc
                      claims_imports:
                        subject:
                          template: '{{ user.sub }}'
                        skip_confirmation: true
                        localpart:
                          action: require
                          template: '{{ user.preferred_username }}'
                          on_conflict: fail
                        displayname:
                          action: force
                        email:
                          action: ignore
                policy:
                  data:
                    registration:
                      allowed_usernames:
                        literals: [owner, reader]
                branding:
                  service_name: Platform Zero private Matrix identity fixture
            """.trimIndent() + "\n",
            "identity-nginx.conf" to nginx("identity", "location / { proxy_pass http://keycloak:8080; proxy_set_header Host ${'$'}http_host; proxy_set_header X-Forwarded-Proto https; proxy_set_header X-Forwarded-For ${'$'}remote_addr; }"),
            "element-nginx.conf" to nginx("element", """
                root /app;
                client_max_body_size 10m;
                location = /config.element.json { return 404; }
                location = /config.json { alias /run/secrets/element.json; default_type application/json; add_header Cache-Control no-store; }
                location = /.well-known/matrix/client {
                    default_type application/json;
                    add_header Access-Control-Allow-Origin '*';
                    return 200 '{"m.homeserver":{"base_url":"https://element:8443"},"org.matrix.msc2965.authentication":{"issuer":"https://auth:8443/","account":"https://auth:8443/account/"}}';
                }
                location ~ ^/_matrix/client/(r0|v3|unstable)/(login|logout|refresh)${'$'} { proxy_pass http://auth:8080; proxy_set_header Host ${'$'}http_host; proxy_set_header X-Forwarded-Proto https; }
                location /_matrix/ { proxy_pass http://synapse:8008; proxy_read_timeout 65s; proxy_buffering off; }
                location / { try_files ${'$'}uri ${'$'}uri/ /index.html; }
            """.trimIndent()),
            "element.json" to """
                {"default_server_config":{"m.homeserver":{"base_url":"https://element:8443","server_name":"matrix.private.invalid"},"org.matrix.msc2965.authentication":{"issuer":"https://auth:8443/","account":"https://auth:8443/account/"}},"oidc_static_clients":{"https://auth:8443/":{"client_id":"$ELEMENT_CLIENT"}},"enable_client_well_known_lookups":false,"disable_custom_urls":true,"disable_guests":true,"disable_3pid_login":true,"brand":"Platform Zero private MAS fixture","integrations_ui_url":"","integrations_rest_url":"","integrations_widgets_urls":[],"bug_report_endpoint_url":null,"default_federate":false}
            """.trimIndent() + "\n")
    }
    private fun nginx(host: String, routes: String) = """
        worker_processes 1;
        pid /tmp/nginx.pid;
        error_log /tmp/nginx-error.log warn;
        events { worker_connections 512; }
        http {
          include /etc/nginx/mime.types;
          access_log off;
          client_body_temp_path /tmp/body;
          proxy_temp_path /tmp/proxy;
          fastcgi_temp_path /tmp/fastcgi;
          uwsgi_temp_path /tmp/uwsgi;
          scgi_temp_path /tmp/scgi;
          proxy_http_version 1.1;
          server { listen 8080; location = /healthz { return 200 'ready'; } location / { return 404; } }
          server {
            listen 8443 ssl;
            server_name $host;
            ssl_certificate /run/secrets/$host-web.pem;
            ssl_certificate_key /run/secrets/$host-web-key.pem;
            ssl_protocols TLSv1.2 TLSv1.3;
            $routes
          }
        }
    """.trimIndent() + "\n"
}
