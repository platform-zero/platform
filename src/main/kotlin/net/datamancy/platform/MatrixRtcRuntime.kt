package net.datamancy.platform

import java.nio.file.Path
import java.security.KeyPairGenerator
import java.util.Base64
import kotlinx.serialization.json.*

/** Opt-in private delegated MatrixRTC deployment. Never rewrites a previously sealed identity recipe.
 * HTTPS/DTLS protect transports; media E2EE keys remain a client responsibility, not an SFU secret.
 */
internal object MatrixRtcRuntime {
    const val SERVER = "matrix.private.invalid"
    const val RTC = "https://rtc:8443"

    /** One release-v2 provider cohort: every feature supplies only its own process, state,
     * provider edge, inputs and explicit cold projection. The coordinator compiles/merges the
     * complete graph purely BEFORE preparing any credential or writing an operation intent.
     */
    fun canonicalFragments(inventory: AcquiredInventory, base: PrivateDeploymentSpec): List<CanonicalProviderFragment> {
        require(base.name.matches(Regex("(?:(?:q-[a-f0-9]{12}-)?canonical-release-v2|q-[a-f0-9]{12}-v2)")) &&
            base.store == RuntimeStore.CANONICAL_V2)
        return listOf(SynapseRuntime.canonicalFragment(inventory, base),
            MatrixIdentityRuntime.canonicalFragment(inventory, base), MatrixRuntime.canonicalFragment(inventory, base),
            LiveKitRuntime.canonicalFragment(inventory, base))
    }

    fun canonicalColdFragments(inventory: AcquiredInventory, base: PrivateDeploymentSpec,
        original: List<CanonicalProviderFragment>): List<CanonicalProviderFragment> {
        val fresh = canonicalFragments(inventory, base)
        require(original == fresh) { "Original MatrixRTC provider and image graph changed" }
        return listOf(SynapseRuntime.canonicalColdFragment(inventory, base, original[0]),
            MatrixIdentityRuntime.canonicalColdFragment(inventory, base, original[1]),
            MatrixRuntime.canonicalColdFragment(inventory, base, original[2]),
            LiveKitRuntime.canonicalColdFragment(inventory, base, original[3]))
    }

    /** One fixed credential projection for the four application fragments. The SAME
     * upstreamClientSecret MUST be included in the A05 realm client before provider inputs
     * are sealed; the caller never substitutes an independent second Keycloak.
     */
    fun canonicalInputs(providerInputs: Map<String, String>, upstreamClientSecret: String,
        password: () -> String = RuntimePreparation::password,
        pki: (String) -> Map<String, String> = { origin ->
            require(origin == "rtc.datamancy.net")
            PrivateWebPki.generate("rtc", dnsNames = listOf("rtc", origin)) }): Map<String, String> {
        val admin = providerInputs.getValue("postgres-admin.env").lineSequence()
            .single { it.startsWith("PGPASSWORD=") }.substringAfter('=')
        require(providerInputs.getValue("postgres.env").lineSequence()
            .single { it.startsWith("POSTGRES_PASSWORD=") }.substringAfter('=') == admin &&
            admin.matches(Regex("[a-f0-9]{64}")) && upstreamClientSecret.matches(Regex("[a-f0-9]{64}")))
        val secrets = List(8) { password() }
        require(secrets.all { it.matches(Regex("[a-f0-9]{64}")) } &&
            (secrets + admin + upstreamClientSecret).distinct().size == 10)
        val synapseDb = secrets[0]; val masDb = secrets[1]
        val masEncryption = secrets[2]; val matrixShared = secrets[3]
        val asToken = secrets[4]; val hsToken = secrets[5]
        val livekitKey = secrets[6]; val livekitSecret = secrets[7]
        val signer = KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }.generateKeyPair().private
        val signingPem = "-----BEGIN PRIVATE KEY-----\n" +
            Base64.getMimeEncoder(64, byteArrayOf(10)).encodeToString(signer.encoded) + "\n-----END PRIVATE KEY-----\n"
        val registration = """
            id: p0v3-matrix-rtc
            as_token: '$asToken'
            hs_token: '$hsToken'
            sender_localpart: _p0v3_rtc
            namespaces:
              users:
                - exclusive: false
                  regex: '^@[^:]+:matrix[.]datamancy[.]net${'$'}'
            url: null
            rate_limited: true
            io.element.msc4502.scopes: ['urn:matrix:client:io.element.msc4502:rooms:is_joined']
            io.element.msc4512.proxy_prefix: rtc/livekit
            io.element.msc4512.proxy_url: http://rtc-authorizer:8080
        """.trimIndent() + "\n"
        val synapse = SynapseRuntime.canonicalInputs(admin, synapseDb).toMutableMap()
        synapse["synapse-homeserver.yaml"] = synapse.getValue("synapse-homeserver.yaml") + """
            matrix_authentication_service:
              enabled: true
              endpoint: http://mas:8080/
              secret: '$matrixShared'
            app_service_config_files: [/run/secrets/rtc-registration.yaml]
            experimental_features:
              msc4143_enabled: true
              msc4222_enabled: true
              msc4502_enabled: true
              msc4512_enabled: true
            max_event_delay_duration: 24h
            matrix_rtc:
              transports:
                - type: livekit
                  livekit_service_url: https://matrix-rtc.datamancy.net/livekit/jwt
        """.trimIndent() + "\n"
        val mas = MatrixIdentityRuntime.canonicalInputs(admin, masDb, upstreamClientSecret,
            signingPem, masEncryption, matrixShared)
        val livekit = LiveKitRuntime.canonicalInputs(livekitKey, livekitSecret, registration, pki("rtc.datamancy.net"))
        val parts = listOf(synapse, mas, MatrixRuntime.canonicalInputs(), livekit,
            mapOf("rtc-registration.yaml" to registration))
        val names = parts.flatMap { it.keys }
        require(names.distinct().size == names.size) { "A MatrixRTC input would overwrite a canonical provider/feature secret" }
        return parts.fold(emptyMap<String, String>()) { result, part -> result + part }
    }

    fun spec(inventory: AcquiredInventory, name: String = "matrix-rtc"): PrivateDeploymentSpec {
        val identity = MatrixIdentityRuntime.spec(inventory, name)
        val livekit = LiveKitRuntime.spec(inventory, name)
        val authorizer = inventory.images.single { it.product == "matrix-rtc-authorizer" }.also {
            require(it.os == "linux" && it.architecture == "amd64")
        }
        return identity.copy(processes = identity.processes.map { process ->
            if (process.id == "synapse") process.copy(files = process.files + RuntimeFile("rtc-registration.yaml", "/run/secrets/rtc-registration.yaml"))
            else if (process.id == "keycloak") process.copy(files = process.files +
                RuntimeFile("keycloak-runtime.env", "/run/secrets/keycloak-runtime.env"))
            else process
        } + livekit.processes.map { process ->
            if (process.id == "rtc") process.copy(files = process.files.map { file ->
                RuntimeFile("rtc-" + file.file, file.target)
            }) else process
        } + RuntimeProcess("rtc-authorizer", authorizer.pinnedImage, authorizer.imageId, 65532,
            dependencies = listOf("synapse", "rtc"), entrypoint = "/lk-jwt-service", environmentFile = "rtc-authorizer.env",
            files = listOf(RuntimeFile("rtc-registration.yaml", "/run/secrets/rtc-registration.yaml"),
                RuntimeFile("rtc-ca.pem", "/etc/ssl/certs/ca-certificates.crt")),
            memoryMiB = 256, apparmorProfile = "p0v3-private-v1", readinessHttpPort = 8080,
            readinessHttpPath = "/healthz")).also { PrivateDeployment.validate(it) }
    }

    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "matrix-rtc",
                store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }

    fun inputs(pki: (String) -> Map<String, String> = { PrivateWebPki.generate(it) }): Map<String, String> {
        val result = MatrixIdentityRuntime.inputs(pki).toMutableMap()
        // Archive the daemon-only credential projection at initial preparation; a restore must not
        // synthesize new credentials or trust archived bootstrap values as initialization authority.
        result["keycloak-runtime.env"] = result.getValue("keycloak.env").lineSequence()
            .filterNot { it.startsWith("KC_BOOTSTRAP_ADMIN_") }.joinToString("\n")
        val sfu = LiveKitRuntime.inputs { pki("rtc") }
        result["livekit.yaml"] = sfu.getValue("livekit.yaml")
        sfu.filterKeys { it != "livekit.yaml" }.forEach { (name, value) -> result["rtc-$name"] = value }
        val credentials = Regex("(?m)^  \"([^\"]+)\": \"([^\"]+)\"$").find(sfu.getValue("livekit.yaml"))
            ?: error("Compiled SFU credential configuration missing")
        val key = credentials.groupValues[1]; val secret = credentials.groupValues[2]
        result["livekit.yaml"] = result.getValue("livekit.yaml") +
            "webhook:\n  api_key: '$key'\n  urls: ['http://rtc-authorizer:8080/sfu_webhook']\n"
        result["rtc-registration.yaml"] = """
            id: p0v3-matrix-rtc
            as_token: '${RuntimePreparation.password()}'
            hs_token: '${RuntimePreparation.password()}'
            sender_localpart: _p0v3_rtc
            namespaces:
              users:
                - exclusive: false
                  regex: '^@[^:]+:matrix[.]private[.]invalid${'$'}'
            url: null
            rate_limited: true
            io.element.msc4502.scopes: ['urn:matrix:client:io.element.msc4502:rooms:is_joined']
            io.element.msc4512.proxy_prefix: rtc/livekit
            io.element.msc4512.proxy_url: http://rtc-authorizer:8080
        """.trimIndent() + "\n"
        result["homeserver.yaml"] = result.getValue("homeserver.yaml").replace("names: [client]", "names: [client, openid]") + """
            app_service_config_files: [/run/secrets/rtc-registration.yaml]
            experimental_features:
              msc4143_enabled: true
              msc4222_enabled: true
              msc4502_enabled: true
              msc4512_enabled: true
            max_event_delay_duration: 24h
            matrix_rtc:
              transports:
                - type: livekit
                  livekit_service_url: $RTC/livekit/jwt
        """.trimIndent() + "\n"
        result["rtc-authorizer.env"] = """
            LIVEKIT_URL=wss://rtc:8443/livekit/sfu
            LIVEKIT_KEY=$key
            LIVEKIT_SECRET=$secret
            LIVEKIT_JWT_BIND=0.0.0.0:8080
            LIVEKIT_FULL_ACCESS_HOMESERVERS=$SERVER
            LIVEKIT_HS_SERVER_NAME=$SERVER
            LIVEKIT_AS_REGISTRATION_FILE=/run/secrets/rtc-registration.yaml
            LIVEKIT_CS_API_URL_OVERRIDES=$SERVER=http://synapse:8008
            LIVEKIT_LOG_LEVEL=warn
            LIVEKIT_SANITY_CHECK_INTERVAL_SECONDS=15
        """.trimIndent() + "\n"
        // No proxy-wide path stripping: SFU WebSocket and Twirp requests share this exact prefix.
        // Match the compiled indentation without depending on template whitespace.
        result["rtc-nginx.conf"] = result.getValue("rtc-nginx.conf")
            .replace("location / {\n", "location /livekit/sfu/ {\n")
            .replace("proxy_pass http://livekit:7880;", "proxy_pass http://livekit:7880/;")
            .replace("location = /fixture", """
                location = /livekit/jwt/sfu/get { proxy_pass http://rtc-authorizer:8080/sfu/get; }
                location = /livekit/jwt/get_token { proxy_pass http://rtc-authorizer:8080/get_token; }
                location = /livekit/jwt/delegate_delayed_leave { proxy_pass http://rtc-authorizer:8080/delegate_delayed_leave; }
                location = /fixture
            """.trimIndent())
        val focus = buildJsonObject { put("type", "livekit"); put("livekit_service_url", "$RTC/livekit/jwt") }
        val config = Json.parseToJsonElement(result.getValue("element.json")).jsonObject.toMutableMap()
        val server = config.getValue("default_server_config").jsonObject.toMutableMap()
        server["org.matrix.msc4143.rtc_foci"] = buildJsonArray { add(focus) }
        config["default_server_config"] = JsonObject(server)
        // Element's bundled Element Call consumes the same discovery; do not point at an external widget.
        config["features"] = buildJsonObject { put("feature_group_calls", true); put("feature_element_call_video_rooms", true) }
        result["element.json"] = JsonObject(config).toString() + "\n"
        val oldDiscovery = "{\"m.homeserver\":{\"base_url\":\"https://element:8443\"},\"org.matrix.msc2965.authentication\":{\"issuer\":\"https://auth:8443/\",\"account\":\"https://auth:8443/account/\"}}"
        result["element-nginx.conf"] = result.getValue("element-nginx.conf").replace(oldDiscovery,
            JsonObject(server.filterKeys { it != "server_name" }).toString())
        return result
    }

    /** Only compiled, cold-imported data may boot; database/realm/signing-key initializers are retired.
     * Caller must perform the generation import and verify its durable completion fence before apply.
     */
    fun restoredSpec(source: PrivateDeploymentSpec, inventory: AcquiredInventory, name: String): PrivateDeploymentSpec {
        require(source.name != name)
        require(source == spec(inventory, source.name).copy(store = source.store)) { "Unrecognized MatrixRTC source recipe" }
        return coldRestoreSpec(source).copy(name = name).also { PrivateDeployment.validate(it) }
    }

    /** D03 calls only after exact compiled archive equality and durable cold-import verification. */
    fun coldRestoreSpec(compiled: PrivateDeploymentSpec): PrivateDeploymentSpec {
        val retired = setOf("postgres-init", "identity-db-init", "synapse-db-init", "signing-key-init", "mas-db-init", "mas-migrate", "mas-config-init")
        require(compiled.processes.filter { it.oneShot }.map { it.id }.toSet() == retired)
        val keycloak = compiled.processes.single { it.id == "keycloak" }
        require(keycloak.command == listOf("start", "--optimized", "--import-realm") &&
            keycloak.files.any { it.file == "keycloak-runtime.env" })
        require(compiled.processes.single { it.id == "auth" }.command ==
            listOf("-c", "/run/secrets/mas.yaml", "server", "--no-migrate", "--no-sync"))
        return compiled.copy(processes = compiled.processes.filterNot { it.oneShot }.map { process ->
            val daemon = if (process.id == "keycloak") process.copy(command = listOf("start", "--optimized"),
                environmentFile = "keycloak-runtime.env", files = process.files.filterNot {
                    it.file in setOf("realm.json", "keycloak-runtime.env")
                }) else process
            daemon.copy(dependencies = daemon.dependencies.filterNot(retired::contains))
        }, databaseAccess = compiled.databaseAccess.filterNot { it.consumer in retired })
            .also { PrivateDeployment.validate(it) }
    }
}
