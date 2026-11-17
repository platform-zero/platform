package net.datamancy.platform

import java.nio.file.Path
import kotlin.test.*
import kotlinx.serialization.json.*

class MatrixRtcRuntimeTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("postgres", "valkey", "ntfy", "synapse",
        "matrix-authentication-service", "element", "livekit", "matrix-rtc-authorizer").map {
        AcquiredImage(it, "upstream", "example.org/app:1", image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `canonical MatrixRTC fragments share one provider cohort and keep original credentials on cold restore`() : Unit {
        val available = Json.decodeFromString<AcquiredInventory>(GenerationAssembly.readInventory(
            Path.of("release/downloaded-candidate-inventory.json")).decodeToString())
        val base = CanonicalCoreRuntime.releaseProvidersSpec(available, "q-abcdef123456-v2")
            .copy(store = RuntimeStore.CANONICAL_V2)
        val pieces = MatrixRtcRuntime.canonicalFragments(available, base)
        assertEquals(listOf("synapse", "matrix-authentication-service", "element", "livekit"), pieces.map { it.product })
        assertTrue(pieces.none { p -> p.spec.processes.any { it.id in setOf("postgres", "keycloak", "caddy", "valkey", "ntfy", "memcached") } ||
            p.spec.volumes.any { it.id in base.volumes.map(RuntimeVolume::id) } })
        assertEquals(mapOf("postgres" to setOf("mas-data")), pieces[1].providerNetworks)
        assertEquals(setOf(CanonicalIdentityWebConsumer.MAS), pieces[1].identityWebConsumers)
        assertEquals(listOf("mas"), pieces[1].spec.processes.filter { "identity-web" in it.networks }.map { it.id })
        assertEquals(setOf("synapse-web", "mas-web", "element-web", "rtc-web", "qualification-web"),
            pieces.flatMap { it.webNetworks }.toSet())
        assertEquals(listOf("rtc-data", "rtc-turn", "qualification-web"),
            pieces[3].spec.processes.single { it.id == "livekit" }.networks)
        assertFalse(pieces[3].spec.processes.filter { it.id != "livekit" }
            .any { "qualification-web" in it.networks })
        val cold = MatrixRtcRuntime.canonicalColdFragments(available, base, pieces)
        assertTrue(cold.flatMap { it.spec.processes }.none { it.oneShot })
        assertEquals(pieces[0].spec.volumes, cold[0].spec.volumes)
        assertEquals(pieces[3], cold[3]) // New ephemeral calls are not claimed restored.
        assertFails { MatrixRtcRuntime.canonicalColdFragments(available, base,
            pieces.map { if (it.product == "synapse") it.copy(spec = it.spec.copy(volumes = emptyList())) else it }) }
        val admin = "a".repeat(64)
        var sequence = 1
        val inputs = MatrixRtcRuntime.canonicalInputs(mapOf("postgres-admin.env" to "PGPASSWORD=$admin\n",
            "postgres.env" to "POSTGRES_PASSWORD=$admin\n"), "b".repeat(64),
            password = { (sequence++).toString(16).padStart(64, '0') },
            pki = { mapOf("ca.pem" to "-----BEGIN CERTIFICATE-----", "web.pem" to "-----BEGIN CERTIFICATE-----",
                "web-key.pem" to "-----BEGIN PRIVATE KEY-----") })
        val publicChain = "-----BEGIN CERTIFICATE-----"
        val publicKey = "-----BEGIN PRIVATE KEY-----"
        val turn = PublicCertificateRevision(
            revisionId = "cert-" + "1".repeat(24), generation = "q-abcdef123456",
            bundleSha256 = "b".repeat(64), host = "rtc.datamancy.net",
            origin = PublicCertificateRevisionOrigin.ACME_ISSUANCE,
            sourceGeneration = "q-abcdef123456", sourceRevisionSha256 = null,
            leafDerSha256 = "c".repeat(64),
            chainPemSha256 = ReleaseLocks.sha256(publicChain.toByteArray()),
            privateKeyPemSha256 = ReleaseLocks.sha256(publicKey.toByteArray()),
            dnsNames = setOf("rtc.datamancy.net"), notBeforeEpochSeconds = 1,
            notAfterEpochSeconds = Long.MAX_VALUE,
            acmeDirectory = "https://acme-v02.api.letsencrypt.org/directory",
            publicTrustStoreSha256 = "d".repeat(64),
            nativeObservation = ActivationInput("/unit/native-observation.json", "e".repeat(64)))
        assertEquals(mapOf("rtc-turn.pem" to publicChain, "rtc-turn-key.pem" to publicKey),
            LiveKitRuntime.effectivePublicTurnInputs("q-abcdef123456", turn, publicChain, publicKey))
        assertFails { LiveKitRuntime.effectivePublicTurnInputs("q-abcdef123456", turn, publicChain, "PRIVATE_UNBOUND") }
        assertFails { LiveKitRuntime.effectivePublicTurnInputs("q-abcdef123456", turn.copy(host = "foreign.datamancy.net"), publicChain, publicKey) }
        val bootstrap = inputs.getValue("livekit.yaml")
        val template = inputs.getValue("livekit-turn-template.yaml")
        assertContains(bootstrap, "turn:\n  enabled: false")
        assertContains(template, "turn:\n  enabled: true")
        assertContains(template, "cert_file: @REVISION_PEM@")
        assertContains(template, "key_file: @REVISION_KEY@")
        val effective = LiveKitRuntime.effectivePublicTurnConfig("q-abcdef123456", turn, bootstrap, template)
        assertContains(effective, "cert_file: /run/turn-revisions/${turn.revisionId}/rtc-turn.pem")
        assertContains(effective, "key_file: /run/turn-revisions/${turn.revisionId}/rtc-turn-key.pem")
        assertFalse(effective.contains("@REVISION_"))
        assertFails { LiveKitRuntime.effectivePublicTurnConfig("q-abcdef123456", turn, bootstrap.replace("enabled: false", "enabled: true"), template) }
        assertFails { LiveKitRuntime.effectivePublicTurnConfig("q-abcdef123456", turn, bootstrap, template.replace("@REVISION_KEY@", "/run/secrets/rtc-turn-key.pem")) }
        assertFails { LiveKitRuntime.effectivePublicTurnConfig("q-abcdef123456", turn.copy(revisionId = "cert-unauthorized"), bootstrap, template) }
        assertEquals(pieces.flatMap { it.spec.processes.flatMap { process ->
            listOfNotNull(process.environmentFile) + process.files.map { file -> file.file }
        } }.toSet() - setOf("postgres-ca.pem", "identity-ca.pem"), inputs.keys)
        assertContains(inputs.getValue("synapse-homeserver.yaml"), "server_name: matrix.datamancy.net")
        assertContains(inputs.getValue("mas.yaml"), "public_base: https://matrix-auth.datamancy.net/")
        assertFalse(inputs.getValue("mas.yaml").contains("chat.datamancy.net/fixture-callback"))
        assertContains(inputs.getValue("synapse-homeserver.yaml"),
            "livekit_service_url: https://matrix-rtc.datamancy.net/livekit/jwt")
        assertContains(inputs.getValue("element.json"),
            "https://matrix-rtc.datamancy.net/livekit/jwt")
        assertFalse(inputs.getValue("element.json").contains("https://login.datamancy.net/"))
        val upstream = MatrixIdentityRuntime.canonicalUpstreamClient("a".repeat(64))
        assertContains(upstream.toString(), "https://matrix-auth.datamancy.net/upstream/callback/")
        assertContains(inputs.getValue("mas.yaml"), "issuer: https://auth.datamancy.net/realms/p0v3")
        val element = Json.parseToJsonElement(inputs.getValue("element.json")).jsonObject
        assertEquals("Platform Zero chat.datamancy.net", element.getValue("brand").jsonPrimitive.content)
        assertEquals("https://matrix.datamancy.net", element.getValue("default_server_config").jsonObject
            .getValue("m.homeserver").jsonObject.getValue("base_url").jsonPrimitive.content)
        assertContains(inputs.getValue("livekit.yaml"), "domain: rtc.datamancy.net")
        assertContains(inputs.getValue("livekit.yaml"), "tls_port: 5349")
        assertContains(inputs.getValue("livekit.yaml"), "turn:\n  enabled: false")
        assertEquals(listOf("livekit.yaml", "livekit-turn-template.yaml", "rtc-turn.pem", "rtc-turn-key.pem"),
            pieces[3].spec.processes.single { it.id == "livekit" }.files.map { it.file })
        assertContains(inputs.getValue("rtc-registration.yaml"), "rooms:is_joined")
        assertFalse(inputs.any { (name, _) -> name == "realm.json" || name == "postgres.env" || name == "keycloak.env" })
    }
    @Test fun `combined recipe uses scoped appservice membership and private TLS without media key custody`() : Unit {
        val spec = MatrixRtcRuntime.spec(inventory)
        assertEquals(16, PrivateDeployment.validate(spec).size)
        assertEquals(9, spec.processes.count { !it.oneShot })
        val inputs = MatrixRtcRuntime.inputs { host -> mapOf("ca.pem" to "$host-ca", "web.pem" to "$host-cert", "web-key.pem" to "$host-key") }
        assertEquals(SingleUserRestore.inputNames(spec), inputs.keys)
        val env = inputs.getValue("rtc-authorizer.env")
        assertContains(env, "LIVEKIT_FULL_ACCESS_HOMESERVERS=matrix.private.invalid\n")
        assertContains(env, "LIVEKIT_AS_REGISTRATION_FILE=/run/secrets/rtc-registration.yaml")
        assertFalse("INSECURE" in env)
        val key = env.lineSequence().single { it.startsWith("LIVEKIT_KEY=") }.substringAfter('=')
        val secret = env.lineSequence().single { it.startsWith("LIVEKIT_SECRET=") }.substringAfter('=')
        assertContains(inputs.getValue("livekit.yaml"), "\"$key\": \"$secret\"")
        assertContains(inputs.getValue("livekit.yaml"), "auto_create: false")
        assertContains(inputs.getValue("homeserver.yaml"), "msc4502_enabled: true")
        assertFalse("KC_BOOTSTRAP_ADMIN_" in inputs.getValue("keycloak-runtime.env"))
        assertContains(inputs.getValue("keycloak-runtime.env"), "KC_DB_PASSWORD=")
        assertContains(inputs.getValue("rtc-registration.yaml"), "rooms:is_joined")
        assertContains(inputs.getValue("rtc-registration.yaml"), "exclusive: false")
        assertContains(inputs.getValue("rtc-nginx.conf"), "location /livekit/sfu/ {")
        assertContains(inputs.getValue("rtc-nginx.conf"), "proxy_pass http://livekit:7880/;")
        assertContains(inputs.getValue("rtc-nginx.conf"), "proxy_pass http://rtc-authorizer:8080/sfu/get;")
        val element = Json.parseToJsonElement(inputs.getValue("element.json")).jsonObject
        val focus = element.getValue("default_server_config").jsonObject.getValue("org.matrix.msc4143.rtc_foci").jsonArray.single().jsonObject
        assertEquals("https://rtc:8443/livekit/jwt", focus.getValue("livekit_service_url").jsonPrimitive.content)
        assertContains(inputs.getValue("element-nginx.conf"), "org.matrix.msc4143.rtc_foci")
        assertTrue(inputs.keys.none { "media-key" in it })
        assertEquals("rtc-ca", inputs.getValue("rtc-ca.pem"))
        assertTrue(spec.processes.all { it.capabilities.isEmpty() })
    }
    @Test fun `restoration retires all initializers and rejects modified recipes`() : Unit {
        val source = MatrixRtcRuntime.spec(inventory)
        val restored = MatrixRtcRuntime.restoredSpec(source, inventory, "matrix-rtc-restored")
        assertTrue(restored.processes.none { it.oneShot })
        val keycloak = restored.processes.single { it.id == "keycloak" }
        assertEquals("keycloak-runtime.env", keycloak.environmentFile)
        assertEquals(listOf("start", "--optimized"), keycloak.command)
        assertTrue(keycloak.files.none { it.file == "realm.json" })
        assertFalse("keycloak.env" in SingleUserRestore.inputNames(restored))
        assertTrue("keycloak-runtime.env" in SingleUserRestore.inputNames(restored))
        assertEquals(source.volumes, restored.volumes)
        assertEquals(source.processes.filterNot { it.oneShot }.map { it.id }, restored.processes.map { it.id })
        val retired = source.processes.filter { it.oneShot }.map { it.id }
        assertTrue(restored.processes.none { it.dependencies.any(retired::contains) })
        assertFails { MatrixRtcRuntime.restoredSpec(source, inventory, source.name) }
        assertFails { MatrixRtcRuntime.restoredSpec(source.copy(volumes = emptyList()), inventory, "other") }
        assertFails { MatrixRtcRuntime.spec(inventory.copy(images = inventory.images.filter { it.product != "matrix-rtc-authorizer" })) }
        assertFails { MatrixRtcRuntime.spec(inventory.copy(images = inventory.images.map { if (it.product == "matrix-rtc-authorizer") it.copy(os = "other") else it })) }
    }
    @Test fun `legacy matrix and stateless SFU projections retire exact initializers only`() : Unit {
        val synapse = SynapseRuntime.spec(inventory)
        val projected = SynapseRuntime.coldRestoreSpec(synapse)
        assertEquals(listOf("postgres", "synapse"), projected.processes.map { it.id })
        assertTrue(projected.processes.all { it.dependencies.isEmpty() })
        assertFalse("database-init.env" in SingleUserRestore.inputNames(projected))
        assertFails { SynapseRuntime.coldRestoreSpec(synapse.copy(processes = synapse.processes.filterNot { it.id == "signing-key-init" })) }
        val matrix = MatrixRuntime.spec(inventory.copy(images = inventory.images + inventory.images.first().copy(product = "caddy")))
        val restored = MatrixRuntime.coldRestoreSpec(matrix)
        assertEquals(matrix.volumes, restored.volumes)
        assertEquals(setOf("postgres", "synapse", "element-web", "caddy"), restored.processes.map { it.id }.toSet())
        assertFails { MatrixRuntime.coldRestoreSpec(synapse) }
        val sfu = LiveKitRuntime.spec(inventory)
        assertEquals(sfu, LiveKitRuntime.coldRestoreSpec(sfu))
        assertFails { LiveKitRuntime.coldRestoreSpec(sfu.copy(volumes = listOf(RuntimeVolume("unexpected", 1000)))) }
        assertFails { LiveKitRuntime.coldRestoreSpec(sfu.copy(processes = sfu.processes.map { it.copy(oneShot = true) })) }
        val rtc = MatrixRtcRuntime.spec(inventory)
        assertFails { MatrixRtcRuntime.coldRestoreSpec(rtc.copy(processes = rtc.processes.filterNot { it.id == "mas-migrate" })) }
        assertFails { MatrixRtcRuntime.coldRestoreSpec(rtc.copy(processes = rtc.processes.map {
            if (it.id == "auth") it.copy(command = listOf("server")) else it
        })) }
    }
}
