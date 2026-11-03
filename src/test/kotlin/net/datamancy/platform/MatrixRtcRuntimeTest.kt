package net.datamancy.platform

import kotlin.test.*
import kotlinx.serialization.json.*

class MatrixRtcRuntimeTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("postgres", "valkey", "ntfy", "synapse",
        "matrix-authentication-service", "element", "livekit", "matrix-rtc-authorizer").map {
        AcquiredImage(it, "upstream", "example.org/app:1", image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `combined recipe uses scoped appservice membership and private TLS without media key custody`() {
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
    @Test fun `restoration retires all initializers and rejects modified recipes`() {
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
    @Test fun `legacy matrix and stateless SFU projections retire exact initializers only`() {
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
