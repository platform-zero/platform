package net.datamancy.platform

import kotlin.test.*
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions

class LiveKitRuntimeTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("livekit", "element").map {
        AcquiredImage(it, "upstream", "example.org/app:1", image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `stateless recovery preserves keys refuses changed inputs and rejects unsupported source recipes`() : Unit {
        val base = Files.createTempDirectory("p0v3-rtc-test-")
        try {
            val source = LiveKitRuntime.spec(inventory)
            val inputs = LiveKitRuntime.inputs { mapOf("ca.pem" to "ca", "web.pem" to "cert", "web-key.pem" to "key") }
            val manifest = RuntimePreparation.prepare(source, base) { inputs }
            val recovered = Files.createDirectory(base.resolve("recovered"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            Files.copy(manifest, recovered.resolve("source-spec.json"))
            inputs.keys.forEach { Files.copy(base.resolve(source.name).resolve(it), recovered.resolve(it)) }
            val restored = LiveKitRuntime.prepareRestore(inventory, recovered, "restored", base)
            assertEquals(source.copy(name = "restored"), PrivateDeployment.read(restored))
            assertEquals(restored, LiveKitRuntime.prepareRestore(inventory, recovered, "restored", base))
            assertEquals(inputs.getValue("livekit.yaml"), Files.readString(base.resolve("restored/livekit.yaml")))
            assertFails { LiveKitRuntime.prepareRestore(inventory, recovered, source.name, base) }
            assertFails { LiveKitRuntime.prepareRestore(inventory, base.resolve("missing"), "other", base) }
            val bad = RuntimePreparation.prepare(source.copy(name = "bad", processes = source.processes.dropLast(1)), base) { mapOf("livekit.yaml" to inputs.getValue("livekit.yaml")) }
            Files.copy(bad, recovered.resolve("source-spec.json"), java.nio.file.StandardCopyOption.REPLACE_EXISTING)
            assertFails { LiveKitRuntime.prepareRestore(inventory, recovered, "other", base) }
            Files.copy(manifest, recovered.resolve("source-spec.json"), java.nio.file.StandardCopyOption.REPLACE_EXISTING)
            Files.writeString(recovered.resolve("livekit.yaml"), "changed")
            assertFails { LiveKitRuntime.prepareRestore(inventory, recovered, "restored", base) }
        } finally { Files.walk(base).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `authenticated bounded private SFU with no persistent room fiction`() : Unit {
        val spec = LiveKitRuntime.spec(inventory)
        assertEquals(listOf("livekit", "rtc"), PrivateDeployment.validate(spec).map { it.id })
        assertTrue(spec.volumes.isEmpty())
        assertTrue(spec.processes.all { it.userId != 0 && it.capabilities.isEmpty() && it.apparmorProfile == "p0v3-private-v1" })
        val inputs = LiveKitRuntime.inputs { mapOf("ca.pem" to "ca", "web.pem" to "cert", "web-key.pem" to "key") }
        assertEquals(SingleUserRestore.inputNames(spec), inputs.keys)
        val config = inputs.getValue("livekit.yaml")
        for (setting in listOf("development: false", "use_external_ip: false", "auto_create: false", "max_participants: 8", "enabled: false", "port_range_end: 50020")) assertContains(config, setting)
        assertContains(inputs.getValue("nginx.conf"), "ssl_protocols TLSv1.2 TLSv1.3")
        assertContains(inputs.getValue("nginx.conf"), "proxy_set_header Upgrade")
        assertNotEquals(config, LiveKitRuntime.inputs { emptyMap() }.getValue("livekit.yaml"))
        assertFails { LiveKitRuntime.spec(inventory.copy(images = inventory.images.drop(1))) }
        assertFails { LiveKitRuntime.spec(inventory.copy(images = inventory.images.map { it.copy(architecture = "arm64") })) }
    }
}
