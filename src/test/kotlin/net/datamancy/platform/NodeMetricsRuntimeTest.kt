package net.datamancy.platform

import java.nio.file.Files
import kotlin.test.*

class NodeMetricsRuntimeTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("node-exporter", "prometheus").map {
        val pin = if (it == "node-exporter") NodeMetricsRuntime.BASE_IMAGE else image
        AcquiredImage(it, "upstream", "example.org/app:1", pin, "b".repeat(64), emptyList(), pin.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `exporter disables host collectors and provides TLS client authenticated scraping`() {
        val spec = NodeMetricsRuntime.spec(inventory)
        assertEquals(listOf("metrics-init", "node", "prometheus"), PrivateDeployment.validate(spec).map { it.id })
        val node = spec.processes.single { it.id == "node" }
        assertEquals(listOf(RuntimeMount("metrics", "/synthetic")), node.volumes)
        assertContains(spec.processes.first().command.last(), "test -z")
        assertContains(node.command, "--collector.disable-defaults")
        assertContains(node.command, "--collector.textfile")
        assertFalse(node.files.any { it.file.startsWith("admin") })
        assertTrue(spec.processes.all { it.capabilities.isEmpty() && it.userId == 65534 && it.apparmorProfile == "p0v3-private-v1" })
        val certificates = listOf("ca.pem", "node.pem", "node-key.pem", "admin.pem", "admin-key.pem").associateWith { "unit-only" }
        val inputs = NodeMetricsRuntime.inputs(certificates)
        assertEquals(SingleUserRestore.inputNames(spec), inputs.keys)
        assertContains(inputs.getValue("web.yaml"), "RequireAndVerifyClientCert")
        assertContains(inputs.getValue("prometheus.yaml"), "insecure_skip_verify: false")
        assertContains(inputs.getValue("prometheus.yaml"), "server_name: node")
        assertContains(inputs.getValue("fixture.prom"), "42")
        assertContains(inputs.getValue("rules.yaml"), "node_textfile_scrape_error")
        assertFalse(inputs.getValue("prometheus.yaml").contains("alertmanagers:"))
        assertFails { NodeMetricsRuntime.inputs(emptyMap()) }
        assertFails { NodeMetricsRuntime.spec(inventory.copy(images = emptyList())) }
        assertFails { NodeMetricsRuntime.spec(inventory.copy(images = inventory.images.map { it.copy(architecture = "arm64") })) }
        assertFails { NodeMetricsRuntime.spec(inventory, "../unsafe") }
    }
    @Test fun `PKI server hostname is bounded and separate keys stay distinct`() {
        val extensions = mutableListOf<String>()
        val certificates = PrivateSearchPki.generate("node") { root, args ->
            if ("-extfile" in args) extensions += Files.readString(root.resolve(args[args.indexOf("-extfile") + 1]))
            for (option in listOf("-out", "-keyout")) if (option in args) Files.writeString(root.resolve(args[args.indexOf(option) + 1]), "unit-only")
        }
        assertContains(extensions.first(), "subjectAltName=DNS:node")
        assertFalse(extensions.last().contains("serverAuth"))
        assertFalse("ca-key.pem" in certificates)
        assertFails { PrivateSearchPki.generate("node\ninjected") { _, _ -> error("must not execute") } }
    }
}
