package net.datamancy.platform

import java.nio.file.Files
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
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
    @Test fun `canonical exporter retains legacy serialized recipe and never contributes a second Prometheus`() {
        val before = Json.encodeToString(NodeMetricsRuntime.spec(inventory))
        val (volume, processes) = NodeMetricsRuntime.canonicalExporter(inventory)
        assertEquals("metrics", volume.id)
        assertEquals(listOf("metrics-init", "node"), processes.map { it.id })
        assertTrue(processes.all { it.volumes == listOf(RuntimeMount("metrics", "/synthetic")) })
        assertEquals(before, Json.encodeToString(NodeMetricsRuntime.spec(inventory)))
        assertFails { NodeMetricsRuntime.canonicalExporter(inventory.copy(images = inventory.images.filterNot { it.product == "node-exporter" })) }
    }
    @Test fun `six canonical metrics products share only one Prometheus and one original exporter`() {
        val all = listOf("alertmanager", "loki", "prometheus", "alloy", "grafana")
        val pins = all.map { product -> AcquiredImage(product, "upstream", "example.org/$product:1", image,
            "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux") }
        val complete = inventory.copy(images = inventory.images + pins.filterNot { it.product == "prometheus" })
        val canonical = ObservabilityRuntime.canonicalSpec(complete)
        assertEquals(1, canonical.processes.count { it.id == "prometheus" })
        assertEquals(setOf("metrics-init", "node", "alertmanager", "alloy", "grafana", "loki", "prometheus"),
            canonical.processes.map { it.id }.toSet())
        assertEquals(6, canonical.volumes.size)
        assertEquals(setOf("node", "alertmanager"), canonical.processes.single { it.id == "prometheus" }.dependencies.toSet())
        assertEquals("/synthetic", canonical.processes.single { it.id == "node" }.volumes.single().target)
        assertTrue(canonical.processes.none { it.command.any { arg -> "--web.enable-admin-api" in arg } })
        assertFails { ObservabilityRuntime.canonicalSpec(complete.copy(images = complete.images.filterNot { it.product == "node-exporter" })) }
        val certs = setOf("ca.pem", "node.pem", "node-key.pem", "admin.pem", "admin-key.pem")
            .associateWith { "unit-only-$it" }
        val legacy = mapOf("alertmanager.yaml" to "receivers: [private-no-outbound]\n",
            "loki.yaml" to "auth_enabled: false\n", "prometheus.yaml" to "alertmanagers: [private]\nscrape_configs:\n",
            "config.alloy" to "loki.source.api\n", "datasources.yaml" to "apiVersion: 1\n",
            "grafana.env" to "GF_SECURITY_ADMIN_USER=p0v3-admin\n")
        val inputs = ObservabilityRuntime.canonicalInputs(certs, legacy)
        assertEquals(PrivateDeployment.inputNames(canonical).toSet(), inputs.keys)
        assertContains(inputs.getValue("prometheus.yaml"), "insecure_skip_verify: false")
        assertContains(inputs.getValue("prometheus.yaml"), "targets: ['node:9100']")
        assertContains(inputs.getValue("rules.yaml"), "P0SyntheticMetricObserved")
        assertFalse(inputs.getValue("alertmanager.yaml").contains("smtp_"))
        assertFails { ObservabilityRuntime.canonicalInputs(emptyMap(), legacy) }
        assertFails { ObservabilityRuntime.canonicalInputs(certs, legacy - "alertmanager.yaml") }
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
