package net.datamancy.platform

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

/** Source regressions only. No project build, tests or runtime has been executed in this run. */
class ObservabilityRuntimeTest {
    private val image = "example.org/obs@sha256:" + "a".repeat(64)
    private val products = listOf("alertmanager", "alloy", "grafana", "loki", "prometheus", "node-exporter")
    private val inventory = AcquiredInventory(1, "unit", products.map { product ->
        val pin = if (product == "node-exporter") NodeMetricsRuntime.BASE_IMAGE else image
        AcquiredImage(product, "upstream", "example.org/$product:1", pin, "b".repeat(64),
            emptyList(), pin.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `historical five product and standalone two product recipes remain byte identical around canonical composition`() {
        val oldFive = Json.encodeToString(ObservabilityRuntime.spec(inventory))
        val oldTwo = Json.encodeToString(NodeMetricsRuntime.spec(inventory))
        val fragment = ObservabilityRuntime.canonicalFragment(inventory, "observability")
        assertEquals("prometheus", fragment.product)
        assertEquals(setOf("observability-web"), fragment.webNetworks)
        assertEquals(RuntimeStore.CANONICAL_V2, fragment.spec.store)
        assertEquals(oldFive, Json.encodeToString(ObservabilityRuntime.spec(inventory)))
        assertEquals(oldTwo, Json.encodeToString(NodeMetricsRuntime.spec(inventory)))
        assertTrue("node" !in oldFive && oldTwo.contains("metrics-init"))
    }
    @Test fun `canonical graph has six real product storage roots and exactly one Prometheus`() {
        val graph = ObservabilityRuntime.canonicalSpec(inventory)
        assertEquals(setOf("metrics", "alertmanager", "alloy", "grafana", "loki", "prometheus"),
            graph.volumes.map { it.id }.toSet())
        assertEquals(1, graph.processes.count { it.id == "prometheus" })
        assertEquals(setOf("metrics-init", "node", "alertmanager", "alloy", "grafana", "loki", "prometheus"),
            graph.processes.map { it.id }.toSet())
        assertEquals(listOf("observability-net", "observability-web"), graph.networks)
        assertEquals(setOf("grafana", "prometheus", "alertmanager"),
            graph.processes.filter { "observability-web" in it.networks }.map { it.id }.toSet())
        assertTrue(graph.processes.all { "observability-net" in it.networks && "net" !in it.networks &&
            "ingress-egress" !in it.networks && "qualification-web" !in it.networks })
        assertEquals(setOf("node", "alloy", "loki", "metrics-init"),
            graph.processes.filter { it.networks == listOf("observability-net") }.map { it.id }.toSet())
        assertTrue(graph.processes.none { it.capabilities.isNotEmpty() })
        assertTrue(graph.processes.none { it.volumes.any { mount -> mount.target.startsWith("/host") } })
        assertTrue(graph.processes.filter { it.oneShot }.map { it.id } == listOf("metrics-init"))
        assertEquals(listOf("alertmanager", "node"), graph.processes.single { it.id == "prometheus" }.dependencies.sorted())
        assertFails { ObservabilityRuntime.canonicalSpec(inventory.copy(images = inventory.images.filterNot { it.product == "node-exporter" })) }
        assertFails { ObservabilityRuntime.canonicalSpec(inventory, "../foreign") }
    }
    @Test fun `canonical input closure pins mTLS scrape and native rule with no outward receiver`() {
        val certificates = setOf("ca.pem", "node.pem", "node-key.pem", "admin.pem", "admin-key.pem")
            .associateWith { "unit-only-$it" }
        val legacy = mapOf("alertmanager.yaml" to "route:\n  receiver: private-no-outbound\nreceivers:\n  - name: private-no-outbound\n",
            "loki.yaml" to "auth_enabled: false\n", "prometheus.yaml" to "alertmanagers: ['alertmanager:9093']\nscrape_configs:\n",
            "config.alloy" to "loki.source.api\n", "datasources.yaml" to "apiVersion: 1\n",
            "grafana.env" to "GF_SECURITY_ADMIN_USER=p0v3-admin\n")
        val inputs = ObservabilityRuntime.canonicalInputs(certificates, legacy)
        assertEquals(PrivateDeployment.inputNames(ObservabilityRuntime.canonicalSpec(inventory)).toSet(), inputs.keys)
        assertContains(inputs.getValue("prometheus.yaml"), "server_name: node")
        assertContains(inputs.getValue("prometheus.yaml"), "insecure_skip_verify: false")
        assertContains(inputs.getValue("prometheus.yaml"), "rule_files:")
        assertContains(inputs.getValue("rules.yaml"), "P0SyntheticMetricObserved")
        assertContains(inputs.getValue("rules.yaml"), "scope: synthetic-only")
        assertContains(inputs.getValue("alertmanager.yaml"), "private-no-outbound")
        assertFalse(inputs.getValue("alertmanager.yaml").contains("smtp_"))
        assertFalse(inputs.getValue("prometheus.yaml").contains("insecure_skip_verify: true"))
        assertFails { ObservabilityRuntime.canonicalInputs(emptyMap(), legacy) }
        assertFails { ObservabilityRuntime.canonicalInputs(certificates, legacy - "grafana.env") }
    }
    @Test fun `cold projection refuses foreign source and drops only original seed while preserving imported data roots`() {
        val original = ObservabilityRuntime.canonicalFragment(inventory, "original")
        val expected = "a".repeat(64)
        val cold = ObservabilityRuntime.canonicalColdFragment(original, inventory, "restored", expected)
        assertEquals(original.spec.volumes, cold.spec.volumes)
        assertEquals(original.spec.networks, cold.spec.networks)
        assertEquals(original.spec.processes.map { it.id }.toSet() - "metrics-init", cold.spec.processes.map { it.id }.toSet())
        assertTrue(cold.spec.processes.none { it.oneShot }) // PrivateDeployment.importCold requires this.
        assertEquals(emptyList(), cold.spec.processes.single { it.id == "node" }.dependencies)
        assertEquals(SingleUserRestore.inputNames(original.spec) - "fixture.prom", SingleUserRestore.inputNames(cold.spec))
        assertFails { ObservabilityRuntime.canonicalColdFragment(original, inventory, "original", expected) }
        assertFails { ObservabilityRuntime.canonicalColdFragment(original, inventory, "other", "bad") }
        assertFails { ObservabilityRuntime.canonicalColdFragment(original.copy(product = "loki"), inventory, "other", expected) }
        val foreign = original.copy(spec = original.spec.copy(processes = original.spec.processes.drop(1)))
        assertFails { ObservabilityRuntime.canonicalColdFragment(foreign, inventory, "other", expected) }
    }
}
