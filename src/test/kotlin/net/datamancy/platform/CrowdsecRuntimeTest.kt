package net.datamancy.platform

import kotlin.test.*

class CrowdsecRuntimeTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf(
        AcquiredImage("crowdsec", "upstream", "example.org/app:1", image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")
    ))
    @Test fun `native detection has no host ingestion sharing or enforcement privilege`(): Unit {
        val spec = CrowdsecRuntime.spec(inventory)
        assertEquals(2, PrivateDeployment.validate(spec).size)
        assertEquals(1, spec.processes.count { !it.oneShot })
        assertTrue(spec.processes.all { it.userId == 1000 && it.capabilities.isEmpty() && it.apparmorProfile == "p0v3-private-v1" })
        val files = CrowdsecRuntime.inputs { mapOf("ca.pem" to "ca", "web.pem" to "cert", "web-key.pem" to "key") }
        assertEquals(SingleUserRestore.inputNames(spec), files.keys)
        val serving = spec.processes.single { !it.oneShot }
        assertFalse(serving.volumes.any { it.volume == "bootstrap" })
        assertEquals(listOf("guard-init"), serving.dependencies)
        assertContains(serving.readiness, "status")
        val init = spec.processes.single { it.oneShot }.command.last()
        assertContains(init, "machines add private-fixture --auto")
        assertContains(init, "bouncers add private-probe")
        assertFalse("--force" in init)
        assertContains(init, "ls -A /data")
        assertContains(files.getValue("crowdsec.yaml"), "insecure_skip_verify: false")
        assertFalse("online_client" in files.getValue("crowdsec.yaml"))
        assertContains(files.getValue("acquis.yaml"), "/synthetic-logs/http.log")
        assertContains(files.getValue("parser.yaml"), "apply_on: Line.Raw")
        assertContains(init, "/staging/etc/crowdsec/patterns")
        assertContains(files.getValue("scenario.yaml"), "capacity: 2")
        assertContains(files.getValue("scenario.yaml"), "evt.Meta.http_status == '401'")
        assertContains(files.getValue("profiles.yaml"), "duration: 30m")
        assertFails { CrowdsecRuntime.spec(inventory.copy(images = emptyList())) }
        assertFails { CrowdsecRuntime.spec(inventory.copy(images = inventory.images.map { it.copy(architecture = "arm64") })) }
        assertFails { CrowdsecRuntime.spec(inventory, "../bad") }
    }
    @Test fun `canonical detector keeps original local machine decision state without reseeding bouncer`(): Unit {
        val graph = CrowdsecRuntime.canonicalFragment(inventory, "q-111111111111-crowdsec")
        val inputs = CrowdsecRuntime.canonicalInputs { mapOf(
            "ca.pem" to "CA", "web.pem" to "cert", "web-key.pem" to "key") }
        assertEquals(PrivateDeployment.inputNames(graph.spec).toSet(), inputs.keys)
        assertContains(inputs.getValue("crowdsec-crowdsec.yaml"),
            "cert_file: /run/secrets/web.pem")
        assertFalse("bouncer-key" in PrivateDeployment.inputNames(graph.spec))
        assertTrue(graph.providerNetworks.isEmpty() && graph.webNetworks.isEmpty())
        assertEquals(listOf("guard-data"), graph.spec.networks)
        val cold = CrowdsecRuntime.coldRestoreFragment(graph)
        assertEquals(graph.spec.volumes, cold.spec.volumes)
        assertEquals(setOf("bootstrap"), cold.spec.unmountedRecoveryVolumes)
        assertEquals(listOf("guard"), PrivateDeployment.validate(cold.spec).map { it.id })
        assertEquals(listOf("guard"), cold.spec.processes.map { it.id })
        assertTrue(cold.spec.processes.single().dependencies.isEmpty())
        assertFalse(cold.spec.processes.single().volumes.any { it.volume == "bootstrap" })
        assertFails { CrowdsecRuntime.coldRestoreFragment(graph.copy(spec = graph.spec.copy(processes = graph.spec.processes.drop(1)))) }
    }
}
