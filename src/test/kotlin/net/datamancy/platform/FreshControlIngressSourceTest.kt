package net.datamancy.platform

import java.nio.file.Path
import org.junit.jupiter.api.Test
import kotlin.test.*

class FreshControlIngressSourceTest {
    @Test fun `selected controller exposes only typed owner operations and device API`() {
        val root=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/q-5962a9fda75b")
        val plan=GenerationAssembly().plan(GenerationAssembly.readRequest(root.resolve("assembly-request.pi-subscription-v5.budgeted.json")),
            GenerationAssembly.readInventory(root.resolve("inventory.json")))
        val source=CanonicalGraphCaddyfile.render(PackagedGraphFragment.pendingV3R9().first,plan.specs.single())
        assertEquals(RuntimeControlSocketMount(GenerationRuntime.BASE.resolve(plan.generation.id)
            .resolve("managed/control/run").toString(),"/run/p0-control"),
            plan.specs.single().processes.single { it.id == "caddy" }.controlSocketMount)
        // A directory bind is possible before the broker creates its socket;
        // no source test assumes the broker has started or the socket is absent.
        val control=source.substringAfter("https://control.datamancy.net {").substringBefore("\nhttps://")
        assertContains(control,"@typed_control path /ops/status /ops/lane/start /ops/lane/stop /ops/device-tokens /ops/device-tokens/*")
        assertContains(control,"reverse_proxy unix//run/p0-control/http.sock")
        assertContains(control,"respond 404")
        assertContains(control,"import p0_auth")
        val api=source.substringAfter("https://api.datamancy.net {").substringBefore("\nhttps://")
        assertContains(api,"@device_api path /v1/models /v1/chat/completions")
        assertContains(api,"request_header -Cookie")
        assertContains(api,"reverse_proxy unix//run/p0-control/http.sock")
        assertFalse(api.contains("/ops/device-tokens"))
    }
}
