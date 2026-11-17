package net.datamancy.platform

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CaddyConfigTest {
    private val image = "example.org/app@sha256:${"a".repeat(64)}"
    private fun lock(caddyState: Boolean = true, target: String = "ntfy") = ReleaseLock(1,
        ProductSelection.bundled().products.map { id ->
            val state = if (id == "caddy" && caddyState) listOf(StateSet("certs", "caddy", "/data", "backup", "restore"))
                        else emptyList()
            ProductContract(id, "1.0", listOf(LockedProcess(id, ProcessRole.DAEMON, image, emptyList(), "ready",
                emptyList(), 65532, if (id == "caddy") listOf(NetworkRole.APP, NetworkRole.INGRESS)
                else listOf(NetworkRole.APP), state.map { it.id })), state,
                if (id == target) listOf(Route("notify.datamancy.net", id, 8080)) else emptyList(),
                listOf(Journey("outcome", "works")))
        })
    @Test fun `approved routes use native ACME HTTP-01 and durable certificate storage`() {
        val approved = setOf("notify.datamancy.net")
        val staging = CaddyConfig.offline(lock(), approved, AcmeEnvironment.STAGING)
        val production = CaddyConfig.offline(lock(), approved, AcmeEnvironment.PRODUCTION)
        assertTrue(staging.contains("storage file_system /data/caddy"))
        assertTrue(staging.contains("disable_tlsalpn_challenge"))
        assertTrue(staging.contains("acme-staging-v02.api.letsencrypt.org"))
        assertTrue(production.contains("acme-v02.api.letsencrypt.org"))
        assertTrue(production.contains("notify.datamancy.net {\n    reverse_proxy p0v3-ntfy:8080"))
        assertFalse(production.contains("tls internal"))
        assertFalse(production.contains("dns cloudflare"))
        assertFalse(production.contains("acme-staging"))
    }
    @Test fun `provider-less Caddy uses pinned image durable state and private empty bootstrap`() {
        val inventory = AcquiredInventory(1, "unit", listOf(AcquiredImage("caddy", "unit", "example.org/app:tag",
            image, "b".repeat(64), listOf(image), "sha256:" + "a".repeat(64), "amd64", "linux")))
        val spec = CaddyRuntime.spec(inventory)
        kotlin.test.assertEquals(image, spec.processes.single().image)
        kotlin.test.assertEquals(setOf("caddy-data", "caddy-config"), spec.volumes.map { it.id }.toSet())
        kotlin.test.assertEquals(setOf("caddy.env", "caddy.json"), CaddyRuntime.inputs().keys)
        assertTrue("127.0.0.1:2019" in CaddyRuntime.inputs().getValue("caddy.json"))
        assertFalse(":443" in CaddyRuntime.inputs().getValue("caddy.json"))
        assertTrue("--resume" in spec.processes.single().command)
        val restored = CaddyRuntime.restoreSpec(inventory, "restored-caddy")
        assertFalse("--resume" in restored.processes.single().command)
        kotlin.test.assertNull(restored.ingress)
        assertFalse(restored.processes.any { it.oneShot })
        val publication = RuntimeIngressPublication("unit", setOf("web.datamancy.net"), "0.0.0.0")
        assertFailsWith<IllegalArgumentException> { CaddyRuntime.publish(spec, publication) }
        val public = CaddyRuntime.publish(spec.copy(store = RuntimeStore.CANONICAL_V2), publication)
        kotlin.test.assertEquals(publication, public.ingress)
        assertEquals("ingress-egress", public.networks.first())
        assertEquals("ingress-egress", public.processes.single().networks.first())
        assertFailsWith<IllegalArgumentException> { CaddyRuntime.publish(public, publication) }
    }
    @Test fun `composed Caddy joins only declared app web networks and never database or admin networks`(): Unit {
        val inventory = AcquiredInventory(1, "unit", listOf(AcquiredImage("caddy", "unit", "example.org/app:tag",
            image, "b".repeat(64), listOf(image), "sha256:" + "a".repeat(64), "amd64", "linux")))
        val base = CaddyRuntime.spec(inventory)
        val app = RuntimeProcess("ntfy-web", image, "b".repeat(64), 1000,
            networks = listOf("ntfy-web"), readiness = listOf("true"))
        val sql = RuntimeProcess("postgres", image, "b".repeat(64), 1000,
            networks = listOf("sql-admin"), readiness = listOf("true"))
        val composed = base.copy(networks = base.networks + listOf("ntfy-web", "sql-admin"), processes = base.processes + app + sql)
        val connected = CaddyRuntime.withFrontendNetworks(composed, setOf("ntfy-web"))
        assertTrue("ntfy-web" in connected.processes.single { it.id == "caddy" }.networks)
        assertFalse("sql-admin" in connected.processes.single { it.id == "caddy" }.networks)
        kotlin.test.assertEquals(connected, CaddyRuntime.withFrontendNetworks(connected, setOf("ntfy-web")))
        assertFailsWith<IllegalArgumentException> { CaddyRuntime.withFrontendNetworks(composed, setOf("sql-admin")) }
        assertFailsWith<IllegalArgumentException> { CaddyRuntime.withFrontendNetworks(composed, setOf("unowned-web")) }
    }

    @Test fun `self routes missing ACME state and unapproved hosts cannot render`() {
        assertFailsWith<IllegalArgumentException> { CaddyConfig.offline(lock(), emptySet(), AcmeEnvironment.PRODUCTION) }
        assertFailsWith<IllegalArgumentException> { CaddyConfig.offline(lock(false), setOf("notify.datamancy.net"), AcmeEnvironment.PRODUCTION) }
        assertFailsWith<IllegalArgumentException> { CaddyConfig.offline(lock(target = "caddy"), setOf("notify.datamancy.net"), AcmeEnvironment.PRODUCTION) }
    }
}
