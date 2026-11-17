package net.datamancy.platform

import java.util.Base64
import kotlinx.serialization.json.*
import kotlin.test.*

class NamespaceCaddyTransportTest {
    private val etag = "\"/config/ 0123456789abcdef\""
    @Test fun `namespace transport audits every request and carries exact CAS and body without credentials in argv`() {
        val mutations = mutableListOf<Boolean>()
        val requests = mutableListOf<JsonObject>()
        val transport = NamespaceCaddyTransport({ mutation, action -> mutations.add(mutation); action(CaddyAdminTarget(42, "a".repeat(64))) }, { bytes ->
            requests += Json.parseToJsonElement(bytes.decodeToString()).jsonObject
            buildJsonObject { put("status", 200); put("etag", etag); put("body", Base64.getEncoder().encodeToString("{}".toByteArray())) }.toString().toByteArray()
        })
        val read = transport.exchange("GET", "/config/", null, null)
        assertEquals(200, read.status); assertEquals(etag, read.etag); assertContentEquals("{}".toByteArray(), read.body)
        transport.exchange("POST", "/config/", etag, "{\"private\":true}".toByteArray())
        transport.exchange("PATCH", "/config/apps/http/servers/owned/routes", etag, "[]".toByteArray())
        assertEquals(listOf(false, true, true), mutations)
        assertEquals(42, requests.first().getValue("pid").jsonPrimitive.int)
        assertEquals(JsonNull, requests.first()["body"])
        assertEquals(etag, requests[1].getValue("etag").jsonPrimitive.content)
        assertContentEquals("{\"private\":true}".toByteArray(), Base64.getDecoder().decode(requests[1].getValue("body").jsonPrimitive.content))
        for ((method, path) in listOf("DELETE" to "/config/", "GET" to "/debug/", "POST" to "/load")) {
            assertFails { transport.exchange(method, path, null, null) }
        }
        assertFails { transport.exchange("POST", "/config/", "stale", byteArrayOf(1)) }
        assertEquals(3, mutations.size)
    }
    @Test fun `namespace helper malformed output and changed target are rejected`() {
        val target: (Boolean, (CaddyAdminTarget) -> CaddyReply) -> CaddyReply = { _, action -> action(CaddyAdminTarget(42, "b".repeat(64))) }
        for (output in listOf("{}", "{\"status\":700,\"etag\":null,\"body\":\"\"}", "{\"status\":200,\"etag\":null,\"body\":\"!\"}")) {
            assertFails { NamespaceCaddyTransport(target) { output.toByteArray() }.exchange("GET", "/config/", null, null) }
        }
        assertFails { NamespaceCaddyTransport({ _, action -> action(CaddyAdminTarget(1, "b".repeat(64))) }) { error("must not run") }
            .exchange("GET", "/config/", null, null) }
        assertFails { NamespaceCaddyTransport({ _, _ -> error("changed runtime fingerprint") }) { error("must not run") }
            .exchange("GET", "/config/", null, null) }
    }
    @Test fun `synthetic helper subprocess has bounded IO failure and timeout paths without native commands`() {
        val request = "synthetic stdin only".toByteArray()
        assertContentEquals(request, runBoundedCaddyHelper(listOf("/usr/bin/python3", "-I", "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"), request))
        assertFails { runBoundedCaddyHelper(listOf("/usr/bin/python3", "-I", "-c", "raise SystemExit(2)"), request) }
        assertFails { runBoundedCaddyHelper(listOf("/usr/bin/python3", "-I", "-c", "import time; time.sleep(10)"), request, 1) }
        assertFails { runBoundedCaddyHelper(emptyList(), byteArrayOf()) }
    }
    @Test fun `restored bridge listener uses only audited client network IP, never all app networks`(): Unit {
        val name = "q-000000000002-ingress"
        val pin = "a".repeat(64)
        val image = "registry.example.invalid/caddy@sha256:${"b".repeat(64)}"
        val caddy = RuntimeProcess("caddy", image, "b".repeat(64), 1000,
            networks = listOf("clients-web", "app-web"), readiness = listOf("true"),
            networkAliases = listOf(RuntimeNetworkAlias("clients-web", "social.datamancy.net")))
        val client = RuntimeProcess("rss-qualification-client", image, "b".repeat(64), 1000,
            networks = listOf("clients-web"), readiness = listOf("true"))
        val spec = PrivateDeploymentSpec(name = name, volumes = emptyList(), processes = listOf(caddy, client),
            networks = listOf("clients-web", "app-web"), store = RuntimeStore.CANONICAL_V2)
        val native = """[{"Config":{"Labels":{"io.p0v3.private-deployment":"$name","io.p0v3.runtime-fingerprint":"$pin"}},
            "State":{"Running":true},"NetworkSettings":{"Networks":{
            "p0v3-live-$name-clients-web":{"IPAddress":"10.89.0.5"},
            "p0v3-live-$name-app-web":{"IPAddress":"10.90.0.8"}}}}]"""
        val commands = RuntimeCommands { args ->
            assertEquals(listOf("inspect", "--type", "container", "p0v3-live-$name-caddy"), args)
            RuntimeCommandResult(0, native)
        }
        val audit: (PrivateDeploymentSpec, String) -> RuntimeAudit = { target, fingerprint ->
            assertEquals(name, target.name); assertEquals(pin, fingerprint)
            RuntimeAudit(name, pin, 3, null, listOf(RuntimeStatus("caddy", "running", null),
                RuntimeStatus("rss-qualification-client", "running", null)))
        }
        assertEquals("10.89.0.5", NamespaceCaddyTransport.ownedClientAddress(spec, pin, "clients-web", commands, audit))
        assertFailsWith<IllegalArgumentException> {
            NamespaceCaddyTransport.ownedClientAddress(spec, pin, "clients-web", RuntimeCommands { _ ->
                RuntimeCommandResult(0, native.replace(pin, "c".repeat(64)))
            }, audit)
        }
        assertFailsWith<IllegalArgumentException> {
            NamespaceCaddyTransport.ownedClientAddress(spec, pin, "app-web", RuntimeCommands { _ ->
                RuntimeCommandResult(0, native.replace("10.90.0.8", "1.1.1.1"))
            }, audit)
        }
    }
    @Test fun `new public listener requires native primary ingress network and exact Podman 80 443 mapping`(): Unit {
        val name = "q-000000000002-ingress"
        val pin = "a".repeat(64)
        val image = "registry.example.invalid/caddy@sha256:${"b".repeat(64)}"
        val caddy = RuntimeProcess("caddy", image, "b".repeat(64), 1000,
            entrypoint = "/usr/bin/caddy", command = listOf("run", "--config", "/run/secrets/caddy.json"),
            networks = listOf("ingress-egress", "app-web"), readiness = listOf("true"),
            capabilities = listOf("NET_BIND_SERVICE"))
        val app = RuntimeProcess("app", image, "b".repeat(64), 1000,
            networks = listOf("app-web"), readiness = listOf("true"))
        val spec = PrivateDeploymentSpec(name = name, volumes = emptyList(), processes = listOf(caddy, app),
            networks = listOf("ingress-egress", "app-web"), store = RuntimeStore.CANONICAL_V2,
            ingress = RuntimeIngressPublication("unit", setOf("web.datamancy.net"), "0.0.0.0"))
        val native = """[{"Config":{"Labels":{"io.p0v3.private-deployment":"$name","io.p0v3.runtime-fingerprint":"$pin"}},
          "State":{"Running":true},"HostConfig":{"NetworkMode":"p0v3-live-$name-ingress-egress",
          "PortBindings":{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"80"}],
          "443/tcp":[{"HostIp":"0.0.0.0","HostPort":"443"}]}},"NetworkSettings":{"Networks":{
          "p0v3-live-$name-ingress-egress":{"IPAddress":"10.89.0.3"},
          "p0v3-live-$name-app-web":{"IPAddress":"10.90.0.8"}}}}]"""
        val commands = RuntimeCommands { _ -> RuntimeCommandResult(0, native) }
        val audit: (PrivateDeploymentSpec, String) -> RuntimeAudit = { _, _ ->
            RuntimeAudit(name, pin, 3, null, listOf(RuntimeStatus("caddy", "running", null),
                RuntimeStatus("app", "running", null)))
        }
        assertEquals("10.89.0.3", NamespaceCaddyTransport.ownedPublicAddress(spec, pin, commands, audit))
        assertFailsWith<IllegalArgumentException> {
            NamespaceCaddyTransport.ownedPublicAddress(spec.copy(networks = listOf("app-web", "ingress-egress")),
                pin, commands, audit)
        }
        assertFailsWith<IllegalArgumentException> {
            NamespaceCaddyTransport.ownedPublicAddress(spec, pin,
                RuntimeCommands { _ -> RuntimeCommandResult(0, native.replace("HostPort\":\"443", "HostPort\":\"8443")) }, audit)
        }
        assertFailsWith<IllegalArgumentException> {
            NamespaceCaddyTransport.ownedPublicAddress(spec, pin,
                RuntimeCommands { _ -> RuntimeCommandResult(0, native.replace("NetworkMode\":\"p0v3-live-$name-ingress-egress",
                    "NetworkMode\":\"bridge")) }, audit)
        }
    }

    @Test fun `every pack case has read-only original feed identity but no bot or status authority`(): Unit {
        for (pack in listOf("analysis", "aus-state", "aus", "china-state", "china", "tas", "us-state", "us", "world")) {
            val service = "rss-pack-$pack"
            assertTrue(exactRssNativeReadScope(service, "rss_original", "", "/api/v1/accounts/verify_credentials"))
            assertFalse(exactRssNativeReadScope(service, "rss_original", "", "/api/v1/statuses/123"))
            assertFalse(exactRssNativeReadScope(service, "rss_original", "", "/api/v1/statuses/123/source"))
            assertFalse(exactRssNativeReadScope(service, "rssq_aaaaaaaaaaaa", "rssq_aaaaaaaaaaaa",
                "/api/v1/accounts/verify_credentials"))
        }
        assertTrue(exactRssNativeReadScope("rss-jobs", "rssq_aaaaaaaaaaaa", "rssq_aaaaaaaaaaaa",
            "/api/v1/statuses/123/source"))
        assertFalse(exactRssNativeReadScope("rss-pack-other", "rss_original", "",
            "/api/v1/accounts/verify_credentials"))
    }

    @Test fun `restored RSS client refuses POST and foreign routes before network or credential reads`(): Unit {
        val root = java.nio.file.Files.createTempDirectory("rss-native-client-unit-")
        java.nio.file.Files.setPosixFilePermissions(root,
            java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"))
        try {
            val target = "q-000000000002"
            val host = "social.datamancy.net"
            val bridge = RestoredBridgeBinding("r-000000000001", "rss", "q-000000000001", target,
                "a".repeat(64), "rss-client", "10.89.0.5", emptySet(), "rss-bridge", "r-000000000003",
                "b".repeat(64), "c".repeat(64), setOf(host),
                listOf(CaddyUpstream(host, "p0v3-live-$target-app-mastodon:443")),
                emptyMap(), emptyMap(), emptyMap(), emptyMap(), setOf("rss-mastodon"))
            var observed = 0
            val actor = RestoredIngressClient(root, root.resolve(target), bridge,
                { observed++; false }, { observed++; "10.89.0.5" },
                { observed++; CaddyReply(200, "{}".toByteArray(), etag) },
                { _ -> observed++; error("must not enter namespace") },
                { _ -> observed++; error("must not invoke native helper") })
            val input = RssIngressClientRequest("r-000000000004", target,
                root.resolve("${bridge.operation}.intent.json").toString(), "d".repeat(64),
                bridge.targetFingerprint, bridge.clientAddress, bridge.clientNetwork, host, "e".repeat(64),
                ActivationInput(root.resolve("ca.pem").toString(), "f".repeat(64)),
                ActivationInput(root.resolve("token").toString(), "f".repeat(64)),
                "RESTORE", "a".repeat(64), "b".repeat(64), "case-${"a".repeat(36)}",
                "rss_reader", "", "GET", "/api/v1/statuses/123/source")
            assertFailsWith<IllegalArgumentException> { actor.request(input.copy(method = "POST", path = "/api/v1/statuses")) }
            assertFailsWith<IllegalArgumentException> { actor.request(input.copy(path = "/admin/realms/p0v3/users")) }
            assertFailsWith<IllegalArgumentException> { actor.request(input.copy(originalHost = "foreign.datamancy.net")) }
            assertFailsWith<IllegalArgumentException> { actor.request(input.copy(phase = "INSTALL")) }
            assertEquals(0, observed)
            assertFalse(java.nio.file.Files.exists(root.resolve("client.pending")))
        } finally {
            java.nio.file.Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(java.nio.file.Files::delete) }
        }
    }

    @Test fun `runtime binding never silently switches admin endpoints or host approvals`() {
        val binding = CaddySiteBinding("unit", "owned", "http://127.0.0.1:2019", setOf("web.datamancy.net"))
        val spec = PrivateDeploymentSpec(name = "unit", volumes = emptyList(), processes = emptyList(), store = RuntimeStore.CANONICAL_V2,
            ingress = RuntimeIngressPublication("unit", binding.approvedHosts, "0.0.0.0"))
        NamespaceCaddyTransport.checkBinding(binding, spec)
        assertFails { NamespaceCaddyTransport.checkBinding(binding.copy(endpoint = "http://127.0.0.1:2020"), spec) }
        assertFails { NamespaceCaddyTransport.checkBinding(binding.copy(approvedHosts = setOf("other.datamancy.net")), spec) }
        assertFails { NamespaceCaddyTransport.real(spec.copy(store = RuntimeStore.LEGACY), "a".repeat(64)) }
        assertFails { NamespaceCaddyTransport.real(spec, "bad") }
    }
}
