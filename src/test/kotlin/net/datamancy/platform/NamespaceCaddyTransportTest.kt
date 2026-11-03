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
