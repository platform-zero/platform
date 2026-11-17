package net.datamancy.platform

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

class NativeQualificationClientTest {
    private val sha = "a".repeat(64)
    private val fixture = NativeLogFixture("obs-abcdef012345", 1_730_000_000_000_000_000L, sha)
    private val query = "/loki/api/v1/query_range?query=%7Bjob%3D%22p0v3-acceptance%22%2Crun%3D%22obs-abcdef012345%22%7D" +
        "&start=1729999999000000000&end=1730000005000000000&limit=10"
    private val read = NativeQualificationRequest("nq-0123456789ab", "q-0123456789ab",
        "q-0123456789ab-canonical-release-v2", sha, "case-alloy-original", "/private/case", sha, sha,
        "RESTORE", "alloy", "loki", "GET", query, "POSITIVE",
        responseFile = "/private/response", sourceStoppedProofSha256 = sha,
        sourceStopped = ActivationInput("/private/bridge-result.json", sha))

    @Test fun `private provider in composed public Caddy plus LiveKit remains isolated on owned net`(): Unit {
        val pinned = "example.invalid/owned@sha256:$sha"
        fun process(id: String, networks: List<String>, uid: Int = 10001): RuntimeProcess =
            RuntimeProcess(id, pinned, sha, uid, networks = networks)
        val processes = listOf(process("caddy", listOf("ingress-control", "ingress-egress", "observability-web")),
            process("livekit", listOf("qualification-web")),
            process("node", listOf("observability-net")),
            process("alloy", listOf("observability-net")),
            process("loki", listOf("observability-net")),
            process("grafana", listOf("observability-net", "observability-web")))
        val composed = PrivateDeploymentSpec(name = "q-0123456789ab-canonical-release-v2",
            store = RuntimeStore.CANONICAL_V2, volumes = emptyList(), processes = processes,
            networks = listOf("ingress-control", "ingress-egress", "observability-net",
                "observability-web", "qualification-web"),
            ingress = RuntimeIngressPublication("site", setOf("start.datamancy.net"), "192.0.2.1"),
            nativeIngress = RuntimeNativeIngressPublication("site", listenAddress = "192.0.2.1"))
        assertEquals("alloy", nativePrivateProviderProcess(composed, "alloy").id)
        assertFailsWith<IllegalArgumentException> { nativePrivateProviderProcess(composed, "caddy") }
        assertFailsWith<IllegalArgumentException> { nativePrivateProviderProcess(composed.copy(
            processes = processes.map { if (it.id == "alloy") it.copy(networks = listOf("net")) else it }), "alloy") }
        assertFailsWith<IllegalArgumentException> { nativePrivateProviderProcess(composed.copy(
            processes = processes + process("foreign-app", listOf("observability-net"))), "loki") }
        assertFailsWith<IllegalArgumentException> { nativePrivateProviderProcess(composed.copy(
            processes = processes.map { if (it.id == "node") it.copy(userId = 0) else it }), "node") }
    }

    @Test fun `fixed original Loki run and timestamp prevent arbitrary selectors and RESTORE mutations`(): Unit {
        assertEquals(3100, nativeQualifiedPath(read, fixture))
        assertFailsWith<IllegalArgumentException> { nativeQualifiedPath(read.copy(path = "$query&extra=1"), fixture) }
        assertFailsWith<IllegalArgumentException> { nativeQualifiedPath(read, fixture.copy(stamp = fixture.stamp + 1)) }
        assertFailsWith<IllegalArgumentException> { nativeQualifiedPath(read.copy(method = "POST", body = ActivationInput("/private/log", sha)), fixture) }
        assertFailsWith<IllegalArgumentException> { nativeQualifiedPath(read.copy(processId = "alloy"), fixture) }
        assertFailsWith<IllegalArgumentException> { nativeQualifiedPath(read.copy(serviceId = "grafana"), fixture) }
        assertFailsWith<IllegalArgumentException> { nativeQualifiedPath(read.copy(authorizationMode = "BASIC"), fixture) }
    }

    @Test fun `only original Alloy INSTALL POST and node exporter mTLS are local native capabilities`(): Unit {
        val post = read.copy(phase = "INSTALL", processId = "alloy", method = "POST", path = "/loki/api/v1/push",
            body = ActivationInput("/private/original-log.json", sha), sourceStopped = null,
            sourceStoppedProofSha256 = null)
        assertEquals(3500, nativeQualifiedPath(post, fixture))
        assertFailsWith<IllegalArgumentException> { nativeQualifiedPath(post.copy(phase = "RESTORE"), fixture) }
        val node = post.copy(serviceId = "node-exporter", processId = "node", method = "GET",
            path = "/metrics", body = null, ca = ActivationInput("/private/ca", sha),
            clientCert = ActivationInput("/private/original-client", sha),
            clientKey = ActivationInput("/private/original-key", sha), originalLeafSha256 = sha)
        assertEquals(9100, nativeQualifiedPath(node, null))
        assertEquals(9100, nativeQualifiedPath(node.copy(assertion = "TLS_CLIENT_DENIAL",
            clientCert = null, clientKey = null), null))
        assertFailsWith<IllegalArgumentException> { nativeQualifiedPath(node.copy(assertion = "TLS_CLIENT_DENIAL"), null) }
        assertFailsWith<IllegalArgumentException> { nativeQualifiedPath(node.copy(ca = null), null) }
        assertFailsWith<IllegalArgumentException> { nativeQualifiedPath(node.copy(method = "POST"), null) }
    }

    @Test fun `fixed OpenSearch native original document forbids RESTORE mutation and arbitrary roles`(): Unit {
        val original = buildJsonObject {
            put("privateText", "a12-original-native-search-case-original")
            put("sourceGeneration", "q-0123456789ab")
            put("version", 1)
        }
        val binding = NativeQualificationCaseBinding("q-0123456789ab", "case-original", "/private/case",
            sha, sha, "opensearch", "INSTALL", "q-0123456789ab-opensearch", sha)
        val file = ActivationInput("/private/original.pem", sha)
        val write = OpenSearchNativeQualificationRequest("nq-0123456789ab", binding,
            "ADMIN", "CREATE", file, file, file, file, file, sha, sha,
            ActivationInput("/private/original-document", sha), responseFile = "/private/response")
        assertEquals("PUT", openSearchNativeFixedOperation(write, original).method)
        assertEquals("/p0v3-private-history/_doc/original-private-event?op_type=create&refresh=wait_for",
            openSearchNativeFixedOperation(write, original).path)
        val restored = write.copy(binding = binding.copy(phase = "RESTORE", generationId = "q-abcdef012345"),
            action = "DOCUMENT", body = null)
        assertEquals("GET", openSearchNativeFixedOperation(restored, original).method)
        assertEquals("GET", openSearchNativeFixedOperation(restored.copy(action = "HISTORY"), original).method)
        assertEquals("GET", openSearchNativeFixedOperation(restored.copy(action = "DENY", role = "NODE"), original).method)
        assertFailsWith<IllegalArgumentException> { openSearchNativeFixedOperation(restored.copy(action = "CREATE"), original) }
        assertFailsWith<IllegalArgumentException> { openSearchNativeFixedOperation(restored.copy(action = "DENY"), original) }
        assertFailsWith<IllegalArgumentException> { openSearchNativeFixedOperation(restored.copy(action = "HISTORY", role = "NODE"), original) }
        assertFailsWith<IllegalArgumentException> { openSearchNativeFixedOperation(write.copy(binding = binding.copy(serviceId = "huly")), original) }
        assertFailsWith<IllegalArgumentException> { openSearchNativeFixedOperation(write.copy(operation = "foreign"), original) }
        assertFailsWith<IllegalArgumentException> { openSearchNativeFixedOperation(write,
            buildJsonObject { put("privateText", "other"); put("sourceGeneration", "q-0123456789ab"); put("version", 1) }) }
    }
}
