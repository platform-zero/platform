package net.datamancy.platform

import java.nio.file.Files
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import kotlin.test.*

class QualificationObservabilityActorTest {
    private val invocation = "case-00000000-0000-0000-0000-000000000001"
    private val json = Json { encodeDefaults = true }
    private fun request(action: String, attempt: Int? = null) = buildJsonObject {
        put("action", action); attempt?.let { put("attempt", it) }
    }

    @Test fun `fixed actions preserve original IDs and reject wider authority and restore append`() {
        val cases = listOf(Triple("alloy", "APPEND_LOG", "owned-source-log-push"),
            Triple("alloy", "DENY_NETWORK", "foreign-source-denial"),
            Triple("loki", "READ_LOG", "original-stream-readback"),
            Triple("loki", "DENY_NETWORK", "unprivileged-network-denial"),
            Triple("node-exporter", "SCRAPE", "original-textfile-scrape"),
            Triple("node-exporter", "DENY_MTLS", "foreign-client-mtls-denial"))
        for ((service, action, tag) in cases) {
            val operation = QualificationObservabilityActor.operation(invocation, service, "INSTALL", request(action))
            assertEquals("nq-" + ReleaseLocks.sha256("$invocation\n$service\n$tag".encodeToByteArray()).take(12), operation.id)
            if (action != "APPEND_LOG") assertEquals(operation,
                QualificationObservabilityActor.operation(invocation, service, "RESTORE", request(action)))
            for (field in listOf("url", "path", "body", "operation", "target", "credential", "attempt"))
                assertFails { QualificationObservabilityActor.operation(invocation, service, "INSTALL",
                    JsonObject(request(action) + (field to JsonPrimitive("foreign")))) }
        }
        assertFails { QualificationObservabilityActor.operation(invocation, "alloy", "RESTORE", request("APPEND_LOG")) }
        assertFails { QualificationObservabilityActor.operation(invocation, "grafana", "INSTALL", request("SCRAPE")) }
        assertFails { QualificationObservabilityActor.operation(invocation, "node-exporter", "INSTALL", request("APPEND_LOG")) }
        assertFails { QualificationObservabilityActor.operation("../escape", "loki", "INSTALL", request("READ_LOG")) }
        val ids = (0..7).map { attempt ->
            QualificationObservabilityActor.operation(invocation, "alloy", "INSTALL", request("READ_LOG", attempt)).id
        }
        assertEquals(8, ids.toSet().size)
        for (attempt in listOf(-1, 8)) assertFails {
            QualificationObservabilityActor.operation(invocation, "alloy", "INSTALL", request("READ_LOG", attempt))
        }
        for (bad in listOf(JsonPrimitive("0"), JsonPrimitive(true), JsonPrimitive(0.5))) assertFails {
            QualificationObservabilityActor.operation(invocation, "alloy", "INSTALL",
                JsonObject(request("READ_LOG") + ("attempt" to bad)))
        }
    }

    @Test fun `append reconstructs exact original sorted bytes and never reseeds timestamp`() {
        val run = "obs-" + ReleaseLocks.sha256(invocation.encodeToByteArray()).take(12)
        val stamp = 123456789012345678L
        val raw = "{\"streams\":[{\"stream\":{\"job\":\"p0v3-acceptance\",\"run\":\"$run\"},\"values\":[[\"$stamp\",\"P0 private original Alloy log $run\"]]}]}".encodeToByteArray()
        val intent = buildJsonObject {
            put("schemaVersion", 1); put("run", run); put("stamp", stamp); put("bodySha256", ReleaseLocks.sha256(raw))
        }
        assertContentEquals(raw, QualificationObservabilityActor.appendBody(invocation, intent))
        for ((key, value) in listOf("stamp" to JsonPrimitive(stamp + 1), "run" to JsonPrimitive("obs-aaaaaaaaaaaa"),
            "bodySha256" to JsonPrimitive("f".repeat(64)), "foreign" to JsonPrimitive(true))) assertFails {
            QualificationObservabilityActor.appendBody(invocation, JsonObject(intent + (key to value)))
        }
        assertFails { QualificationObservabilityActor.query(run, Long.MAX_VALUE) }
        assertFails { QualificationObservabilityActor.query("$run&limit=999", stamp) }
    }

    @Test fun `next readback requires original acknowledged empty response not missing lost or populated result`() {
        val home = Files.createTempDirectory("observability-actor-unit-")
        try {
            val binding = NativeQualificationCaseBinding("q-0123456789ab", invocation, "/unit/case", "a".repeat(64),
                "b".repeat(64), "alloy", "INSTALL", "q-0123456789ab-v2", "c".repeat(64))
            val first = QualificationObservabilityActor.operation(invocation, "alloy", "INSTALL", request("READ_LOG", 0))
            val next = QualificationObservabilityActor.operation(invocation, "alloy", "INSTALL", request("READ_LOG", 1))
            val path = QualificationObservabilityActor.query("obs-0123456789ab", 123456789012345678L)
            QualificationObservabilityActor.requireEmptyPrevious(binding, first, home, path)
            assertFails { QualificationObservabilityActor.requireEmptyPrevious(binding, next, home, path) }
            val native = NativeQualificationRequest(first.id, binding.generationId, binding.targetMemberName,
                binding.targetFingerprint, invocation, binding.caseDirectory, binding.caseIntentSha256,
                binding.caseClaimSha256, "INSTALL", "alloy", "loki", "GET", path, "POSITIVE",
                responseFile = home.resolve("${first.id}.response").toString())
            val raw = json.encodeToString(native).encodeToByteArray()
            ReleasePrivateFiles.save(home.resolve("${first.id}.request.json"), raw)
            assertFails { QualificationObservabilityActor.requireEmptyPrevious(binding, next, home, path) }
            fun evidence(response: String, status: Int = 200) {
                // Synthetic UNIT originals only; replace local fixtures to exercise refusal readers.
                Files.deleteIfExists(home.resolve("${first.id}.response"))
                Files.deleteIfExists(home.resolve("${first.id}.result.json"))
                val bytes = response.encodeToByteArray()
                ReleasePrivateFiles.save(home.resolve("${first.id}.response"), bytes)
                val result = NativeQualificationResult(first.id, invocation, binding.caseClaimSha256,
                    binding.targetFingerprint, "alloy", "loki", "d".repeat(64), 123, 456, 789,
                    ReleaseLocks.sha256(raw), status, "HTTP", null, native.responseFile, ReleaseLocks.sha256(bytes))
                ReleasePrivateFiles.save(home.resolve("${first.id}.result.json"), json.encodeToString(result).encodeToByteArray())
            }
            val empty = "{\"status\":\"success\",\"data\":{\"resultType\":\"streams\",\"result\":[]}}"
            evidence(empty)
            QualificationObservabilityActor.requireEmptyPrevious(binding, next, home, path)
            assertFails { QualificationObservabilityActor.requireEmptyPrevious(binding, next, home, "$path&foreign=1") }
            evidence(empty, 503)
            assertFails { QualificationObservabilityActor.requireEmptyPrevious(binding, next, home, path) }
            evidence(empty.replace("[]", "[{\"values\":[[\"123\",\"present\"]]}]"))
            assertFails { QualificationObservabilityActor.requireEmptyPrevious(binding, next, home, path) }
            evidence("{\"status\":\"error\"}")
            assertFails { QualificationObservabilityActor.requireEmptyPrevious(binding, next, home, path) }
        } finally { Files.walk(home).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}
