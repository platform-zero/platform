package net.datamancy.platform

import kotlinx.serialization.json.*
import kotlin.test.*

class QualificationNativeContextsTest {
    private val generation = "q-0123456789ab"
    private fun pin(process: String, inputs: Map<String, String> = emptyMap()): GenerationPin {
        val spec = PrivateDeploymentSpec(name = "$generation-v2", volumes = emptyList(),
            processes = listOf(RuntimeProcess(process, "registry.example.invalid/unit@sha256:${"a".repeat(64)}",
                "b".repeat(64), 1000, readiness = listOf("/usr/bin/true"),
                files = inputs.keys.map { RuntimeFile(it, "/run/secrets/$it") })), store = RuntimeStore.CANONICAL_V2)
        return GenerationPin(GenerationMember(spec.name), "c".repeat(64), inputs,
            PrivateDeployment.expectedFingerprint(spec, inputs), spec)
    }

    @Test fun `native target and office backend are derived from exact sealed member`() {
        val pin = pin("seafile-backend")
        val context = QualificationNativeContexts.prepare(generation, pin, "onlyoffice") { error("No credentials needed") }
        assertEquals(generation, context.getValue("targetGeneration").jsonPrimitive.content)
        assertEquals(pin.spec.name, context.getValue("callbackDeploymentName").jsonPrimitive.content)
        assertEquals(pin.spec.processes.single().imageId, context.getValue("backendImageId").jsonPrimitive.content)
        val target = context.getValue("nativeTargets").jsonObject.getValue("onlyoffice").jsonObject
        assertEquals("seafile-backend", target.getValue("processId").jsonPrimitive.content)
        assertEquals(pin.runtimeFingerprint, target.getValue("targetFingerprint").jsonPrimitive.content)
        assertFails { QualificationNativeContexts.prepare("q-aaaaaaaaaaaa", pin, "onlyoffice") }
        assertFails { QualificationNativeContexts.prepare(generation, pin.copy(runtimeFingerprint = "f".repeat(64)), "onlyoffice") }
    }

    @Test fun `alloy target closure includes only its fixed Loki read edge`() {
        val base = pin("alloy")
        val spec = base.spec.copy(processes = base.spec.processes + base.spec.processes.single().copy(id = "loki"))
        val sealed = base.copy(spec = spec, runtimeFingerprint = PrivateDeployment.expectedFingerprint(spec, emptyMap()))
        val targets = QualificationNativeContexts.prepare(generation, sealed, "alloy").getValue("nativeTargets").jsonObject
        assertEquals(setOf("alloy", "loki"), targets.keys)
        assertEquals("loki", targets.getValue("loki").jsonObject.getValue("processId").jsonPrimitive.content)
        assertFails { QualificationNativeContexts.prepare(generation, base, "alloy") }
    }

    @Test fun `node credentials derive from sealed mounted files without exposing secret bytes`() {
        val certificates = PrivateSearchPki.generate("node").filterKeys { it != "node-key.pem" }
        val hashes = certificates.mapValues { ReleaseLocks.sha256(it.value.encodeToByteArray()) }
        val base = pin("node", hashes)
        val node = base.spec.processes.single().copy(files = listOf("ca.pem", "node.pem").map { RuntimeFile(it, "/run/secrets/$it") })
        val prometheus = node.copy(id = "prometheus", files = listOf("admin.pem", "admin-key.pem").map { RuntimeFile(it, "/run/secrets/$it") })
        val spec = base.spec.copy(processes = listOf(node, prometheus))
        val sealed = base.copy(spec = spec, runtimeFingerprint = PrivateDeployment.expectedFingerprint(spec, hashes))
        val context = QualificationNativeContexts.prepare(generation, sealed, "node-exporter") { path ->
            certificates.getValue(path.fileName.toString()).encodeToByteArray()
        }
        val tls = context.getValue("nodeTls").jsonObject
        assertEquals(setOf("caFile", "caSha256", "clientCertFile", "clientCertSha256", "clientKeyFile",
            "clientKeySha256", "serverLeafSha256"), tls.keys)
        assertEquals(hashes.getValue("admin-key.pem"), tls.getValue("clientKeySha256").jsonPrimitive.content)
        assertFalse(context.toString().contains("BEGIN"))
        assertFails { QualificationNativeContexts.prepare(generation, sealed, "node-exporter") { "changed".encodeToByteArray() } }
    }

    @Test fun `caller native field cannot override owner derivation`() {
        val fields = buildJsonObject { put("targetGeneration", generation); put("backendImageId", "b".repeat(64)) }
        assertEquals(fields, QualificationNativeContexts.merge(buildJsonObject {}, fields))
        assertEquals(fields, QualificationNativeContexts.merge(fields, fields))
        assertFails { QualificationNativeContexts.merge(buildJsonObject { put("targetGeneration", "q-aaaaaaaaaaaa") }, fields) }
    }

    @Test fun `native credential metadata rejects changed original bytes before certificate parsing`() {
        val pin = pin("opensearch", mapOf("opensearch-ca.pem" to "f".repeat(64)))
        var reads = 0
        assertFailsWith<IllegalArgumentException> {
            QualificationNativeContexts.prepare(generation, pin, "opensearch") { path ->
                reads++
                assertEquals(PrivateDeployment.BASE.resolve(pin.spec.name).resolve("opensearch-ca.pem"), path)
                "synthetic changed bytes".encodeToByteArray()
            }
        }
        assertEquals(1, reads)
    }
}
