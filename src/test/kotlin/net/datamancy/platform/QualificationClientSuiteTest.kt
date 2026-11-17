package net.datamancy.platform

import kotlinx.serialization.json.*
import kotlin.test.*

class QualificationClientSuiteTest {
    private val runner = "scripts/qualified-runner.py"
    private val adapter = "runners/grafana-native.py"
    private val helper = "runners/native_control.py"
    private val row = buildJsonObject {
        put("serviceId", "grafana"); put("surface", "HEADLESS")
        put("variant", "NATIVE"); put("journey", "workflow")
        put("runner", runner); put("adapter", adapter)
        put("runnerFiles", buildJsonArray { add(helper) })
    }
    private val manifest = buildJsonObject {
        put("schemaVersion", 2); put("cases", buildJsonArray { add(row) })
    }.toString().encodeToByteArray()
    private val manifestSha = ReleaseLocks.sha256(manifest)
    private val hashes = mapOf(runner to "a".repeat(64), adapter to "b".repeat(64), helper to "c".repeat(64))
    private val definition = buildJsonObject {
        put("inventorySha256", "d".repeat(64)); put("manifestSha256", manifestSha)
        put("runnerHashes", JsonObject(hashes.toSortedMap().mapValues { JsonPrimitive(it.value) }))
        put("requirementsSha256", "e".repeat(64))
    }.toString().encodeToByteArray()
    private val closure = QualificationClientSuite(
        ActivationInput("/private/phase-trial-install.definition-v2.json", ReleaseLocks.sha256(definition)),
        manifestSha, hashes + ("cases/manifest.json" to manifestSha))
    private val intent = JsonObject(row + mapOf(
        "inventorySha256" to JsonPrimitive("d".repeat(64)),
        "manifestSha256" to JsonPrimitive(manifestSha),
        "runnerSha256" to JsonPrimitive(hashes.getValue(runner)),
        "binding" to buildJsonObject {
            put("candidate", buildJsonObject { put("acceptanceSha256", closure.definition.sha256) })
        }))

    @Test fun `candidate preimage permits only the selected exact transitive source closure`() {
        assertEquals(row, QualificationClientSuites.verifyDefinition(closure, intent, definition, manifest))
        for (changed in listOf(
            closure.copy(files = closure.files - helper),
            closure.copy(files = closure.files + ("runners/foreign.py" to "f".repeat(64))),
            closure.copy(files = closure.files + (adapter to "f".repeat(64))),
            closure.copy(manifestSha256 = "f".repeat(64)),
            closure.copy(definition = closure.definition.copy(sha256 = "f".repeat(64))))) {
            assertFails { QualificationClientSuites.verifyDefinition(changed, intent, definition, manifest) }
        }
        assertFails { QualificationClientSuites.verifyDefinition(closure, intent, definition + byteArrayOf(10), manifest) }
        assertFails { QualificationClientSuites.verifyDefinition(closure, intent, definition, manifest + byteArrayOf(10)) }
    }

    @Test fun `changed case selection inventory or runner cannot inherit another projection`() {
        for ((field, value) in listOf("serviceId" to "loki", "surface" to "WEB", "variant" to "BROWSER",
            "journey" to "foreign", "inventorySha256" to "f".repeat(64), "runnerSha256" to "f".repeat(64))) {
            assertFails { QualificationClientSuites.verifyDefinition(closure,
                JsonObject(intent + (field to JsonPrimitive(value))), definition, manifest) }
        }
    }

    @Test fun `projection filenames cannot grant traversal checkout or secret mounts`() {
        assertEquals(setOf(runner, adapter, helper), QualificationClientSuites.files(row))
        for (name in listOf("/etc/passwd", "runners/../secret", "runners/./helper.py", "runners//helper.py",
            "../runners/helper.py", "credentials/token", "scripts/")) {
            assertFails { QualificationClientSuites.files(JsonObject(row + ("adapter" to JsonPrimitive(name)))) }
        }
        val invocation = "case-00000000-0000-0000-0000-000000000001"
        assertEquals(GenerationRuntime.BASE.resolve("q-0123456789ab/qualification-client-suites/$invocation"),
            QualificationClientSuites.destination("q-0123456789ab", invocation))
        assertFails { QualificationClientSuites.destination("../foreign", invocation) }
        assertFails { QualificationClientSuites.destination("q-0123456789ab", "case-../foreign") }
    }
}
