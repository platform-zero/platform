package net.datamancy.platform

import kotlinx.serialization.json.*
import kotlin.test.*

class QualificationHubCaseInputsTest {
    private val generation = "q-012345abcdef"
    private val credentials = mapOf("alice" to "a".repeat(64), "bob" to "b".repeat(64),
        "outsider" to "c".repeat(64))
    private fun settings(generation: String = this.generation, accounts: Map<String,String> = credentials,
        servers: Set<String> = setOf("alice","bob")): ByteArray = buildJsonObject {
        put("notebookGeneration",generation)
        put("passwords",JsonObject(accounts.mapValues { JsonPrimitive(it.value) }))
        put("servers",buildJsonObject { servers.forEach { put(it,buildJsonObject {
            put("parentControlKey","d".repeat(64)) }) } })
        put("proxyToken","e".repeat(64))
    }.toString().encodeToByteArray()

    @Test fun `selected sealed settings expose only scoped passwords`() {
        val bytes = settings()
        assertEquals(credentials,QualificationHubCaseInputs.passwords(bytes,
            ReleaseLocks.sha256(bytes),generation))
        assertTrue(QualificationHubCaseInputs.passwords(bytes,
            ReleaseLocks.sha256(bytes),generation).values.none { it == "e".repeat(64) })
    }

    @Test fun `changed source bytes and generation cannot authorize identities`() {
        val bytes = settings()
        val digest = ReleaseLocks.sha256(bytes)
        assertFails { QualificationHubCaseInputs.passwords(settings(accounts = credentials +
            ("alice" to "f".repeat(64))),digest,generation) }
        assertFails { QualificationHubCaseInputs.passwords(bytes,digest,"q-fedcba987654") }
        assertFails { QualificationHubCaseInputs.passwords(bytes,"f".repeat(64),generation) }
    }

    @Test fun `incomplete foreign or duplicated roles fail before projection`() {
        for (foreign in listOf(credentials - "outsider", credentials + ("admin" to "f".repeat(64)),
            credentials + ("bob" to credentials.getValue("alice")),
            credentials + ("alice" to "not-a-selected-password"))) {
            val bytes = settings(accounts = foreign)
            assertFails { QualificationHubCaseInputs.passwords(bytes,ReleaseLocks.sha256(bytes),generation) }
        }
        val missing = settings(servers = setOf("alice"))
        assertFails { QualificationHubCaseInputs.passwords(missing,ReleaseLocks.sha256(missing),generation) }
    }
}
