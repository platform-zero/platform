package net.datamancy.platform

import org.junit.jupiter.api.Assertions.assertEquals
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class QualificationMatrixActorTest {
    private val owner = "00000000-0000-4000-8000-000000000001"
    private val reader = "00000000-0000-4000-8000-000000000002"
    private val ownerUpstream = "00000000-0000-4000-8000-000000000003"
    private val readerUpstream = "00000000-0000-4000-8000-000000000004"
    private val issuer = QualificationMatrixActor.fixedProviderUuid()
    private fun rows(firstIssuer: String = issuer, readerSubject: String = reader,
        extra: String = "") = "owner\t$ownerUpstream\t$owner\t$firstIssuer\tf\n" +
        "reader\t$readerUpstream\t$readerSubject\t$issuer\tf\n" + extra

    @Test fun `exact two selected native MAS links only`() {
        val readback = QualificationMatrixActor.parseMasLinks(rows())
        assertEquals(setOf("owner", "reader"), readback.keys)
        assertEquals(reader, readback.getValue("reader").jsonObject.getValue("nativeSubject").jsonPrimitive.content)
    }

    @Test fun `rejects changed provider duplicated principal and extra row`() {
        for (bad in listOf(rows(firstIssuer = "00000000-0000-4000-8000-000000000099"),
            rows(extra = "third\t$owner\t$reader\t$issuer\tf\n"),
            rows(readerSubject = owner), rows().replace("reader\t", "owner\t"),
            rows().replace("\tf\n", "\tt\n"), rows().replace(owner, "not-a-uuid"))) {
            assertThrows(IllegalArgumentException::class.java) { QualificationMatrixActor.parseMasLinks(bad) }
        }
    }
}
