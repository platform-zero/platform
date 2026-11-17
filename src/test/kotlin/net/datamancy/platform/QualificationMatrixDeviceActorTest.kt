package net.datamancy.platform

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class QualificationMatrixDeviceActorTest {
    @Test fun `only exactly one genuinely new issuer ID can be selected`() {
        val before = setOf("ORIGINAL01", "READER002")
        assertEquals("ANDROID03", QualificationMatrixDeviceActor.oneNew(before,
            before + "ANDROID03"))
        for (after in listOf(before, before + setOf("NEW00001", "NEW00002"),
            setOf("READER002", "ANDROID03"), before + "lowercase", emptySet())) {
            assertThrows(IllegalArgumentException::class.java) {
                QualificationMatrixDeviceActor.oneNew(before, after)
            }
        }
    }
}
