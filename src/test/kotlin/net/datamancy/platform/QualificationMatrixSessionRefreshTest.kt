package net.datamancy.platform

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails

/** Pure ordinal/owner-lineage faults. Core alone runs these and the real MAS/native tests. */
class QualificationMatrixSessionRefreshTest {
    private val original = "case-00000000-0000-0000-0000-000000000001"
    private val next = "case-00000000-0000-0000-0000-000000000002"

    @Test fun `eight cases consume one continuous rotating credential without shared refresh reuse`() {
        val issued = QualificationMatrixSessionRefresh
        var prior: String? = null
        for (case in 1..8) {
            val actor = "case-00000000-0000-0000-0000-%012d".format(case)
            for (step in 1..4) {
                val ordinal = (case - 1) * 4 + step
                assertEquals(ordinal,issued.nextOrdinal(ordinal - 1,prior,actor,step))
                prior = actor
            }
        }
        assertFails { issued.nextOrdinal(32,prior,"case-00000000-0000-0000-0000-000000000009",1) }
    }

    @Test fun `partial previous case and foreign same-case actor cannot begin another group`() {
        val issued = QualificationMatrixSessionRefresh
        assertFails { issued.nextOrdinal(0,original,original,1) }
        assertFails { issued.nextOrdinal(0,null,original,2) }
        assertFails { issued.nextOrdinal(1,original,next,2) }
        assertFails { issued.nextOrdinal(3,original,next,1) }
        assertFails { issued.nextOrdinal(4,original,original,1) }
        assertFails { issued.nextOrdinal(4,original,next,2) }
        assertEquals(5,issued.nextOrdinal(4,original,next,1))
        assertFails { issued.nextOrdinal(5,next,original,2) }
    }
}
