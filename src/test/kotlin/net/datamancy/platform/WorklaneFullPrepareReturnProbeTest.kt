package net.datamancy.platform

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class WorklaneFullPrepareReturnProbeTest {
    @Test fun exactProductionPrepareReturnAndFreshNativeAttestationAreNotGenerationAcks() {
        val pin=GenerationAfterQ583Lineage.isolatedFullPrepare
        val result=WorklaneFullPrepareReturnProbe.verifyLive(pin)
        assertEquals("absent",result.worklaneState)
        assertEquals(0,result.nativeContainers)
        assertTrue(result.productionBackendAttested && result.brokerSocketAbsent)
        assertTrue(result.graphAllocatedBytes>=4294967296L && result.graphEntries>180000)
        assertFalse(result.originalGenerationImportAcknowledged)
        assertFalse(result.applicationStarted)
        assertFalse(result.qualificationEvidence)
    }
}
