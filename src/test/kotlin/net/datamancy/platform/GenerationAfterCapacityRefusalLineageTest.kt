package net.datamancy.platform

import kotlin.test.Test
import kotlin.test.assertFailsWith

class GenerationAfterCapacityRefusalLineageTest {
    @Test fun `qc3 pre-native refusal and q4d uncertain import must both retain typed exact predecessor pointers`() {
        GenerationAfterCapacityRefusalLineage.verify(GenerationAfterCapacityRefusalLineage.qc3,
            GenerationAfterNativeImportLineage.terminal,GenerationAfterNativeImportLineage.probe)
        assertFailsWith<IllegalArgumentException> {
            GenerationAfterCapacityRefusalLineage.verify(
                ActivationInput(GenerationAfterCapacityRefusalLineage.qc3.path,"0".repeat(64)),
                GenerationAfterNativeImportLineage.terminal,GenerationAfterNativeImportLineage.probe)
        }
        assertFailsWith<IllegalArgumentException> {
            GenerationAfterCapacityRefusalLineage.verify(GenerationAfterCapacityRefusalLineage.qc3,
                ActivationInput(GenerationAfterNativeImportLineage.terminal.path,"0".repeat(64)),
                GenerationAfterNativeImportLineage.probe)
        }
    }
}
