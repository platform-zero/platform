package net.datamancy.platform

import kotlin.test.Test
import kotlin.test.assertFailsWith

class GenerationAfterNativeImportLineageTest {
    @Test fun `fresh successor refuses fake terminal or borrowed probe receipt`() {
        assertFailsWith<IllegalArgumentException> {
            GenerationAfterNativeImportLineage.verify(GenerationAfterNativeImportLineage.terminal,
                ActivationInput(GenerationAfterNativeImportLineage.probe.path,"0".repeat(64)))
        }
        assertFailsWith<IllegalArgumentException> {
            GenerationAfterNativeImportLineage.verify(
                ActivationInput(GenerationAfterNativeImportLineage.terminal.path,"0".repeat(64)),
                GenerationAfterNativeImportLineage.probe)
        }
    }
    @Test fun `actual typed terminal and independent scratch receipt are source evidence only`() {
        GenerationAfterNativeImportLineage.verify(GenerationAfterNativeImportLineage.terminal,
            GenerationAfterNativeImportLineage.probe)
    }
}
