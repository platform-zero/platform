package net.datamancy.platform

import kotlin.test.Test
import kotlin.test.assertFailsWith

class Qc3PreparedNoStartTerminalTest {
    @Test fun `caller cannot synthesize a terminal or borrow q5712 or q4d disposition`() {
        assertFailsWith<IllegalArgumentException> {
            Qc3PreparedNoStartTerminal.verify(ActivationInput(
                "/mnt/media/p0-v3/release-generations/q-4d3c1cb287e5/uncertain-native-worklane-import-v1.disposition.json",
                GenerationAfterNativeImportLineage.terminalSha))
        }
        assertFailsWith<IllegalArgumentException> {
            Qc3PreparedNoStartTerminal.verify(ActivationInput(
                "/mnt/media/p0-v3/release-generations/q-c3a7a9e29391/stage.result.json",
                "0".repeat(64)))
        }
    }
}
