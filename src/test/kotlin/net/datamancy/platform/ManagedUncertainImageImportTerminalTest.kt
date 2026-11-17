package net.datamancy.platform

import kotlin.test.Test
import kotlin.test.assertFailsWith

class ManagedUncertainImageImportTerminalTest {
    @Test fun `new terminal refuses a caller-composed ACK or disposition path`() {
        assertFailsWith<IllegalArgumentException> {
            ManagedUncertainImageImportTerminal.verify(ActivationInput(
                "/mnt/media/p0-v3/release-generations/q-dd36ebcf43ef/failed-pre-unit-stage-v1.disposition.json",
                "0".repeat(64)))
        }
        assertFailsWith<IllegalArgumentException> {
            ManagedUncertainImageImportTerminal.verify(ActivationInput(
                "/mnt/media/p0-v3/release-generations/q-4d3c1cb287e5/uncertain-native-worklane-import-v1.result.json",
                "0".repeat(64)))
        }
    }
}
