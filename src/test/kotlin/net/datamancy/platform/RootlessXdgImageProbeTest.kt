package net.datamancy.platform

import kotlin.test.Test
import kotlin.test.assertFailsWith

class RootlessXdgImageProbeTest {
    @Test fun `isolated probe refuses historical or caller selected release identity before any effect`() {
        for (generation in listOf("q-dd36ebcf43ef", "q-4d3c1cb287e5", "../../other", "q-000000000000")) {
            assertFailsWith<IllegalArgumentException> { RootlessXdgImageProbe.issue(generation) }
        }
    }
}
