package net.datamancy.platform

import kotlin.test.Test
import kotlin.test.assertEquals

class RuntimeQuadletReadinessBudgetTest {
    @Test fun `only first-use Grafana keeps its exact HTTP barrier through bounded migrations`() {
        val spec = FragmentAssemblyFixture.plan().specs.single()
        val process = spec.processes.single { it.id == "forgejo" }
        assertEquals(90L, quadletReadinessBudgetSeconds(process))
        assertEquals(300L, quadletReadinessBudgetSeconds(process.copy(id = "grafana")))
    }
}
