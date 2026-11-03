package net.datamancy.platform

import kotlin.test.*

class RuntimeLockBudgetTest {
    private fun commands(free: String, root: String = PrivateRootfulCommands.ROOT, exit: Int = 0) = RuntimeCommands {
        assertEquals(listOf("info", "--format", "json"), it)
        RuntimeCommandResult(exit, """{"store":{"graphRoot":"$root","runRoot":"${PrivateRootfulCommands.RUN}"},"host":{"freeLocks":$free}}""")
    }
    @Test fun `exact dedicated store free-lock observation fails closed`() {
        assertEquals(0L, RuntimeLockBudget.available(commands("0")))
        assertEquals(2048L, RuntimeLockBudget.available(commands("2048")))
        for (invalid in listOf("-1", "null", "\"not-a-number\"", "\"2048\"", "2147483648")) assertFails { RuntimeLockBudget.available(commands(invalid)) }
        assertFails { RuntimeLockBudget.available(commands("20", root = "/var/lib/containers/storage")) }
        assertFails { RuntimeLockBudget.available(commands("20", exit = 1)) }
    }
    @Test fun `stopped retained objects consume capacity and transient helper headroom is never waived`() {
        RuntimeLockBudget.requireAvailable(4)
        assertFails { RuntimeLockBudget.requireAvailable(3) }
        RuntimeLockBudget.requireAvailable(7, workers = 3)
        assertFails { RuntimeLockBudget.requireAvailable(6, workers = 3) }
        assertFails { RuntimeLockBudget.requireAvailable(100, workers = 4) }
        val spec = PrivateDeploymentSpec(name = "unit", volumes = listOf(RuntimeVolume("data", 1000)),
            processes = listOf(RuntimeProcess("daemon", "example.test/app@sha256:" + "a".repeat(64), "b".repeat(64), 1000)))
        RuntimeLockBudget.requireAvailable(8, listOf(spec), workers = 2)
        val denied = assertFailsWith<InsufficientRuntimeLocks> { RuntimeLockBudget.requireAvailable(7, listOf(spec), workers = 2) }
        assertEquals(7L, denied.available); assertEquals(8L, denied.required)
        assertFails { RuntimeLockBudget.requireAvailable(-1) }
    }
}
