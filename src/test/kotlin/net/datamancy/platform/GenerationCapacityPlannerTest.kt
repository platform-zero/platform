package net.datamancy.platform

import kotlin.test.*

class GenerationCapacityPlannerTest {
    private fun process(id: String, memory: Int, oneShot: Boolean = false, dependencies: List<String> = emptyList()) =
        RuntimeProcess(id, "example.test/unit@sha256:" + "a".repeat(64), "b".repeat(64), 1000,
            memoryMiB = memory, oneShot = oneShot, dependencies = dependencies,
            readiness = if (oneShot) emptyList() else listOf("true"))
    private fun spec(name: String = "unit") = PrivateDeploymentSpec(name = name, volumes = emptyList(), processes = listOf(
        process("init", 2048, true), process("service", 512, dependencies = listOf("init")),
        process("migration", 1024, true, listOf("service")), process("frontend", 256, dependencies = listOf("migration"))))

    @Test fun `serial initialization peak does not sum nonoverlapping workers or weaken daemon limits`() {
        val plan = GenerationCapacityPlanner.plan(listOf(spec()), 1024)
        assertEquals(2048L, plan.install.memoryMiB)
        assertEquals(768L, plan.steady.memoryMiB)
        assertEquals(listOf(2048L, 512L, 1536L, 768L), plan.startup.map { it.memoryMiB })
        assertEquals(GenerationResources(0, 1024, 4), plan.stopped)
        assertEquals(listOf(true, false, true, false), plan.startup.map { it.oneShot })
        val two = GenerationCapacityPlanner.plan(listOf(spec(), spec("next")), 2048)
        assertEquals(2816L, two.install.memoryMiB)
        assertEquals(1536L, two.steady.memoryMiB)
        assertEquals(8L, two.stopped.objectLocks)
    }

    @Test fun `working envelope and independent hard ceilings stay separate under serialized startup`() {
        val selected = spec()
        val budget = GenerationWorkingBudget(ActivationInput("/tmp/evidence", "a".repeat(64)), mapOf(
            "unit/init" to 512L, "unit/service" to 256L,
            "unit/migration" to 512L, "unit/frontend" to 128L))
        val plan = GenerationCapacityPlanner.plan(listOf(selected),1024,budget)
        assertEquals(768L,plan.install.memoryMiB)
        assertEquals(384L,plan.steady.memoryMiB)
        assertEquals(768L,plan.steadyHardCeilingsMiB)
        assertEquals(listOf(512L,256L,768L,384L),plan.startup.map { it.memoryMiB })
        val reservation = GenerationCapacityPlanner.phase(plan,GenerationPhase.INSTALL)
        GenerationCapacityPlanner.admit(reservation,768+16384,1024+10240,
            plan.stopped.objectLocks+RuntimeLockBudget.TRANSIENT_HEADROOM)
        assertFails { GenerationCapacityPlanner.plan(listOf(selected),1024,budget.copy(
            workingMiB = budget.workingMiB - "unit/frontend")) }
        assertFails { GenerationCapacityPlanner.plan(listOf(selected),1024,budget.copy(
            workingMiB = budget.workingMiB + ("unit/service" to 513L))) }
        assertFails { GenerationCapacityPlanner.plan(listOf(selected),1024,budget.copy(
            workingMiB = budget.workingMiB + ("unit/other" to 128L))) }
    }

    @Test fun `fresh first start admits one unchanged next ceiling not a phantom already resident stack`() {
        val selected = spec()
        val preliminary = GenerationWorkingBudget(ActivationInput("/tmp/evidence", "a".repeat(64)),
            mapOf("unit/init" to 512L, "unit/service" to 256L,
                "unit/migration" to 512L, "unit/frontend" to 128L),
            scope = "r9-full-private-incremental-first-start")
        val plan = GenerationCapacityPlanner.plan(listOf(selected), 1024, preliminary)
        assertTrue(plan.incrementalFirstStart)
        assertEquals(2560L, plan.install.memoryMiB)
        assertEquals(384L, plan.steady.memoryMiB)
        assertEquals(768L, plan.steadyHardCeilingsMiB)
        val reservation = GenerationCapacityPlanner.phase(plan, GenerationPhase.INSTALL)
        GenerationCapacityPlanner.admit(reservation, 2560 + 16384, 1024 + 10240,
            reservation.resources.objectLocks + RuntimeLockBudget.TRANSIENT_HEADROOM)
        assertFails { GenerationCapacityPlanner.admit(reservation, 2560 + 16383, 1024 + 10240,
            reservation.resources.objectLocks + RuntimeLockBudget.TRANSIENT_HEADROOM) }
        for (phase in GenerationPhase.entries.filter { it != GenerationPhase.INSTALL })
            assertFails { GenerationCapacityPlanner.phase(plan, phase) }
    }

    @Test fun `standalone Hub fiction never substitutes for assembled r9 bootstrap budget`() {
        val hub = PrivateDeploymentSpec(name = "q-012345abcdef-jupyterhub", volumes = emptyList(),
            processes = listOf(process("alice",2048),process("bob",2048),process("hub",256)))
        val prefix = hub.name + "/"
        val proposed = GenerationWorkingBudget(ActivationInput("/tmp/evidence","a".repeat(64)), mapOf(
            prefix+"alice" to 256L,prefix+"bob" to 256L,prefix+"hub" to 128L))
        assertFalse(NotebookSelectedGraph.selected(GenerationRuntime.BASE.resolve("q-012345abcdef"),hub))
        // Non-selected process names cannot claim that r9's *assembled* Hub
        // retired its real Alice/Bob containers. Only selected graph custody
        // triggers the r9 bootstrap hard-ceiling reservation in the planner.
        val diagnostic = GenerationCapacityPlanner.plan(listOf(hub),1024,proposed)
        assertEquals(640L,diagnostic.steady.memoryMiB)
        assertEquals(4352L,diagnostic.steadyHardCeilingsMiB)
    }

    @Test fun `restore overlap and maintenance retain both disk and stopped object reservations`() {
        val plan = GenerationCapacityPlanner.plan(listOf(spec()), 2048)
        val worker = GenerationResources(1024, 512, 1)
        val overlap = GenerationCapacityPlanner.phase(plan, GenerationPhase.RESTORE_IMPORT, plan, work = worker)
        val maintenance = GenerationCapacityPlanner.phase(plan, GenerationPhase.RESTORE_IMPORT, plan,
            SourceCapacityMode.ISOLATED, worker)
        assertEquals(GenerationResources(1792, 4608, 9), overlap.resources)
        assertEquals(GenerationResources(1024, 4608, 9), maintenance.resources)
        val verify = GenerationCapacityPlanner.phase(plan, GenerationPhase.RESTORE_VERIFY, plan,
            SourceCapacityMode.ISOLATED, GenerationResources(512, 256, 1))
        assertEquals(GenerationResources(1280, 4352, 9), verify.resources)
        assertEquals(GenerationResources(2816, 4096, 8),
            GenerationCapacityPlanner.phase(plan, GenerationPhase.UPDATE, plan).resources)
        assertEquals(plan.steady, GenerationCapacityPlanner.phase(plan, GenerationPhase.STEADY).resources)
        assertEquals(plan.install, GenerationCapacityPlanner.phase(plan, GenerationPhase.INSTALL).resources)
        assertEquals(GenerationResources(1024, 2560, 5),
            GenerationCapacityPlanner.phase(plan, GenerationPhase.BACKUP, work = worker).resources)
    }

    @Test fun `phase admission preserves hard floors retained allocations and transient locks`() {
        val plan = GenerationCapacityPlanner.plan(listOf(spec()), 2048)
        val reservation = GenerationCapacityPlanner.phase(plan, GenerationPhase.INSTALL,
            retained = GenerationResources(100, 200, 3))
        val memory = reservation.resources.memoryMiB + 16384
        val disk = reservation.resources.diskMiB + 10240
        val locks = reservation.resources.objectLocks + RuntimeLockBudget.TRANSIENT_HEADROOM
        GenerationCapacityPlanner.admit(reservation, memory, disk, locks)
        assertFailsWith<IllegalArgumentException> { GenerationCapacityPlanner.admit(reservation, memory - 1, disk, locks) }
        assertFailsWith<IllegalArgumentException> { GenerationCapacityPlanner.admit(reservation, memory, disk - 1, locks) }
        val failed = assertFailsWith<InsufficientRuntimeLocks> { GenerationCapacityPlanner.admit(reservation, memory, disk, locks - 1) }
        assertEquals(locks, failed.required)
        assertFails { GenerationCapacityPlanner.admit(reservation, -1, disk, locks) }
        assertFails { GenerationCapacityPlanner.phase(plan, GenerationPhase.INSTALL, memoryHeadroomMiB = 16383) }
        assertFails { GenerationCapacityPlanner.phase(plan, GenerationPhase.INSTALL, diskHeadroomMiB = 10239) }
        assertFails { GenerationCapacityPlanner.phase(plan, GenerationPhase.UPDATE) }
        assertFails { GenerationCapacityPlanner.phase(plan, GenerationPhase.INSTALL, sourceMode = SourceCapacityMode.ISOLATED) }
        for (phase in listOf(GenerationPhase.BACKUP, GenerationPhase.RESTORE_IMPORT)) {
            assertFails { GenerationCapacityPlanner.phase(plan, phase) }
            assertFails { GenerationCapacityPlanner.phase(plan, phase, work = GenerationResources(1024, 0, 1)) }
            assertFails { GenerationCapacityPlanner.phase(plan, phase, work = GenerationResources(1024, 1, 0)) }
        }
    }

    @Test fun `malformed plans and overflowing reservations fail closed`() {
        assertFails { GenerationCapacityPlanner.plan(emptyList(), 1024) }
        assertFails { GenerationCapacityPlanner.plan(listOf(spec(), spec()), 2048) }
        assertFails { GenerationCapacityPlanner.plan(listOf(spec()), 0) }
        assertFails { GenerationCapacityPlanner.plan(listOf(spec().copy(processes = emptyList())), 1024) }
        assertFails { GenerationResources(-1, 0, 0) }
        assertFailsWith<ArithmeticException> { GenerationResources(Long.MAX_VALUE, 0, 0) + GenerationResources(1, 0, 0) }
        val plan = GenerationCapacityPlanner.plan(listOf(spec()), 1024)
        assertFailsWith<ArithmeticException> { GenerationCapacityPlanner.phase(plan, GenerationPhase.STEADY,
            retained = GenerationResources(Long.MAX_VALUE, 0, 0)) }
    }
}
