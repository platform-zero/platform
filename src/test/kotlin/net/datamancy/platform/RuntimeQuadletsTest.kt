package net.datamancy.platform

import kotlin.test.*

class RuntimeQuadletsTest {
    @Test fun `bundle retains resources and delegates readiness and lifecycle to controller`() {
        val spec = FragmentAssemblyFixture.plan().specs.single()
        val bundle = RuntimeQuadlets.render(spec)
        assertEquals(bundle, RuntimeQuadlets.render(spec))
        assertEquals(spec.processes.size * 2, bundle.files.size)
        assertFalse(bundle.runtimeAdmitted)
        assertTrue(bundle.files.keys.none { it.endsWith(".network") || it.endsWith(".volume") })
        for (process in spec.processes) {
            val unit = RuntimeQuadlets.unit(spec, process)
            val source = bundle.files.getValue("$unit.container")
            val dropIn = bundle.files.getValue("$unit.service.d/50-p0-lifecycle.conf")
            assertTrue("Restart=no" in source && "--replace=false --rm=false" in source)
            assertTrue("ConditionPathExists=!/\n" in source)
            assertTrue("[Unit]\nConditionPathExists=\n" in dropIn)
            assertFalse("[Install]" in source || "Requires=p0v3-" in source || "After=p0v3-" in source)
            assertTrue("--module=${spec.store.module}" in source && "--root=${spec.store.graph}" in source)
            assertTrue("ExecStartPre=\nExecStartPre=" in dropIn && " unit-admit " in dropIn)
            assertTrue("Delegate=yes\nDelegateSubgroup=p0v3-supervisor\n" in dropIn)
            assertTrue("ExecStop=\nExecStop=" in dropIn && "ExecStopPost=\nExecStopPost=" in dropIn)
            assertTrue(" unit-stop " in dropIn && !dropIn.contains("podman rm"))
            assertTrue("/releases/${spec.fragmentBinding!!.controllerSha256}/bin/" in dropIn)
            assertTrue("--reuid=${spec.fragmentBinding.controllerUid}" in dropIn)
        }
    }

    @Test fun `shell placeholders are escaped for systemd but no secret values are rendered`() {
        val spec = FragmentAssemblyFixture.plan().specs.single()
        val text = RuntimeQuadlets.render(spec).files.values.joinToString("\n")
        assertTrue("${'$'}${'$'}POSTGRES_PASSWORD" in text)
        assertTrue("${'$'}${'$'}FORGEJO_MIGRATION_PASSWORD" in text)
        assertFalse("PGPASSWORD=" in text)
        assertTrue("${'$'}{P0_RUNTIME_FINGERPRINT}" in text)
    }

    @Test fun `unsupported execution fields and missing controller binding refuse`() {
        val spec = FragmentAssemblyFixture.plan().specs.single()
        assertFails { RuntimeQuadlets.render(spec.copy(executionBackend = RuntimeExecutionBackend.DIRECT_PODMAN_V1)) }
        assertFails { RuntimeQuadlets.render(spec.copy(fragmentBinding = spec.fragmentBinding!!.copy(controllerUid = null))) }
        assertFails { RuntimeQuadlets.render(spec.copy(volumes = spec.volumes.map {
            it.copy(mappedOwners = listOf(RuntimeVolumeOwner(0, 0)))
        })) }
    }

    @Test fun `diagnostic refuses changed bundle before invoking generator`() {
        val spec = FragmentAssemblyFixture.plan().specs.single()
        val bundle = RuntimeQuadlets.render(spec)
        assertFails { RuntimeQuadletDiagnostics.verify(spec, bundle.copy(files = emptyMap())) { _, _ -> error("Must not execute") } }
        assertFails { RuntimeQuadletDiagnostics.verify(spec, bundle) { _, _ -> RuntimeCommandResult(0, "5.5.0") } }
    }
}
