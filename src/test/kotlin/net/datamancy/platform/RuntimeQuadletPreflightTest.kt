package net.datamancy.platform

import kotlin.test.*

class RuntimeQuadletPreflightTest {
    private val spec = FragmentAssemblyFixture.plan().specs.single()
    private fun commands(fault: String = ""): RuntimeCommands = RuntimeCommands { args ->
        when {
            args == listOf("info", "--format", "json") -> RuntimeCommandResult(0,
                """{"store":{"graphRoot":"${spec.store.graph}","runRoot":"${spec.store.run}"},
                    "host":{"security":{"rootless":${if (fault == "rootless") "true" else "false"},
                    "apparmorEnabled":true,"seccompEnabled":true}}}""".trimIndent())
            args.size == 3 && args.take(2) == listOf("image", "inspect") -> {
                val p = spec.processes.first { it.image == args[2] }
                RuntimeCommandResult(0, """[{"Id":"sha256:${if (fault == "image") "0".repeat(64) else p.imageId}",
                    "Digest":"${p.image.substringAfter('@')}"}]""".trimIndent())
            }
            args.takeLast(2) == listOf("--format", "{{.Names}}") -> RuntimeCommandResult(0,
                if (fault == "container") "p0v3-live-${spec.name}-postgres\n" else "")
            args.takeLast(2) == listOf("--format", "{{.Name}}") -> RuntimeCommandResult(0,
                if (fault == args.first()) "p0v3-live-${spec.name}-foreign\n" else "")
            else -> error("Unexpected native preflight request: $args")
        }
    }
    @Test fun `read-only store image and namespace prerequisites must all pass`() {
        RuntimeQuadletPreflight.verify(spec, commands())
        for (fault in listOf("rootless", "image", "container", "network", "volume", "secret")) {
            assertFailsWith<IllegalArgumentException>(fault) { RuntimeQuadletPreflight.verify(spec, commands(fault)) }
        }
        assertFails { RuntimeQuadletPreflight.verify(spec, RuntimeCommands { RuntimeCommandResult(1, "") }) }
    }
}
