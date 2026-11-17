package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

class RuntimeQuadletInstallReconcileTest {
    @Test fun `original missing ACK can receive separate terminal disposition only after exact inactive evidence`() {
        val base = Files.createTempDirectory("p0v3-install-terminal-",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try {
            val plan = FragmentAssemblyFixture.plan()
            val spec = plan.specs.single()
            val generation = plan.generation.id
            val root = Files.createDirectory(base.resolve(generation),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            val bundle = GenerationBundle(plan.generation, listOf(GenerationPin(GenerationMember(spec.name),
                "b".repeat(64), emptyMap(), "c".repeat(64), spec)), 4096)
            val json = Json { encodeDefaults = true }
            val bundleBytes = json.encodeToString(bundle).toByteArray()
            ReleasePrivateFiles.save(root.resolve("bundle.json"), bundleBytes)
            val expected = ReleaseLocks.sha256(bundleBytes)
            val source = base.resolve("quadlets"); val systemd = base.resolve("units")
            val rendered = RuntimeQuadlets.render(spec)
            val destinations = rendered.files.mapKeys { (relative, _) ->
                (if (relative.endsWith(".container")) source else systemd).resolve(relative).toString()
            }.mapValues { ReleaseLocks.sha256(it.value.toByteArray()) }
            val intent = QuadletInstallIntent(generation = generation, bundleSha256 = expected,
                member = spec.name, specSha256 = rendered.specSha256, filesSha256 = destinations,
                stagedDestinations = destinations.keys.toList())
            ReleasePrivateFiles.save(root.resolve("quadlet-install-${spec.name}.intent.json"),
                json.encodeToString(intent).toByteArray())
            var active = true
            val reconcile = RuntimeQuadletInstallReconcile(base, source, systemd,
                audit = { _, _ -> "d".repeat(64) }, inactive = { !active }, namespaceEmpty = { true })
            assertFails { reconcile.terminal(root, generation, expected, spec) }
            assertFalse(Files.exists(root.resolve("quadlet-install-${spec.name}.terminal.json")))
            active = false
            val terminal = reconcile.terminal(root, generation, expected, spec)
            assertEquals("terminal-incomplete-installed-inactive", terminal.disposition)
            assertFalse(terminal.originalAcknowledged)
            assertFalse(terminal.startAuthorized)
            assertEquals(spec.processes.size, terminal.observedInstalledPolicy.size)
            assertFalse(Files.exists(root.resolve("quadlet-install-${spec.name}.result.json")))
            assertFails { reconcile.terminal(root, generation, expected, spec) }
        } finally { FragmentAssemblyFixture.remove(base) }
    }
}
