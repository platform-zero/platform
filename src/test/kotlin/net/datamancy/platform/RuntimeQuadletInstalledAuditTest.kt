package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*

/** These tests substitute a fake manager response. They do NOT prove a real installed service. */
class RuntimeQuadletInstalledAuditTest {
    private val directory = PosixFilePermissions.fromString("rwx------")
    private val file = PosixFilePermissions.fromString("rw-------")
    private fun fixture(action: (Path, PrivateDeploymentSpec, RuntimeProcess, Path, Path, String) -> Unit) {
        val root = Files.createTempDirectory("quadlet-installed-audit-",
            PosixFilePermissions.asFileAttribute(directory))
        try {
            val spec = FragmentAssemblyFixture.plan().specs.single()
            val process = spec.processes.single { it.id == "forgejo" }
            val unit = RuntimeQuadlets.unit(spec, process)
            val sourceDir = Files.createDirectory(root.resolve("quadlets"), PosixFilePermissions.asFileAttribute(directory))
            val systemdDir = Files.createDirectory(root.resolve("systemd"), PosixFilePermissions.asFileAttribute(directory))
            val dropDir = Files.createDirectory(systemdDir.resolve("$unit.service.d"), PosixFilePermissions.asFileAttribute(directory))
            val generatedDir = Files.createDirectory(root.resolve("generated"), PosixFilePermissions.asFileAttribute(directory))
            val bundle = RuntimeQuadlets.render(spec)
            val source = Files.write(sourceDir.resolve("$unit.container"), bundle.files.getValue("$unit.container").toByteArray())
            val drop = Files.write(dropDir.resolve("50-p0-lifecycle.conf"),
                bundle.files.getValue("$unit.service.d/50-p0-lifecycle.conf").toByteArray())
            Files.setPosixFilePermissions(source, file)
            Files.setPosixFilePermissions(drop, file)
            val start = "/usr/bin/podman --remote=false --module=${spec.store.module} " +
                "--root=${spec.store.graph} --runroot=${spec.store.run} --network-config-dir=${spec.store.network} " +
                "run --name p0v3-live-${spec.name}-${process.id} --replace --rm --pull never --read-only " +
                "--security-opt=no-new-privileges --user ${process.userId}:${process.groupId} --replace=false --rm=false " +
                "--memory=${process.memoryMiB}m --pids-limit=512 ${process.image} web"
            val generated = Files.writeString(generatedDir.resolve("$unit.service"),
                "SourcePath=$source\nExecStart=$start\n")
            Files.setPosixFilePermissions(generated, file)
            action(root, spec, process, source, drop, RuntimeQuadletEffectiveAuditTest().show(spec, process, start))
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    private fun inspector(root: Path, show: (String) -> String) = RuntimeQuadletInstalledAudit(
        root.resolve("quadlets"), root.resolve("systemd"), show, UnixSystem().uid, root,
        verifyController = { assertTrue(it.matches(Regex("[a-f0-9]{64}"))) },
        generatedRoot = root.resolve("generated"), translatedStart = { spec, process ->
            val generated = Files.readString(root.resolve("generated/${RuntimeQuadlets.unit(spec, process)}.service"))
            RuntimeQuadletGeneratedStart.parse(spec, process, generated.lineSequence().single {
                it.startsWith("ExecStart=") }.substringAfter('='))
        })

    @Test fun `native generator unordered unique flag pairs are equivalent but repeated or reordered effects are not`() {
        val image = "registry.invalid/image@sha256:" + "a".repeat(64)
        val fixed = listOf("/usr/bin/podman", "--remote=false", "run", "--cgroups=split")
        val tail = listOf("--volume", "first:/state", "--volume", "second:/state", image, "serve")
        val a = fixed + listOf("--pull", "never", "--entrypoint", "/bin/serve", "--network-alias", "private") + tail
        val b = fixed + listOf("--network-alias", "private", "--entrypoint", "/bin/serve", "--pull", "never") + tail
        val audit = RuntimeQuadletInstalledAudit()
        assertTrue(audit.equivalentStart(a, b, image))
        assertFalse(audit.equivalentStart(a, b.dropLast(1) + "other", image))
        assertFalse(audit.equivalentStart(a, b.dropLast(5) + listOf("--volume", "second:/state", "--volume", "first:/state", image, "serve"), image))
        assertFalse(audit.equivalentStart(a, b.take(4) + listOf("--pull", "always") + b.drop(4), image))
        assertFalse(audit.equivalentStart(a, b + listOf("--pull", "never"), image))
    }
    @Test fun `read-only installed-file audit requires bound source dropin and effective properties`() =
        fixture { root, spec, process, _, _, effective ->
            val audit = inspector(root) { effective }
            assertTrue(audit.audit(spec, process).matches(Regex("[a-f0-9]{64}")))
            assertFails { inspector(root) { effective.replace("Restart=no", "Restart=always") }.audit(spec, process) }
        }

    @Test fun `symlink writable dropin and mutation during manager inspection fail closed`() =
        fixture { root, spec, process, source, drop, effective ->
            assertFails { inspector(root) {
                Files.writeString(source, "mutated")
                effective
            }.audit(spec, process) }
            Files.setPosixFilePermissions(drop, PosixFilePermissions.fromString("rw-rw----"))
            assertFails { inspector(root) { effective }.audit(spec, process) }
            Files.setPosixFilePermissions(drop, file)
            Files.delete(source)
            Files.createSymbolicLink(source, drop)
            assertFails { inspector(root) { effective }.audit(spec, process) }
        }
}
