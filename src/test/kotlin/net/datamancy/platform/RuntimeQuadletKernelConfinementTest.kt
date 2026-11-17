package net.datamancy.platform

import java.nio.file.Files
import kotlin.test.*

class RuntimeQuadletKernelConfinementTest {
    @Test fun `native CID cannot be acknowledged without exact delegated kernel memory and pids caps`() {
        val spec = FragmentAssemblyFixture.plan().specs.single()
        val p = spec.processes.single { it.id == "forgejo" }
        val cid = "a".repeat(64)
        val root = Files.createTempDirectory("p0v3-kernel-proof-")
        try {
            val proc = root.resolve("proc")
            val sys = root.resolve("sys")
            val cgroup = "/system.slice/${RuntimeQuadlets.unit(spec, p)}.service/p0v3-supervisor/libpod-payload-$cid"
            val payload = sys.resolve(cgroup.removePrefix("/"))
            Files.createDirectories(payload)
            val pid = proc.resolve("1234/cgroup")
            Files.createDirectories(pid.parent)
            Files.writeString(pid, "0::$cgroup\n")
            Files.writeString(payload.resolve("memory.max"), "${p.memoryMiB.toLong() * 1024 * 1024}\n")
            Files.writeString(payload.resolve("pids.max"), "512\n")
            fun check() = RuntimeQuadletKernelConfinement.verify(spec, p, cid, 1234, proc, sys)
            check()
            Files.writeString(payload.resolve("memory.max"), "max\n")
            assertFails { check() }
            Files.writeString(payload.resolve("memory.max"), "${p.memoryMiB.toLong() * 1024 * 1024}\n")
            Files.writeString(payload.resolve("pids.max"), "max\n")
            assertFails { check() }
            Files.writeString(payload.resolve("pids.max"), "512\n")
            Files.writeString(pid, "0::/user.slice/podman-1234.scope/libpod-payload-$cid\n")
            assertFails { check() }
            Files.writeString(pid, "0::$cgroup\n")
            Files.delete(payload.resolve("memory.max"))
            assertFails { check() }
        } finally {
            Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
}
