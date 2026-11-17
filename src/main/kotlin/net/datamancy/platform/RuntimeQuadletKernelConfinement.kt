package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path

/** The generated --memory/--pids-limit flags are necessary but not an ACK that
 * the kernel actually installed both limits. Check the exact original payload
 * cgroup before committing a daemon launch CID; never loosen a missing limit.
 */
internal object RuntimeQuadletKernelConfinement {
    fun verify(spec: PrivateDeploymentSpec, process: RuntimeProcess, cid: String, pid: Long,
        procRoot: Path = Path.of("/proc"), cgroupRoot: Path = Path.of("/sys/fs/cgroup")) {
        require(process in spec.processes && !process.oneShot && cid.matches(Regex("[a-f0-9]{64}")) && pid > 1)
        val unit = RuntimeQuadlets.unit(spec, process) + ".service"
        val expected = "/system.slice/$unit/p0v3-supervisor/libpod-payload-$cid"
        val proc = procRoot.resolve("$pid/cgroup")
        fun identity(): String {
            val bytes = Files.newInputStream(proc).use { it.readNBytes(4097) }
            require(bytes.size in 1..4096)
            val lines = bytes.decodeToString(throwOnInvalidSequence = true).lineSequence()
                .filter { it.isNotBlank() }.toList()
            require(lines.size == 1 && lines.single() == "0::$expected") {
                "Native payload left the delegated unit cgroup"
            }
            return lines.single()
        }
        val before = identity()
        val base = cgroupRoot.resolve(expected.removePrefix("/"))
        fun limited(file: String, expectedValue: Long) {
            val path = base.resolve(file)
            require(Files.isRegularFile(path, NOFOLLOW_LINKS)) { "Kernel cgroup limit missing" }
            val bytes = Files.newInputStream(path, NOFOLLOW_LINKS).use { it.readNBytes(65) }
            require(bytes.size in 1..64 && bytes.decodeToString(throwOnInvalidSequence = true)
                .trim().toLongOrNull() == expectedValue) { "Native kernel confinement differs from sealed limits" }
        }
        limited("memory.max", process.memoryMiB.toLong() * 1024L * 1024L)
        limited("pids.max", 512)
        require(identity() == before) { "Native payload cgroup changed during limit inspection" }
    }
}
