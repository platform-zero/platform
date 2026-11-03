package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

class ColdVolumeMetadataTest {
    private val observation = "999\n999\n700\n-1\n1969-12-31 23:59:59.500000000 +0000\ndirectory"
    private val spec = PrivateDeploymentSpec(name = "q-123456789abc-openbao", volumes = listOf(RuntimeVolume("data", 999)),
        processes = listOf(RuntimeProcess("app", "example.test/app@sha256:" + "a".repeat(64), "b".repeat(64), 999,
            volumes = listOf(RuntimeMount("data", "/data")), readiness = listOf("check"))))
    private val root = VolumeTarEntry(".", true, 448, 999, 999, 0, ReleaseLocks.sha256(byteArrayOf()), -1, 500000000)

    @Test fun `precise stat rejects symlink malformed and inconsistent observations`() {
        assertEquals(VolumeRootMetadata(999, 999, 448, VolumeTimestamp(-1, 500000000)), VolumeRootMetadata.parse(observation))
        for (bad in listOf(observation + "\n", observation.replace("directory", "symbolic link"), observation.replace("700", "900"),
            observation.replace("999\n999", "65535\n999"), observation.replace("-1\n", "0\n"),
            observation.replace("+0000", "+0100"), observation.replace(".500000000", ".5"), observation.replace("12-31", "13-32")))
            assertFails(bad) { VolumeRootMetadata.parse(bad) }
    }

    @Test fun `root restoration uses exact owned path and verifies nanoseconds after writes`() {
        val calls = mutableListOf<List<String>>()
        val engine = ColdVolumeMetadata { argv, home ->
            calls += argv
            assertEquals(Path.of("${spec.store.graph}/volumes/p0v3-live-${spec.name}-volume-data"), home)
            if ("/usr/bin/stat" in argv) observation else ""
        }
        engine.restore(spec, spec.volumes.single(), root)
        assertEquals(5, calls.size)
        assertTrue(calls.all { it.take(5) == listOf("/usr/bin/sudo", "-n", "/usr/bin/timeout", "--kill-after=5s", "15s") })
        assertTrue(calls.all { it.takeLast(2) == listOf("--", "${spec.store.graph}/volumes/p0v3-live-${spec.name}-volume-data/_data") })
        assertTrue("--date=@-0.5" in calls[3])
        assertFalse(calls.any { "-R" in it || "-c" in it })
        assertTrue(calls[0].single { it.startsWith("--printf=") }.contains("%y"))
    }

    @Test fun `root drift and writes failing retain refusal instead of rounding or resuming`() {
        var observations = 0
        val engine = ColdVolumeMetadata { argv, _ ->
            if ("/usr/bin/stat" in argv) {
                observations++
                if (observations == 1) observation else observation.replace(".500000000", ".500000001")
            } else ""
        }
        assertFailsWith<IllegalArgumentException> { engine.restore(spec, spec.volumes.single(), root) }
        for (failure in listOf("/usr/bin/stat", "/usr/bin/chown", "/usr/bin/chmod", "/usr/bin/touch")) {
            val calls = mutableListOf<List<String>>()
            val broken = ColdVolumeMetadata { argv, _ ->
                calls += argv
                check(failure !in argv) { "Synthetic failure" }
                if ("/usr/bin/stat" in argv) observation else ""
            }
            assertFails { broken.restore(spec, spec.volumes.single(), root) }
            assertTrue(failure in calls.last())
        }
    }

    @Test fun `unsafe root or bootstrap definitions are refused before writes`() {
        val calls = mutableListOf<List<String>>()
        val engine = ColdVolumeMetadata { argv, _ -> calls += argv; observation.replace("directory", "symbolic link") }
        for (entry in listOf(root.copy(path = "../other"), root.copy(directory = false), root.copy(uid = 0), root.copy(mode = 2048), root.copy(modifiedNanos = -1)))
            assertFails { engine.restore(spec, spec.volumes.single(), entry) }
        assertFails { engine.restore(spec.copy(processes = spec.processes.map { it.copy(oneShot = true) }), spec.volumes.single(), root) }
        assertFails { engine.restore(spec.copy(name = "ordinary"), spec.volumes.single(), root) }
        assertFails { engine.restore(spec, RuntimeVolume("foreign", 999), root) }
        assertTrue(calls.isEmpty())
        assertFails { engine.restore(spec, spec.volumes.single(), root) }
        assertEquals(1, calls.size)
        assertTrue("/usr/bin/stat" in calls.single())
    }

    @Test fun `bounded process uses clean UTC environment and rejects failure excessive output and timeout`() {
        val home = Files.createTempDirectory("metadata-process-unit-")
        try {
            val env = ColdMetadataProcess.run(listOf("/usr/bin/env"), home).lines().filter { it.isNotEmpty() }.toSet()
            assertEquals(setOf("PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "TZ=UTC", "HOME=$home"), env)
            assertFails { ColdMetadataProcess.execute(listOf("/bin/sh", "-c", "printf private-diagnostic >&2; exit 1"), home, 1000) }
            assertFails { ColdMetadataProcess.execute(listOf("/bin/sh", "-c", "head -c 1025 /dev/zero"), home, 1000) }
            assertFails { ColdMetadataProcess.execute(listOf("/bin/sh", "-c", "exec sleep 10"), home, 50) }
            assertFails { ColdMetadataProcess.execute(emptyList(), home, 1000) }
            assertFails { ColdMetadataProcess.execute(listOf("/usr/bin/env"), home, 0) }
            Thread.currentThread().interrupt()
            try {
                assertFailsWith<InterruptedException> { ColdMetadataProcess.run(listOf("/usr/bin/env"), home) }
                assertTrue(Thread.currentThread().isInterrupted)
            } finally { Thread.interrupted() }
        } finally { Files.delete(home) }
    }

    @Test fun `process interruption preserves the flag and terminates only its synthetic invocation`() {
        val home = Files.createTempDirectory("metadata-interrupt-unit-")
        val ready = home.resolve("ready")
        var failure: Throwable? = null
        var interrupted = false
        val thread = Thread {
            try { ColdMetadataProcess.run(listOf("/bin/sh", "-c", "printf ready > \"\$HOME/ready\"; exec sleep 10"), home) }
            catch (error: Throwable) { failure = error; interrupted = Thread.currentThread().isInterrupted }
        }
        try {
            thread.start()
            val deadline = System.nanoTime() + 5_000_000_000L
            while (!Files.exists(ready) && thread.isAlive && System.nanoTime() < deadline) Thread.sleep(5)
            assertTrue(Files.exists(ready))
            thread.interrupt(); thread.join(5000)
            assertFalse(thread.isAlive)
            assertIs<InterruptedException>(failure); assertTrue(interrupted)
        } finally { thread.interrupt(); thread.join(5000); Files.deleteIfExists(ready); Files.delete(home) }
    }
}
