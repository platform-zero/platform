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

    @Test fun `child metadata applies fixed ACL binary xattr and timestamp before root, never follows links`() {
        val target = Files.createTempDirectory("native-tree-unit-")
        try {
            val calls = mutableListOf<List<String>>()
            val engine = ColdVolumeMetadata({ argv, _ ->
                calls += argv
                when {
                    "/usr/bin/realpath" in argv -> argv.last() + "\n"
                    "/usr/bin/stat" in argv -> if (argv.last().endsWith("/child")) "regular file" else "directory"
                    else -> ""
                }
            })
            val child = VolumeTarEntry("dir/child", false, 384, 999, 999, 8, "a".repeat(64),
                1710000000, 123000000, accessAcl = "user::rw-,group::---,other::---",
                userXattrs = mapOf("user.binary" to "0x00ff10"))
            val directory = root.copy(path = "dir")
            engine.restoreTreeAt(target, listOf(root, directory, child), 999) { calls += listOf("root-last") }
            assertEquals(listOf("/usr/bin/stat", "/usr/bin/chown", "/usr/bin/chmod", "/usr/bin/setfacl", "/usr/bin/setfattr", "/usr/bin/touch"),
                calls.filter { it.lastOrNull() == target.resolve("dir/child").toString() }.map { it[5] })
            assertTrue(calls.any { it.contains("--value=0x00ff10") })
            assertEquals(listOf("root-last"), calls.last())
            calls.clear()
            assertFails { engine.restoreTreeAt(target, listOf(root, child), 999) { calls += listOf("root") } }
            assertTrue(calls.isEmpty()) // Missing parent is a pure pre-effect refusal.
            calls.clear()
            assertFails { engine.restoreTreeAt(target, listOf(root, directory,
                child.copy(path = "dir/alias", linkKind = "symbolic", linkTarget = "/outside")), 999) { calls += listOf("root") } }
            assertTrue(calls.isEmpty()) // Symlink ACL or xattr cannot be applied through its target.
        } finally { Files.delete(target) }
    }
    @Test fun `read only native preflight accepts empty regular files but rejects symlinks`() {
        val target = Files.createTempDirectory("native-empty-file-unit-")
        try {
            val calls = mutableListOf<List<String>>()
            var nativeKind = "regular empty file"
            val engine = ColdVolumeMetadata({ argv, _ ->
                calls += argv
                when {
                    "/usr/bin/realpath" in argv -> argv.last() + "\n"
                    "/usr/bin/stat" in argv -> nativeKind
                    else -> error("Read-only audit tried a metadata effect")
                }
            })
            val empty = VolumeTarEntry("empty", false, 384, 999, 999, 0,
                ReleaseLocks.sha256(byteArrayOf()), 1710000000)
            engine.restoreTreeAt(target, listOf(root, empty), 999, readOnlyPreflight = true) {
                error("Read-only audit tried a root metadata effect")
            }
            assertTrue(calls.all { "/usr/bin/realpath" in it || "/usr/bin/stat" in it })
            nativeKind = "symbolic link"
            assertFailsWith<IllegalStateException> {
                engine.restoreTreeAt(target, listOf(root, empty), 999, readOnlyPreflight = true) {
                    error("Read-only audit tried a root metadata effect")
                }
            }
        } finally { Files.delete(target) }
    }
    @Test fun `native readback compares complete original entry set not only payload bytes`() {
        val source = Files.createTempFile("original-volume-", ".tar")
        val target = Files.createTempFile("imported-volume-", ".tar")
        try {
            val before = VolumeTarTest.tar(VolumeTarTest.root(), VolumeTarTest.member("state", data = "original".toByteArray()))
            Files.write(source, before); Files.write(target, before)
            Files.setPosixFilePermissions(source, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"))
            Files.setPosixFilePermissions(target, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"))
            assertEquals(listOf(".", "state"), ColdVolumeImport.verifyImported(source, target, 999).map { it.path })
            Files.write(target, VolumeTarTest.tar(VolumeTarTest.root(), VolumeTarTest.member("state", data = "changed".toByteArray())))
            assertFails { ColdVolumeImport.verifyImported(source, target, 999) }
            Files.write(target, VolumeTarTest.tar(VolumeTarTest.root(), VolumeTarTest.member("state", data = "original".toByteArray(), mode = 448)))
            assertFails { ColdVolumeImport.verifyImported(source, target, 999) }
        } finally { Files.delete(source); Files.delete(target) }
    }
    @Test fun `export refuses too-small native streaming allowance before any privileged process`() {
        val output = Path.of("/not-an-owned-directory/source.tar")
        assertFailsWith<IllegalArgumentException> {
            ColdVolumeExport.export(spec, spec.volumes.single(), output,
                maximumBytes = VolumeTar.MAX_METADATA_PREFIX + 1023L)
        }
        assertFailsWith<IllegalArgumentException> {
            ColdVolumeExport.export(spec, spec.volumes.single(), output,
                maximumBytes = RecoveryCapsule.MAX_TOTAL + 1L)
        }
    }
    @Test fun `precise stat rejects symlink malformed and inconsistent observations`() {
        assertEquals(VolumeRootMetadata(999, 999, 448, VolumeTimestamp(-1, 500000000)), VolumeRootMetadata.parse(observation))
        for (bad in listOf(observation + "\n", observation.replace("directory", "symbolic link"), observation.replace("700", "900"),
            observation.replace("999\n999", "65535\n999"), observation.replace("-1\n", "0\n"),
            observation.replace("+0000", "+0100"), observation.replace(".500000000", ".5"), observation.replace("12-31", "13-32")))
            assertFails(bad) { VolumeRootMetadata.parse(bad) }
    }

    @Test fun `root restoration uses exact owned path and verifies nanoseconds after writes`() {
        val calls = mutableListOf<List<String>>()
        val engine = ColdVolumeMetadata(execute = { argv, home ->
            calls += argv
            assertEquals(Path.of("${spec.store.graph}/volumes/p0v3-live-${spec.name}-volume-data"), home)
            if ("/usr/bin/stat" in argv) observation else ""
        })
        engine.restore(spec, spec.volumes.single(), root)
        assertEquals(5, calls.size)
        assertTrue(calls.all { it.take(5) == listOf("/usr/bin/sudo", "-n", "/usr/bin/timeout", "--kill-after=5s", "15s") })
        assertTrue(calls.all { it.takeLast(2) == listOf("--", "${spec.store.graph}/volumes/p0v3-live-${spec.name}-volume-data/_data") })
        assertTrue("--date=@-0.5" in calls[3])
        assertFalse(calls.any { "-R" in it || "-c" in it })
        assertTrue(calls[0].single { it.startsWith("--printf=") }.contains("%y"))
    }

    @Test fun `mount root ACL xattrs and security labels are observed before export`() {
        val extended = mutableListOf<List<String>>()
        var attributes = "# file: root\nuser.source-id=0x6f726967696e616c\n"
        val engine = ColdVolumeMetadata({ argv, _ ->
            assertTrue("/usr/bin/stat" in argv); observation
        }, { argv, _ ->
            extended += argv
            if ("/usr/bin/getfacl" in argv) "user::rwx\nuser:999:r--\ngroup::---\nother::---\n" else attributes
        })
        val observed = engine.observeFull(spec, spec.volumes.single(), Path.of("/owned"))
        assertEquals("user::rwx,user:999:r--,group::---,other::---", observed.accessAcl)
        assertEquals("0x6f726967696e616c", observed.userXattrs["user.source-id"])
        assertEquals(2, extended.size)
        assertTrue(extended.any { "/usr/bin/getfattr" in it })
        attributes = "security.selinux=0x6869\n"
        assertFails { engine.observeFull(spec, spec.volumes.single(), Path.of("/owned")) }
    }
    @Test fun `root ACL and approved xattrs are applied before original timestamp`() {
        val calls = mutableListOf<List<String>>()
        val engine = ColdVolumeMetadata(execute = { argv, _ ->
            calls += argv
            if ("/usr/bin/stat" in argv) observation else ""
        })
        engine.restore(spec, spec.volumes.single(), root.copy(
            accessAcl = "user::rwx,group::---,other::---",
            defaultAcl = "user::rwx,group::---,other::---",
            userXattrs = mapOf("user.source-id" to "0x6f726967696e616c")))
        assertEquals(listOf("/usr/bin/stat", "/usr/bin/chown", "/usr/bin/chmod", "/usr/bin/setfacl",
            "/usr/bin/setfacl", "/usr/bin/setfattr", "/usr/bin/touch", "/usr/bin/stat"),
            calls.map { it[5] })
        assertTrue(calls[5].contains("--name=user.source-id"))
        assertFails { engine.restore(spec, spec.volumes.single(), root.copy(userXattrs = mapOf("security.selinux" to "unexpected"))) }
    }
    @Test fun `root drift and writes failing retain refusal instead of rounding or resuming`() {
        var observations = 0
        val engine = ColdVolumeMetadata(execute = { argv, _ ->
            if ("/usr/bin/stat" in argv) {
                observations++
                if (observations == 1) observation else observation.replace(".500000000", ".500000001")
            } else ""
        })
        assertFailsWith<IllegalArgumentException> { engine.restore(spec, spec.volumes.single(), root) }
        for (failure in listOf("/usr/bin/stat", "/usr/bin/chown", "/usr/bin/chmod", "/usr/bin/touch")) {
            val calls = mutableListOf<List<String>>()
            val broken = ColdVolumeMetadata(execute = { argv, _ ->
                calls += argv
                check(failure !in argv) { "Synthetic failure" }
                if ("/usr/bin/stat" in argv) observation else ""
            })
            assertFails { broken.restore(spec, spec.volumes.single(), root) }
            assertTrue(failure in calls.last())
        }
    }

    @Test fun `unsafe root or bootstrap definitions are refused before writes`() {
        val calls = mutableListOf<List<String>>()
        val engine = ColdVolumeMetadata(execute = { argv, _ -> calls += argv; observation.replace("directory", "symbolic link") })
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
