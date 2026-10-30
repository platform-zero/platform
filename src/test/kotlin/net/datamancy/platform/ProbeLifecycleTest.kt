package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ProbeLifecycleTest {
    private val selection = ProbeSelection("fixture", "sha256:${"a".repeat(64)}")
    private class FakeCommands : ProbeCommands {
        val calls = mutableListOf<List<String>>()
        var created = false
        var running = false
        override fun invoke(arguments: List<String>): String {
            calls.add(arguments)
            return when (arguments.first()) {
                "image" -> ""
                "ps" -> if (created && ("-a" in arguments || running)) "p0v3-isolated-probe-fixture" else ""
                "create" -> { created = true; "container-id" }
                "start" -> { running = true; "" }
                "stop" -> { running = false; "" }
                "rm" -> { created = false; "" }
                else -> error("Unexpected Podman action")
            }
        }
    }
    private fun clean(root: Path) {
        Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
    }

    @Test fun `install stop snapshot isolated restore and remove are confined to sandbox`() {
        val root = Files.createTempDirectory("p0v3-probe-test-")
        val fake = FakeCommands()
        val lifecycle = ProbeLifecycle(root) { fake }
        try {
            lifecycle.prepare(selection)
            lifecycle.install(selection)
            assertTrue(fake.running)
            assertFailsWith<IllegalArgumentException> { lifecycle.install(selection) }
            val create = fake.calls.single { it.first() == "create" }
            assertTrue("--network=none" in create && "--pull=never" in create && "--read-only" in create)
            assertTrue(create.any { it.startsWith("--volume=${root.resolve("probe-fixture/data")}") })
            Files.writeString(root.resolve("probe-fixture/data/fake.txt"), "before")
            assertFailsWith<IllegalArgumentException> { lifecycle.snapshot(selection, "first") }
            lifecycle.stop(selection)
            lifecycle.snapshot(selection, "first")
            Files.writeString(root.resolve("probe-fixture/data/fake.txt"), "after")
            lifecycle.restoreIsolated(selection, "first")
            assertEquals("before", Files.readString(root.resolve("probe-fixture/restores/first/fake.txt")))
            assertEquals("after", Files.readString(root.resolve("probe-fixture/data/fake.txt")))
            assertFailsWith<IllegalArgumentException> { lifecycle.restoreIsolated(selection, "first") }
            assertFailsWith<IllegalArgumentException> { lifecycle.snapshot(selection, "first") }
            lifecycle.remove(selection)
            assertFalse(fake.created)
            assertEquals("before", Files.readString(root.resolve("probe-fixture/snapshots/first/fake.txt")))
            assertFailsWith<IllegalArgumentException> { lifecycle.stop(selection) }
        } finally { clean(root) }
    }

    @Test fun `tampered snapshot and symlinks are rejected without altering data`() {
        val root = Files.createTempDirectory("p0v3-probe-test-")
        val outside = Files.createTempFile("p0v3-unrelated-", ".txt")
        val lifecycle = ProbeLifecycle(root) { FakeCommands() }
        try {
            Files.writeString(outside, "untouched")
            lifecycle.install(selection)
            Files.writeString(root.resolve("probe-fixture/data/test"), "before")
            lifecycle.snapshot(selection, "first") // fake backend in this test is not running
            val snapshot = root.resolve("probe-fixture/snapshots/first/test")
            Files.writeString(snapshot, "corrupt")
            assertFailsWith<IllegalArgumentException> { lifecycle.restoreIsolated(selection, "first") }
            assertFalse(Files.exists(root.resolve("probe-fixture/restores/first")))
            Files.createSymbolicLink(root.resolve("probe-fixture/data/linked"), outside)
            assertFailsWith<IllegalArgumentException> { lifecycle.snapshot(selection, "second") }
            assertEquals("untouched", Files.readString(outside))
        } finally { clean(root); Files.delete(outside) }
    }

    @Test fun `selection and owner boundary fail closed`() {
        assertFailsWith<IllegalArgumentException> { ProbeSelection("../software_lab", selection.imageId) }
        assertFailsWith<IllegalArgumentException> { ProbeSelection("fixture", "busybox:latest") }
        assertFailsWith<IllegalArgumentException> {
            ProbeLifecycle(Path.of("/etc")) { FakeCommands() }.prepare(selection)
        }
        val root = Files.createTempDirectory("p0v3-probe-test-")
        try {
            Files.setPosixFilePermissions(root, setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE, PosixFilePermission.GROUP_READ))
            assertFailsWith<IllegalArgumentException> { ProbeLifecycle(root) { FakeCommands() }.install(selection) }
            Files.setPosixFilePermissions(root, setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE))
            val other = ProbeLifecycle(root) { FakeCommands() }
            other.install(selection)
            assertFailsWith<IllegalArgumentException> { other.stop(selection.copy(imageId = "sha256:${"b".repeat(64)}")) }
            Files.writeString(root.resolve("probe-fixture/unrelated"), "do not touch")
            assertFailsWith<IllegalArgumentException> { other.stop(selection) }
            assertEquals("do not touch", Files.readString(root.resolve("probe-fixture/unrelated")))
        } finally { clean(root) }
    }
}
