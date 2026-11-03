package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

class NodeMetricsRecoveryTest {
    private val inventory = AcquiredInventory(1, "candidate", listOf("node-exporter", "prometheus").map {
        val pin = if (it == "node-exporter") NodeMetricsRuntime.BASE_IMAGE else "example.org/prometheus@sha256:" + "a".repeat(64)
        AcquiredImage(it, "upstream", "example.org/app:1", pin, "b".repeat(64), emptyList(), pin.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `only exact metrics recipe restores with two independent completion guards and no seeding`() {
        val source = NodeMetricsRuntime.spec(inventory, "source")
        val restored = NodeMetricsRecovery.spec(source, inventory, "restored", "a".repeat(64))
        val guard = restored.processes.first()
        assertEquals(source.volumes.size, guard.volumes.size)
        assertEquals(SingleUserRestore.inputNames(source), SingleUserRestore.inputNames(restored))
        for (id in listOf("metrics", "prometheus")) {
            assertContains(guard.command.last(), "test ! -L /recovered/$id/.restore-in-progress")
            assertContains(guard.command.last(), "test ! -L /recovered/$id/.p0v3-restore-complete")
        }
        assertContains(guard.command.last(), "stat -c %s")
        assertContains(guard.command.last(), "/recovered/prometheus/wal")
        assertFalse(guard.command.last().contains("cp "))
        assertEquals(source.processes.drop(1), restored.processes.drop(1))
        assertFails { NodeMetricsRecovery.spec(source, inventory, "source", "a".repeat(64)) }
        assertFails { NodeMetricsRecovery.spec(source, inventory, "other", "bad") }
        assertFails { NodeMetricsRecovery.spec(source.copy(processes = source.processes.drop(1)), inventory, "other", "a".repeat(64)) }
        assertFails { NodeMetricsRecovery.spec(source, inventory, "../bad", "a".repeat(64)) }
    }
    @Test fun `recovered inputs stay private exact and immutable across preparation`() {
        val root = Files.createTempDirectory("metrics-restore-unit")
        fun private(path: Path, text: String) { Files.writeString(path, text); Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------")) }
        try {
            val recovered = Files.createDirectory(root.resolve("recovered"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            val target = Files.createDirectory(root.resolve("deployments"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            val source = NodeMetricsRuntime.spec(inventory, "source")
            private(recovered.resolve("source-spec.json"), Json.encodeToString(source))
            val certificates = listOf("ca.pem", "node.pem", "node-key.pem", "admin.pem", "admin-key.pem").associateWith { "unit-only-$it" }
            val inputs = NodeMetricsRuntime.inputs(certificates)
            inputs.forEach { (name, contents) -> private(recovered.resolve(name), contents) }
            val path = NodeMetricsRecovery.prepare(inventory, recovered, "restored", target)
            assertEquals(path, NodeMetricsRecovery.prepare(inventory, recovered, "restored", target))
            assertEquals("restored", PrivateDeployment.read(path).name)
            private(recovered.resolve("ca.pem"), "changed")
            assertFails { NodeMetricsRecovery.prepare(inventory, recovered, "restored", target) }
            assertFails { NodeMetricsRecovery.prepare(inventory, Path.of("relative"), "other", target) }
            val link = root.resolve("link"); Files.createSymbolicLink(link, recovered)
            assertFails { NodeMetricsRecovery.prepare(inventory, link, "other", target) }
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}
