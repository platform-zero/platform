package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

class PinnedBackupControllerTest {
    private fun mode(path: Path, permissions: String) = Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(permissions))
    private fun fixture(application: String = "p0-v3-platform", block: (Path, String) -> Unit) {
        val root = Files.createTempDirectory("pinned-backup-unit-"); mode(root, "rwxr-xr-x")
        try {
            for (name in listOf("bin", "lib")) { Files.createDirectory(root.resolve(name)); mode(root.resolve(name), "rwxr-xr-x") }
            val pins = sortedMapOf<String, PinnedBackupController.FilePin>()
            for (name in listOf("bin/$application", "lib/$application.jar")) {
                val path = root.resolve(name); Files.writeString(path, "unit-not-executed")
                val executable = name.startsWith("bin/"); mode(path, if (executable) "rwxr-xr-x" else "rw-r--r--")
                pins[name] = PinnedBackupController.FilePin(if (executable) 493 else 420, RecoveryCapsule.fileHash(path))
            }
            val text = Json.encodeToString<Map<String, PinnedBackupController.FilePin>>(pins); Files.writeString(root.resolve("controller.json"), text); mode(root.resolve("controller.json"), "rw-r--r--")
            block(root, ReleaseLocks.sha256(text.toByteArray()))
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    private fun verify(root: Path, hash: String) = PinnedBackupController.verifyTree(root, hash, root.resolve("lib/p0-v3-platform.jar"), UnixSystem().uid)
    @Test fun `exact modes bytes tree and invocation origin are required`() = fixture { root, hash ->
        verify(root, hash)
        assertFails { verify(root, "a".repeat(64)) }
        assertFails { PinnedBackupController.verifyTree(root, hash, root.resolve("other.jar"), UnixSystem().uid) }
        assertFails { PinnedBackupController.verifyTree(root, hash, root.resolve("lib/p0-v3-platform.jar"), UnixSystem().uid + 1) }
        Files.writeString(root.resolve("lib/undeclared.jar"), "unit"); assertFails { verify(root, hash) }
        Files.delete(root.resolve("lib/undeclared.jar"))
        Files.writeString(root.resolve("lib/p0-v3-platform.jar"), "changed"); assertFails { verify(root, hash) }
        assertFails { PinnedBackupController.verify("invalid") }
    }
    @Test fun `acceptance verifier distribution uses the same exact pinned tree policy`() = fixture("p0-v3-acceptance") { root, hash ->
        PinnedBackupController.verifyDistribution(root, hash, "p0-v3-acceptance", UnixSystem().uid)
        assertFails { PinnedBackupController.verifyDistribution(root, hash, "foreign", UnixSystem().uid) }
        assertFails { PinnedBackupController.verifyDistribution(root, hash, "p0-v3-platform", UnixSystem().uid) }
    }
    @Test fun `symlink writable file and malformed descriptors fail closed`() {
        for (fault in listOf("symlink", "mode", "keys", "encoding")) fixture { root, hash ->
            var expected = hash
            when (fault) {
                "symlink" -> {
                    val path = root.resolve("lib/p0-v3-platform.jar"); Files.delete(path)
                    Files.createSymbolicLink(path, root.resolve("bin/p0-v3-platform"))
                }
                "mode" -> mode(root.resolve("bin/p0-v3-platform"), "rwxrwxr-x")
                "keys", "encoding" -> {
                    val path = root.resolve("controller.json")
                    val text = if (fault == "keys") "{}" else Files.readString(path) + "\n"
                    Files.writeString(path, text); expected = ReleaseLocks.sha256(text.toByteArray())
                }
            }
            assertFails { verify(root, expected) }
        }
    }
}
