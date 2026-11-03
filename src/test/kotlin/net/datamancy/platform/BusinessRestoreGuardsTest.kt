package net.datamancy.platform

import java.nio.file.Files
import kotlin.test.*

/** Runs only /bin/sh against test-owned temporary files; no container/service/native probe. */
class BusinessRestoreGuardsTest {
    @Test fun `guard rejects incomplete linked foreign duplicate and uncertain completion records`() {
        val root = Files.createTempDirectory("business-restore-")
        val hash = "a".repeat(64)
        val complete = root.resolve(".p0v3-restore-complete")
        val progress = root.resolve(".restore-in-progress")
        fun accepted() = ProcessBuilder("/bin/sh", "-ec", BusinessRestoreGuards.marker(root.toString(), hash))
            .redirectErrorStream(true).start().let { it.inputStream.readBytes(); it.waitFor() == 0 }
        try {
            assertFalse(accepted())
            Files.writeString(complete, "$hash\n")
            assertTrue(accepted())
            Files.createSymbolicLink(progress, root.resolve("absent"))
            assertFalse(accepted())
            Files.delete(progress)
            Files.writeString(progress, "incomplete")
            assertFalse(accepted())
            Files.delete(progress)
            Files.writeString(complete, "$hash\n$hash\n")
            assertFalse(accepted())
            Files.writeString(complete, "b".repeat(64) + "\n")
            assertFalse(accepted())
            Files.writeString(complete, "$hash\n")
            val other = root.resolve("other")
            Files.move(complete, other)
            Files.createSymbolicLink(complete, other)
            assertFalse(accepted())
            Files.delete(complete)
            Files.createLink(complete, other)
            assertFalse(accepted())
            Files.delete(other)
            assertTrue(accepted())
            assertFails { BusinessRestoreGuards.marker("/tmp;false", hash) }
            assertFails { BusinessRestoreGuards.marker("/tmp", "bad") }
        } finally { root.toFile().deleteRecursively() }
    }
}
