package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import kotlin.test.*

class ForgejoCiPreEffectRemainderTest {
    @Test fun `unattempted CI remainder produces exact private outputs in isolated fixture`(@TempDir temp: Path) {
        val anchor=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/q-5962a9fda75b")
        val request=GenerationAssembly.readRequest(anchor.resolve("assembly-request.pi-subscription-v4.budgeted.json"))
        val ci=requireNotNull(request.forgejoCi)
        val root=temp.resolve(ci.generation)
        Files.createDirectory(root)
        Files.setPosixFilePermissions(root,PosixFilePermissions.fromString("rwx------"))
        ForgejoCiSourcePlan.prepare(root,ci)
        val output=root.resolve("ci")
        assertTrue(Files.isDirectory(output))
        for(name in listOf("runner-config.yaml","transport-ca.pem","transport-leaf.pem","transport-leaf-key.pem",
            "transport-upstream.pending.json","guard.py","account-stage.py","workflow.sha256")) {
            assertTrue(Files.isRegularFile(output.resolve(name)),"Missing CI output: $name")
            assertEquals(PosixFilePermissions.fromString("rw-------"),Files.getPosixFilePermissions(output.resolve(name)))
        }
        assertFalse(Files.exists(root.resolve("bundle.json")))
    }
}
