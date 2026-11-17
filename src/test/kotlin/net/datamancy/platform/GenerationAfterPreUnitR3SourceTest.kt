package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

/** The same exact r3 admission helper guards prospective assembly and runtime load.
 * Never repin the prior writable r2 inode to make a historical source pass. */
class GenerationAfterPreUnitR3SourceTest {
    @Test fun `assembly and runtime share exact immutable read-only r3 archive authority`() {
        val r3=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/worklane-platform-r3/worklane-platform.oci.tar")
        assumeTrue(Files.isRegularFile(r3))
        val accepted=ManagedLaneImageBinding(ActivationInput(r3.toString(),
            "8c1cc42df10cd5086b33e817012e08a63b3ae6899270b1c76494dd831224e7bd"),
            Files.size(r3),34359738368L,"sha256:${"a".repeat(64)}",
            "localhost/worklane@sha256:${"b".repeat(64)}","sha256:${"b".repeat(64)}",
            listOf("sha256:${"c".repeat(64)}"))
        assertEquals(accepted,GenerationNormalizedWorklaneImage.requireSelected(accepted))
        assertFailsWith<IllegalArgumentException> { GenerationNormalizedWorklaneImage.requireSelected(
            accepted.copy(archive=accepted.archive.copy(path=r3.toString().replace("-r3/","-r2/")))) }
        assertFailsWith<IllegalArgumentException> { GenerationNormalizedWorklaneImage.requireSelected(
            accepted.copy(maximumUnpackedBytes=17179869184L)) }
        assertFailsWith<IllegalArgumentException> { GenerationNormalizedWorklaneImage.requireSelected(
            accepted.copy(archive=accepted.archive.copy(sha256="0".repeat(64)))) }
        val source=Path.of("/home/gerald/p0_v3/platform/src/main/kotlin/net/datamancy/platform")
        if (Files.isDirectory(source)) {
            assertTrue(Files.readString(source.resolve("GenerationAssembly.kt")).contains(
                "GenerationNormalizedWorklaneImage.requireSelected(request.managedLanes?.native?.imageArchive)"))
            assertTrue(Files.readString(source.resolve("GenerationRuntime.kt")).contains(
                "GenerationNormalizedWorklaneImage.requireSelected(bundle.request.managedLanes?.native?.imageArchive)"))
        }
    }
}
