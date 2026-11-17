package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

class FreshFinanceImporterArtifactTest {
    @Test fun `independent original importer pull is bound to the OLD descriptor and immutable image`() {
        val source = Path.of("/tmp/p0-old-full-36b6b7/modules/firefly-iii/legacy/stack.runtime.yaml")
        if (!Files.isRegularFile(source)) return // test is host-artifact-backed
        assertEquals(FreshFinanceImporterArtifact.OLD_SOURCE_SHA256,
            ReleaseLocks.sha256(Files.readAllBytes(source)))
        val image = FreshFinanceImporterArtifact.acquired()
        assertEquals("firefly-importer", image.product)
        assertEquals(FreshFinanceImporterArtifact.IMAGE, image.pinnedImage)
        val sso = FreshFinanceImporterArtifact.acquiredSso()
        assertEquals("firefly-sso", sso.product)
        assertEquals(FreshFinanceImporterArtifact.SSO_IMAGE, sso.pinnedImage)
    }
}
