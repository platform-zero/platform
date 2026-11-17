package net.datamancy.platform

import org.junit.jupiter.api.Test
import kotlin.test.*
import java.nio.file.Files
import java.nio.file.Path

/** Artifact-backed source only; does not create a registration, import, account or RSS enrollment. */
class GenerationR9BoundSourceTest {
    @Test fun `fresh reviewed repository and three independently pinned OCI sources validate`() {
        val ci=GenerationR9CiSourceBindings.bind("q-5962a9fda75b")
        ci.validate("q-5962a9fda75b")
        assertTrue(ci.graphOwnedLateUpstream && ci.freshIssuerBootstrap)
        assertNull(ci.upstreamCa)
        assertNull(ci.privateUpstream)
        assertEquals("0".repeat(64),ci.registrationToken.sha256)
        assertEquals(3,setOf(ci.jobArchive.archive.sha256,ci.runnerImage!!.archive.sha256,
            ci.transportImage!!.archive.sha256).size)
        assertEquals(ReleaseLocks.sha256(Files.readAllBytes(Path.of(ci.workflow.path))),ci.workflow.sha256)
        assertEquals(ReleaseLocks.sha256(Files.readAllBytes(Path.of(ci.trustedRepositoryBundle!!.path))),
            ci.trustedRepositoryBundle.sha256)
    }
    @Test fun `selected portal projection is bound to one graph not guessed aliases`() {
        val root=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/q-5962a9fda75b")
        val bytes=ReleasePrivateFiles.read(root.resolve("graph-portal-routes.json"),65536)
        assertEquals("6646c44d6c30f2818c02662fdef6f6c282ae24c2db3fced5cc216fd5a88d583c",
            ReleaseLocks.sha256(bytes))
        val closure=ReleasePrivateFiles.read(root.resolve("rss-source-artifact-closure.json"),65536)
        assertEquals("e2313b57a836d2fb020fad8528b7f2c0da80a4b60bc720d5ac13c11c7393b2fa",
            ReleaseLocks.sha256(closure))
        assertEquals(47,RssPacks.load().size)
        assertFalse(RssPacks.reviewedForPublication()) // A source closure is not content approval.
    }
}
