package net.datamancy.platform

import java.nio.file.Files
import org.junit.jupiter.api.Test
import kotlin.test.*

class GenerationCiMemberPreEffectContinuationTest {
    @Test fun `two failed results persist and CI issuer grants cannot become member ACK`() {
        val root=GenerationRuntime.BASE.resolve(GenerationCiPreEffectContinuation.GENERATION)
        val first=GenerationCiPreEffectContinuation.binding(root)
        GenerationCiPreEffectContinuation.verify(root,first)
        val second=GenerationRuntime.privateInput(root.resolve(GenerationCiPreEffectContinuation.RESULT)).decodeToString()
        assertContains(second,"\"passed\":false")
        val member=PrivateDeployment.BASE.resolve("q-5962a9fda75b-v2")
        val file=root.resolve(GenerationCiMemberPreEffectContinuation.FILE)
        if (Files.exists(file)) {
            val pin=GenerationCiMemberPreEffectContinuation.binding(root)
            val record=GenerationCiMemberPreEffectContinuation.verify(root,pin)
            assertFalse(record.originalPassed)
            assertFailsWith<IllegalArgumentException> {
                GenerationCiMemberPreEffectContinuation.verify(root,pin.copy(sha256="0".repeat(64)))
            }
            if (!Files.exists(root.resolve(GenerationCiMemberPreEffectContinuation.INTENT)))
                GenerationCiMemberPreEffectContinuation.verify(root,pin,beforeEffects=true)
            else assertFailsWith<IllegalArgumentException> {
                GenerationCiMemberPreEffectContinuation.verify(root,pin,beforeEffects=true)
            }
        } else {
            val observation=GenerationCiMemberPreEffectContinuation.inspect(root,member,first,true)
            assertEquals(15,observation.ciSourceSha256.size)
            assertEquals(2,observation.freshIssuerSha256.size)
            assertTrue(observation.memberRootLockOnly)
        }
        if (Files.exists(root.resolve("bundle.json"))) {
            val completed=GenerationRuntime.privateInput(root.resolve(GenerationCiMemberPreEffectContinuation.RESULT)).decodeToString()
            assertContains(completed,"\"passed\":true")
        }
    }
}
