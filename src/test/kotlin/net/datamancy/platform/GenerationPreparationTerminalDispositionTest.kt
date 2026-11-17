package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import org.junit.jupiter.api.Test
import kotlin.test.*

/** Read-only original-source regression. Native absence and terminal saving
 * are separately owner-locked effects; this test does not issue either ACK. */
class GenerationPreparationTerminalDispositionTest {
    @Test fun `fresh identity and inventory remain fenced until independently passed terminal`() {
        val prior=GenerationRuntime.BASE.resolve("q-5962a9fda75b")
        if(!Files.exists(prior.resolve(GenerationPreparationTerminalDisposition.NAME)) &&
            !Files.exists(prior.resolve(GenerationPreparationTerminalDisposition.V2_NAME)) &&
            !Files.exists(prior.resolve(GenerationPreparationTerminalDisposition.V3_NAME))) {
            assertFailsWith<IllegalArgumentException> {
                GenerationPreparationTerminalDisposition.requireClosedForNewSource("q-eddce4f578b1")
            }
        }
    }
    @Test fun `passed separate v3 journal releases only source-name eligibility not issuance or old results`() {
        val prior=GenerationRuntime.BASE.resolve("q-5962a9fda75b")
        val result=prior.resolve("preparation-terminal-v3.result.json")
        val disposition=prior.resolve(GenerationPreparationTerminalDisposition.V3_NAME)
        if(Files.isRegularFile(result) && Files.isRegularFile(disposition)) {
            val outcome=kotlinx.serialization.json.Json.decodeFromString<PreparationTerminalResult>(
                ReleasePrivateFiles.read(result,8192).decodeToString(throwOnInvalidSequence=true))
            assertTrue(outcome.passed)
            assertEquals(outcome.dispositionSha256,ReleaseLocks.sha256(ReleasePrivateFiles.read(disposition,1048576)))
            GenerationPreparationTerminalDisposition.requireClosedForNewSource("q-eddce4f578b1")
            for(name in listOf("assembly.result.json","assembly-ci-pre-effect-v2.result.json",
                "assembly-ci-member-v3.result.json","preparation-terminal.result.json")) {
                assertEquals("false",kotlinx.serialization.json.Json.parseToJsonElement(
                    ReleasePrivateFiles.read(prior.resolve(name),8192).decodeToString())
                    .let { it as kotlinx.serialization.json.JsonObject }.getValue("passed").toString())
            }
            assertFalse(Files.exists(prior.resolve("bundle.json")))
            assertFalse(Files.exists(prior.resolve("preparation-terminal-v2.intent.json")))
        }
    }
    @Test fun `distinct terminal continuation rejects a substituted prior failure without writing`() {
        val root=GenerationRuntime.BASE.resolve("q-5962a9fda75b")
        if(Files.isRegularFile(root.resolve("preparation-terminal.result.json"))) {
            val census=ActivationInput(Path.of("/home/gerald/p0_v3/.coord/rapid-completion/"+
                "core-q5962-member-v3-postinput-observation-735.json").toString(),
                "54ab7b8617df9eef62081fc0d1d22a093383f980de79e4778297f19a945da7c4")
            val prior=ActivationInput(root.resolve("preparation-terminal.intent.json").toString(),"0".repeat(64))
            val result=ActivationInput(root.resolve("preparation-terminal.result.json").toString(),"0".repeat(64))
            assertFails { GenerationRuntime.real().reconcileFailedPreparationTerminal("q-5962a9fda75b",
                census,prior,result) }
        }
    }
    @Test fun `original failed preparation remains a byte-exact three failure and full member`() {
        val generation="q-5962a9fda75b"
        val root=GenerationRuntime.BASE.resolve(generation)
        val census=ActivationInput(Path.of("/home/gerald/p0_v3/.coord/rapid-completion/"+
            "core-q5962-member-v3-postinput-observation-735.json").toString(),
            "54ab7b8617df9eef62081fc0d1d22a093383f980de79e4778297f19a945da7c4")
        val source=GenerationPreparationTerminalDisposition.inspectSource(root,census)
        assertEquals(generation,source.generation)
        assertEquals(3,source.failedOutcomes.size)
        assertEquals(296,source.memberFileSha256.size)
        assertEquals(135,source.nativeUnitCount)
        assertEquals("6014ccac9f06d8e6a2f82aebb7336dfc6e3e740993248efadb06d013fc8bd38c",
            source.manifestSha256)
        assertEquals(5,source.otherSourceFileSha256.size)
        assertTrue(source.nativeNamespaceSha256.isEmpty())
        assertFalse(source.bundlePresent || source.originalPreparationPassed || source.unitOrCidEffectObserved)
        assertFalse(Files.exists(root.resolve("bundle.json")))
    }
}
