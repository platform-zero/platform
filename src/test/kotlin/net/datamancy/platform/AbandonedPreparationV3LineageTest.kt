package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import org.junit.jupiter.api.Test
import kotlin.test.*

/** Source-only: inspect passed old v3 terminal without issuing a new q,
 * generation credential, request, controller tree or native phase ACK. */
class AbandonedPreparationV3LineageTest {
    @Test fun `new request lineage must bind passed v3 terminal and corrected source not old controller`() {
        val old="q-5962a9fda75b"
        val target="q-eddce4f578b1"
        val root=GenerationRuntime.BASE.resolve(old)
        val census=Path.of("/home/gerald/p0_v3/.coord/rapid-completion/"+
            "core-q5962-member-v3-postinput-observation-735.json")
        val disposition=root.resolve(GenerationPreparationTerminalDisposition.V3_NAME)
        require(Files.isRegularFile(disposition))
        val lineage=AbandonedPreparationLineage(old,
            ActivationInput(disposition.toString(),ReleaseLocks.sha256(ReleasePrivateFiles.read(disposition,1048576))),
            ActivationInput(census.toString(),ReleaseLocks.sha256(Files.readAllBytes(census))),
            priorControllerSha256="80f3d3d195534d51766eb4114641b3e50637bebd884ba60bff0e7728cacdc27f",
            correctedOwnershipSourceSha256=ReleaseLocks.sha256(Files.readAllBytes(Path.of(
                "/home/gerald/p0_v3/platform/src/main/kotlin/net/datamancy/platform/SiteOwnership.kt"))))
        val changedController="1".repeat(64) // source-only negative/positive shape, never an issued controller
        val saved=AbandonedPreparationLineages.inspect(target,changedController,lineage)
        assertEquals(old,saved.generation)
        assertEquals(3,saved.failedOutcomes.size)
        assertEquals(296,saved.memberFileSha256.size)
        assertEquals(ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("preparation-terminal-v2-pre-effect.disposition.json"),16384)),
            saved.predecessorV2PreEffectDispositionSha256)
        assertEquals(ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("preparation-terminal.result.json"),8192)),
            saved.predecessorFailedTerminalResultSha256)
        assertFailsWith<IllegalArgumentException> {
            AbandonedPreparationLineages.inspect(target,lineage.priorControllerSha256,lineage)
        }
        assertFailsWith<IllegalArgumentException> {
            AbandonedPreparationLineages.inspect(target,changedController,lineage.copy(
                terminal=lineage.terminal.copy(sha256="0".repeat(64))))
        }
        assertFailsWith<IllegalArgumentException> {
            AbandonedPreparationLineages.inspect(target,changedController,lineage.copy(
                generationScopedCredentials="adopt-old-grants"))
        }
        assertFailsWith<IllegalArgumentException> {
            AbandonedPreparationLineages.inspect(target,changedController,lineage.copy(
                correctedOwnershipSourceSha256="0".repeat(64)))
        }
    }
}
