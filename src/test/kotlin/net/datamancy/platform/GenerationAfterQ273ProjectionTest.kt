package net.datamancy.platform

import java.nio.file.Path
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/** New Worklane host authority AND every typed predecessor survive plan,
 * ownership projection and actual no-effect bind before any seal. */
class GenerationAfterQ273ProjectionTest {
    private val root=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/${GenerationAfterQ273Lineage.generation}")
    @Test fun allOriginalTerminalAndNativeProofFieldsProjectAndBindWithoutNativeEffects() {
        val historical=GenerationAssembly.readRequest(root.resolve("assembly-request.r10-after-q273-import.budgeted-v2.json"))
        // q583's sealed old ownership-source hash cannot be reissued. Exercise
        // only a theoretical current-source projection; never mutate its file.
        val current=ReleaseLocks.sha256(Files.readAllBytes(Path.of(
            "/home/gerald/p0_v3/platform/src/main/kotlin/net/datamancy/platform/SiteOwnership.kt")))
        val request=historical.copy(abandonedPreparation=assertNotNull(historical.abandonedPreparation).copy(
            correctedOwnershipSourceSha256=current))
        val inventory=GenerationAssembly.readInventory(root.resolve("inventory.json"))
        val assembly=GenerationAssembly()
        val plan=assembly.plan(request,inventory)
        val expected=GenerationAfterQ273Lineage.predecessor
        assertEquals(expected,request.q273UncertainImportPredecessor)
        assertEquals(GenerationAfterCapacityRefusalLineage.qc3,request.qc3PreparedNoStartPredecessor)
        assertEquals(GenerationAfterNativeImportLineage.terminal,request.uncertainNativeImportPredecessor)
        assertEquals(GenerationAfterNativeImportLineage.probe,request.isolatedRootlessProbePredecessor)
        assertNotNull(request.preparedNoStartPredecessor)
        assertNotNull(request.failedPreUnitStagePredecessor)
        assertNotNull(request.abandonedPreparation)
        assertEquals(WorklaneLateBrokerImportProof.binarySha,request.managedLanes?.native?.worklane?.sha256)
        WorklaneLateBrokerImportProof.verifySelected(assertNotNull(request.managedLanes).native.worklane)
        assertEquals(plan.generation,SiteOwnerships.project(plan.summary.request))
        assertEquals(plan.generation,SiteOwnerships.project(request))
        val routes=assertNotNull(request.portalRoutes)
        val approved=ReleaseLocks.approvedHosts(Path.of(
            "/mnt/media/p0-v3/release-bootstrap-anchors/assembly/q-273337d6772c/approved-hosts.r10-after-capacity-refusal.json"))
        val contract=CanonicalTopology.ownership(assembly.canonicalPlan(request,inventory),
            "full-private-r10",routes,approved)
        val bound=SiteOwnerships.bind(plan,contract,approved)
        assertEquals(request,bound.assembly.request)
        assertEquals(134,bound.assembly.members.single().daemons.size+bound.assembly.members.single().initializers.size)
    }
}
