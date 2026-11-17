package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/** One lossless request projection for plan, ownership bind and seal. */
class GenerationAfterNativeImportProjectionTest {
    private val dir=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/q-c3a7a9e29391")
    private val inventory by lazy { GenerationAssembly.readInventory(dir.resolve("inventory.json")) }
    private fun corrected():AssemblyRequest {
        val original=GenerationAssembly.readRequest(dir.resolve("assembly-request.r10-after-native-import.budgeted.json"))
        val source=Path.of("/home/gerald/p0_v3/platform/src/main/kotlin/net/datamancy/platform/SiteOwnership.kt")
        return original.copy(abandonedPreparation=assertNotNull(original.abandonedPreparation).copy(
            correctedOwnershipSourceSha256=ReleaseLocks.sha256(Files.readAllBytes(source))))
    }
    @Test fun `all current optional lineage fields survive projection even when alternatives are mutually exclusive at admission`() {
        val request=corrected()
        val plan=GenerationAssembly().plan(request,inventory)
        val pin=ActivationInput("/lineage-only/typed.json","a".repeat(64))
        val all=request.copy(predecessorDisposition=pin,memberPredecessorDisposition=pin,
            abandonedPreparation=assertNotNull(request.abandonedPreparation),
            preparedNoStartPredecessor=assertNotNull(request.preparedNoStartPredecessor),
            failedPreUnitStagePredecessor=assertNotNull(request.failedPreUnitStagePredecessor),
            uncertainNativeImportPredecessor=assertNotNull(request.uncertainNativeImportPredecessor),
            isolatedRootlessProbePredecessor=assertNotNull(request.isolatedRootlessProbePredecessor),
            qc3PreparedNoStartPredecessor=GenerationAfterCapacityRefusalLineage.qc3,
            q273UncertainImportPredecessor=GenerationAfterQ273Lineage.predecessor,
            q583PreparedNoStartPredecessor=GenerationAfterQ583Lineage.predecessor,
            isolatedFullWorklanePreparePredecessor=GenerationAfterQ583Lineage.isolatedFullPrepare,
            q9bColdPreparedUninstalledPredecessor=GenerationAfterQ9bLineage.predecessor,
            q07PartialInstalledPredecessor=GenerationAfterQ07Lineage.predecessor)
        assertEquals(plan.generation.copy(predecessorDisposition=pin,memberPredecessorDisposition=pin,
            qc3PreparedNoStartPredecessor=GenerationAfterCapacityRefusalLineage.qc3,
            q273UncertainImportPredecessor=GenerationAfterQ273Lineage.predecessor,
            q583PreparedNoStartPredecessor=GenerationAfterQ583Lineage.predecessor,
            isolatedFullWorklanePreparePredecessor=GenerationAfterQ583Lineage.isolatedFullPrepare,
            q9bColdPreparedUninstalledPredecessor=GenerationAfterQ9bLineage.predecessor,
            q07PartialInstalledPredecessor=GenerationAfterQ07Lineage.predecessor),
            SiteOwnerships.project(all))
    }
    @Test fun `full qc3 assembly ownership binds exact typed predecessors without native effects`() {
        val request=corrected()
        val assembly=GenerationAssembly()
        val plan=assembly.plan(request,inventory)
        assertEquals(plan.generation,SiteOwnerships.project(request))
        val selected=PackagedGraphFragment.pendingV3R10().first
        val hosts=requireNotNull(selected.integratedReference).modules.flatMap {
            it.privateRoutes.map(CanonicalIngressRoute::host)
        }.toSet()
        val contract=CanonicalTopology.ownership(assembly.canonicalPlan(request,inventory),
            "full-private-r10",requireNotNull(request.portalRoutes),hosts)
        val bound=SiteOwnerships.bind(plan,contract,ReleaseLocks.approvedHosts(
            dir.resolve("approved-hosts.r10-after-native-import.json")))
        assertEquals(plan.summary.request,bound.assembly.request)
        assertEquals(134,bound.assembly.members.single().daemons.size+bound.assembly.members.single().initializers.size)
    }
}
