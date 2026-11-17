package net.datamancy.platform

import java.nio.file.Path
import java.nio.file.Files
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class GenerationAfterQ9bProjectionTest {
    private val json=Json { encodeDefaults=true;ignoreUnknownKeys=false }
    @Test fun fullFrozenTerminalChainProjectsAndRoundTripsBeforeAnyNativeEffect() {
        val root=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/${GenerationAfterQ9bLineage.generation}")
        val request=GenerationAssembly.readRequest(root.resolve("assembly-request.r10-after-q9b-cold-prepared.budgeted.json"))
        assertEquals(GenerationAfterQ9bLineage.generation,request.id)
        assertEquals(request,json.decodeFromString<AssemblyRequest>(json.encodeToString(request)))
        val q9b=assertNotNull(request.q9bColdPreparedUninstalledPredecessor)
        val q583=assertNotNull(request.q583PreparedNoStartPredecessor)
        val full=assertNotNull(request.isolatedFullWorklanePreparePredecessor)
        GenerationAfterQ9bLineage.verify(q9b,q583,full,
            assertNotNull(request.q273UncertainImportPredecessor),
            assertNotNull(request.qc3PreparedNoStartPredecessor),
            assertNotNull(request.uncertainNativeImportPredecessor),
            assertNotNull(request.isolatedRootlessProbePredecessor))
        // q07 historical source stays sealed; project a theoretical current
        // ownership-source clone, not a rewrite of its request.
        val current=ReleaseLocks.sha256(Files.readAllBytes(Path.of(
            "/home/gerald/p0_v3/platform/src/main/kotlin/net/datamancy/platform/SiteOwnership.kt")))
        val candidate=request.copy(abandonedPreparation=assertNotNull(request.abandonedPreparation).copy(
            correctedOwnershipSourceSha256=current))
        val plan=GenerationAssembly().plan(candidate,GenerationAssembly.readInventory(root.resolve("inventory.json")))
        val projected=SiteOwnerships.project(plan.summary.request)
        assertEquals(plan.generation,projected)
        assertEquals(q9b,projected.q9bColdPreparedUninstalledPredecessor)
        assertEquals(q583,projected.q583PreparedNoStartPredecessor)
        assertEquals(full,projected.isolatedFullWorklanePreparePredecessor)
        assertEquals(request.q273UncertainImportPredecessor,projected.q273UncertainImportPredecessor)
        assertEquals(request.qc3PreparedNoStartPredecessor,projected.qc3PreparedNoStartPredecessor)
        assertEquals(request.uncertainNativeImportPredecessor,projected.uncertainNativeImportPredecessor)
        assertEquals(request.isolatedRootlessProbePredecessor,projected.isolatedRootlessProbePredecessor)
        assertEquals(request.failedPreUnitStagePredecessor,projected.failedPreUnitStagePredecessor)
        assertEquals(request.preparedNoStartPredecessor,projected.preparedNoStartPredecessor)
        assertEquals(projected,json.decodeFromString<GenerationRequest>(json.encodeToString(projected)))
        assertEquals(134,plan.specs.single().processes.size)
        assertTrue(projected.workingBudget!=null)
    }
}
