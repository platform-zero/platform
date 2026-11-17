package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class GenerationAfterQ07ProjectionTest {
    private val json=Json { encodeDefaults=true;ignoreUnknownKeys=false }
    @Test fun allCurrentOriginalLineageAndIncompleteInstalledUnitsProjectWithoutNativeReplay() {
        val root=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/${GenerationAfterQ07Lineage.generation}")
        val request=GenerationAssembly.readRequest(root.resolve("assembly-request.r10-after-q07-partial-install.budgeted.json"))
        assertEquals(GenerationAfterQ07Lineage.generation,request.id)
        assertEquals(request,json.decodeFromString<AssemblyRequest>(json.encodeToString(request)))
        GenerationAfterQ07Lineage.verify(assertNotNull(request.q07PartialInstalledPredecessor),
            assertNotNull(request.q9bColdPreparedUninstalledPredecessor),
            assertNotNull(request.q583PreparedNoStartPredecessor),
            assertNotNull(request.isolatedFullWorklanePreparePredecessor),
            assertNotNull(request.q273UncertainImportPredecessor),
            assertNotNull(request.qc3PreparedNoStartPredecessor),
            assertNotNull(request.uncertainNativeImportPredecessor),
            assertNotNull(request.isolatedRootlessProbePredecessor))
        val plan=GenerationAssembly().plan(request,GenerationAssembly.readInventory(root.resolve("inventory.json")))
        val projected=SiteOwnerships.project(plan.summary.request)
        assertEquals(plan.generation,projected)
        for ((source,target) in listOf(request.q07PartialInstalledPredecessor to projected.q07PartialInstalledPredecessor,
            request.q9bColdPreparedUninstalledPredecessor to projected.q9bColdPreparedUninstalledPredecessor,
            request.q583PreparedNoStartPredecessor to projected.q583PreparedNoStartPredecessor,
            request.isolatedFullWorklanePreparePredecessor to projected.isolatedFullWorklanePreparePredecessor,
            request.q273UncertainImportPredecessor to projected.q273UncertainImportPredecessor,
            request.qc3PreparedNoStartPredecessor to projected.qc3PreparedNoStartPredecessor,
            request.uncertainNativeImportPredecessor to projected.uncertainNativeImportPredecessor,
            request.isolatedRootlessProbePredecessor to projected.isolatedRootlessProbePredecessor,
            request.failedPreUnitStagePredecessor to projected.failedPreUnitStagePredecessor,
            request.preparedNoStartPredecessor to projected.preparedNoStartPredecessor)) assertEquals(source,target)
        assertEquals(projected,json.decodeFromString<GenerationRequest>(json.encodeToString(projected)))
        assertEquals(134,plan.specs.single().processes.size)
        assertTrue(projected.workingBudget!=null)
    }
}
