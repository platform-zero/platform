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

class GenerationAfterQ583ProjectionTest {
    private val json=Json { encodeDefaults=true;ignoreUnknownKeys=false }
    @Test fun allCurrentTerminalProbeAndOwnedFieldsRoundTripWithoutNativeEffects() {
        val root=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/${GenerationAfterQ583Lineage.generation}")
        val source=root.resolve("assembly-request.r10-after-q583-no-start.budgeted.json")
        val request=GenerationAssembly.readRequest(source)
        assertEquals(GenerationAfterQ583Lineage.generation,request.id)
        val decoded=json.decodeFromString<AssemblyRequest>(json.encodeToString(request))
        assertEquals(request,decoded)
        val pin=assertNotNull(request.q583PreparedNoStartPredecessor)
        val full=assertNotNull(request.isolatedFullWorklanePreparePredecessor)
        GenerationAfterQ583Lineage.verify(pin,full,
            assertNotNull(request.q273UncertainImportPredecessor),
            assertNotNull(request.qc3PreparedNoStartPredecessor),
            assertNotNull(request.uncertainNativeImportPredecessor),
            assertNotNull(request.isolatedRootlessProbePredecessor))
        // Historical q9b sources remain frozen; project a current-source copy,
        // not a reissued historical ownership-source hash.
        val current=ReleaseLocks.sha256(Files.readAllBytes(Path.of(
            "/home/gerald/p0_v3/platform/src/main/kotlin/net/datamancy/platform/SiteOwnership.kt")))
        val candidate=request.copy(abandonedPreparation=assertNotNull(request.abandonedPreparation).copy(
            correctedOwnershipSourceSha256=current))
        val plan=GenerationAssembly().plan(candidate,GenerationAssembly.readInventory(root.resolve("inventory.json")))
        val projected=SiteOwnerships.project(plan.summary.request)
        assertEquals(plan.generation,projected)
        assertEquals(pin,projected.q583PreparedNoStartPredecessor)
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
