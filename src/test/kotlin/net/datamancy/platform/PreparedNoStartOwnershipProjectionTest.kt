package net.datamancy.platform

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class PreparedNoStartOwnershipProjectionTest {
    @Test fun `site owner projection keeps exact prepared predecessor before any owned prepare`() {
        val predecessor=ActivationInput("/mnt/media/p0-v3/release-generations/q-5712d9335843/prepared-no-start-v2.disposition.json",
            "6f7b62cc78299a4e4ca365ffea595411165e7e33917d6ae160abd439a36ce6ef")
        val request=AssemblyRequest(id="q-dd36ebcf43ef",candidateSha256="a".repeat(64),
            inventorySha256="b".repeat(64),
            selections=listOf(AssemblySelection(CanonicalSharedYamlGraph.R10_ASSEMBLY_RECIPE)),
            diskReservationMiB=131072,store=RuntimeStore.CANONICAL_V2,
            preparedNoStartPredecessor=predecessor,
            failedPreUnitStagePredecessor=ActivationInput(
                "/mnt/media/p0-v3/release-generations/q-dd36ebcf43ef/failed-pre-unit-stage-v1.disposition.json",
                "1ffd7dea5f9b6c5141f19d263e9f817ceaf9180ce39d413579fa06e94bfd0ee3"))
        val projected=SiteOwnerships.project(request)
        assertEquals(predecessor,projected.preparedNoStartPredecessor)
        assertEquals(request.failedPreUnitStagePredecessor,projected.failedPreUnitStagePredecessor)
        assertEquals(request.id,projected.id)
        assertEquals(request.candidateSha256,projected.candidateSha256)
        assertNotEquals(SiteOwnerships.project(request.copy(preparedNoStartPredecessor=null)),projected)
        assertNotEquals(SiteOwnerships.project(request.copy(failedPreUnitStagePredecessor=null)),projected)
    }
}
