package net.datamancy.platform

import java.nio.file.Path
import kotlin.test.*

class PrivateAssembledStackGapTest {
    @Test fun `independent private providers cannot hide duplicate PostgreSQL behind distinct recipe capabilities`() {
        val bytes = GenerationAssembly.readInventory(Path.of("release/downloaded-candidate-inventory.json"))
        val request = AssemblyRequest(id = "q-abcdef123456", candidateSha256 = "a".repeat(64),
            inventorySha256 = ReleaseLocks.sha256(bytes),
            selections = listOf(AssemblySelection("foundation"), AssemblySelection("identity")),
            diskReservationMiB = 131072, store = RuntimeStore.CANONICAL_V2)
        val plan = GenerationAssembly().plan(request, bytes)
        val gap = PrivateAssembledStackGapReport.inspect(plan)
        assertEquals(2, gap.singletonProviderDuplicates.getValue("postgres").size)
        assertTrue(gap.singletonProviderDuplicates.getValue("postgres").any { it.contains("foundation/postgres") })
        assertTrue(gap.singletonProviderDuplicates.getValue("postgres").any { it.contains("identity/postgres") })
        assertFalse(gap.isFullAssembledInstallAdmitted)
        assertFails { CanonicalTopology.compile(plan, false) }
    }
    @Test fun `unfrozen multi-member graph reports real missing journeys and never grants assembled installation`() {
        val bytes = GenerationAssembly.readInventory(Path.of("release/downloaded-candidate-inventory.json"))
        val request = AssemblyRequest(id = "q-abcdef123456", candidateSha256 = "a".repeat(64),
            inventorySha256 = ReleaseLocks.sha256(bytes),
            selections = listOf(AssemblySelection("foundation"), AssemblySelection("sql-cache", listOf("foundation"))),
            diskReservationMiB = 131072, store = RuntimeStore.CANONICAL_V2)
        val gap = PrivateAssembledStackGapReport.inspect(GenerationAssembly().plan(request, bytes))
        assertEquals(2, gap.selectedMembers)
        assertEquals(1, gap.declaredCrossMemberDependencies)
        assertEquals(gap.declaredSteadyMemoryMiB, gap.declaredSteadyMemoryByMemberMiB.values.sum())
        assertEquals(gap.selectedMembers, gap.declaredSteadyMemoryByMemberMiB.size)
        assertEquals(gap.declaredInstallPeakMemoryMiB + request.memoryHeadroomMiB,
            gap.minimumAvailableMemoryForInstallMiB)
        assertEquals(request.diskReservationMiB + request.diskHeadroomMiB,
            gap.minimumUsableDiskForInstallMiB)
        assertEquals(ProductSelection.bundled().products.size, gap.requiredProducts)
        assertTrue(gap.missingCapabilities.containsAll(setOf("forgejo", "worklane", "tuios", "pi")))
        assertEquals(setOf("q-abcdef123456-foundation", "q-abcdef123456-sql-cache"), gap.nonQuadletMembers.toSet())
        assertContains(gap.missingAcceptanceJourneys, "restored-original-account-authentication")
        assertContains(gap.missingAcceptanceJourneys, "CI-runner-build-and-evidence")
        assertContains(gap.missingAcceptanceJourneys, "real-private-onboarding")
        assertFalse(gap.isFullAssembledInstallAdmitted)
        assertFalse(gap.candidateFrozen)
        assertFalse(gap.qualificationPass)
    }
}
