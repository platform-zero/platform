package net.datamancy.platform

import kotlinx.serialization.Serializable

@Serializable internal data class PrivateAssembledStackGap(val assemblySha256: String,
    val selectedMembers: Int, val selectedProcesses: Int, val pinnedArtifactsUsed: Int,
    val requiredProducts: Int, val missingCapabilities: List<String>,
    val unclassifiedDaemons: List<String>, val singletonProviderDuplicates: Map<String, List<String>>,
    val nonQuadletMembers: List<String>, val declaredCrossMemberDependencies: Int,
    val declaredSteadyMemoryMiB: Long, val declaredInstallPeakMemoryMiB: Long,
    val declaredSteadyMemoryByMemberMiB: Map<String, Long>,
    val minimumAvailableMemoryForInstallMiB: Long, val declaredObjectLocks: Long,
    val declaredDiskReservationMiB: Long, val minimumUsableDiskForInstallMiB: Long,
    val missingAcceptanceJourneys: List<String>,
    val isFullAssembledInstallAdmitted: Boolean = false,
    val candidateFrozen: Boolean = false, val qualificationPass: Boolean = false,
    val publicActivation: Boolean = false)

/** Offline preview, never an installation grant. Identifies the real shared
 * provider conflicts and unported backends before credentials, source state,
 * image pulls or systemd units are touched.
 */
internal object PrivateAssembledStackGapReport {
    fun inspect(plan: AssemblyPlan): PrivateAssembledStackGap {
        val owned = SiteOwnerships.inspect(plan)
        val singleton = setOf("postgres", "mariadb", "valkey", "memcached", "keycloak", "openbao", "ntfy")
        val duplicates = owned.processes.filterNot { it.oneShot }.filter { it.compiledProduct in singleton }
            .groupBy { requireNotNull(it.compiledProduct) }.filterValues { it.size > 1 }
            .mapValues { (_, values) -> values.map { it.process }.sorted() }.toSortedMap()
        val capacity = GenerationCapacityPlanner.plan(plan.specs, plan.generation.diskReservationMiB, plan.generation.workingBudget)
        val missingJourneys = listOf("restored-original-account-authentication", "restored-Git-repository-and-issues",
            "CI-runner-build-and-evidence", "real-private-onboarding", "product-functional-journeys",
            "qualification-producer-and-operator-trust", "two-fresh-full-install-and-isolated-restore-passes")
        return PrivateAssembledStackGap(assemblySha256 = owned.assemblySha256,
            selectedMembers = plan.specs.size,
            selectedProcesses = owned.processes.size,
            pinnedArtifactsUsed = owned.processes.map { it.image to it.imageId }.distinct().size,
            requiredProducts = ProductSelection.bundled().products.size,
            missingCapabilities = plan.summary.missingCapabilities.sorted(),
            unclassifiedDaemons = owned.unclassifiedDaemons.sorted(),
            singletonProviderDuplicates = duplicates,
            nonQuadletMembers = plan.specs.filter { it.executionBackend != RuntimeExecutionBackend.QUADLET_V2 }
                .map { it.name }.sorted(),
            declaredCrossMemberDependencies = plan.generation.members.sumOf { it.dependencies.size },
            declaredSteadyMemoryMiB = capacity.steady.memoryMiB,
            declaredInstallPeakMemoryMiB = capacity.install.memoryMiB,
            declaredSteadyMemoryByMemberMiB = plan.specs.associate { spec -> spec.name to
                spec.processes.filterNot { it.oneShot }.sumOf { it.memoryMiB.toLong() } }.toSortedMap()
                .also { require(it.values.sum() == capacity.steady.memoryMiB) },
            minimumAvailableMemoryForInstallMiB = Math.addExact(capacity.install.memoryMiB,
                plan.generation.memoryHeadroomMiB),
            declaredObjectLocks = capacity.install.objectLocks,
            declaredDiskReservationMiB = capacity.install.diskMiB,
            minimumUsableDiskForInstallMiB = Math.addExact(capacity.install.diskMiB,
                plan.generation.diskHeadroomMiB),
            missingAcceptanceJourneys = missingJourneys)
    }
}
