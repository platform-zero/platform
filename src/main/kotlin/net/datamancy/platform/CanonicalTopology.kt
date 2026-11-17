package net.datamancy.platform

import kotlinx.serialization.Serializable

@Serializable internal data class CanonicalProvider(val product: String, val process: String, val state: List<String>)
@Serializable internal data class CanonicalNetwork(val network: String, val processes: List<String>)
@Serializable internal data class CanonicalInput(val input: String, val owner: String, val consumers: List<String>,
    val bootstrapOnly: Boolean)
@Serializable internal data class CanonicalTopologyReport(val assemblySha256: String, val providers: List<CanonicalProvider>,
    val networks: List<CanonicalNetwork>, val inputs: List<CanonicalInput>, val databaseAccess: List<SiteDatabaseInventory>,
    val capacity: GenerationCapacityPlan, val missingCapabilities: Set<String>, val complete: Boolean,
    val runtimeValidated: Boolean = false, val publicActivation: Boolean = false)
internal data class CanonicalAssemblyPlan(val assembly: AssemblyPlan, val topology: CanonicalTopologyReport)

/** Canonical compilation is stricter than the private recipe catalog. Primary capabilities alone
 * are insufficient: every support process must have a selected authoritative product, and central
 * providers must have exactly one daemon. Never deduplicate a fixture's storage/credentials by name.
 */
internal object CanonicalTopology {
    private val singletonProviders = setOf("postgres", "mariadb", "valkey", "memcached", "keycloak", "openbao", "ntfy")

    fun compile(plan: AssemblyPlan, requireComplete: Boolean = true): CanonicalAssemblyPlan {
        val inventory = SiteOwnerships.inspect(plan)
        val capabilities = plan.summary.members.flatMap { it.primaryCapabilities }.toSet()
        require(inventory.processes.all { it.compiledProduct != null && it.compiledProduct in capabilities }) {
            "Canonical assembly requires selected ownership of every support process; private provider copies are not canonical"
        }
        val daemons = inventory.processes.filterNot { it.oneShot }
        val providers = singletonProviders.sorted().mapNotNull { product ->
            val instances = daemons.filter { it.compiledProduct == product }
            require(instances.size == if (product in capabilities) 1 else 0) { "Canonical provider $product is missing or duplicated" }
            instances.singleOrNull()?.let { process -> CanonicalProvider(product, process.process,
                inventory.state.filter { process.process in it.writers }.map { it.volume }.sorted()) }
        }
        val byId = inventory.processes.associateBy { it.process }
        val inputs = inventory.inputs.map { input ->
            requireNotNull(input.compiledProduct) { "Unresolved shared canonical input ownership" }
            CanonicalInput(input.input, input.compiledProduct, input.consumers,
                input.consumers.all { byId.getValue(it).oneShot })
        }
        // A bootstrap credential cannot become an ordinary daemon mount simply through composition.
        val bootstrapNames = setOf("postgres.env", "postgres-admin.env", "planka-bootstrap.env", "ntfy-bootstrap.env",
            "mariadb-bootstrap.env", "identity-db-admin.env", "identity-migration.env", "identity-realm.json",
            "firefly-db-admin.env", "firefly-migration.env", "planka-db-admin.env",
            "planka-migration.env", "mariadb-bootstrap.env")
        require(inputs.none { it.input.substringAfter('/') in bootstrapNames && !it.bootstrapOnly }) {
            "Canonical daemon consumes bootstrap or migration authority"
        }
        val missing = plan.summary.missingCapabilities
        require(!requireComplete || missing.isEmpty()) { "Canonical capability closure is incomplete: ${missing.sorted().joinToString()}" }
        val networks = plan.specs.flatMap { spec -> spec.networks.map { network ->
            CanonicalNetwork("${spec.name}/$network", spec.processes.filter { network in it.networks }.map { "${spec.name}/${it.id}" }.sorted())
        } }
        val managedMemory = GenerationManagedComponents.memoryReservationMiB(plan.generation)
        val capacity = GenerationCapacityPlanner.plan(plan.specs, plan.generation.diskReservationMiB, plan.generation.workingBudget).let { base ->
            if (managedMemory == 0L) base else base.copy(
                steady = base.steady + GenerationResources(managedMemory, 0, 0),
                install = base.install + GenerationResources(managedMemory, 0, 0))
        }
        return CanonicalAssemblyPlan(plan, CanonicalTopologyReport(inventory.assemblySha256, providers, networks, inputs,
            inventory.databaseAccess, capacity,
            missing, missing.isEmpty()))
    }

    /** Deterministic exact ownership for a canonical graph. Network database writers merge their
     * mounted volumes with the provider's physical state; separate recovery groups cannot split them.
     * Routes are still explicit caller requests, checked against an exact approved host set.
     */
    fun ownership(compiled: CanonicalAssemblyPlan, site: String, routes: List<SiteRouteOwner>, approvedHosts: Set<String>): SiteOwnership {
        if (CanonicalSharedYamlGraph.manifest().scope == "full-private" &&
            compiled.assembly.summary.request.selections.any { it.recipe == CanonicalSharedYamlGraph.RECIPE })
            require(routes == compiled.assembly.summary.request.portalRoutes) {
                "Portal links and effective private route owners must be the same sealed cohort"
            }
        val fullRecipe = compiled.assembly.summary.request.selections.singleOrNull()?.recipe
        if (fullRecipe in setOf(CanonicalSharedYamlGraph.R9_ASSEMBLY_RECIPE,
                CanonicalSharedYamlGraph.R10_ASSEMBLY_RECIPE) || CanonicalSharedYamlGraph.manifest().revision == 9) {
            val manifest = when (fullRecipe) {
                CanonicalSharedYamlGraph.R9_ASSEMBLY_RECIPE -> PackagedGraphFragment.pendingV3R9().first
                CanonicalSharedYamlGraph.R10_ASSEMBLY_RECIPE -> PackagedGraphFragment.pendingV3R10().first
                else -> CanonicalSharedYamlGraph.manifest()
            }
            val expected = CanonicalGraphCaddyfile.siteRoutes(manifest,
                compiled.assembly.specs.single { spec -> spec.processes.any { it.id == "caddy" } })
            require(routes.sortedBy { it.host } == expected &&
                approvedHosts == requireNotNull(manifest.integratedReference).modules.flatMap {
                    it.privateRoutes.map(CanonicalIngressRoute::host)
                }.toSet()) { "Full selected site authority must equal graph routes and every explicit private host" }
        } else require(approvedHosts.all { it.endsWith(".datamancy.net") && '*' !in it && it != "datamancy.net" }) {
            "Canonical sites require exact approved datamancy.net hosts"
        }
        // Recompile instead of trusting a caller-constructed CanonicalAssemblyPlan/report.
        val checked = compile(compiled.assembly, false)
        require(checked.topology == compiled.topology) { "Canonical topology changed" }
        val graph = SiteOwnerships.inspect(compiled.assembly)
        val owners = graph.processes.associate { it.process to requireNotNull(it.compiledProduct) }
        val parent = graph.state.associate { it.volume to it.volume }.toMutableMap()
        fun root(value: String): String {
            var at = value
            while (parent.getValue(at) != at) at = parent.getValue(at)
            return at
        }
        fun join(volumes: List<String>) {
            if (volumes.isEmpty()) return
            val first = root(volumes.first())
            volumes.drop(1).forEach { parent[root(it)] = first }
        }
        graph.processes.forEach { process -> join(graph.state.filter {
            process.process in it.writers || process.process in it.networkWriters
        }.map { it.volume }) }
        val groups = graph.state.map { root(it.volume) }.distinct().sorted().withIndex().associate { it.value to "state-${it.index + 1}" }
        val contract = SiteOwnership(site = site, assemblySha256 = graph.assemblySha256,
            processes = owners.map { SiteProcessOwner(it.key, it.value) },
            state = graph.state.map { state -> SiteStateOwner(state.volume, owners.getValue(state.writers.first()), groups.getValue(root(state.volume))) },
            inputs = graph.inputs.map { SiteInputOwner(it.input, requireNotNull(it.compiledProduct), true, it.consumers) },
            routes = routes, managed = GenerationManagedComponents.ownership(compiled.assembly.generation))
        SiteOwnerships.check(compiled.assembly, contract, approvedHosts)
        return contract
    }
}
