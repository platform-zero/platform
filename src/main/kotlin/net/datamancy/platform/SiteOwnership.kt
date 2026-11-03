package net.datamancy.platform

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** References describe compiled resources, never arbitrary host paths or credential values. */
@Serializable internal data class SiteProcessOwner(val process: String, val product: String)
@Serializable internal data class SiteStateOwner(val volume: String, val product: String, val recoveryGroup: String)
@Serializable internal data class SiteInputOwner(val input: String, val product: String, val credential: Boolean,
    val consumers: List<String>)
@Serializable internal data class SiteRouteOwner(val host: String, val product: String, val process: String, val port: Int)
@Serializable internal data class SiteOwnership(val schemaVersion: Int = 1, val site: String,
    val assemblySha256: String, val processes: List<SiteProcessOwner>, val state: List<SiteStateOwner>,
    val inputs: List<SiteInputOwner>, val routes: List<SiteRouteOwner>)
@Serializable internal data class SiteOwnershipReport(val site: String, val assemblySha256: String,
    val ownershipSha256: String, val missingCapabilities: Set<String>,
    val serviceArtifactProcesses: Map<String, List<String>>, val repeatedServiceArtifacts: Map<String, List<String>>,
    val unclassifiedDaemonArtifacts: List<String>, val unverifiedProcessRoles: List<String>, val recoveryGroups: Map<String, List<String>>,
    val executable: Boolean = false, val centralWiringVerified: Boolean = false, val publicActivation: Boolean = false)

@Serializable internal data class SiteProcessInventory(val process: String, val image: String, val imageId: String,
    val artifactProducts: List<String>, val oneShot: Boolean, val dependencies: List<String>, val compiledProduct: String? = null)
/** writers are mount writers only; networkWriters are distinct logical database consumers. */
@Serializable internal data class SiteVolumeInventory(val volume: String, val userId: Int, val writers: List<String>,
    val networkWriters: List<String> = emptyList())
@Serializable internal data class SiteDatabaseInventory(val member: String, val access: RuntimeDatabaseAccess)
@Serializable internal data class SiteInputInventory(val input: String, val consumers: List<String>, val compiledProduct: String? = null)
@Serializable internal data class SiteOwnershipInventory(val assemblySha256: String, val missingCapabilities: Set<String>,
    val processes: List<SiteProcessInventory>, val state: List<SiteVolumeInventory>, val inputs: List<SiteInputInventory>,
    val repeatedServiceArtifacts: Map<String, List<String>>, val unclassifiedDaemons: List<String>,
    val memoryReservationMiB: Long? = null, val executable: Boolean = false,
    val databaseAccess: List<SiteDatabaseInventory> = emptyList())

@Serializable internal data class BoundSiteOwnership(val assembly: AssemblySummary, val contract: SiteOwnership,
    val approvedHosts: Set<String>)

/** Exact ownership contracts for typed assemblies. Structural validity is NOT central network/identity wiring. */
internal object SiteOwnerships {
    private val json = Json { ignoreUnknownKeys = false }
    private val compiledRoles = CompiledProcessOwners.recipes
    private val slug = Regex("[a-z][a-z0-9-]{0,63}")
    private val hostname = Regex("[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?(?:\\.[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?)+")
    // Same representation as GenerationRuntime's durable assembly.intent.json, including defaults.
    private val assemblyJson = Json { encodeDefaults = true }
    fun assemblyDigest(plan: AssemblyPlan): String = ReleaseLocks.sha256(assemblyJson.encodeToString(plan.summary).toByteArray())
    fun decode(bytes: ByteArray): SiteOwnership {
        require(bytes.size in 1..1048576) { "Missing or oversized site ownership contract" }
        return json.decodeFromString(bytes.decodeToString(throwOnInvalidSequence = true))
    }
    private fun project(request: AssemblyRequest) = GenerationRequest(schemaVersion = request.schemaVersion,
        id = request.id, candidateSha256 = request.candidateSha256,
        members = request.selections.map { GenerationMember("${request.id}-${it.recipe}", it.dependencies.map { d -> "${request.id}-$d" }) },
        diskReservationMiB = request.diskReservationMiB, memoryHeadroomMiB = request.memoryHeadroomMiB,
        diskHeadroomMiB = request.diskHeadroomMiB, purpose = request.purpose, store = request.store, rssPlan = request.rssPlan)
    fun bind(plan: AssemblyPlan, contract: SiteOwnership, approvedHosts: Set<String>,
        update: OwnedUpdateLineage? = null): BoundSiteOwnership {
        // Snapshot caller-owned collections before preparation callbacks can run.
        val binding = json.decodeFromString<BoundSiteOwnership>(json.encodeToString(BoundSiteOwnership(plan.summary, contract, approvedHosts)))
        val projected = project(binding.assembly.request)
        GenerationRssPlan.validateOwnership(projected, binding)
        require(projected == plan.generation && GenerationRuntime.validateScope(projected) ==
            binding.assembly.members.map { GenerationMember(it.name, it.dependencies) }) { "Ownership generation identity differs from compiled assembly" }
        val report = check(plan.copy(summary = binding.assembly), binding.contract, binding.approvedHosts, update)
        require(report.unverifiedProcessRoles.isEmpty()) { "Ownership-bound preparation requires explicit compiled roles for every process" }
        return binding
    }
    fun checkSealed(bundle: GenerationBundle) {
        GenerationRssPlan.validateOwnership(bundle.request, bundle.ownership)
        val binding = bundle.ownership ?: return
        val projected = project(binding.assembly.request)
        require(bundle.recoverySourceArchiveSha256 == null && bundle.recoverySourceKopia == null && projected == bundle.request &&
            GenerationRuntime.validateScope(projected) == bundle.members.map { it.member } &&
            bundle.assemblySha256 == binding.contract.assemblySha256) { "Foreign or inherited live site ownership" }
        val plan = AssemblyPlan(binding.assembly, bundle.request, AcquiredInventory(1, "ownership-validation-only", emptyList()),
            bundle.members.map { it.spec }, emptyList())
        val report = check(plan, binding.contract, binding.approvedHosts, bundle.ownedUpdate)
        require(report.unverifiedProcessRoles.isEmpty()) { "Unverified sealed process ownership" }
    }
    private fun bound(plan: AssemblyPlan) {
        require(plan.specs.map { it.name } == plan.summary.members.map { it.name } && plan.specs.zip(plan.summary.members).all { (spec, member) ->
            ReleaseLocks.sha256(json.encodeToString(spec).toByteArray()) == member.specSha256
        }) { "Compiled specifications differ from assembly binding" }
    }
    private fun roles(plan: AssemblyPlan): Map<String, String> = plan.summary.members.flatMap { member ->
        compiledRoles[member.recipe].orEmpty().map { (id, product) -> "${member.name}/$id" to product }
    }.toMap()
    /** Read-only planning inventory: no owner guesses for unknown derived images and no credentials generated. */
    fun inspect(plan: AssemblyPlan): SiteOwnershipInventory {
        bound(plan)
        val artifacts = plan.inventory.images.groupBy { it.pinnedImage to it.imageId }
        val roles = roles(plan)
        val processes = plan.specs.flatMap { m -> m.processes.map { p -> SiteProcessInventory("${m.name}/${p.id}", p.image, p.imageId,
            artifacts[p.image to p.imageId].orEmpty().map { it.product }.distinct().sorted(), p.oneShot,
            p.dependencies.map { "${m.name}/$it" }, roles["${m.name}/${p.id}"]) } }
        val state = plan.specs.flatMap { m -> m.volumes.map { v -> SiteVolumeInventory("${m.name}/${v.id}", v.userId,
            m.processes.filter { p -> p.volumes.any { it.volume == v.id } }.map { "${m.name}/${it.id}" }.sorted(),
            m.databaseAccess.filter { it.volume == v.id }.map { "${m.name}/${it.consumer}" }.sorted()) } }
        val recipes = plan.summary.members.associate { it.name to it.recipe }
        val inputs = plan.specs.flatMap { m -> PrivateDeployment.inputNames(m).map { file ->
            val consumers = m.processes.filter { it.environmentFile == file || it.files.any { f -> f.file == file } }.map { "${m.name}/${it.id}" }.sorted()
            SiteInputInventory("${m.name}/$file", consumers,
                CompiledProcessOwners.inputOwner(recipes.getValue(m.name), file, consumers.map { roles[it] }.toSet()))
        } }
        val known = processes.filter { !it.oneShot && it.artifactProducts.size == 1 && it.artifactProducts.single() in GenerationAssembly.requiredCapabilities }
        val repeated = known.groupBy { it.artifactProducts.single() }.filterValues { it.size > 1 }.toSortedMap()
            .mapValues { (_, actors) -> actors.map { it.process }.sorted() }
        return SiteOwnershipInventory(assemblyDigest(plan), plan.summary.missingCapabilities, processes, state, inputs,
            repeated, processes.filter { !it.oneShot && it !in known }.map { it.process }.sorted(),
            plan.specs.sumOf { spec -> spec.processes.filterNot { it.oneShot }.sumOf { it.memoryMiB.toLong() } +
                (spec.processes.filter { it.oneShot }.maxOfOrNull { it.memoryMiB } ?: 0) },
            databaseAccess = plan.specs.flatMap { m -> m.databaseAccess.map { SiteDatabaseInventory(m.name, it) } })
    }
    /** Only snapshot-authenticated original initializers may disappear from an owned update.
     * Fresh installs still require the complete compiled role map. Recovery carries no site authority.
     */
    private fun updateRoles(plan: AssemblyPlan, contract: SiteOwnership, approvedHosts: Set<String>,
        update: OwnedUpdateLineage): Map<String, String> {
        val source = OwnedReleaseUpdates.original(update)
        val owner = requireNotNull(source.ownership)
        val intent = update.intent
        require(plan.generation.id == intent.targetGeneration && plan.generation.candidateSha256 == intent.candidateSha256 &&
            plan.generation.store == RuntimeStore.CANONICAL_V2 &&
            plan.summary.request.inventorySha256 == intent.candidateInventorySha256 && approvedHosts == owner.approvedHosts) {
            "Owned update changed generation, candidate or approved site authority"
        }
        fun rename(value: String): String {
            require(value.startsWith(source.request.id + "-")) { "Foreign original ownership reference" }
            return intent.targetGeneration + value.removePrefix(source.request.id)
        }
        require(plan.specs.map { it.name } == source.members.map { rename(it.spec.name) } &&
            plan.specs.zip(source.members).all { (spec, old) -> spec.volumes == old.spec.volumes && spec.networks == old.spec.networks }) {
            "Owned update changed state or network ownership"
        }
        val daemons = source.members.flatMap { pin -> pin.spec.processes.filterNot { it.oneShot }.map { rename("${pin.spec.name}/${it.id}") } }.toSet()
        val actors = plan.specs.flatMap { spec -> spec.processes.map { "${spec.name}/${it.id}" } }.toSet()
        require(actors == daemons && plan.specs.all { spec -> spec.processes.none { it.oneShot } }) {
            "Owned update must retain every original daemon and retire all original initializers"
        }
        val inputs = plan.specs.flatMap { spec -> PrivateDeployment.inputNames(spec).map { "${spec.name}/$it" } }.toSet()
        val expected = owner.contract.copy(assemblySha256 = contract.assemblySha256,
            processes = owner.contract.processes.map { it.copy(process = rename(it.process)) }.filter { it.process in actors },
            state = owner.contract.state.map { it.copy(volume = rename(it.volume)) },
            inputs = owner.contract.inputs.map { it.copy(input = rename(it.input), consumers = it.consumers.map(::rename).filter(actors::contains)) }
                .filter { it.input in inputs },
            routes = owner.contract.routes.map { it.copy(process = rename(it.process)) })
        require(contract == expected) { "Owned update expanded or reassigned original site ownership" }
        val retired = source.members.flatMap { pin -> pin.spec.processes.filter { it.oneShot }.map { rename("${pin.spec.name}/${it.id}") } }.toSet()
        return roles(plan).filterKeys { it !in retired }
    }

    fun check(plan: AssemblyPlan, contract: SiteOwnership, approvedHosts: Set<String>,
        update: OwnedUpdateLineage? = null): SiteOwnershipReport {
        require(contract.schemaVersion == 1 && slug.matches(contract.site) && contract.assemblySha256 == assemblyDigest(plan)) {
            "Site ownership is not bound to this compiled assembly"
        }
        require(approvedHosts.size <= 64 && approvedHosts.all(hostname::matches)) { "Invalid site host boundary" }
        bound(plan)
        val members = plan.specs.associateBy { it.name }
        val processes = plan.specs.flatMap { member -> member.processes.map { "${member.name}/${it.id}" to it } }.toMap()
        val volumes = plan.specs.flatMap { member -> member.volumes.map { "${member.name}/${it.id}" } }.toSet()
        val inputs = plan.specs.flatMap { member -> PrivateDeployment.inputNames(member).map { "${member.name}/$it" } }.toSet()
        fun exact(actual: List<String>, expected: Set<String>, kind: String) {
            require(actual.size == expected.size && actual.toSet() == expected) { "Exact unique $kind ownership required" }
        }
        exact(contract.processes.map { it.process }, processes.keys, "process")
        exact(contract.state.map { it.volume }, volumes, "state")
        exact(contract.inputs.map { it.input }, inputs, "input")
        val capabilities = plan.summary.members.flatMap { it.primaryCapabilities }.toSet()
        require((contract.processes.map { it.product } + contract.state.map { it.product } +
            contract.inputs.map { it.product } + contract.routes.map { it.product }).all { it in capabilities }) {
            "Ownership references a product absent from this assembly"
        }
        val owners = contract.processes.associate { it.process to it.product }
        require(owners.values.toSet() == capabilities) { "Every selected capability needs an explicit process owner" }
        val roles = roles(plan)
        val requiredRoles = if (update == null) roles else updateRoles(plan, contract, approvedHosts, update)
        require(requiredRoles.all { (actor, product) -> owners[actor] == product }) { "Ownership differs from compiled service role" }
        val stateByVolume = contract.state.associateBy { it.volume }
        contract.state.forEach { require(slug.matches(it.recoveryGroup)) { "Invalid recovery group" } }
        plan.specs.forEach { member ->
            member.processes.forEach { process ->
                val actor = "${member.name}/${process.id}"
                val states = process.volumes.map { stateByVolume.getValue("${member.name}/${it.volume}") }
                require(states.all { it.product == owners.getValue(actor) }) { "State writer differs from authoritative owner" }
                val logical = member.databaseAccess.filter { it.consumer == process.id }.map {
                    stateByVolume.getValue("${member.name}/${it.volume}")
                }
                require((states + logical).map { it.recoveryGroup }.distinct().size <= 1) { "One writer crosses recovery groups" }
            }
        }
        contract.inputs.forEach { input ->
            val memberName = input.input.substringBefore('/')
            val file = input.input.substringAfter('/')
            val expected = members.getValue(memberName).processes.filter { p ->
                p.environmentFile == file || p.files.any { it.file == file }
            }.map { "$memberName/${it.id}" }.toSet()
            exact(input.consumers, expected, "input consumer")
            val products = expected.map { roles[it] }.toSet()
            val recipe = plan.summary.members.single { it.name == memberName }.recipe
            val compiledOwner = if (update != null && products.isNotEmpty() && null !in products)
                CompiledProcessOwners.sharedInputs[recipe]?.get(file) ?: CompiledProcessOwners.inputOwner(recipe, file, products)
            else CompiledProcessOwners.inputOwner(recipe, file, products)
            // Retiring a provider's initializer can leave its CA consumed only by clients.
            // Preserve the authenticated original owner, never reassign trust to a consumer.
            val retainedProviderInput = update != null && null !in products && compiledOwner == input.product &&
                input.product in owners.values
            require(input.consumers.any { owners.getValue(it) == input.product } || retainedProviderInput) {
                "Input owner is not a declared consumer or authenticated surviving provider"
            }
            if (null !in products) {
                require(compiledOwner != null && input.product == compiledOwner) { "Missing or conflicting compiled input ownership" }
            }
        }
        require(contract.routes.size <= 64 && contract.routes.map { it.host }.distinct().size == contract.routes.size) {
            "Duplicate or excessive site routes"
        }
        contract.routes.forEach { route ->
            val process = processes[route.process]
            require(hostname.matches(route.host) && route.host in approvedHosts && process != null && !process.oneShot &&
                route.port in 1..65535 && owners[route.process] == route.product) { "Unapproved or foreign site route" }
        }
        // Exact image+local-ID identity only. Unknown derived artifacts remain unclassified, never inferred from a name.
        val artifacts = plan.inventory.images.groupBy { it.pinnedImage to it.imageId }
        val instances = sortedMapOf<String, MutableList<String>>()
        val unknown = mutableListOf<String>()
        processes.filterValues { !it.oneShot }.toSortedMap().forEach { (actor, process) ->
            val products = artifacts[process.image to process.imageId]?.map { it.product }?.distinct().orEmpty()
            if (products.size != 1) unknown += actor else {
                val product = products.single()
                if (product in GenerationAssembly.requiredCapabilities) {
                    // Image provenance is not service identity: generic artifacts can legitimately serve other roles.
                    instances.getOrPut(product) { mutableListOf() } += actor
                } else unknown += actor
            }
        }
        return SiteOwnershipReport(contract.site, contract.assemblySha256,
            ReleaseLocks.sha256(json.encodeToString(contract).toByteArray()), plan.summary.missingCapabilities,
            instances, instances.filterValues { it.size > 1 }, unknown.sorted(), (processes.keys - roles.keys).sorted(),
            contract.state.groupBy { it.recoveryGroup }.toSortedMap().mapValues { (_, states) -> states.map { it.volume }.sorted() })
    }
}
