package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable internal data class AssemblySelection(val recipe: String, val dependencies: List<String> = emptyList())
@Serializable internal data class AssemblyRequest(val schemaVersion: Int = 1, val id: String,
    val candidateSha256: String, val inventorySha256: String, val selections: List<AssemblySelection>,
    val diskReservationMiB: Long, val memoryHeadroomMiB: Long = 16384, val diskHeadroomMiB: Long = 10240,
    val purpose: String = "private-component-integration",
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val store: RuntimeStore = RuntimeStore.LEGACY,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val rssPlan: GenerationRssPlan? = null)
@Serializable internal data class AssemblyState(val id: String, val userId: Int, val potentialWriters: List<String>)
@Serializable internal data class AssemblyInput(val name: String, val consumers: List<String>)
@Serializable internal data class AssemblyMember(val recipe: String, val name: String, val dependencies: List<String>,
    val primaryCapabilities: Set<String>, val specSha256: String, val images: Map<String, String>,
    val daemons: List<String>, val initializers: List<String>, val state: List<AssemblyState>, val inputs: List<AssemblyInput>)
@Serializable internal data class AssemblySummary(val request: AssemblyRequest, val members: List<AssemblyMember>,
    val missingCapabilities: Set<String>, val globalIntegrationValidated: Boolean = false,
    val fullStackQualification: Boolean = false, val publicActivation: Boolean = false)
@Serializable internal data class AssemblyPreparationOutcome(val assemblySha256: String, val passed: Boolean,
    val bundleSha256: String? = null, val failureType: String? = null)
@Serializable internal data class AssemblyMemberIntent(val assemblySha256: String, val name: String, val specSha256: String)
internal data class PrivateRecipe(val id: String, val capabilities: Set<String>,
    val spec: (AcquiredInventory, String) -> PrivateDeploymentSpec,
    val prepare: (AcquiredInventory, Path, String, RuntimeStore) -> Path)
internal data class AssemblyPlan(val summary: AssemblySummary, val generation: GenerationRequest,
    val inventory: AcquiredInventory, val specs: List<PrivateDeploymentSpec>, val recipes: List<PrivateRecipe>)

/** Typed existing PRIVATE recipes. Supporting database/identity copies are NOT central release wiring. */
internal class GenerationAssembly(private val recipes: List<PrivateRecipe> = catalog) {
    companion object {
        private val json = Json { ignoreUnknownKeys = false }
        val requiredCapabilities: Set<String> = ProductSelection.bundled().products.toSet() +
            setOf("openbao", "keykeeper", "worklane", "tuios", "pi")
        val catalog: List<PrivateRecipe> = listOf(
            PrivateRecipe("foundation", setOf("postgres", "valkey", "ntfy"), FoundationRuntime::spec, FoundationRuntime::prepare),
            PrivateRecipe("canonical-core", setOf("postgres", "valkey", "ntfy", "planka"), CanonicalCoreRuntime::spec, CanonicalCoreRuntime::prepare),
            PrivateRecipe("canonical-providers", setOf("postgres", "valkey", "ntfy", "planka", "mariadb", "memcached", "keycloak", "firefly-iii", "caddy"),
                CanonicalCoreRuntime::providersSpec, CanonicalCoreRuntime::prepareProviders),
            PrivateRecipe("identity", setOf("keycloak"), IdentityRuntime::spec, IdentityRuntime::prepare),
            PrivateRecipe("caddy", setOf("caddy"), CaddyRuntime::spec, CaddyRuntime::prepare),
            PrivateRecipe("observability", setOf("alertmanager", "alloy", "grafana", "loki", "prometheus"), ObservabilityRuntime::spec, ObservabilityRuntime::prepare),
            PrivateRecipe("forgejo", setOf("forgejo"), ForgejoRuntime::spec, ForgejoRuntime::prepare),
            PrivateRecipe("planka", setOf("planka"), PlankaRuntime::spec, PlankaRuntime::prepare),
            PrivateRecipe("sql-cache", setOf("mariadb", "memcached"), SqlCacheRuntime::spec, SqlCacheRuntime::prepare),
            PrivateRecipe("jellyfin", setOf("jellyfin"), JellyfinRuntime::spec, JellyfinRuntime::prepare),
            PrivateRecipe("donetick", setOf("donetick"), DonetickRuntime::spec, DonetickRuntime::prepare),
            PrivateRecipe("homeassistant", setOf("homeassistant"), HomeAssistantRuntime::spec, HomeAssistantRuntime::prepare),
            PrivateRecipe("notebook", setOf("jupyter-notebook"), NotebookRuntime::spec, NotebookRuntime::prepare),
            PrivateRecipe("qbittorrent", setOf("qbittorrent"), QbittorrentRuntime::spec, QbittorrentRuntime::prepare),
            PrivateRecipe("synapse", setOf("synapse"), SynapseRuntime::spec, SynapseRuntime::prepare),
            PrivateRecipe("matrix", setOf("synapse", "element"), MatrixRuntime::spec, MatrixRuntime::prepare),
            PrivateRecipe("matrix-identity", setOf("synapse", "element", "matrix-authentication-service"), MatrixIdentityRuntime::spec, MatrixIdentityRuntime::prepare),
            PrivateRecipe("matrix-rtc", setOf("synapse", "element", "matrix-authentication-service", "livekit"), MatrixRtcRuntime::spec, MatrixRtcRuntime::prepare),
            PrivateRecipe("opensearch", setOf("opensearch"), OpenSearchRuntime::spec, OpenSearchRuntime::prepare),
            PrivateRecipe("firefly", setOf("firefly-iii"), FireflyRuntime::spec, FireflyRuntime::prepare),
            PrivateRecipe("bookstack", setOf("bookstack"), BookStackRuntime::spec, BookStackRuntime::prepare),
            PrivateRecipe("knowledge-identity", setOf("bookstack"), KnowledgeIdentityRuntime::spec, KnowledgeIdentityRuntime::prepare),
            PrivateRecipe("livekit", setOf("livekit"), LiveKitRuntime::spec, LiveKitRuntime::prepare),
            PrivateRecipe("openbao", setOf("openbao"), OpenBaoRuntime::spec, OpenBaoRuntime::prepare),
            PrivateRecipe("mastodon", setOf("mastodon"), MastodonRuntime::spec, MastodonRuntime::prepare),
            PrivateRecipe("searxng", setOf("searxng"), SearxngRuntime::spec, SearxngRuntime::prepare),
            PrivateRecipe("erpnext", setOf("erpnext"), ErpNextRuntime::spec, ErpNextRuntime::prepare),
            PrivateRecipe("crowdsec", setOf("crowdsec"), CrowdsecRuntime::spec, CrowdsecRuntime::prepare),
            PrivateRecipe("seafile", setOf("seafile"), SeafileRuntime::spec, SeafileRuntime::prepare),
            PrivateRecipe("office", setOf("seafile", "onlyoffice"), OfficeRuntime::spec, OfficeRuntime::prepare),
            PrivateRecipe("keykeeper", setOf("keykeeper", "openbao"), KeykeeperRuntime::spec, KeykeeperRuntime::prepare),
            PrivateRecipe("node-metrics", setOf("node-exporter"), NodeMetricsRuntime::spec, NodeMetricsRuntime::prepare),
            PrivateRecipe("backup", setOf("kopia"), KopiaRuntime::spec, KopiaRuntime::prepare),
            PrivateRecipe("huly", setOf("huly"), HulyRuntime::spec, HulyRuntime::prepare),
            PrivateRecipe("jupyterhub", setOf("jupyterhub"), JupyterHubRuntime::spec, JupyterHubRuntime::prepare),
            PrivateRecipe("sogo", setOf("sogo"), { inventory, name -> SogoRuntime.spec(inventory, name) }, SogoRuntime::prepare),
            PrivateRecipe("mail", setOf("mailserver"), { _, name -> MailRuntime.spec(name) }, { _, base, name, store -> MailRuntime.prepare(base, name, store) }),
            PrivateRecipe("sogo-mail", setOf("sogo", "mailserver"), SogoMailRuntime::spec, SogoMailRuntime::prepare)
        )
        fun readRequest(path: Path): AssemblyRequest = json.decodeFromString(
            GenerationRuntime.privateInput(path).decodeToString(throwOnInvalidSequence = true))
        fun readInventory(path: Path): ByteArray {
            require(Files.isRegularFile(path) && Files.size(path) in 1..2000000) { "Missing or oversized artifact inventory" }
            return Files.readAllBytes(path)
        }
    }

    fun canonicalPlan(request: AssemblyRequest, inventoryBytes: ByteArray, requireComplete: Boolean = true): CanonicalAssemblyPlan =
        CanonicalTopology.compile(plan(request, inventoryBytes), requireComplete)

    fun plan(request: AssemblyRequest, inventoryBytes: ByteArray): AssemblyPlan {
        require(request.schemaVersion == 1 && inventoryBytes.size in 1..2000000 &&
            ReleaseLocks.sha256(inventoryBytes) == request.inventorySha256) { "Assembly inventory binding mismatch" }
        val registry = recipes.associateBy { it.id }
        require(registry.size == recipes.size && recipes.all { recipe ->
            recipe.id.matches(Regex("[a-z][a-z0-9-]{0,23}")) && recipe.capabilities.isNotEmpty() &&
                requiredCapabilities.containsAll(recipe.capabilities)
        }) { "Invalid typed recipe registry" }
        require(request.selections.isNotEmpty() && request.selections.size <= 64 &&
            request.selections.map { it.recipe }.distinct().size == request.selections.size &&
            request.selections.all { it.recipe in registry }) { "Unknown or duplicate assembly recipe" }
        val capabilities = request.selections.flatMap { registry.getValue(it.recipe).capabilities }
        require(capabilities.distinct().size == capabilities.size) { "Conflicting primary product ownership; select one composite, not duplicate proofs" }
        val generation = GenerationRequest(id = request.id, candidateSha256 = request.candidateSha256,
            members = request.selections.map { selected -> GenerationMember("${request.id}-${selected.recipe}",
                selected.dependencies.map { "${request.id}-$it" }) }, diskReservationMiB = request.diskReservationMiB,
            memoryHeadroomMiB = request.memoryHeadroomMiB, diskHeadroomMiB = request.diskHeadroomMiB, purpose = request.purpose, store = request.store, rssPlan = request.rssPlan)
        val order = GenerationRuntime.validateScope(generation)
        val inventory = json.decodeFromString<AcquiredInventory>(inventoryBytes.decodeToString(throwOnInvalidSequence = true))
        require(inventory.schemaVersion == 1 && inventory.images.size in 1..256 &&
            inventory.images.map { it.product }.distinct().size == inventory.images.size) { "Invalid assembly inventory" }
        val adapters = order.map { registry.getValue(it.name.removePrefix("${request.id}-")) }
        // Resolve and validate EVERY recipe before generating ANY credentials or files.
        val specs = adapters.zip(order).map { (adapter, member) -> adapter.spec(inventory, member.name).copy(store = request.store).also {
            require(it.name == member.name) { "Recipe returned foreign namespace" }
            PrivateDeployment.validate(it)
        } }
        require(request.diskReservationMiB >= specs.sumOf { it.volumes.size.toLong() * 1024 } +
            (if (request.rssPlan != null) GenerationRssPlan.DISK_MIB else 0)) { "Assembly disk reservation below state minimum" }
        val members = specs.indices.map { index ->
            val spec = specs[index]
            val state = spec.volumes.map { volume ->
                val writers = spec.processes.filter { process -> process.volumes.any { it.volume == volume.id } }.map { it.id }.sorted()
                require(writers.isNotEmpty()) { "Unowned assembly state" }
                AssemblyState(volume.id, volume.userId, writers)
            }
            val inputs = PrivateDeployment.inputNames(spec).map { name -> AssemblyInput(name,
                spec.processes.filter { it.environmentFile == name || it.files.any { file -> file.file == name } }.map { it.id }.sorted()) }
            AssemblyMember(adapters[index].id, spec.name, order[index].dependencies, adapters[index].capabilities,
                ReleaseLocks.sha256(json.encodeToString(spec).toByteArray()), spec.processes.associate { it.image to it.imageId }.also { images ->
                    require(spec.processes.all { images[it.image] == it.imageId }) { "Conflicting image identities" }
                }, spec.processes.filterNot { it.oneShot }.map { it.id }, spec.processes.filter { it.oneShot }.map { it.id }, state, inputs)
        }
        return AssemblyPlan(AssemblySummary(request, members, requiredCapabilities - capabilities.toSet()), generation, inventory, specs, adapters)
    }
}
