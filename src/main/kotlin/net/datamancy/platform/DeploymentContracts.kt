package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** Operator-authored contracts. Catalog IDs alone never produce a component or route. */
@Serializable
enum class ComponentMode { DAEMON, ONE_SHOT, BUILD_ONLY }

@Serializable
data class ComponentContract(val id: String, val mode: ComponentMode, val image: String, val secretKeys: List<String>)

@Serializable
data class PersistenceContract(val componentId: String, val volume: String, val containerPath: String)

@Serializable
data class ModuleContract(
    val id: String,
    val dependsOn: List<String>,
    val components: List<ComponentContract>,
    val persistence: List<PersistenceContract>
)

@Serializable
data class ApprovedRoute(val host: String, val componentId: String, val containerPort: Int)

@Serializable
data class DeploymentSite(val schemaVersion: Int, val siteId: String, val modules: List<ModuleContract>, val routes: List<ApprovedRoute>) {
    companion object {
        /** Secret values are NOT accepted. On POSIX filesystems this file must be owner-only, with no symlink. */
        private val json = Json { ignoreUnknownKeys = false }
        fun hostLocal(path: Path): DeploymentSite = json.decodeFromString(privateText(path))

        /** Separately supplied, owner-only approval list; site documents cannot approve their own routes. */
        fun approvedHosts(path: Path): Set<String> {
            val hosts = json.decodeFromString<List<String>>(privateText(path))
            require(hosts.isNotEmpty() && hosts.size <= 64 && hosts.distinct().size == hosts.size) { "Invalid route approval list" }
            return hosts.toSet()
        }

        private fun privateText(path: Path): String {
            require(Files.isRegularFile(path, NOFOLLOW_LINKS) && Files.size(path) <= 131072) { "Missing or oversized local input" }
            val permissions = Files.getPosixFilePermissions(path, NOFOLLOW_LINKS)
            require(PosixFilePermission.OWNER_READ in permissions && permissions.none {
                it.name.startsWith("GROUP_") || it.name.startsWith("OTHERS_")
            }) { "Local input must be owner-only" }
            return Files.readString(path)
        }
    }
}

/** Supplied by a separately reviewed operator boundary, never taken from the site document. */
data class DeploymentBoundary(val dataRoot: Path, val backupRoot: Path, val approvedHosts: Set<String>)

@Serializable
enum class WorkflowKind { INSTALL, STOP, REMOVE, SNAPSHOT, VERIFY_SNAPSHOT, RESTART, RESTORE_ISOLATED, REQUIRE_FUNCTIONAL_TEST, REQUIRE_VERIFIED_BACKUP }

@Serializable
data class WorkflowStep(
    val kind: WorkflowKind,
    val moduleId: String? = null,
    val componentId: String? = null,
    val volume: String? = null
)

@Serializable
data class DeploymentWorkflow(
    val siteId: String,
    val dataPath: String,
    val backupPath: String,
    val routes: List<ApprovedRoute>,
    val modules: List<ModuleContract>,
    val install: List<WorkflowStep>,
    val teardown: List<WorkflowStep>,
    val backup: List<WorkflowStep>,
    val restore: List<WorkflowStep>
)

/** A deterministic non-executable workflow; no Podman, systemd, filesystem, proxy or secret effects. */
object DeploymentContracts {
    private val slug = Regex("[a-z][a-z0-9-]{0,29}")
    private val key = Regex("[A-Z][A-Z0-9_]{0,63}")
    private val image = Regex("[a-z0-9]+(?:[.-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+@sha256:[a-f0-9]{64}")
    private val hostname = Regex("[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?(?:\\.[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?)+")
    private val mount = Regex("/(?:[a-zA-Z0-9_-]+/)*[a-zA-Z0-9_-]+")

    fun plan(site: DeploymentSite, boundary: DeploymentBoundary): DeploymentWorkflow {
        require(site.schemaVersion == 1 && slug.matches(site.siteId)) { "Invalid deployment site schema or ID" }
        val dataRoot = boundary.dataRoot.normalize()
        val backupRoot = boundary.backupRoot.normalize()
        require(dataRoot.isAbsolute && backupRoot.isAbsolute && dataRoot == boundary.dataRoot &&
            backupRoot == boundary.backupRoot && dataRoot.nameCount > 1 && backupRoot.nameCount > 1 &&
            !dataRoot.startsWith(backupRoot) && !backupRoot.startsWith(dataRoot)) { "Unreviewed or overlapping roots" }
        require(site.modules.isNotEmpty() && site.modules.size <= 46 && site.modules.map { it.id }.distinct().size == site.modules.size) {
            "Expected distinct explicit modules"
        }
        val catalog = ServiceCatalog.bundled().modules.associateBy { it.id }
        val byId = site.modules.associateBy { it.id }
        val components = mutableSetOf<String>()
        val volumes = mutableSetOf<String>()
        site.modules.forEach { module ->
            val known = catalog[module.id] ?: throw IllegalArgumentException("Unknown module contract: ${module.id}")
            require(module.components.isNotEmpty() && module.dependsOn.distinct().size == module.dependsOn.size) { "Missing components or duplicate dependencies" }
            require(module.components.map { it.id }.toSet() == known.services.toSet() &&
                module.components.map { it.id }.distinct().size == module.components.size) { "Explicit module requires every named component, with no extras" }
            require(module.dependsOn.all { it in byId && it != module.id }) { "Missing or self dependency" }
            module.components.forEach { component ->
                require(component.id in known.services && components.add(component.id) && image.matches(component.image)) {
                    "Component must be explicitly pinned in its known module"
                }
                require(component.secretKeys.distinct().size == component.secretKeys.size && component.secretKeys.all(key::matches)) {
                    "Only distinct logical secret keys are permitted"
                }
            }
            module.persistence.forEach { persistence ->
                require(persistence.componentId in module.components.map { it.id } && slug.matches(persistence.volume) &&
                    mount.matches(persistence.containerPath) && volumes.add(persistence.volume)) { "Invalid or duplicate persistence contract" }
            }
            require(module.persistence.map { it.componentId to it.containerPath }.distinct().size == module.persistence.size) {
                "Duplicate container mount point"
            }
        }
        require(site.routes.size <= 64 && site.routes.map { it.host }.distinct().size == site.routes.size) { "Duplicate or excessive routes" }
        site.routes.forEach { route ->
            require(hostname.matches(route.host) && route.host in boundary.approvedHosts && route.componentId in components &&
                site.modules.flatMap { it.components }.single { it.id == route.componentId }.mode == ComponentMode.DAEMON &&
                route.containerPort in 1..65535) { "Unapproved route or unknown or non-daemon target" }
        }
        // Sorted DFS ensures deterministic order independent of input order, and detects all cycles.
        val visited = mutableSetOf<String>()
        val visiting = mutableSetOf<String>()
        val ordered = mutableListOf<String>()
        fun visit(id: String) {
            require(visiting.add(id)) { "Module dependency cycle" }
            if (id !in visited) {
                byId.getValue(id).dependsOn.sorted().forEach(::visit)
                visited.add(id)
                ordered.add(id)
            }
            visiting.remove(id)
        }
        byId.keys.sorted().forEach(::visit)
        val reverse = ordered.reversed()
        fun steps(kind: WorkflowKind, modules: List<String>) = modules.map { WorkflowStep(kind, it) }
        fun daemons(kind: WorkflowKind, modules: List<String>) = modules.flatMap { id ->
            byId.getValue(id).components.filter { it.mode == ComponentMode.DAEMON }.sortedBy { it.id }
                .map { WorkflowStep(kind, id, it.id) }
        }
        val snapshots = ordered.flatMap { id -> byId.getValue(id).persistence.sortedBy { it.volume }
            .map { WorkflowStep(WorkflowKind.SNAPSHOT, id, it.componentId, it.volume) } }
        return DeploymentWorkflow(
            site.siteId, dataRoot.resolve(site.siteId).toString(), backupRoot.resolve(site.siteId).toString(),
            site.routes.sortedBy { it.host }, ordered.map { id ->
                byId.getValue(id).let { module ->
                    module.copy(dependsOn = module.dependsOn.sorted(), components = module.components.sortedBy { it.id },
                        persistence = module.persistence.sortedWith(compareBy({ it.componentId }, { it.volume })))
                }
            },
            steps(WorkflowKind.INSTALL, ordered),
            listOf(WorkflowStep(WorkflowKind.REQUIRE_VERIFIED_BACKUP), WorkflowStep(WorkflowKind.REQUIRE_FUNCTIONAL_TEST)) +
                steps(WorkflowKind.REMOVE, reverse),
            daemons(WorkflowKind.STOP, reverse) + snapshots +
                listOf(WorkflowStep(WorkflowKind.VERIFY_SNAPSHOT)) + daemons(WorkflowKind.RESTART, ordered),
            listOf(WorkflowStep(WorkflowKind.RESTORE_ISOLATED), WorkflowStep(WorkflowKind.REQUIRE_FUNCTIONAL_TEST))
        )
    }
}
