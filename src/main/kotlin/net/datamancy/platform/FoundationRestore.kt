package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

internal interface GenerationImportBackend {
    fun importCold(spec: PrivateDeploymentSpec, archives: Map<String, Path>, sourceArchiveSha256: String, verificationRoot: Path, expectedHashes: Map<String, String>): MaintenanceFence
}

internal interface GenerationRestoreStartupBackend {
    fun startImported(spec: PrivateDeploymentSpec, fence: String): List<RuntimeStatus>
}

internal enum class ColdRestoreCohort(val recipes: Set<String>, val identity: String) {
    FOUNDATION(setOf("foundation", "sql-cache"), "foundation-cold-import-v1"),
    APPLICATIONS(setOf("foundation", "sql-cache", "forgejo", "planka"), "applications-cold-import-v1"),
    CANONICAL_CORE(setOf("canonical-core", "sql-cache", "forgejo"), "canonical-core-cold-import-v1"),
    WHOLE_RELEASE(emptySet(), "compiled-whole-release-cold-import-v1")
}

/** Exact compiled cohorts only; archived bootstraps are never executable restore authority. */
internal object FoundationRestore {
    private fun daemons(compiled: PrivateDeploymentSpec, recipe: String): PrivateDeploymentSpec {
        // Explicit feature-owned safety projections; no generic initializer stripping for unknown recipes.
        when (recipe) {
            "canonical-providers" -> return CanonicalCoreRuntime.coldRestoreProvidersSpec(compiled)
            "openbao" -> return OpenBaoRuntime.coldRestoreSpec(compiled)
            "seafile" -> return SeafileRuntime.coldRestoreSpec(compiled)
            "office" -> return OfficeRuntime.coldRestoreSpec(compiled)
            "notebook" -> return NotebookRuntime.coldRestoreSpec(compiled)
            "homeassistant" -> return HomeAssistantRuntime.coldRestoreSpec(compiled)
            "jupyterhub" -> return JupyterHubRuntime.coldRestoreSpec(compiled)
            "synapse" -> return SynapseRuntime.coldRestoreSpec(compiled)
            "matrix" -> return MatrixRuntime.coldRestoreSpec(compiled)
            "matrix-rtc" -> return MatrixRtcRuntime.coldRestoreSpec(compiled)
            "livekit" -> return LiveKitRuntime.coldRestoreSpec(compiled)
            "erpnext", "firefly", "bookstack", "sogo", "mail", "sogo-mail", "node-metrics", "qbittorrent", "searxng", "opensearch" ->
                return BusinessApplicationRecovery.coldRestoreSpec(recipe, compiled)
        }
        require(recipe in setOf("foundation", "canonical-core", "sql-cache", "forgejo", "planka")) {
            "No safe compiled cold-restore projection for $recipe"
        }
        val retired = compiled.processes.filter { it.oneShot }.map { it.id }.toSet()
        return compiled.copy(processes = compiled.processes.filterNot { it.oneShot }.map {
            it.copy(dependencies = if (recipe in setOf("planka", "canonical-core") && it.id == "planka") listOf("postgres") else it.dependencies.filterNot { it in retired },
                environmentFile = if (recipe in setOf("foundation", "planka") && it.id == "postgres") "postgres.env" else it.environmentFile)
        }, databaseAccess = compiled.databaseAccess.filterNot { it.consumer in retired })
    }
    fun bundle(source: GenerationBundle, inventory: AcquiredInventory, target: String, archiveSha: String,
        cohort: ColdRestoreCohort = ColdRestoreCohort.FOUNDATION, targetStore: RuntimeStore = RuntimeStore.LEGACY): GenerationBundle {
        require(target != source.request.id && archiveSha.matches(Regex("[a-f0-9]{64}")))
        SiteOwnerships.checkSealed(source)
        require(source.request.rssPlan == null) { "Managed RSS recovery requires complete controller payload capture and exclusion" }
        require(cohort == ColdRestoreCohort.WHOLE_RELEASE ||
            source.members.map { it.member.name.removePrefix(source.request.id + "-") }.toSet() == cohort.recipes) {
            "Source does not match the selected compiled restore cohort"
        }
        val continuing = source.recoverySourceKopia != null
        if (continuing) {
            KopiaGenerationStore.validate(requireNotNull(source.recoverySourceKopia))
            require(cohort in setOf(ColdRestoreCohort.CANONICAL_CORE, ColdRestoreCohort.WHOLE_RELEASE) && source.recoverySourceArchiveSha256 == null &&
                source.ownership == null && source.assemblySha256 == null && source.recoverySourceKopia.generation != source.request.id) {
                "Only private Kopia compiled recovery can continue without site authority"
            }
        }
        val names = source.members.associate { it.member.name to it.member.name.replaceFirst(source.request.id, target) }
        val pins = source.members.map { old ->
            val recipe = old.member.name.removePrefix(source.request.id + "-")
            val compiler = GenerationAssembly.catalog.singleOrNull { it.id == recipe }
                ?: error("Unknown compiled restoration recipe")
            val compiled = compiler.spec(inventory, old.member.name)
            val restored = when {
                recipe == "caddy" -> CaddyRuntime.restoreSpec(inventory, old.member.name)
                recipe == "planka" && cohort == ColdRestoreCohort.WHOLE_RELEASE -> PlankaRuntime.coldRestoreSpec(compiled)
                else -> daemons(compiled, recipe)
            }
            require(restored.processes.none { it.oneShot } && restored.volumes == compiled.volumes &&
                restored.networks == compiled.networks && restored.processes.all { daemon ->
                    compiled.processes.any { it.id == daemon.id && !it.oneShot && it.image == daemon.image &&
                        it.imageId == daemon.imageId && it.userId == daemon.userId && it.groupId == daemon.groupId }
                }) { "Restore projection changed state/network/artifact ownership or retained initialization" }
            require(old.spec.store == source.request.store) { "Mixed runtime-store source" }
            val expected = (if (continuing) restored else compiled).copy(store = source.request.store)
            PrivateDeployment.validate(old.spec)
            // Source-only publication is authenticated history, never inherited restore authority.
            require(old.spec.copy(ingress = null) == expected.copy(ingress = null)) { "Archived definition is not the compiled compatibility-tested recipe" }
            require(old.inputHashes.keys == PrivateDeployment.inputNames(expected).toSet()) { "Archived input set differs from compiled recipe" }
            val spec = restored.copy(name = names.getValue(old.member.name), store = targetStore, ingress = null)
            PrivateDeployment.validate(spec)
            val requiredInputs = PrivateDeployment.inputNames(spec).toSet()
            require(old.inputHashes.keys.containsAll(requiredInputs)) { "Missing authenticated restore inputs" }
            // Bootstrap-only files stay authenticated in recovered/source, not mounted into live target daemons.
            val inputs = old.inputHashes.filterKeys { it in requiredInputs }
            val member = GenerationMember(spec.name, old.member.dependencies.map { names.getValue(it) })
            GenerationPin(member, ReleaseLocks.sha256(Json.encodeToString(spec).toByteArray()), inputs,
                PrivateDeployment.expectedFingerprint(spec, inputs), spec)
        }
        val request = source.request.copy(id = target, members = pins.map { it.member }, store = targetStore,
            releaseCandidateSha256 = source.request.releaseCandidateSha256 ?: source.request.candidateSha256,
            diskReservationMiB = maxOf(source.request.diskReservationMiB, 3 * RecoveryCapsule.MAX_TOTAL / 1048576 + 512),
            candidateSha256 = ReleaseLocks.sha256(("${cohort.identity}\n$archiveSha\n" + Json.encodeToString(pins)).toByteArray()))
        val order = GenerationRuntime.validateScope(request)
        require(pins.map { it.member } == order)
        // Original ownership remains authenticated inside the source capsule/bundle. Its host policy is not
        // authorization for a fresh private restore namespace: do not inherit live site/route ownership.
        return GenerationBundle(request, pins, pins.sumOf { it.spec.processes.sumOf { p -> p.memoryMiB.toLong() } },
            recoverySourceArchiveSha256 = archiveSha)
    }
}
