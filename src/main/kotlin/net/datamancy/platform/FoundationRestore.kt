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
    FORGEJO_POSTGRES(setOf(FragmentRecipes.FORGEJO_POSTGRES), "forgejo-postgres-cold-import-v2"),
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
        cohort: ColdRestoreCohort = ColdRestoreCohort.FOUNDATION, targetStore: RuntimeStore = RuntimeStore.LEGACY,
        managedSourceManifest: ByteArray? = null, targetManagedImage: ManagedLaneImageBinding? = null,
        targetControllerSha256: String? = null, ciRecoveryGrant: ForgejoCiRecoveryGrant? = null): GenerationBundle {
        require(target != source.request.id && archiveSha.matches(Regex("[a-f0-9]{64}")) &&
            (targetControllerSha256 == null || targetControllerSha256.matches(Regex("[a-f0-9]{64}"))))
        SiteOwnerships.checkSealed(source)
        // This is a pure projection, never controller-custody, enrollment or startup authority.
        // Native callers must authenticate/restore the controller payload under the held-source exclusion.
        val managed = source.request.managedLanes?.let { plan ->
            require(targetStore == RuntimeStore.CANONICAL_V2 && cohort == ColdRestoreCohort.WHOLE_RELEASE)
            ManagedLaneRecovery.projectPlan(plan, target, requireNotNull(managedSourceManifest) {
                "Authenticated original managed manifest required for cold projection"
            }, requireNotNull(targetManagedImage) { "Pinned local target managed image required" })
        }
        require(source.request.managedLanes != null || (managedSourceManifest == null && targetManagedImage == null))
        require(cohort == ColdRestoreCohort.WHOLE_RELEASE ||
            source.members.map { GenerationAssembly.recipeForMember(source.request.id, it.member.name) }.toSet() == cohort.recipes) {
            "Source does not match the selected compiled restore cohort"
        }
        val continuing = source.recoverySourceKopia != null
        // A functional restore of the narrowly supported owned candidate is still a private
        // recovery, never a second update or inherited promotion authority. The native caller
        // must separately bind its held snapshot and completed owned-start record.
        val ownedCandidate = source.ownedUpdate != null
        if (ownedCandidate) {
            require(cohort == ColdRestoreCohort.WHOLE_RELEASE && targetStore == RuntimeStore.CANONICAL_V2 && !continuing)
            OwnedReleaseUpdates.validate(source)
        }
        if (continuing) {
            KopiaGenerationStore.validate(requireNotNull(source.recoverySourceKopia))
            require(cohort in setOf(ColdRestoreCohort.CANONICAL_CORE, ColdRestoreCohort.FORGEJO_POSTGRES, ColdRestoreCohort.WHOLE_RELEASE) && source.recoverySourceArchiveSha256 == null &&
                source.ownership == null && source.assemblySha256 == null && source.recoverySourceKopia.generation != source.request.id) {
                "Only private Kopia compiled recovery can continue without site authority"
            }
        }
        val names = source.members.associate { it.member.name to it.member.name.replaceFirst(source.request.id, target) }
        val pins = source.members.map { old ->
            val namespaceRecipe = GenerationAssembly.recipeForMember(source.request.id, old.member.name)
            // The name suffix `-v2` is shared by canonical V2 and the pending
            // full r9 assembly. Only the sealed graph binding may disambiguate
            // cold compilation; never infer a different active recipe from it.
            val recipe = if (namespaceRecipe == "canonical-release-v2" &&
                old.spec.fragmentBinding?.recipe == CanonicalSharedYamlGraph.RECIPE)
                CanonicalSharedYamlGraph.RECIPE else namespaceRecipe
            val compiler = GenerationAssembly.catalog.singleOrNull { it.id == recipe }
                ?: error("Unknown compiled restoration recipe")
            val packaged = recipe in FragmentRecipes.recipeIds || recipe == CanonicalSharedYamlGraph.RECIPE
            val sharedRevision = if (recipe == CanonicalSharedYamlGraph.RECIPE) {
                val binding = requireNotNull(old.spec.fragmentBinding)
                val r9 = "fragments/v3/canonical/r9/index.yaml" in binding.resources
                val r10 = "fragments/v3/canonical/r10/index.yaml" in binding.resources
                require(!(r9 && r10)) { "Ambiguous sealed original full-graph revision" }
                (if (r10) 10 else if (r9) 9 else null)?.also { revision ->
                    require(QualificationPrivateTls.selectedManifest(binding).revision == revision) {
                        "Original graph lacks the exact sealed selected index closure"
                    }
                }
            } else null
            fun shared(name: String, phase: FragmentPhase, binding: RuntimeFragmentBinding): PrivateDeploymentSpec =
                when (sharedRevision) {
                    10 -> CanonicalSharedYamlGraph.pendingR10Spec(inventory,name,phase,
                        binding.controllerSha256,binding.controllerUid,binding.controllerGid)
                    9 -> CanonicalSharedYamlGraph.pendingR9Spec(inventory,name,phase,
                        binding.controllerSha256,binding.controllerUid,binding.controllerGid)
                    else -> CanonicalSharedYamlGraph.spec(inventory,name,phase,
                        binding.controllerSha256,binding.controllerUid,binding.controllerGid)
                }
            val compiled = if (packaged) {
                val binding = requireNotNull(old.spec.fragmentBinding)
                require(binding.controllerSha256 != null && binding.controllerUid != null && binding.controllerGid != null &&
                    targetStore == RuntimeStore.CANONICAL_V2)
                if (recipe == CanonicalSharedYamlGraph.RECIPE)
                    shared(old.member.name,FragmentPhase.INSTALL,binding)
                else FragmentRecipes.spec(inventory, old.member.name, FragmentPhase.INSTALL,
                    binding.controllerSha256, binding.controllerUid, binding.controllerGid)
            } else compiler.spec(inventory, old.member.name)
            val restored = when {
                packaged -> {
                    val binding = requireNotNull(compiled.fragmentBinding)
                    if (recipe == CanonicalSharedYamlGraph.RECIPE)
                        shared(old.member.name,FragmentPhase.RESTORE,binding)
                    else FragmentRecipes.spec(inventory, old.member.name, FragmentPhase.RESTORE,
                        binding.controllerSha256, binding.controllerUid, binding.controllerGid)
                }
                recipe == "caddy" -> CaddyRuntime.restoreSpec(inventory, old.member.name)
                recipe == "planka" && cohort == ColdRestoreCohort.WHOLE_RELEASE -> PlankaRuntime.coldRestoreSpec(compiled)
                else -> daemons(compiled, recipe)
            }
            val expectedRestoreNetworks = if (recipe == CanonicalSharedYamlGraph.RECIPE && sharedRevision != null)
                compiled.networks.filter { network -> restored.processes.any { network in it.networks } }
            else compiled.networks
            require(restored.processes.none { it.oneShot } && restored.volumes == compiled.volumes &&
                restored.networks == expectedRestoreNetworks && restored.processes.all { daemon ->
                    compiled.processes.any { it.id == daemon.id && !it.oneShot && it.image == daemon.image &&
                        it.imageId == daemon.imageId && it.userId == daemon.userId && it.groupId == daemon.groupId }
                }) { "Restore projection changed state/network/artifact ownership or retained initialization" }
            require(old.spec.store == source.request.store) { "Mixed runtime-store source" }
            val expected = (if (continuing || ownedCandidate) restored else compiled).copy(store = source.request.store)
            PrivateDeployment.validate(old.spec)
            // Source-only publication is authenticated history, never inherited restore authority.
            require(old.spec.copy(ingress = null, nativeIngress = null) == expected.copy(ingress = null, nativeIngress = null)) {
                "Archived definition is not the compiled compatibility-tested recipe"
            }
            require(old.inputHashes.keys == PrivateDeployment.inputNames(expected).toSet()) { "Archived input set differs from compiled recipe" }
            if (sharedRevision == 10) require(targetControllerSha256 != null) {
                "r10 target requires an independently pinned current controller distribution"
            }
            val targetBinding = if (targetControllerSha256 != null && packaged) {
                require(targetStore == RuntimeStore.CANONICAL_V2)
                requireNotNull(restored.fragmentBinding).copy(controllerSha256 = targetControllerSha256)
            } else restored.fragmentBinding
            val spec = if (recipe == CanonicalSharedYamlGraph.RECIPE && sharedRevision != null) {
                val target=shared(names.getValue(old.member.name),FragmentPhase.RESTORE,
                    requireNotNull(targetBinding))
                require(target.fragmentBinding == targetBinding &&
                    targetBinding.resources == restored.fragmentBinding?.resources &&
                    targetBinding.phase == FragmentPhase.RESTORE.name &&
                    target.copy(name=restored.name,fragmentBinding=restored.fragmentBinding,
                        processes=target.processes.map { p ->
                            val sourceMount=restored.processes.single { it.id==p.id }.controlSocketMount
                            p.copy(controlSocketMount=sourceMount)
                        }) == restored) {
                    "Target selected graph differs from original except current controller auth and control sockets"
                }
                target
            } else restored.copy(name = names.getValue(old.member.name), store = targetStore,
                ingress = null, nativeIngress = null, fragmentBinding = targetBinding)
            PrivateDeployment.validate(spec)
            val requiredInputs = PrivateDeployment.inputNames(spec).toSet()
            require(old.inputHashes.keys.containsAll(requiredInputs)) { "Missing authenticated restore inputs" }
            // Bootstrap-only files stay authenticated in recovered/source, not mounted into live target daemons.
            val inputs = old.inputHashes.filterKeys { it in requiredInputs }
            val member = GenerationMember(spec.name, old.member.dependencies.map { names.getValue(it) })
            GenerationPin(member, ReleaseLocks.sha256(Json.encodeToString(spec).toByteArray()), inputs,
                PrivateDeployment.expectedFingerprint(spec, inputs), spec)
        }
        val stateReservation = source.request.recoveryStateReservationMiB ?: source.request.diskReservationMiB
        val originalBao = source.request.baoBootstrapOperation?.let { operation ->
            operation.validate(source.request.id)
            require(cohort == ColdRestoreCohort.WHOLE_RELEASE && targetStore == RuntimeStore.CANONICAL_V2)
            GenerationFreshBaoStage.verifyNative(source,ReleaseLocks.sha256(Json.encodeToString(source).toByteArray()))
            val path=GenerationRuntime.BASE.resolve(source.request.id).resolve("bao-custody")
                .resolve("${source.request.id}-original-issuer.result.json")
            ActivationInput(path.toString(),ReleaseLocks.sha256(ReleasePrivateFiles.read(path,8192)))
        }
        val projected = source.request.copy(id = target, members = pins.map { it.member }, store = targetStore,
            baoBootstrapOperation = null, recoveredBaoOriginal = originalBao,
            freshPlankaActorGrant = null,
            managedLanes = managed?.plan,
            releaseCandidateSha256 = source.request.releaseCandidateSha256 ?: source.request.candidateSha256,
            diskReservationMiB = maxOf(source.request.diskReservationMiB,
                Math.addExact(Math.multiplyExact(3L, stateReservation), 512L)),
            recoveryStateReservationMiB = stateReservation,
            candidateSha256 = ReleaseLocks.sha256(("${cohort.identity}\n$archiveSha\n" + Json.encodeToString(pins)).toByteArray()))
        val request = if (source.request.rssPlan != null || source.request.recoveredRssPlan != null)
            GenerationRssPlan.coldRecoveryTarget(source.request, projected) else projected
        val inertCiOriginal = if (source.request.forgejoCi != null || source.request.recoveredForgejoCi != null)
            ForgejoCiSourcePlan.coldRecoveryTarget(source.request, request) else request
        val inertCi = ciRecoveryGrant?.let { grant ->
            val original = requireNotNull(inertCiOriginal.recoveredForgejoCi)
            grant.validate(original, target)
            require(cohort == ColdRestoreCohort.WHOLE_RELEASE && targetStore == RuntimeStore.CANONICAL_V2)
            inertCiOriginal.copy(ciRecoveryGrant = grant, recoveredForgejoCiTarget = grant.targetPlan(original))
        } ?: inertCiOriginal
        val order = GenerationRuntime.validateScope(inertCi)
        require(pins.map { it.member } == order)
        // Original ownership remains authenticated inside the source capsule/bundle. Its host policy is not
        // authorization for a fresh private restore namespace: do not inherit live site/route ownership.
        return GenerationBundle(inertCi, pins, Math.addExact(
            pins.sumOf { it.spec.processes.sumOf { p -> p.memoryMiB.toLong() } },
            GenerationManagedComponents.memoryReservationMiB(inertCi)), 
            recoverySourceArchiveSha256 = archiveSha)
    }
}
