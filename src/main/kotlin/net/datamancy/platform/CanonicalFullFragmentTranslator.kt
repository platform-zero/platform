package net.datamancy.platform

/** Offline-only translation of a reviewed canonical adapter into the restricted YAML DTO.
 * This does not admit a recipe or synthesize an initializer/credential. The caller must
 * supply the original cold projection and explicit per-input custody; a mismatch fails
 * rather than inventing a permissive RESTORE or guessing which provider owns a secret.
 */
internal object CanonicalFullFragmentTranslator {
    fun translate(fresh: CanonicalProviderFragment, cold: CanonicalProviderFragment,
        inventory: AcquiredInventory, processOwners: Map<String, String>, inputOwners: Map<String, String>,
        id: String, revision: Int = 1): GraphFragment {
        require(fresh.product == cold.product && fresh.spec.store == RuntimeStore.CANONICAL_V2 &&
            cold.spec.store == RuntimeStore.CANONICAL_V2 && fresh.spec.name == cold.spec.name &&
            fresh.spec.executionBackend == cold.spec.executionBackend &&
            cold.spec.processes.none { it.oneShot } &&
            fresh.spec.processes.filterNot { it.oneShot }.map { it.id }.toSet() ==
                cold.spec.processes.map { it.id }.toSet() &&
            fresh.spec.networks == cold.spec.networks && fresh.spec.volumes == cold.spec.volumes &&
            fresh.providerNetworks == cold.providerNetworks && fresh.webNetworks == cold.webNetworks) {
            "Native cold projection differs from reviewed fresh provider"
        }
        val live = fresh.spec.processes.associateBy { it.id }
        require(live.size == fresh.spec.processes.size &&
            cold.spec.processes.all { restored ->
                val original = live.getValue(restored.id)
                val allowed = original.copy(dependencies = emptyList(), command = restored.command,
                    entrypoint = restored.entrypoint, environmentFile = restored.environmentFile)
                allowed == restored.copy(dependencies = emptyList()) &&
                    (restored.environmentFile == original.environmentFile || restored.environmentFile == null)
            }) { "Restore changes process authority beyond a bounded reviewed cold command" }
        val images = inventory.images.associateBy { it.imageId }
        require(inventory.images.map { it.imageId }.distinct().size == inventory.images.size &&
            processOwners.keys.containsAll(live.keys) && processOwners.values.contains(fresh.product))
        val providers = (fresh.spec.processes + cold.spec.processes).flatMap { it.dependencies }
            .filterNot { processOwners[it] == fresh.product }.map { requireNotNull(processOwners[it]) }.distinct()
        val actualInputs = fresh.spec.processes.flatMap { it.files.map(RuntimeFile::file) + listOfNotNull(it.environmentFile) }
            .distinct()
        require(inputOwners.keys == actualInputs.toSet() && inputOwners.values.all { it == fresh.product || it in providers }) {
            "Every sealed input needs an explicit, selected owner"
        }
        val inputDeclarations = actualInputs.map { file -> FragmentInput(file, inputOwners.getValue(file),
            if (inputOwners.getValue(file) == fresh.product && fresh.spec.processes.filter {
                    it.files.any { f -> f.file == file } || it.environmentFile == file
                }.all { it.oneShot }) FragmentInputPurpose.BOOTSTRAP else FragmentInputPurpose.RUNTIME,
            fresh.spec.processes.filter { it.files.any { f -> f.file == file } || it.environmentFile == file }
                .map { it.id }) }
        val declared = GraphFragment(schemaVersion = 2, id = id, revision = revision, product = fresh.product,
            artifacts = fresh.spec.processes.map {
                requireNotNull(images[it.imageId]) { "No acquired image for adapter process ${it.id}" }.product
            }.distinct(),
            providers = providers, networks = (fresh.spec.networks +
                fresh.spec.processes.flatMap { it.networks }).distinct(),
            providerNetworks = fresh.providerNetworks.mapValues { it.value.sorted() },
            webNetworks = fresh.webNetworks.sorted(), volumes = fresh.spec.volumes,
            inputs = inputDeclarations,
            processes = fresh.spec.processes.map { p -> FragmentProcess(
                id = p.id, artifact = requireNotNull(images[p.imageId]) {
                    "No acquired image for adapter process ${p.id}"
                }.product,
                userId = p.userId, groupId = p.groupId, entrypoint = p.entrypoint,
                command = p.command, environmentFile = p.environmentFile, volumes = p.volumes,
                files = p.files, tmpfs = p.tmpfs, readiness = p.readiness,
                oneShot = p.oneShot, memoryMiB = p.memoryMiB, capabilities = p.capabilities,
                apparmorProfile = requireNotNull(p.apparmorProfile), readinessHttpPort = p.readinessHttpPort,
                readinessHttpPath = p.readinessHttpPath ?: "/", networks = p.networks,
                networkAliases = p.networkAliases) },
            install = FragmentPhaseGraph(fresh.spec.processes.map { it.id },
                fresh.spec.processes.associate { it.id to it.dependencies }, fresh.spec.databaseAccess),
            restore = FragmentPhaseGraph(cold.spec.processes.map { it.id },
                cold.spec.processes.associate { it.id to it.dependencies }, cold.spec.databaseAccess,
                processOverrides = cold.spec.processes.mapNotNull { restored ->
                    val original = live.getValue(restored.id)
                    if (restored.command == original.command && restored.entrypoint == original.entrypoint &&
                        restored.environmentFile == original.environmentFile) null else
                        restored.id to FragmentColdProcessOverride(restored.command,
                            clearEnvironmentFile = original.environmentFile != null && restored.environmentFile == null,
                            entrypoint = restored.entrypoint.takeIf { it != original.entrypoint })
                }.toMap()))
        return declared.validate()
    }
}
