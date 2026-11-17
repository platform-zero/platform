package net.datamancy.platform

import kotlinx.serialization.Serializable

@Serializable internal enum class FragmentInputPurpose { BOOTSTRAP, RUNTIME }
@Serializable internal enum class FragmentPhase { INSTALL, RESTORE }
@Serializable internal data class FragmentInput(
    val name: String, val owner: String, val purpose: FragmentInputPurpose, val consumers: List<String>)
@Serializable internal data class FragmentColdProcessOverride(
    val command: List<String>, val clearEnvironmentFile: Boolean = false,
    val entrypoint: String? = null)
@Serializable internal data class FragmentPhaseGraph(
    val processes: List<String>, val dependencies: Map<String, List<String>>,
    val databaseAccess: List<RuntimeDatabaseAccess> = emptyList(),
    val additionalArguments: Map<String, List<String>> = emptyMap(),
    val processOverrides: Map<String, FragmentColdProcessOverride> = emptyMap())

/** Image identities are supplied by the exact acquired artifact closure, never YAML tags. */
@Serializable internal data class FragmentProcess(
    val id: String, val artifact: String, val userId: Int, val groupId: Int = userId,
    val entrypoint: String? = null, val command: List<String> = emptyList(),
    val environmentFile: String? = null, val volumes: List<RuntimeMount> = emptyList(),
    val files: List<RuntimeFile> = emptyList(), val tmpfs: List<String> = listOf("/tmp"),
    val readiness: List<String> = emptyList(), val oneShot: Boolean = false,
    val memoryMiB: Int = 512, val capabilities: List<String> = emptyList(),
    val apparmorProfile: String = "p0v3-private-v1", val readinessHttpPort: Int? = null,
    val readinessHttpPath: String = "/", val networks: List<String>,
    val networkAliases: List<RuntimeNetworkAlias> = emptyList()) {
    fun bind(image: AcquiredImage, dependencies: List<String>) = RuntimeProcess(
        id, image.pinnedImage, image.imageId, userId, groupId, dependencies, entrypoint, command,
        environmentFile, volumes, files, tmpfs, readiness, oneShot, memoryMiB, capabilities,
        apparmorProfile, readinessHttpPort, readinessHttpPath, networks, networkAliases)
}

/** An offline declaration, NOT an admitted recipe or an executable caller-supplied runtime. */
@Serializable internal data class GraphFragment(
    val schemaVersion: Int, val id: String, val revision: Int, val product: String,
    val artifacts: List<String>, val providers: List<String> = emptyList(),
    val networks: List<String>, val providerNetworks: Map<String, List<String>> = emptyMap(),
    val providerProcesses: Map<String, List<String>> = emptyMap(),
    val webNetworks: List<String> = emptyList(), val volumes: List<RuntimeVolume> = emptyList(),
    val inputs: List<FragmentInput>, val processes: List<FragmentProcess>,
    val install: FragmentPhaseGraph, val restore: FragmentPhaseGraph,
    val templates: List<FragmentTemplateSpec> = emptyList(),
    val exportedInputs: List<String> = emptyList()) {

    fun phase(phase: FragmentPhase) = when (phase) { FragmentPhase.INSTALL -> install; FragmentPhase.RESTORE -> restore }

    /** Local validation. Full canonical ownership/capacity validation remains mandatory after composition. */
    fun validate(): GraphFragment {
        val slug = Regex("[a-z][a-z0-9-]{0,39}")
        val file = Regex("[a-z][a-z0-9.-]{0,79}")
        fun distinct(values: List<String>) = values.distinct().size == values.size
        require(schemaVersion == 2 && revision > 0 && slug.matches(id) && slug.matches(product))
        require(artifacts.isNotEmpty() && distinct(artifacts) && artifacts.all(slug::matches))
        require(distinct(exportedInputs) && exportedInputs.all { file.matches(it) && !it.startsWith("runtime.") })
        require(distinct(providers) && providers.all(slug::matches) && product !in providers)
        require(networks.isNotEmpty() && distinct(networks) && networks.all(slug::matches))
        require(distinct(webNetworks) && networks.containsAll(webNetworks))
        require(providerNetworks.keys.all { it in providers } && providerNetworks.values.all {
            it.isNotEmpty() && distinct(it) && networks.containsAll(it)
        } && providerProcesses.keys.all { it in providers } && providerProcesses.values.all {
            it.isNotEmpty() && distinct(it) && it.all(slug::matches)
        } && providerProcesses.values.flatten().distinct().size == providerProcesses.values.sumOf { it.size })
        val byId = processes.associateBy { it.id }
        require(processes.size in 1..128 && byId.size == processes.size && byId.keys.all(slug::matches) &&
            byId.keys.intersect(providerProcesses.values.flatten().toSet()).isEmpty())
        require(byId.keys.none { it in providers } && processes.map { it.artifact }.toSet() == artifacts.toSet())
        require(volumes.map { it.id }.distinct().size == volumes.size)
        val inputsByName = inputs.associateBy { it.name }
        require(inputsByName.size == inputs.size && inputs.all { input ->
            file.matches(input.name) && !input.name.startsWith("runtime.") &&
                (input.owner == product || input.owner in providers) && input.consumers.isNotEmpty() &&
                distinct(input.consumers) && input.consumers.all { it in byId } &&
                (input.purpose != FragmentInputPurpose.BOOTSTRAP || input.consumers.all { byId.getValue(it).oneShot })
        }) { "Invalid fragment input ownership or bootstrap consumer" }
        require(templates.map { it.output }.distinct().size == templates.size && templates.all {
            file.matches(it.resource) && it.resource != "fragment.yaml" &&
                inputsByName[it.output]?.owner == product
        }) { "Invalid template output or resource" }
        for (process in processes) {
            val used = process.files.map { it.file } + listOfNotNull(process.environmentFile)
            require(used.toSet() == inputs.filter { process.id in it.consumers }.map { it.name }.toSet()) {
                "Fragment input consumers differ from process references"
            }
            require(process.artifact in artifacts && process.networks.all { it in networks } &&
                process.volumes.all { mount -> volumes.any { it.id == mount.volume } }) {
                "Fragment process references undeclared image, network or local volume"
            }
        }
        require(install.processes.toSet() == byId.keys) { "INSTALL must account for every declared process" }
        require(restore.processes.isNotEmpty() && restore.processes.all { byId[it]?.oneShot == false }) {
            "RESTORE cannot include initialization"
        }
        // Daemons cannot silently disappear from the cold projection.
        require(restore.processes.toSet() == processes.filterNot { it.oneShot }.map { it.id }.toSet())
        for (graph in listOf(install, restore)) {
            require(distinct(graph.processes) && graph.dependencies.keys == graph.processes.toSet())
            require(graph.processOverrides.isEmpty() || graph === restore && graph.processOverrides.keys.all {
                it in graph.processes && byId.getValue(it).oneShot.not()
            } && graph.processOverrides.values.all { override -> override.command.isNotEmpty() &&
                override.command.size <= 128 && override.command.all { it.length in 1..32768 && '\u0000' !in it } }) {
                "Only an explicit bounded cold process command may replace the installed command"
            }
            require(graph.additionalArguments.keys.all { it in graph.processes } &&
                graph.additionalArguments.values.all { args -> args.size <= 128 &&
                    args.all { it.length <= 32768 && '\u0000' !in it } })
            require(graph.dependencies.all { (id, deps) -> distinct(deps) && deps.none { it == id } &&
                deps.all { it in graph.processes || it in providers ||
                    providerProcesses.values.any { processes -> it in processes } } })
            require(graph.databaseAccess.all { it.consumer in graph.processes && it.provider in providers })
            val visiting = mutableSetOf<String>(); val visited = mutableSetOf<String>()
            fun visit(id: String) {
                if (id in visited || id in providers || providerProcesses.values.any { id in it }) return
                require(visiting.add(id)) { "Fragment dependency cycle" }
                graph.dependencies.getValue(id).forEach(::visit)
                visiting.remove(id); visited.add(id)
            }
            graph.processes.forEach(::visit)
        }
        return this
    }

    companion object {
        fun lint(bytes: ByteArray): GraphFragment = FragmentYaml.decode(bytes, serializer()).validate()
    }
}

/** Only classpath/hash-bound fragments can project into runtime types. No public file-to-runtime path. */
internal class PackagedGraphFragment private constructor(
    private val definitionBytes: ByteArray, private val hashes: Map<String, String>,
    private val templates: Map<String, String>, private val retainedResources: Map<String, ByteArray>) {
    // Callers may inspect DTOs, but cannot mutate the packaged authority via mutable List/Map casts.
    val definition: GraphFragment get() = GraphFragment.lint(definitionBytes)
    val resourceHashes: Map<String, String> get() = hashes.toMap()
    fun exportResources(): Map<String, ByteArray> = retainedResources.mapValues { it.value.copyOf() }
    fun template(resource: String): String = templates.getValue(resource)
    fun requiredInputs(phase: FragmentPhase): List<FragmentInput> {
        val definition = this.definition
        val graph = definition.phase(phase)
        return definition.inputs.filter { input -> input.consumers.any { id ->
            id in graph.processes && definition.processes.single { it.id == id }.let { process ->
                process.files.any { it.file == input.name } ||
                    (process.environmentFile == input.name &&
                        graph.processOverrides[id]?.clearEnvironmentFile != true)
            }
        } }
    }

    /** Pure partial graph for composition/inspection. It is deliberately NOT registered for execution. */
    fun project(inventory: AcquiredInventory, member: String, phase: FragmentPhase): CanonicalProviderFragment {
        val definition = this.definition
        require(inventory.schemaVersion == 1 && inventory.images.map { it.product }.distinct().size == inventory.images.size)
        val byArtifact = definition.artifacts.associateWith { id -> inventory.images.single { it.product == id }.also {
            require(it.os == "linux" && it.architecture == "amd64" &&
                it.selectedManifestDigest.matches(Regex("sha256:[a-f0-9]{64}")) &&
                it.imageId.matches(Regex("[a-f0-9]{64}")) &&
                it.pinnedImage.matches(Regex("[a-z0-9.-]+/[a-zA-Z0-9/_.-]+@sha256:[a-f0-9]{64}")) &&
                it.pinnedImage.endsWith("@${it.selectedManifestDigest}"))
        } }
        val graph = definition.phase(phase)
        val processes = graph.processes.map { id -> definition.processes.single { it.id == id }.let { p ->
            val cold = graph.processOverrides[id]
            p.copy(command = cold?.command ?: p.command + graph.additionalArguments.getOrDefault(id, emptyList()),
                entrypoint = cold?.entrypoint ?: p.entrypoint,
                environmentFile = if (cold?.clearEnvironmentFile == true) null else p.environmentFile)
                .bind(byArtifact.getValue(p.artifact), graph.dependencies.getValue(id))
        } }
        val unmounted = definition.volumes.map { it.id }.toSet() - processes.flatMap { it.volumes }.map { it.volume }.toSet()
        require(phase == FragmentPhase.RESTORE || unmounted.isEmpty())
        val spec = PrivateDeploymentSpec(name = member, volumes = definition.volumes, processes = processes,
            networks = definition.networks, databaseAccess = graph.databaseAccess, store = RuntimeStore.CANONICAL_V2,
            unmountedRecoveryVolumes = unmounted)
        return CanonicalProviderFragment(definition.product, spec,
            definition.providerNetworks.mapValues { it.value.toSet() }, definition.webNetworks.toSet())
    }

    companion object {
        private val path = Regex("[a-z][a-z0-9-]{0,39}/r[1-9][0-9]*/fragment.yaml")
        fun load(id: String, revision: Int): PackagedGraphFragment = loadFrom("/fragments/v2", id, revision)
        /** Independent CI-enabled V2 source index: r7's V2 index and historical
         * resource hashes remain immutable while full-private selects r5. */
        fun loadFullForgejo(): PackagedGraphFragment = loadFrom("/fragments/v2",
            "forgejo-postgres", 5, "canonical/r5/index.yaml")
        /** Independent V3 index; adding new shared components cannot change V2 provenance or
         * any historical recipe's source hashes, bindings or original receipts. */
        fun loadV3(id: String, revision: Int): PackagedGraphFragment = loadFrom("/fragments/v3", id, revision)
        fun loadPendingV3(id: String, revision: Int, candidate: Int = 8): PackagedGraphFragment {
            require(candidate in setOf(8, 9, 10))
            return loadFrom("/fragments/v3", id, revision, "canonical/r$candidate/index.yaml")
        }
        /** Lint the unactivated complete-source candidate without changing the
         * live r7 selection or conferring admission on missing native owners. */
        fun pendingV3R8(): Pair<CanonicalSharedManifest, Map<String, String>> {
            val root = "/fragments/v3"
            val indexBytes = resource("$root/canonical/r8/index.yaml")
            val index = FragmentYaml.decode(indexBytes, FragmentIndex.serializer())
            val manifestBytes = resource("$root/canonical/r8/manifest.yaml")
            val r7Index = resource("$root/canonical/r7/index.yaml")
            val r7Manifest = resource("$root/canonical/r7/manifest.yaml")
            require(index.schemaVersion == 2 && index.manifestResource == "canonical/r8/manifest.yaml" &&
                index.manifestSha256 == ReleaseLocks.sha256(manifestBytes) &&
                index.recentManifestSha256 == ReleaseLocks.sha256(r7Manifest) &&
                ReleaseLocks.sha256(r7Index) == "8b490d8b6b525e0bd59363ea197f11dc17ca5654308bb9ce4d8050351dd15345" &&
                ReleaseLocks.sha256(resource("$root/index.yaml")) == ReleaseLocks.sha256(r7Index) &&
                index.provenanceSha256 == ReleaseLocks.sha256(resource("$root/provenance.json")))
            val manifest = FragmentYaml.decode(manifestBytes, CanonicalSharedManifest.serializer())
            require(manifest.revision == 8 && manifest.scope == "full-private" &&
                manifest.fragments.size == 41 && index.entries.size == 39 &&
                manifest.fragments.take(2) == listOf(CanonicalSharedFragmentRef("postgres-timescale", 1),
                    CanonicalSharedFragmentRef("forgejo-postgres", 5)) &&
                manifest.fragments.drop(2).map { it.id to it.revision } ==
                    index.entries.map { it.id to it.revision })
            val pins = linkedMapOf("canonical/r8/index.yaml" to ReleaseLocks.sha256(indexBytes),
                "canonical/r8/manifest.yaml" to ReleaseLocks.sha256(manifestBytes))
            load("postgres-timescale", 1).exportResources().forEach { (path, bytes) ->
                pins["v2/$path"] = ReleaseLocks.sha256(bytes)
            }
            loadFullForgejo().exportResources().forEach { (path, bytes) ->
                pins["v2/$path"] = ReleaseLocks.sha256(bytes)
            }
            for (entry in index.entries) {
                val loaded = loadFrom(root, entry.id, entry.revision, "canonical/r8/index.yaml")
                pins.putAll(loaded.exportResources().mapValues { ReleaseLocks.sha256(it.value) })
            }
            return manifest to pins
        }
        /** Fresh-only full graph source, independently packaged; r7 active and r8
         * historical candidate stay byte-for-byte untouched until admission. */
        fun pendingV3R9(): Pair<CanonicalSharedManifest, Map<String, String>> {
            val root = "/fragments/v3"
            val indexBytes = resource("$root/canonical/r9/index.yaml")
            val index = FragmentYaml.decode(indexBytes, FragmentIndex.serializer())
            val manifestBytes = resource("$root/canonical/r9/manifest.yaml")
            require(index.schemaVersion == 2 && index.manifestResource == "canonical/r9/manifest.yaml" &&
                index.manifestSha256 == ReleaseLocks.sha256(manifestBytes) &&
                index.recentManifestSha256 == ReleaseLocks.sha256(resource("$root/canonical/r8/manifest.yaml")) &&
                ReleaseLocks.sha256(resource("$root/index.yaml")) == ReleaseLocks.sha256(resource("$root/canonical/r7/index.yaml")) &&
                index.provenanceSha256 == ReleaseLocks.sha256(resource("$root/provenance.json")))
            val generated = resource("$root/canonical/r9/generated-caddy.json")
            require(index.caddyResource == "canonical/r9/generated-caddy.json" &&
                index.adaptedCaddyJsonSha256 == ReleaseLocks.sha256(generated) &&
                index.generatedCaddyfileSha256?.matches(Regex("[a-f0-9]{64}")) == true &&
                generated.size in 5000..1_048_576) { "Adapted full ingress config is not source-pinned" }
            val manifest = FragmentYaml.decode(manifestBytes, CanonicalSharedManifest.serializer())
            require(manifest.revision == 9 && manifest.scope == "full-private" &&
                manifest.fragments.size == 41 && index.entries.size == 39 &&
                manifest.fragments.drop(2).map { it.id to it.revision } ==
                    index.entries.map { it.id to it.revision })
            val pins = linkedMapOf("canonical/r9/index.yaml" to ReleaseLocks.sha256(indexBytes),
                "canonical/r9/manifest.yaml" to ReleaseLocks.sha256(manifestBytes),
                "canonical/r9/generated-caddy.json" to ReleaseLocks.sha256(generated))
            load("postgres-timescale", 1).exportResources().forEach { (path, bytes) ->
                pins["v2/$path"] = ReleaseLocks.sha256(bytes)
            }
            loadFullForgejo().exportResources().forEach { (path, bytes) ->
                pins["v2/$path"] = ReleaseLocks.sha256(bytes)
            }
            for (entry in index.entries) {
                val loaded = loadFrom(root, entry.id, entry.revision, "canonical/r9/index.yaml")
                pins.putAll(loaded.exportResources().mapValues { ReleaseLocks.sha256(it.value) })
            }
            return manifest to pins
        }
        /** New source revision: old r9 index/manifest and its sealed member remain immutable.
         * Planka r2 adds a separate, first-use original actor enrollment after serving.
         * This is source authority only, never an initializer or user-account ACK. */
        fun pendingV3R10(): Pair<CanonicalSharedManifest, Map<String, String>> {
            val root = "/fragments/v3"
            val indexBytes = resource("$root/canonical/r10/index.yaml")
            val index = FragmentYaml.decode(indexBytes, FragmentIndex.serializer())
            val manifestBytes = resource("$root/canonical/r10/manifest.yaml")
            val r9 = resource("$root/canonical/r9/manifest.yaml")
            val generated = resource("$root/canonical/r10/generated-caddy.json")
            require(index.schemaVersion == 2 && index.manifestResource == "canonical/r10/manifest.yaml" &&
                index.manifestSha256 == ReleaseLocks.sha256(manifestBytes) &&
                index.recentManifestSha256 == ReleaseLocks.sha256(r9) &&
                index.provenanceSha256 == ReleaseLocks.sha256(resource("$root/provenance.json")) &&
                index.caddyResource == "canonical/r10/generated-caddy.json" &&
                index.adaptedCaddyJsonSha256 == ReleaseLocks.sha256(generated) &&
                index.generatedCaddyfileSha256?.matches(Regex("[a-f0-9]{64}")) == true)
            val manifest = FragmentYaml.decode(manifestBytes, CanonicalSharedManifest.serializer())
            require(manifest.revision == 10 && manifest.scope == "full-private" &&
                manifest.fragments.size == 41 && index.entries.size == 39 &&
                manifest.fragments.drop(2).map { it.id to it.revision } ==
                    index.entries.map { it.id to it.revision } &&
                index.entries.single { it.id == "planka-postgres" }.let { it.revision == 2 &&
                    it.resource == "planka/r2/fragment.yaml" &&
                    it.sha256 == "9b9c9fac25ee9037e0ef045f5bd9c024f0e021f65ff595ccfd34339b166117ca" })
            val pins = linkedMapOf("canonical/r10/index.yaml" to ReleaseLocks.sha256(indexBytes),
                "canonical/r10/manifest.yaml" to ReleaseLocks.sha256(manifestBytes),
                "canonical/r10/generated-caddy.json" to ReleaseLocks.sha256(generated))
            load("postgres-timescale", 1).exportResources().forEach { (path, bytes) ->
                pins["v2/$path"] = ReleaseLocks.sha256(bytes)
            }
            loadFullForgejo().exportResources().forEach { (path, bytes) ->
                pins["v2/$path"] = ReleaseLocks.sha256(bytes)
            }
            for (entry in index.entries) {
                val loaded = loadFrom(root, entry.id, entry.revision, "canonical/r10/index.yaml")
                pins.putAll(loaded.exportResources().mapValues { ReleaseLocks.sha256(it.value) })
            }
            return manifest to pins
        }
        fun v3Manifest(): Pair<ByteArray, Map<String, String>> {
            val indexBytes = resource("/fragments/v3/index.yaml")
            val index = FragmentYaml.decode(indexBytes, FragmentIndex.serializer())
            require(index.schemaVersion == 2 && index.manifestSha256?.matches(Regex("[a-f0-9]{64}")) == true)
            val manifestPath = index.manifestResource ?: "manifest.yaml"
            require(manifestPath.matches(Regex("(?:manifest.yaml|canonical/r[1-9][0-9]*/manifest.yaml)")))
            val manifest = resource("/fragments/v3/$manifestPath")
            val previous = resource("/fragments/v3/manifest.yaml")
            val intermediate = resource("/fragments/v3/canonical/r2/manifest.yaml")
            val prior = resource("/fragments/v3/canonical/r3/manifest.yaml")
            val latestPrior = resource("/fragments/v3/canonical/r4/manifest.yaml")
            val penultimate = resource("/fragments/v3/canonical/r5/manifest.yaml")
            val last = resource("/fragments/v3/canonical/r6/manifest.yaml")
            val archiveR7 = if (manifestPath == "canonical/r7/manifest.yaml") null else {
                require(manifestPath in setOf("canonical/r8/manifest.yaml", "canonical/r9/manifest.yaml")) {
                    "Unarchived V3 manifest revision"
                }
                val archive = resource("/fragments/v3/canonical/r7/index.yaml")
                val manifestR7 = resource("/fragments/v3/canonical/r7/manifest.yaml")
                val parentManifest = if (manifestPath == "canonical/r9/manifest.yaml") {
                    require(ReleaseLocks.sha256(resource("/fragments/v3/canonical/r8/index.yaml")) ==
                        "1b5412a884ba3fa39e808265982f2a6fe24379ae30ab9a31803097b21690a383")
                    resource("/fragments/v3/canonical/r8/manifest.yaml")
                } else manifestR7
                require(ReleaseLocks.sha256(archive) == "8b490d8b6b525e0bd59363ea197f11dc17ca5654308bb9ce4d8050351dd15345" &&
                    index.recentManifestSha256 == ReleaseLocks.sha256(parentManifest)) { "Historical V3 parent index changed" }
                archive to manifestR7
            }
            val provenance = resource("/fragments/v3/provenance.json")
            require(ReleaseLocks.sha256(manifest) == index.manifestSha256 &&
                (index.previousManifestSha256 == null || ReleaseLocks.sha256(previous) == index.previousManifestSha256) &&
                (index.intermediateManifestSha256 == null ||
                    ReleaseLocks.sha256(intermediate) == index.intermediateManifestSha256) &&
                (index.priorManifestSha256 == null || ReleaseLocks.sha256(prior) == index.priorManifestSha256) &&
                (index.latestPriorManifestSha256 == null ||
                    ReleaseLocks.sha256(latestPrior) == index.latestPriorManifestSha256) &&
                (index.penultimateManifestSha256 == null ||
                    ReleaseLocks.sha256(penultimate) == index.penultimateManifestSha256) &&
                (index.lastManifestSha256 == null || ReleaseLocks.sha256(last) == index.lastManifestSha256) &&
                ReleaseLocks.sha256(provenance) == index.provenanceSha256) { "Packaged V3 manifest or provenance changed" }
            return manifest to mapOf("index.yaml" to ReleaseLocks.sha256(indexBytes),
                manifestPath to ReleaseLocks.sha256(manifest),
                "manifest.yaml" to ReleaseLocks.sha256(previous),
                "canonical/r2/manifest.yaml" to ReleaseLocks.sha256(intermediate),
                "canonical/r3/manifest.yaml" to ReleaseLocks.sha256(prior),
                "canonical/r4/manifest.yaml" to ReleaseLocks.sha256(latestPrior),
                "canonical/r5/manifest.yaml" to ReleaseLocks.sha256(penultimate),
                "canonical/r6/manifest.yaml" to ReleaseLocks.sha256(last),
                "provenance.json" to ReleaseLocks.sha256(provenance)) +
                (archiveR7?.let { (archive, manifestR7) -> mapOf(
                    "canonical/r7/manifest.yaml" to ReleaseLocks.sha256(manifestR7),
                    "canonical/r7/index.yaml" to ReleaseLocks.sha256(archive)) } ?: emptyMap()) +
                (if (manifestPath == "canonical/r9/manifest.yaml") mapOf(
                    "canonical/r8/manifest.yaml" to ReleaseLocks.sha256(resource("/fragments/v3/canonical/r8/manifest.yaml")),
                    "canonical/r8/index.yaml" to ReleaseLocks.sha256(resource("/fragments/v3/canonical/r8/index.yaml")))
                else emptyMap())
        }
        /** Original r4 index bytes were retained from the immutable controller
         * distribution. Historical ownership must use these exact archived pins,
         * not the current r5 index or an unauthenticated revision guess. */
        fun v3HistoricalR4Manifest(): Pair<CanonicalSharedManifest, Map<String, String>> = v3HistoricalManifest(4)
        fun v3HistoricalManifest(revision: Int): Pair<CanonicalSharedManifest, Map<String, String>> {
            require(revision in setOf(4, 5, 6, 7))
            val archive = resource("/fragments/v3/canonical/r$revision/index.yaml")
            val knownIndex = when (revision) {
                4 -> "f3be0c686903151aceb8abb2ab26ccaceec5b11a6a9274352c5122942ca546b0"
                5 -> "c32526e8e31d900fe7972f81ff8d944983107fe9ba44ec146b44248e37b70526"
                6 -> "03760b5473a8bdf3fdac52de5a720015b2429811e4356b0dccf01265cde196b1"
                else -> "8b490d8b6b525e0bd59363ea197f11dc17ca5654308bb9ce4d8050351dd15345"
            }
            require(ReleaseLocks.sha256(archive) == knownIndex)
            val index = FragmentYaml.decode(archive, FragmentIndex.serializer())
            require(index.schemaVersion == 2 && index.manifestResource == "canonical/r$revision/manifest.yaml" &&
                index.manifestSha256 == when (revision) {
                    4 -> "fad72915041487cd34c1dcf650d8f924f873a196d3f02305222c15423ae3b0cb"
                    5 -> "01a16971a26a2b30e2e8c395029ef46bee1081c4380c32ad323b4ce9171199a8"
                    6 -> "08bbd8fb06880329deb6fc60de1876d621b049abe177eb65262cf640bd7f5355"
                    else -> "8cbf33dc09e207b0ce5daaddb12d6b871b61bfb9c7d85db91c0565335fd28ae3"
                } &&
                index.provenanceSha256 == ReleaseLocks.sha256(resource("/fragments/v3/provenance.json")))
            val manifest = resource("/fragments/v3/canonical/r$revision/manifest.yaml")
            require(ReleaseLocks.sha256(manifest) == index.manifestSha256)
            val parsed = FragmentYaml.decode(manifest, CanonicalSharedManifest.serializer())
            require(parsed.id == CanonicalSharedYamlGraph.RECIPE && parsed.revision == revision &&
                parsed.fragments.drop(2).all { ref -> index.entries.any { it.id == ref.id && it.revision == ref.revision } } &&
                index.entries.all { e -> e.resource.matches(path) && e.sha256 ==
                    ReleaseLocks.sha256(resource("/fragments/v3/${e.resource}")) })
            val old = mapOf("index.yaml" to ReleaseLocks.sha256(archive),
                "canonical/r$revision/manifest.yaml" to ReleaseLocks.sha256(manifest),
                "manifest.yaml" to ReleaseLocks.sha256(resource("/fragments/v3/manifest.yaml")),
                "canonical/r2/manifest.yaml" to ReleaseLocks.sha256(resource("/fragments/v3/canonical/r2/manifest.yaml")),
                "canonical/r3/manifest.yaml" to ReleaseLocks.sha256(resource("/fragments/v3/canonical/r3/manifest.yaml")),
                "provenance.json" to ReleaseLocks.sha256(resource("/fragments/v3/provenance.json"))) +
                (if (revision >= 5) mapOf("canonical/r4/manifest.yaml" to
                    ReleaseLocks.sha256(resource("/fragments/v3/canonical/r4/manifest.yaml"))) else emptyMap()) +
                (if (revision >= 6) mapOf("canonical/r5/manifest.yaml" to
                    ReleaseLocks.sha256(resource("/fragments/v3/canonical/r5/manifest.yaml"))) else emptyMap()) +
                (if (revision == 7) mapOf("canonical/r6/manifest.yaml" to
                    ReleaseLocks.sha256(resource("/fragments/v3/canonical/r6/manifest.yaml"))) else emptyMap())
            require(index.previousManifestSha256 == old["manifest.yaml"] &&
                index.intermediateManifestSha256 == old["canonical/r2/manifest.yaml"] &&
                index.priorManifestSha256 == old["canonical/r3/manifest.yaml"] &&
                (revision == 4 || index.latestPriorManifestSha256 == old["canonical/r4/manifest.yaml"]) &&
                (revision != 7 || index.penultimateManifestSha256 == old["canonical/r5/manifest.yaml"]) &&
                (revision != 6 || index.lastManifestSha256 == old["canonical/r5/manifest.yaml"]) &&
                (revision != 7 || index.lastManifestSha256 == old["canonical/r6/manifest.yaml"]))
            return parsed to old
        }
        fun exportV3AssemblyResources(): Map<String, ByteArray> = v3Manifest().second.mapValues { (path, hash) ->
            resource("/fragments/v3/$path").also { require(ReleaseLocks.sha256(it) == hash) }
        }
        private fun loadFrom(root: String, id: String, revision: Int,
            indexResource: String = "index.yaml"): PackagedGraphFragment {
            require(root == "/fragments/v2" || root == "/fragments/v3")
            require(indexResource == "index.yaml" || root == "/fragments/v2" &&
                indexResource == "canonical/r5/index.yaml" && id == "forgejo-postgres" && revision == 5 ||
                root == "/fragments/v3" && indexResource in setOf("canonical/r8/index.yaml", "canonical/r9/index.yaml", "canonical/r10/index.yaml"))
            val indexBytes = resource("$root/$indexResource")
            val index = FragmentYaml.decode(indexBytes, FragmentIndex.serializer())
            require(index.schemaVersion == 2 && index.provenanceSha256.matches(Regex("[a-f0-9]{64}")) && index.entries.size in 1..128 &&
                index.entries.map { it.id to it.revision }.distinct().size == index.entries.size)
            require(index.entries.map { it.resource }.distinct().size == index.entries.size)
            index.entries.forEach {
                require(path.matches(it.resource) && it.sha256.matches(Regex("[a-f0-9]{64}")) &&
                    it.templates.all { (name, hash) -> name.matches(Regex("[a-z][a-z0-9.-]{0,79}")) &&
                        name != "fragment.yaml" && hash.matches(Regex("[a-f0-9]{64}")) })
            }
            val provenance = resource("$root/provenance.json")
            require(ReleaseLocks.sha256(provenance) == index.provenanceSha256) { "Packaged provenance digest mismatch" }
            val entry = index.entries.single { it.id == id && it.revision == revision }
            val bytes = resource("$root/${entry.resource}")
            require(ReleaseLocks.sha256(bytes) == entry.sha256) { "Packaged fragment digest mismatch" }
            val definition = GraphFragment.lint(bytes)
            require(definition.id == id && definition.revision == revision &&
                entry.resource == "${definition.product}/r$revision/fragment.yaml")
            require(definition.templates.map { it.resource }.toSet() == entry.templates.keys)
            val templateBytes = entry.templates.mapValues { (name, hash) ->
                resource("$root/${entry.resource.substringBeforeLast('/')}/$name").also {
                    require(ReleaseLocks.sha256(it) == hash) { "Packaged template digest mismatch" }
                }
            }
            val texts = templateBytes.mapValues { (_, bytes) -> bytes.decodeToString(throwOnInvalidSequence = true) }
            definition.templates.forEach { FragmentTemplates.validate(it, texts.getValue(it.resource)) }
            val retained = mapOf(indexResource to indexBytes, "provenance.json" to provenance, entry.resource to bytes) +
                templateBytes.mapKeys { "${entry.resource.substringBeforeLast('/')}/${it.key}" }
            return PackagedGraphFragment(bytes, retained.mapValues { ReleaseLocks.sha256(it.value) }, texts, retained)
        }
        internal fun r10CaddyJson(): ByteArray {
            pendingV3R10()
            return resource("/fragments/v3/canonical/r10/generated-caddy.json")
        }
        internal fun r10CaddySourceHash(): String {
            val index = FragmentYaml.decode(resource("/fragments/v3/canonical/r10/index.yaml"), FragmentIndex.serializer())
            pendingV3R10()
            return requireNotNull(index.generatedCaddyfileSha256)
        }
        internal fun r9CaddyJson(): ByteArray {
            pendingV3R9() // binds the artifact to its exact r9 index before returning it
            return resource("/fragments/v3/canonical/r9/generated-caddy.json")
        }
        internal fun r9CaddySourceHash(): String {
            val index = FragmentYaml.decode(resource("/fragments/v3/canonical/r9/index.yaml"), FragmentIndex.serializer())
            pendingV3R9()
            return requireNotNull(index.generatedCaddyfileSha256)
        }
        private fun resource(path: String): ByteArray = requireNotNull(PackagedGraphFragment::class.java.getResourceAsStream(path)).use {
            it.readNBytes(FragmentYaml.MAX_BYTES + 1).also { bytes -> require(bytes.size <= FragmentYaml.MAX_BYTES) }
        }
    }
}

@Serializable private data class FragmentIndex(val schemaVersion: Int, val provenanceSha256: String, val entries: List<FragmentIndexEntry>,
    val manifestSha256: String? = null, val manifestResource: String? = null,
    val previousManifestSha256: String? = null, val intermediateManifestSha256: String? = null,
    val priorManifestSha256: String? = null, val latestPriorManifestSha256: String? = null,
    val lastManifestSha256: String? = null, val penultimateManifestSha256: String? = null,
    val recentManifestSha256: String? = null,
    val generatedCaddyfileSha256: String? = null, val adaptedCaddyJsonSha256: String? = null,
    val caddyResource: String? = null)
@Serializable private data class FragmentIndexEntry(val id: String, val revision: Int, val resource: String,
    val sha256: String, val templates: Map<String, String> = emptyMap())
