package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.Serializable

@Serializable internal data class CanonicalSharedFragmentRef(val id: String, val revision: Int)
@Serializable internal data class CanonicalSharedManifest(val schemaVersion: Int, val id: String, val revision: Int,
    val fragments: List<CanonicalSharedFragmentRef>, val scope: String = "development-core",
    val integratedReference: IntegratedOldReference? = null,
    val extraBindings: List<IntegratedExtraBinding> = emptyList())
/** Pinned OLD descriptors remain auditable even when an agreed v3 release
 * deliberately folds or EXCLUDES them. Excluded references contribute zero
 * processes, native controls, credentials, routes and capacity.
 */
@Serializable internal enum class HistoricalSupportDisposition {
    EXECUTABLE_SUPPORT, ROOTLESS_CI_CONTROL, FOLDED_POSTGRES, FOLDED_FOUNDATION,
    FOLDED_IDENTITY, MANAGED_TEST_RUNTIME, EXCLUDED_REFERENCE
}
@Serializable internal data class IntegratedExtraBinding(val id: String, val nativeDaemons: List<String> = emptyList(),
    val nativeControl: String? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val historicalDisposition: HistoricalSupportDisposition? = null)

/** Public, pinned OLD integrated architecture in the SAME packaged manifest as executable fragments.
 * These reference IDs never authorize running legacy images, scripts, routes or credentials.
 */
@Serializable internal data class IntegratedOldReference(val repository: String, val commit: String,
    val generatorRepository: String, val generatorCommit: String, val generatorSha256: String,
    val routeSourceSha256: String, val modules: List<IntegratedOldModule>,
    val routes: List<IntegratedOldRoute>, val deviations: List<IntegratedDeviation>,
    val wiring: List<IntegratedWiring>) {
    fun validate(selected: Set<String>) {
        val sha = Regex("[a-f0-9]{64}")
        require(repository == "geraldsummers/p0-modules" &&
            commit == "36b6b74211036df8d425f8c6d6bec276c5f50aae" &&
            generatorRepository == "geraldsummers/sso-stack-generator" &&
            generatorCommit == "42bd13939bc95439b3237cd3f53b06d03f6b85d4" &&
            generatorSha256 == "92aaf2c9bbeea10c6cbe1b91bbc3950dda6548431ffd80fadf35629ee1deb1e6" &&
            routeSourceSha256 == "cd5297dd239b573ea677539a61415a21cd0ed9d32917b064120ea640862775e6" &&
            modules.size == 47 &&
            modules.map { it.id }.distinct().size == modules.size &&
            modules.filter { it.role == "selected" }.map { it.id }.toSet() == selected &&
            modules.filter { it.role == "historical-support" }.map { it.id }.toSet() ==
                setOf("forgejo-runner", "keycloak-auth-gateway", "legal-research-mcp", "onboarding", "portal",
                    "postgres-ssd", "stack-foundation", "test-runners"))
        val mapped = modules.flatMap { it.nativeDaemons }
        require(mapped.distinct().size == mapped.size && modules.all {
            (it.nativeDaemons.isEmpty() || it.role == "selected") &&
                (it.nativeControl == null || (it.role == "selected" && it.nativeDaemons.isEmpty() &&
                    it.nativeControl.matches(Regex("[a-z][a-z-]{1,63}"))))
        } && mapped.isNotEmpty()) {
            "Native processes must have unique selected reference owners"
        }
        val services = modules.flatMap { it.services }
        val ids = services.map { it.id }.toSet()
        require(services.isNotEmpty() && ids.size == services.size &&
            modules.all { it.descriptorSha256.matches(sha) && it.runtimeSha256.matches(sha) &&
                it.services.isNotEmpty() } &&
            services.all { service -> service.lifecycle in setOf("daemon", "oneshot", "on-demand") &&
                service.dependsOn.distinct().size == service.dependsOn.size &&
                service.dependsOn.all { it in ids && it != service.id } &&
                service.networks.distinct().size == service.networks.size &&
                service.state.distinct().size == service.state.size } &&
            routes.isNotEmpty() && routes.map { it.label }.distinct().size == routes.size &&
            routes.all { it.label.matches(Regex("[a-z][a-z0-9-]*(?:\\.[a-z][a-z0-9-]*)?")) &&
                it.upstreams.isNotEmpty() && it.upstreams.all(ids::contains) } &&
            deviations.map { it.id }.toSet() == setOf("vault", "postgres", "forgejo-ci", "managed-lanes",
                "backup", "identity", "routes", "lifecycle", "search", "resource") &&
            deviations.size == 10 && deviations.all { it.source.isNotBlank() &&
                it.destination.isNotBlank() && it.contract.isNotBlank() } &&
            wiring.size in 120..512 && wiring.distinct().size == wiring.size &&
            wiring.all { edge -> edge.source != edge.target &&
                edge.source in selected + setOf("keykeeper", "openbao", "worklane", "tuios", "pi") &&
                edge.target in selected + setOf("keykeeper", "openbao", "worklane", "tuios", "pi") &&
                edge.kind in setOf("startup", "provider", "route", "state-backup", "identity", "config",
                    "telemetry", "deviation", "managed-lane") && edge.requirement.isNotBlank() } &&
            selected.all { product -> wiring.any { it.source == product || it.target == product } } &&
            modules.filter { module -> module.id in selected && module.services.any { it.state.isNotEmpty() } &&
                module.id != "kopia" }.all { module ->
                    wiring.any { it.source == module.id && it.target == "kopia" && it.kind == "state-backup" } } &&
            setOf("keycloak" to "matrix-authentication-service", "matrix-authentication-service" to "synapse",
                "seafile" to "onlyoffice", "mailserver" to "sogo", "keykeeper" to "openbao").all { (a, b) ->
                wiring.any { it.source == a && it.target == b && it.kind in setOf("identity", "config") } }) {
            "Incomplete or disconnected pinned integrated reference topology"
        }
        val endpoints = selected + setOf("keykeeper", "openbao", "worklane", "tuios", "pi")
        val connected = mutableSetOf("postgres")
        do {
            val before = connected.size
            wiring.forEach { edge ->
                if (edge.source in connected) connected.add(edge.target)
                if (edge.target in connected) connected.add(edge.source)
            }
        } while (connected.size != before)
        require(connected == endpoints) { "The selected integrated private topology is disconnected" }
        // Old startup cycles are not transferable as initialization ordering.
        // Every future runnable fragment must independently declare its ordered dependencies.
    }
}
@Serializable internal data class IntegratedOldModule(val id: String, val role: String,
    val descriptorSha256: String, val runtimeSha256: String, val services: List<IntegratedOldService>,
    val nativeDaemons: List<String> = emptyList(), val nativeControl: String? = null,
    /** Fresh-only ingress owned by this selected module; never OLD's untrusted listener state. */
    val privateRoutes: List<CanonicalIngressRoute> = emptyList())
@Serializable internal data class CanonicalIngressRoute(val label: String, val host: String,
    val process: String? = null, val network: String? = null, val port: Int? = null,
    val policy: String, val special: String = "", val tlsName: String? = null,
    val caInput: String? = null, val aliasOf: String? = null, val groups: String? = null)

@Serializable internal data class IntegratedOldService(val id: String, val lifecycle: String,
    val dependsOn: List<String>, val networks: List<String>, val state: List<String>)
@Serializable internal data class IntegratedOldRoute(val label: String, val upstreams: List<String>)
@Serializable internal data class IntegratedWiring(val source: String, val target: String,
    val kind: String, val requirement: String)
@Serializable internal data class IntegratedDeviation(val id: String, val source: String,
    val destination: String, val contract: String)

/** First actual V3 shared-provider Quadlet composition, NOT the full release recipe.
 * The sealed YAML manifest alone selects components. Historical V2 index/recipes are
 * byte-for-byte unchanged. Later components must join this same provider namespace,
 * never add a second database or another private standalone member.
 */
internal object CanonicalSharedYamlGraph {
    const val RECIPE = "canonical-shared-core-v3"
    const val R9_ASSEMBLY_RECIPE = "full-private-r9"
    const val R10_ASSEMBLY_RECIPE = "full-private-r10"

    fun manifest(): CanonicalSharedManifest = validateManifest(FragmentYaml.decode(
        PackagedGraphFragment.v3Manifest().first, CanonicalSharedManifest.serializer()))

    /** Offline source closure against the independent, unactivated r8 index.
     * This cannot select a runtime graph or confer native admission. */
    fun pendingR8Source(): Map<String, Int> {
        val pending = PackagedGraphFragment.pendingV3R8()
        val release = validateManifest(pending.first)
        require(release.scope == "full-private" && release.revision == 8)
        val v2 = FragmentRecipes.fragments(5)
        val extensions = release.fragments.drop(2).map { PackagedGraphFragment.loadPendingV3(it.id, it.revision) }
        val all = v2 + extensions
        require(all.map { it.definition.product }.distinct().size == all.size &&
            all.flatMap { it.definition.processes.map { process -> process.id } }.distinct().size ==
                all.sumOf { it.definition.processes.size } &&
            all.flatMap { it.definition.inputs.map { input -> input.name to input.owner } }
                .groupBy { it.first }.values.all { producers -> producers.map { it.second }.distinct().size == 1 }) {
            "Full-private source has duplicate daemon or conflicting credential producers"
        }
        return linkedMapOf("selectedFragments" to release.fragments.size,
            "sourceProcesses" to all.sumOf { it.definition.processes.size },
            "sourceInputs" to all.flatMap { it.definition.inputs }.map { it.name }.distinct().size,
            "historicalModules" to requireNotNull(release.integratedReference).modules.size)
    }

    internal fun pendingR9OwnerFor(process: String): String? = PackagedGraphFragment.pendingV3R9().first.fragments.drop(2)
        .map { PackagedGraphFragment.loadPendingV3(it.id, it.revision, 9).definition }
        .singleOrNull { fragment -> fragment.processes.any { it.id == process } }?.product

    fun pendingR9FreshSource(): Map<String, Int> {
        val pending = PackagedGraphFragment.pendingV3R9()
        val release = validateManifest(pending.first)
        require(release.scope == "full-private" && release.revision == 9 &&
            release.fragments.single { it.id == "private-mastodon-shared-redis-bridge" }.revision == 5)
        val selected = FragmentRecipes.fragments(5) + release.fragments.drop(2).map {
            PackagedGraphFragment.loadPendingV3(it.id, it.revision, 9)
        }
        require(selected.map { it.definition.product }.distinct().size == selected.size &&
            selected.flatMap { it.definition.processes.map { p -> p.id } }.distinct().size ==
                selected.sumOf { it.definition.processes.size } &&
            selected.flatMap { it.definition.inputs.map { i -> i.name to i.owner } }
                .groupBy { it.first }.values.all { values -> values.map { it.second }.distinct().size == 1 })
        return linkedMapOf("selectedFragments" to release.fragments.size,
            "sourceProcesses" to selected.sumOf { it.definition.processes.size },
            "sourceInputs" to selected.flatMap { it.definition.inputs }.map { it.name }.distinct().size)
    }

    private fun validateManifest(parsed: CanonicalSharedManifest): CanonicalSharedManifest {
        require(parsed.schemaVersion == 2 && parsed.id == RECIPE && parsed.revision in 1..128 &&
            parsed.scope in setOf("development-core", "full-private") &&
            parsed.fragments.size in 3..64 &&
            parsed.fragments.map { it.id to it.revision }.distinct().size == parsed.fragments.size &&
            parsed.fragments.take(2) == listOf(CanonicalSharedFragmentRef("postgres-timescale", 1),
                CanonicalSharedFragmentRef("forgejo-postgres", if (parsed.scope == "full-private") 5 else 4)) &&
            parsed.fragments.drop(2).all { it.id.matches(Regex("[a-z][a-z0-9-]{0,39}")) && it.revision in 1..128 }) {
            "V3 manifest must select the reviewed shared provider topology"
        }
        if (parsed.revision >= 7) {
            val baseline = requireNotNull(parsed.integratedReference) {
                "Integrated old reference must be bound into current packaged graph"
            }
            baseline.validate(ProductSelection.bundled().products.toSet())
            val mapped = baseline.modules.filter { it.nativeDaemons.isNotEmpty() }.map { it.id }.toSet()
            val controlled = baseline.modules.filter { it.nativeControl != null }.map { it.id }.toSet()
            val extraDaemons = parsed.extraBindings.flatMap { it.nativeDaemons }
            // OLD stays traceable; only approved executable/CI support owners
            // are release bindings. Folded, managed and excluded descriptors
            // do not add products, daemon slots or admission prerequisites.
            val requiredSupport = mapOf(
                "forgejo-runner" to HistoricalSupportDisposition.ROOTLESS_CI_CONTROL,
                "keycloak-auth-gateway" to HistoricalSupportDisposition.EXECUTABLE_SUPPORT,
                "portal" to HistoricalSupportDisposition.EXECUTABLE_SUPPORT)
            val foldedReferences = mapOf(
                "onboarding" to HistoricalSupportDisposition.FOLDED_IDENTITY,
                "postgres-ssd" to HistoricalSupportDisposition.FOLDED_POSTGRES,
                "stack-foundation" to HistoricalSupportDisposition.FOLDED_FOUNDATION,
                "test-runners" to HistoricalSupportDisposition.MANAGED_TEST_RUNTIME,
                "legal-research-mcp" to HistoricalSupportDisposition.EXCLUDED_REFERENCE)
            require(requiredSupport.keys + foldedReferences.keys == baseline.modules
                .filter { it.role == "historical-support" }.map { it.id }.toSet())
            require(parsed.extraBindings.map { it.id }.distinct().size == parsed.extraBindings.size &&
                (mapped.isNotEmpty() && mapped.intersect(parsed.extraBindings.map { it.id }.toSet()).isEmpty()) &&
                extraDaemons.distinct().size == extraDaemons.size &&
                (parsed.scope == "development-core" && mapped.size < 39 && parsed.extraBindings.isEmpty() ||
                    parsed.scope == "full-private" && mapped + controlled == ProductSelection.bundled().products.toSet() &&
                        controlled == setOf("kopia", "mastodon-rss-publisher") &&
                        baseline.modules.single { it.id == "kopia" }.nativeControl == "kopia-generation-store" &&
                        baseline.modules.single { it.id == "mastodon-rss-publisher" }.nativeControl == "rss-scheduled-controller" &&
                        parsed.extraBindings.map { it.id }.toSet() ==
                            setOf("keykeeper", "openbao", "worklane", "tuios", "pi") +
                            requiredSupport.keys &&
                        parsed.extraBindings.filter { it.id in setOf("keykeeper", "openbao") }.all {
                            it.nativeDaemons.isNotEmpty() && it.nativeControl == null &&
                                it.historicalDisposition == null
                        } &&
                        parsed.extraBindings.filter { it.id in setOf("worklane", "tuios", "pi") }.all {
                            it.nativeDaemons.isEmpty() && !it.nativeControl.isNullOrBlank() &&
                                it.historicalDisposition == null
                        } && parsed.extraBindings.filter { it.id in requiredSupport }.all { support ->
                            support.historicalDisposition == requiredSupport.getValue(support.id) &&
                                when (support.historicalDisposition) {
                                    HistoricalSupportDisposition.EXECUTABLE_SUPPORT ->
                                        support.nativeDaemons == listOf(if (support.id == "keycloak-auth-gateway")
                                            "auth-gateway" else support.id) && support.nativeControl == null &&
                                            parsed.fragments.drop(2).any { it.id == "private-${support.id}" }
                                    HistoricalSupportDisposition.ROOTLESS_CI_CONTROL ->
                                        support.nativeDaemons.isEmpty() &&
                                            support.nativeControl == "forgejo-ephemeral-rootless-runner"
                                    else -> false
                                }
                        } && parsed.fragments.drop(2).none { it.id in foldedReferences })) {
                "Unbound families cannot be released as an integrated full stack"
            }
        }
        return parsed
    }

    fun capabilities(): Set<String> {
        val release = manifest()
        return setOf("postgres", "forgejo") +
            release.fragments.drop(2).map { PackagedGraphFragment.loadV3(it.id, it.revision).definition.product } +
            (if (release.scope == "full-private") requireNotNull(release.integratedReference).modules
                .filter { it.nativeControl != null && it.id in setOf("kopia", "mastodon-rss-publisher") }
                .map { it.id } else emptyList())
    }

    fun pendingR10Capabilities(): Set<String> {
        val release = PackagedGraphFragment.pendingV3R10().first
        require(release.scope == "full-private" && release.revision == 10)
        return setOf("postgres", "forgejo") +
            release.fragments.drop(2).map { PackagedGraphFragment.loadPendingV3(it.id, it.revision, 10).definition.product } +
            requireNotNull(release.integratedReference).modules.filter { it.nativeControl != null &&
                it.id in setOf("kopia", "mastodon-rss-publisher") }.map { it.id }
    }

    fun pendingR9Capabilities(): Set<String> {
        val release = PackagedGraphFragment.pendingV3R9().first
        require(release.scope == "full-private" && release.revision == 9)
        return setOf("postgres", "forgejo") +
            release.fragments.drop(2).map { PackagedGraphFragment.loadPendingV3(it.id, it.revision, 9).definition.product } +
            requireNotNull(release.integratedReference).modules.filter { it.nativeControl != null &&
                it.id in setOf("kopia", "mastodon-rss-publisher") }.map { it.id }
    }

    fun processOwners(): Map<String, String> = FragmentRecipes.processOwners(FragmentRecipes.FORGEJO_POSTGRES) +
        manifest().fragments.drop(2).flatMap { ref -> PackagedGraphFragment.loadV3(ref.id, ref.revision).definition.let { f ->
            f.processes.map { it.id to f.product } } }.toMap()

    /** Historical native readback resolves exact ORIGINAL packaged resource closure. Never infer
     * missing old role ACKs from the current manifest, or waive sealed ownership on a retired source.
     */
    internal fun processOwnersFor(spec: PrivateDeploymentSpec): Map<String, String> {
        val binding = requireNotNull(spec.fragmentBinding)
        require(binding.recipe == RECIPE && spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2)
        val old = FragmentRecipes.processOwners(FragmentRecipes.FORGEJO_POSTGRES)
        val extras = boundExtensions(spec).flatMap { fragment -> fragment.definition.let { definition ->
            definition.processes.map { it.id to definition.product }
        } }.toMap()
        val roles = old + extras
        val ids = spec.processes.map { it.id }.toSet()
        require(ids.size == spec.processes.size && roles.keys.containsAll(ids) &&
            (binding.phase == FragmentPhase.RESTORE.name || roles.keys == ids)) {
            "Sealed native process roles differ from original packaged revision"
        }
        return roles.filterKeys(ids::contains)
    }

    private fun boundExtensions(spec: PrivateDeploymentSpec): List<PackagedGraphFragment> {
        val binding = requireNotNull(spec.fragmentBinding)
        require(binding.recipe == RECIPE && binding.phase in setOf(FragmentPhase.INSTALL.name, FragmentPhase.RESTORE.name))
        val baseline = FragmentRecipes.fragments()
        val current = manifest()
        val candidates = listOf(current.fragments.drop(2) to PackagedGraphFragment.v3Manifest().second) +
            (listOf(4, 5, 6) + if (manifest().revision > 7) listOf(7) else emptyList())
                .map(PackagedGraphFragment::v3HistoricalManifest).map {
                it.first.fragments.drop(2) to it.second
            }
        return candidates.map { (refs, manifestHashes) ->
            val extensions = refs.map { PackagedGraphFragment.loadV3(it.id, it.revision) }
            val selectedBaseline = if (refs == current.fragments.drop(2) && current.scope == "full-private")
                FragmentRecipes.fragments(5) else baseline
            val expected = (selectedBaseline.flatMap { f -> f.resourceHashes.entries.map { "fragments/v2/${it.key}" to it.value } } +
                extensions.flatMap { f -> f.resourceHashes.entries.map { "fragments/v3/${it.key}" to it.value } } +
                manifestHashes.map { "fragments/v3/${it.key}" to it.value }).toMap()
            expected to extensions
        }.let { historical ->
            val pending = PackagedGraphFragment.pendingV3R9()
            val r9 = pending.first.fragments.drop(2).map { PackagedGraphFragment.loadPendingV3(it.id, it.revision, 9) }
            val expected = (FragmentRecipes.fragments(5).flatMap { f -> f.resourceHashes.entries.map {
                "fragments/v2/${it.key}" to it.value } } +
                r9.flatMap { f -> f.resourceHashes.entries.map { "fragments/v3/${it.key}" to it.value } } +
                pending.second.filterKeys { !it.startsWith("v2/") }.map {
                    "fragments/v3/${it.key}" to it.value }).toMap()
            val next = PackagedGraphFragment.pendingV3R10()
            val r10 = next.first.fragments.drop(2).map { PackagedGraphFragment.loadPendingV3(it.id, it.revision, 10) }
            val nextExpected = (FragmentRecipes.fragments(5).flatMap { f -> f.resourceHashes.entries.map {
                "fragments/v2/${it.key}" to it.value } } +
                r10.flatMap { f -> f.resourceHashes.entries.map { "fragments/v3/${it.key}" to it.value } } +
                next.second.filterKeys { !it.startsWith("v2/") }.map {
                    "fragments/v3/${it.key}" to it.value }).toMap()
            historical + (expected to r9) + (nextExpected to r10)
        }.single { it.first == binding.resources }.second
    }

    fun inputOwnersFor(spec: PrivateDeploymentSpec): Map<String, String> {
        val selected = boundExtensions(spec)
        val roles = processOwnersFor(spec)
        val inputs = FragmentRecipes.inputOwners(FragmentRecipes.FORGEJO_POSTGRES) +
            selected.flatMap { fragment -> fragment.definition.inputs.map { it.name to it.owner } }.also { rows ->
                require(rows.groupBy { it.first }.values.all { group -> group.map { it.second }.distinct().size == 1 })
            }.toMap()
        require(roles.values.containsAll(inputs.values))
        return inputs.filterKeys(PrivateDeployment.inputNames(spec).toSet()::contains)
    }

    fun inputOwners(): Map<String, String> {
        val shared = FragmentRecipes.inputOwners(FragmentRecipes.FORGEJO_POSTGRES)
        val extra = manifest().fragments.drop(2).flatMap { ref ->
            PackagedGraphFragment.loadV3(ref.id, ref.revision).definition.inputs.map { it.name to it.owner }
        }
        require(extra.groupBy { it.first }.values.all { group -> group.map { it.second }.distinct().size == 1 } &&
            extra.all { (name, owner) -> name !in shared || shared[name] == owner })
        return shared + extra
    }

    fun exportedProviderInput(spec: PrivateDeploymentSpec, file: String, owner: String): Boolean {
        val binding = spec.fragmentBinding ?: return false
        if (binding.recipe != RECIPE || spec.executionBackend != RuntimeExecutionBackend.QUADLET_V2 ||
            file != "postgres-ca.pem" || owner != "postgres" ||
            binding.phase !in setOf(FragmentPhase.INSTALL.name, FragmentPhase.RESTORE.name)) return false
        val baseline = FragmentRecipes.fragments(if (manifest().scope == "full-private") 5 else 4)
        val matching = runCatching { boundExtensions(spec) }.getOrNull() ?: return false
        if (file !in baseline.single { it.definition.product == owner }.definition.exportedInputs ||
            spec.processes.none { it.id == "postgres" && !it.oneShot }) return false
        val declared = (baseline + matching).flatMap { it.definition.inputs }
            .filter { it.name == file && it.owner == owner }.flatMap { it.consumers }.toSet()
        val actual = spec.processes.filter { it.environmentFile == file || it.files.any { f -> f.file == file } }
            .map { it.id }.toSet()
        return actual.isNotEmpty() && declared.containsAll(actual)
    }

    fun bindController(spec: PrivateDeploymentSpec, request: AssemblyRequest): PrivateDeploymentSpec {
        require(request.store == RuntimeStore.CANONICAL_V2 && spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2 &&
            spec.fragmentBinding?.recipe == RECIPE && spec.fragmentBinding.phase == FragmentPhase.INSTALL.name &&
            ((manifest().scope != "full-private" && request.selections.none { it.recipe in setOf(R9_ASSEMBLY_RECIPE, R10_ASSEMBLY_RECIPE) }) ||
                request.managedLanes?.let { lanes ->
                lanes.validate(request.id)
                FreshWorklaneCandidate.requireSelected(lanes)
                val fresh = request.freshIdentity ?: return@let false
                fresh.validate()
                val rss = request.rssPlan ?: return@let false
                rss.validate()
                request.originalIdentity == null && request.originalMastodon == null &&
                    request.forgejoCi?.let { ci -> ci.validate(request.id); true } == true &&
                    request.portalRoutes?.let { routes -> routes.isNotEmpty() &&
                        routes.map { it.host }.distinct().size == routes.size } == true &&
                    request.mastodonRedisScripts?.let { source ->
                        source.sha256.matches(Regex("[a-f0-9]{64}")) &&
                            Path.of(source.path).normalize() == Path.of(source.path) &&
                            source.path.startsWith("/mnt/media/p0-v3/release-bootstrap-anchors/mastodon/")
                    } == true &&
                    (if (request.selections.singleOrNull()?.recipe in setOf(R9_ASSEMBLY_RECIPE, R10_ASSEMBLY_RECIPE))
                        request.baoBootstrapOperation?.also { it.validate(request.id) } != null &&
                            request.baoBootstrapToken == null
                    else request.baoBootstrapToken?.let { source ->
                        source.sha256.matches(Regex("[a-f0-9]{64}")) &&
                            Path.of(source.path).normalize() == Path.of(source.path) &&
                            source.path.startsWith("/mnt/media/p0-v3/release-bootstrap-anchors/bao/")
                    } == true) &&
                    rss.mastodonOrigin == "https://social.datamancy.net" &&
                    lanes.ownerSubject == fresh.ownerUuid &&
                    lanes.lanes.all { it.subject !in setOf(fresh.ownerUuid,
                        fresh.outsiderUuid, fresh.appNonMemberUuid) } &&
                    lanes.readerSubject?.let { reader -> reader !in setOf(fresh.ownerUuid,
                        fresh.outsiderUuid, fresh.appNonMemberUuid) } == true &&
                    lanes.native.brokerHost?.let { host -> host.validate(request.id); true } == true &&
                    lanes.native.imageArchive != null && lanes.native.broker != null &&
                    lanes.capabilities == setOf("worklane", "tuios", "pi")
            } == true))
        if (request.selections.any { it.recipe in setOf(R9_ASSEMBLY_RECIPE, R10_ASSEMBLY_RECIPE) }) {
            val revision = if (request.selections.single().recipe == R10_ASSEMBLY_RECIPE) 10 else 9
            val selected = if (revision == 10) PackagedGraphFragment.pendingV3R10()
                else PackagedGraphFragment.pendingV3R9()
            val binding = requireNotNull(spec.fragmentBinding)
            require(spec.name == "${request.id}-v2" &&
                binding.resources["fragments/v3/canonical/r$revision/index.yaml"] == selected.second.getValue("canonical/r$revision/index.yaml") &&
                binding.resources["fragments/v3/canonical/r$revision/manifest.yaml"] == selected.second.getValue("canonical/r$revision/manifest.yaml")) {
                "Full candidate must bind exactly the selected r$revision index/manifest"
            }
            if (revision == 10) GenerationFreshPlankaGrant.original(request.id,
                requireNotNull(request.freshPlankaActorGrant))
        }
        val controller = requireNotNull(request.quadletControllerSha256)
        require(controller.matches(Regex("[a-f0-9]{64}")))
        val identity = com.sun.security.auth.module.UnixSystem()
        require(identity.uid in 1..65534 && identity.gid in 1..65534)
        return spec.copy(fragmentBinding = requireNotNull(spec.fragmentBinding).copy(controllerSha256 = controller,
            controllerUid = identity.uid.toInt(), controllerGid = identity.gid.toInt()))
    }

    fun prepareWithRequest(inventory: AcquiredInventory, base: Path, spec: PrivateDeploymentSpec,
        request: AssemblyRequest): Path {
        require(request.id == spec.name.substring(0, 14))
        if (manifest().scope == "full-private" || request.selections.singleOrNull()?.recipe in setOf(R9_ASSEMBLY_RECIPE, R10_ASSEMBLY_RECIPE)) {
            val fresh = requireNotNull(request.freshIdentity).also { it.validate() }
            require(request.originalIdentity == null && request.originalMastodon == null &&
                request.managedLanes != null && request.rssPlan != null)
            FreshWorklaneCandidate.requireSelected(requireNotNull(request.managedLanes))
            val ci = requireNotNull(request.forgejoCi)
            ci.validate(request.id)
            val workflow = GenerationRuntime.privateInput(Path.of(ci.workflow.path))
            require(ReleaseLocks.sha256(workflow) == ci.workflow.sha256)
            ForgejoWorkflowSource.inspect(ci.enrollment, ci.enrollment.trustedCommit, workflow)
            val revision = when (request.selections.singleOrNull()?.recipe) {
                R9_ASSEMBLY_RECIPE -> 9
                R10_ASSEMBLY_RECIPE -> 10
                else -> null
            }
            val pendingR9 = revision != null
            val token = if (pendingR9) {
                require(request.baoBootstrapOperation?.also { it.validate(request.id) } != null &&
                    request.baoBootstrapToken == null && spec.processes.single { it.id == "keeper" }
                        .lateEnvironmentFile == "keeper-bao-late.env")
                null
            } else {
                require(request.baoBootstrapOperation == null)
                val source = requireNotNull(request.baoBootstrapToken)
                require(source.sha256.matches(Regex("[a-f0-9]{64}")) &&
                    source.path.startsWith("/mnt/media/p0-v3/release-bootstrap-anchors/bao/"))
                val sealedToken = GenerationRuntime.privateInput(Path.of(source.path))
                require(ReleaseLocks.sha256(sealedToken) == source.sha256)
                sealedToken.decodeToString(throwOnInvalidSequence = true).trimEnd('\n').also {
                    require(it.isNotBlank() && '\n' !in it && '\r' !in it && it.length <= 4096)
                }
            }
            val scripts = requireNotNull(request.mastodonRedisScripts)
            require(scripts.sha256.matches(Regex("[a-f0-9]{64}")) &&
                scripts.path.startsWith("/mnt/media/p0-v3/release-bootstrap-anchors/mastodon/"))
            val scriptBytes = GenerationRuntime.privateInput(Path.of(scripts.path))
            require(ReleaseLocks.sha256(scriptBytes) == scripts.sha256 && scriptBytes.size <= 65536)
            val scriptManifest = scriptBytes.decodeToString(throwOnInvalidSequence = true)
            // Every complete-release source credential requires its own reviewed
            // closure; never fall back to the 26-process development producer.
            if (pendingR9) {
                val binding = requireNotNull(spec.fragmentBinding)
                val selected = if (revision == 10) pendingR10Spec(inventory, spec.name,
                    controllerSha256 = binding.controllerSha256, controllerUid = binding.controllerUid,
                    controllerGid = binding.controllerGid) else pendingR9Spec(inventory, spec.name,
                    controllerSha256 = binding.controllerSha256, controllerUid = binding.controllerUid,
                    controllerGid = binding.controllerGid)
                require(spec == selected) {
                    "Prepared whole-release member differs from selected pending r$revision graph"
                }
            }
            return RuntimePreparation.prepare(spec, base, request.memberPredecessorDisposition) {
                // This runs only after the exact member.prepare intent is durable. Either source
                // issuer can leave a partial effect: the member intent then fences any retry.
                // No standalone fixture, OLD record, or second member may regenerate grants.
                val caddy = if (pendingR9) Path.of("/home/gerald/p0_v3/.coord/rapid-completion/caddy-config-check-bin-142") else null
                val ingressRecord = if (pendingR9) Path.of(
                    "/mnt/media/p0-v3/release-bootstrap-anchors/ingress/fresh/${request.id}.json") else null
                val ntfyRecord = if (pendingR9) Path.of(
                    "/mnt/media/p0-v3/release-bootstrap-anchors/identity/ntfy-fresh/${request.id}.json") else null
                if (pendingR9 && request.memberPredecessorDisposition == null) {
                    require(!Files.exists(requireNotNull(ingressRecord), java.nio.file.LinkOption.NOFOLLOW_LINKS) &&
                        !Files.exists(requireNotNull(ntfyRecord), java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                        "Fresh ingress issuer was already attempted; do not replay member preparation"
                    }
                    for (parent in listOf(ingressRecord.parent.parent, ingressRecord.parent, ntfyRecord.parent)) {
                        if (!Files.exists(parent, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                            Files.createDirectory(parent, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
                            ReleasePrivateFiles.sync(parent.parent)
                        }
                        ReleasePrivateFiles.directory(parent)
                    }
                }
                val ingress = if (pendingR9) FreshNativeIngressCustody.issueOnce(
                    requireNotNull(ingressRecord), requireNotNull(caddy)) {
                        require(request.memberPredecessorDisposition == null) { "Original ingress grant cannot be regenerated" }
                        RuntimePreparation.password()
                    } else null
                val ntfy = if (pendingR9) FreshNtfyCustody.issueOnce(requireNotNull(ntfyRecord), requireNotNull(caddy)) {
                    require(request.memberPredecessorDisposition == null) { "Original ntfy grant cannot be regenerated" }
                    RuntimePreparation.password()
                } else null
                inputs(inventory, spec.name, freshIdentity = fresh, baoToken = token,
                    mastodonRedisScripts = scriptManifest, portalRoutes = requireNotNull(request.portalRoutes),
                    managedLanesSubject = request.managedLanes.lanes.first().subject,
                    managedReaderSubject = requireNotNull(request.managedLanes.readerSubject),
                    managedBrokerHost = requireNotNull(request.managedLanes.native.brokerHost),
                    freshIngressGrants = if (pendingR9) requireNotNull(ingress).copy(
                        ntfySsoToken = requireNotNull(ntfy).ssoToken) else null,
                    freshIngressRecord = ingressRecord, freshNtfy = ntfy, freshCaddyCli = caddy,
                    candidateRevision = revision,
                    freshPlankaActorGrant = if (revision == 10) GenerationFreshPlankaGrant.original(
                        request.id, requireNotNull(request.freshPlankaActorGrant)) else null)
            }
        }
        return prepareBound(inventory, base, spec)
    }

    fun prepareBound(inventory: AcquiredInventory, base: Path, spec: PrivateDeploymentSpec): Path {
        val binding = requireNotNull(spec.fragmentBinding)
        require(binding.controllerSha256 != null && binding.controllerUid != null && binding.controllerGid != null &&
            spec == spec(inventory, spec.name, controllerSha256 = binding.controllerSha256,
                controllerUid = binding.controllerUid, controllerGid = binding.controllerGid)) {
            "Prepared shared Quadlet graph differs from packaged YAML"
        }
        return RuntimePreparation.prepare(spec, base) { inputs(inventory, spec.name) }
    }

    fun spec(inventory: AcquiredInventory, name: String, phase: FragmentPhase = FragmentPhase.INSTALL,
        controllerSha256: String? = null, controllerUid: Int? = null, controllerGid: Int? = null): PrivateDeploymentSpec =
        compileSpec(inventory, name, phase, controllerSha256, controllerUid, controllerGid, null)

    /** Source-only full-r9 projection; never selected by the active release or
     * permitted to replace a sealed historical member. No native actuator. */
    /** Pending r9 ingress is a derivative of the selected module graph, not an
     * independent admin-API topology. Offline callers may test it without startup. */
    fun pendingR9CaddyInputs(spec: PrivateDeploymentSpec): Map<String, String> =
        CaddyRuntime.inputs() + ("caddy.json" to CanonicalGraphCaddyfile.adaptedJson(
            PackagedGraphFragment.pendingV3R9().first, spec))

    fun pendingR9Spec(inventory: AcquiredInventory, name: String,
        phase: FragmentPhase = FragmentPhase.INSTALL, controllerSha256: String? = null,
        controllerUid: Int? = null, controllerGid: Int? = null): PrivateDeploymentSpec =
        compileSpec(inventory, name, phase, controllerSha256, controllerUid, controllerGid, 9)

    fun pendingR10Spec(inventory: AcquiredInventory, name: String,
        phase: FragmentPhase = FragmentPhase.INSTALL, controllerSha256: String? = null,
        controllerUid: Int? = null, controllerGid: Int? = null): PrivateDeploymentSpec =
        compileSpec(inventory, name, phase, controllerSha256, controllerUid, controllerGid, 10)

    private fun compileSpec(inventory: AcquiredInventory, name: String, phase: FragmentPhase,
        controllerSha256: String?, controllerUid: Int?, controllerGid: Int?, candidate: Int?): PrivateDeploymentSpec {
        val pending = when (candidate) {
            9 -> PackagedGraphFragment.pendingV3R9()
            10 -> PackagedGraphFragment.pendingV3R10()
            null -> null
            else -> error("Unknown pending full-private graph revision")
        }
        val manifest = pending?.first?.let(::validateManifest) ?: manifest()
        if (manifest.scope == "full-private") require(inventory.images.any { it.product == "kopia" }) {
            "Full private release requires the pinned Kopia recovery worker"
        }
        // The V2 source has exactly one Timescale/PostgreSQL and one PostgreSQL-backed
        // Forgejo, with installed-only database roles and explicit TLS/network edges.
        val base = FragmentRecipes.spec(inventory, name, phase, controllerSha256, controllerUid, controllerGid,
            forgejoRevision = if (manifest.scope == "full-private") 5 else 4)
        val extensions = manifest.fragments.drop(2).map {
            if (candidate != null) PackagedGraphFragment.loadPendingV3(it.id, it.revision, candidate)
            else PackagedGraphFragment.loadV3(it.id, it.revision)
        }
        val declared = extensions.map { it.definition }
        if (manifest.scope == "full-private") require(
            (declared.map { it.product }.toSet() + setOf("postgres", "forgejo")) ==
                ProductSelection.bundled().products.toSet() -
                manifest.integratedReference?.modules.orEmpty().filter { it.nativeControl != null }.map { it.id }.toSet() +
                manifest.extraBindings.filter { it.nativeDaemons.isNotEmpty() }.map { it.id }.toSet()
        ) { "An incomplete integrated stack cannot be admitted as a full private release" }
        require(declared.map { it.product }.distinct().size == declared.size &&
            declared.none { it.product in setOf("postgres", "forgejo") } &&
            declared.all { f -> f.providers.all { provider ->
                provider in setOf("postgres", "forgejo") || declared.any { it.product == provider }
            } && f.providerProcesses.all { (provider, processes) ->
                val providerRoles = if (provider in setOf("postgres", "forgejo"))
                    base.processes.filterNot { it.oneShot }.map { it.id }.toSet() else
                    declared.single { it.product == provider }.processes.filterNot { it.oneShot }
                        .map { it.id }.toSet()
                processes.all { it in providerRoles }
            } })
        val projected = extensions.map { it.project(inventory, name, phase) }
        // Provider attachment applies to every selected provider, not just V2 base processes.
        // Without this, an added frontend (Caddy) cannot reach a later selected app network.
        // The single shared Caddy may trust only selected, exactly exported
        // original private upstream CAs. These mounts bind the SAME generation
        // bytes as each native HTTPS frontend, not newly generated proxy CAs.
        val approvedFrontCa = mapOf("jupyterhub" to ("jupyterhub-ca.pem" to "hub-ca.pem"),
            "huly" to ("huly-ca.pem" to "huly-ca.pem"),
            "mastodon" to ("mastodon-ca.pem" to "mastodon-ca.pem"),
            "erpnext" to ("erp-ca.pem" to "erp-ca.pem"),
            "sogo" to ("sogo-ca.pem" to "sogo-ca.pem"),
            "seafile" to ("seafile-ca.pem" to "seafile-ca.pem"),
            "onlyoffice" to ("onlyoffice-office-ca.pem" to "onlyoffice-ca.pem"),
            "opensearch" to ("opensearch-ca.pem" to "opensearch-ca.pem"),
            "keykeeper" to ("keeper-ca.pem" to "keeper-ca.pem")) +
            (if (candidate != null) mapOf("firefly-iii" to
                ("finance-ingress-ca.pem" to "finance-ingress-ca.pem")) else emptyMap())
        val caddyCa = declared.filter { it.product in approvedFrontCa }.map { owner ->
            val (file, target) = approvedFrontCa.getValue(owner.product)
            require(file in owner.exportedInputs && owner.inputs.any { input ->
                input.name == file && input.owner == owner.product &&
                    input.purpose == FragmentInputPurpose.RUNTIME &&
                    input.consumers.any { id -> owner.processes.single { it.id == id }.oneShot.not() }
            }) { "Caddy trust must use a selected daemon's exported generation CA" }
            RuntimeFile(file, "/run/secrets/$target")
        } + if (manifest.scope == "full-private") {
            val identity = declared.single { it.product == "keycloak" }
            require(identity.inputs.any { input -> input.name == "identity-ca.pem" &&
                input.owner == "keycloak" && input.purpose == FragmentInputPurpose.RUNTIME &&
                input.consumers.any { id -> identity.processes.single { it.id == id }.oneShot.not() } })
            listOf(RuntimeFile("identity-ca.pem", "/run/secrets/identity-ca.pem"))
        } else emptyList()
        val r9SiteLeaves = if (candidate != null) listOf(
            Triple("onlyoffice", "onlyoffice-office-web.pem", "office-web.pem"),
            Triple("onlyoffice", "onlyoffice-office-web-key.pem", "office-web-key.pem"),
            Triple("seafile", "seafile-web.pem", "files-web.pem"),
            Triple("seafile", "seafile-web-key.pem", "files-web-key.pem"),
            Triple("huly", "huly-web.pem", "work-web.pem"),
            Triple("huly", "huly-web-key.pem", "work-web-key.pem"),
            Triple("sogo", "sogo-web.pem", "groupware-web.pem"),
            Triple("sogo", "sogo-web-key.pem", "groupware-web-key.pem"),
            Triple("firefly-iii", "finance-ingress-web.pem", "finance-ingress-web.pem"),
            Triple("firefly-iii", "finance-ingress-web-key.pem", "finance-ingress-web-key.pem")
        ).map { (product,file,target) ->
            val owner = declared.single { it.product == product }
            require(owner.inputs.any { input -> input.name == file && input.owner == product &&
                input.purpose == FragmentInputPurpose.RUNTIME && input.consumers.any { id ->
                    owner.processes.single { it.id == id }.files.any { mounted -> mounted.file == file }
                } }) { "Fresh site leaf must be the selected app's own runtime certificate" }
            RuntimeFile(file, "/run/secrets/$target")
        } else emptyList()
        val r9IngressNetworks = if (candidate != null) requireNotNull(manifest.integratedReference)
            .modules.flatMap { it.privateRoutes }.mapNotNull { route -> route.network?.takeIf {
                network -> network.endsWith("-web") && network != "identity-web"
            } }.toSet().also { networks ->
                require(networks.size <= 64 && networks.all { network ->
                    network in (base.networks + projected.flatMap { it.spec.networks }) &&
                        (base.processes + projected.flatMap { it.spec.processes }).any { process ->
                            !process.oneShot && process.id != "caddy" && network in process.networks
                        }
                }) { "An r9 route cannot attach Caddy to a private data network" }
            } else emptySet()
        val r9CallerAliases = if (candidate != null) listOf(
            RuntimeNetworkAlias("seafile-web","office.datamancy.net"),
            RuntimeNetworkAlias("onlyoffice-web","files.datamancy.net"),
            RuntimeNetworkAlias("firefly-importer-web","firefly.datamancy.net"),
            RuntimeNetworkAlias("bookstack-web","bookstack.datamancy.net")
        ).also { aliases ->
            require(aliases.all { alias -> alias.network in r9IngressNetworks &&
                requireNotNull(manifest.integratedReference).modules.any { module ->
                    module.privateRoutes.any { it.host == alias.host }
                } && projected.any { fragment -> fragment.spec.processes.any { p ->
                    p.id != "caddy" && alias.network in p.networks
                } } }) { "Private caller alias must belong to a selected route and shared web network" }
        } else emptyList()
        fun attach(process: RuntimeProcess): RuntimeProcess {
            val seafileOfficeCaller = candidate != null && process.id == "seafile-backend" &&
                projected.single { it.product == "seafile" }.let { fragment ->
                    require("seafile-web" in fragment.spec.networks && "office-data" in process.networks &&
                        "seafile-data" in process.networks && !process.oneShot &&
                        fragment.spec.processes.any { it.id == process.id })
                    true
                }
            val attachments = projected.flatMap { it.providerNetworks[process.id].orEmpty() } +
                (if (process.id == "caddy") r9IngressNetworks else emptySet()) +
                (if (seafileOfficeCaller) setOf("seafile-web") else emptySet())
            return process.copy(networks = (process.networks + attachments).distinct(),
                networkAliases = process.networkAliases + if (process.id == "caddy") r9CallerAliases else emptyList(),
                lateEnvironmentFile = if (candidate != null && process.id == "keeper")
                    "keeper-bao-late.env" else process.lateEnvironmentFile,
                files = process.files + if (process.id == "caddy") caddyCa + r9SiteLeaves else emptyList(),
                controlSocketMount = if (candidate != null && process.id == "caddy") {
                    val controls = requireNotNull(manifest.integratedReference).modules
                        .flatMap { it.privateRoutes }.filter { it.special in setOf("controller", "agent-api") }
                    require(controls.map { it.special }.toSet() == setOf("controller", "agent-api") &&
                        base.name.startsWith("q-") && process.controlSocketMount == null)
                    RuntimeControlSocketMount(GenerationRuntime.BASE.resolve(base.name.substring(0, 14))
                        .resolve("managed/control/run").toString(), "/run/p0-control")
                } else if (candidate != null && process.id == "hub-controller" &&
                    process.files.any { it.file == "jupyterhub-hub-settings.json" }) {
                    require(process.controlSocketMount == null)
                    RuntimeControlSocketMount(GenerationRuntime.BASE.resolve(base.name.substring(0, 14))
                        .resolve("notebooks/control.sock").toString(), "/run/p0-notebooks/control.sock")
                } else process.controlSocketMount)
        }
        val additions = projected.flatMap { fragment -> fragment.spec.processes.map(::attach) }
        val attachedBase = base.processes.map(::attach)
        val all = attachedBase + additions
        val extNetworks = projected.flatMap { it.spec.networks }
        val repeatedNetworks = (base.networks + extNetworks).groupBy { it }
            .filterValues { it.size > 1 }.keys
        val acceptedRepeatedNetworks = repeatedNetworks.filter { network ->
            if (network == "db-admin") {
                base.processes.any { it.id == "postgres" && network in it.networks } &&
                    declared.filter { network in it.networks }.all { fragment ->
                        "postgres" in fragment.providers && fragment.processes
                            .filter { network in it.networks }.all { it.oneShot }
                    }
            } else if (network == "metrics-private") {
                declared.filter { network in it.networks }.all { it.product in setOf(
                    "alertmanager", "prometheus", "grafana", "alloy", "loki", "node-exporter") }
            } else if (network in base.networks) {
                // The baseline owns its administrative networks. An extension may
                // borrow one only with an explicit edge to its selected base provider.
                declared.filter { network in it.networks }.all { fragment ->
                    fragment.providerNetworks.any { (provider, shared) ->
                        provider in setOf("postgres", "forgejo") && network in shared &&
                            base.processes.any { p -> p.id == provider && network in p.networks }
                    }
                }
            } else {
                val owners = declared.filter { fragment -> network in fragment.networks &&
                    (network in fragment.webNetworks || fragment.providerNetworks.values.none { network in it }) }
                owners.size == 1 && declared.filter { network in it.networks && it != owners.single() }
                    .all { fragment -> network in fragment.providerNetworks[owners.single().product].orEmpty() }
            }
        }
        require(acceptedRepeatedNetworks.size == repeatedNetworks.size &&
            all.map { it.id }.distinct().size == all.size &&
            (base.volumes + projected.flatMap { it.spec.volumes }).map { it.id }.distinct().size ==
                base.volumes.size + projected.sumOf { it.spec.volumes.size }) {
            "V3 shared process, volume or private network duplicates an existing provider: " +
                "unboundNetworks=${repeatedNetworks - acceptedRepeatedNetworks.toSet()} " +
                "duplicateProcesses=${all.map { it.id }.groupingBy { it }.eachCount().filterValues { it > 1 }} " +
                "duplicateVolumes=${(base.volumes + projected.flatMap { it.spec.volumes }).map { it.id }.groupingBy { it }.eachCount().filterValues { it > 1 }}"
        }
        val extraInputs = extensions.flatMap { it.requiredInputs(phase) }
        val inputNames = extraInputs.map { it.name }
        val shared = inputNames.toSet().intersect(PrivateDeployment.inputNames(base).toSet())
        val baselineExports = FragmentRecipes.fragments().associate { it.definition.product to it.definition.exportedInputs.toSet() }
        val selectedExports = declared.associate { it.product to it.exportedInputs.toSet() }
        val exactHistoricalExports = mapOf("keycloak" to
            (if (candidate != null) setOf("identity-ca.pem", "identity-web.pem", "identity-web-key.pem")
                else setOf("identity-ca.pem")))
        require(extraInputs.groupBy { it.name }.values.all { declarations ->
                declarations.map { it.owner to it.purpose }.distinct().size == 1 } &&
            extraInputs.filter { it.name in shared }.all { declaration ->
                declaration.purpose == FragmentInputPurpose.RUNTIME &&
                    declaration.name in baselineExports[declaration.owner].orEmpty() &&
                    FragmentRecipes.exportedProviderInput(base, declaration.name, declaration.owner)
            } && declared.all { fragment -> fragment.inputs.filter { it.owner != fragment.product }.all { imported ->
                imported.purpose == FragmentInputPurpose.RUNTIME &&
                    (imported.name in baselineExports[imported.owner].orEmpty() ||
                        imported.name in selectedExports[imported.owner].orEmpty() ||
                        imported.name in exactHistoricalExports[imported.owner].orEmpty()) &&
                    (imported.owner in setOf("postgres", "forgejo") ||
                        declared.singleOrNull { it.product == imported.owner }?.inputs?.any {
                            it.name == imported.name && it.owner == imported.owner
                        } == true)
            } }) {
            "Unexported or conflicting shared credential input: " +
                "conflicts=${extraInputs.groupBy { it.name }.filterValues { sources -> sources.map { it.owner to it.purpose }.distinct().size > 1 }.keys} " +
                "shared=${extraInputs.filter { it.name in shared && (it.name !in baselineExports[it.owner].orEmpty() || !FragmentRecipes.exportedProviderInput(base, it.name, it.owner)) }.map { it.name to it.owner }} " +
                "unexported=${declared.flatMap { owner -> owner.inputs.filter { input -> input.owner != owner.product && input.name !in baselineExports[input.owner].orEmpty() && input.name !in selectedExports[input.owner].orEmpty() && input.name !in exactHistoricalExports[input.owner].orEmpty() }.map { owner.product to it.name } }}"
        }
        val extResources = sortedMapOf<String, String>()
        (pending?.second?.filterKeys { !it.startsWith("v2/") } ?:
            PackagedGraphFragment.v3Manifest().second).forEach { (path, hash) ->
            extResources["fragments/v3/$path"] = hash
        }
        extensions.forEach { fragment -> fragment.resourceHashes.forEach { (path, hash) ->
            val key = "fragments/v3/$path"
            require(extResources.putIfAbsent(key, hash)?.let { it == hash } != false)
        } }
        val binding = requireNotNull(base.fragmentBinding).copy(recipe = RECIPE,
            resources = (base.fragmentBinding.resources + extResources).toSortedMap())
        val composed = base.copy(processes = all, volumes = base.volumes + projected.flatMap { it.spec.volumes },
            // INSTALL-only enrollment namespaces must not remain as orphan networks
            // when RESTORE selects only the serving processes and original volumes.
            networks = (base.networks + extNetworks).distinct().filter { network ->
                all.any { process -> network in process.networks }
            },
            databaseAccess = base.databaseAccess + projected.flatMap { it.spec.databaseAccess },
            unmountedRecoveryVolumes = base.unmountedRecoveryVolumes + projected.flatMap { it.spec.unmountedRecoveryVolumes },
            fragmentBinding = binding)
        PrivateDeployment.validate(composed)
        manifest.integratedReference?.let { baseline ->
            require(composed.processes.filterNot { it.oneShot }.map { it.id }.toSet() ==
                (baseline.modules.flatMap { it.nativeDaemons } + manifest.extraBindings.flatMap { it.nativeDaemons }).toSet()) {
                "Executable Quadlet daemons differ from the single packaged integrated topology"
            }
        }
        require(PrivateDeployment.inputNames(composed).toSet() ==
            PrivateDeployment.inputNames(base).toSet() + inputNames.toSet() &&
            composed.processes.single { it.id == "postgres" }.networks.contains("planka-data") &&
            composed.databaseAccess.filter { it.consumer.startsWith("planka") }.all {
                it.provider == "postgres" && it.volume == "postgres" && it.network == "planka-data" })
        return composed
    }

    /** Private development producer for the added Valkey principal. Original Forgejo/PG
     * credentials remain in their established six-secret producer; never infer them from
     * a source marker or recreate them on cold restore.
     */
    /** r9-only selected-origin projection; leaves the pinned v2/r5 baseline and
     * historical deployed generations byte-for-byte unchanged. */
    internal fun freshForgejoSelectedOrigin(baseline: Map<String, String>): Map<String, String> = baseline +
        listOf("forgejo-migration.ini", "forgejo-runtime.ini").associateWith { file ->
            val source = baseline.getValue(file)
            val old = "ROOT_URL = https://git.datamancy.net/"
            require(source.split(old).size == 2 && !source.contains("ROOT_URL = https://forgejo.datamancy.net/"))
            source.replace(old, "ROOT_URL = https://forgejo.datamancy.net/")
        }

    fun inputs(inventory: AcquiredInventory, name: String,
        password: () -> String = RuntimePreparation::password,
        pki: () -> Map<String, String> = { PrivateWebPki.generate("postgres") },
        identityPki: () -> Map<String, String> = { PrivateWebPki.generate("keycloak",
            listOf("keycloak", "auth.datamancy.net")) },
        originalIdentity: OriginalIdentityBinding? = null, baoToken: String? = null,
        mastodonRedisScripts: String? = null,
        portalRoutes: List<SiteRouteOwner>? = null,
        originalMastodon: CanonicalMastodonSourceBinding? = null,
        freshIdentity: FreshIdentityBootstrap? = null,
        managedLanesSubject: String? = null,
        managedReaderSubject: String? = null,
        managedBrokerHost: ManagedBrokerHostBinding? = null,
        freshIngressGrants: FreshNativeIngressGrants? = null,
        freshCaddyCli: Path? = null,
        freshNtfy: FreshNtfyGrants? = null,
        candidateRevision: Int? = null,
        freshIngressRecord: Path? = null,
        freshPlankaActorGrant: FreshPlankaActorGrant? = null): Map<String, String> {
        require(candidateRevision == null || candidateRevision in setOf(9, 10))
        val freshFull = candidateRevision != null
        val selected = when (candidateRevision) {
            9 -> PackagedGraphFragment.pendingV3R9().first
            10 -> PackagedGraphFragment.pendingV3R10().first
            else -> manifest()
        }
        val selectedCapabilities = if (freshFull) selected.fragments.drop(2).map { ref ->
            PackagedGraphFragment.loadPendingV3(ref.id, ref.revision, candidateRevision!!).definition.product
        }.toSet() else capabilities()
        val spec = when (candidateRevision) {
            9 -> pendingR9Spec(inventory, name)
            10 -> pendingR10Spec(inventory, name)
            else -> spec(inventory, name)
        }
        val literals = selected.fragments.drop(2).flatMap { ref ->
            val fragment = if (freshFull) PackagedGraphFragment.loadPendingV3(ref.id, ref.revision, candidateRevision!!)
                else PackagedGraphFragment.loadV3(ref.id, ref.revision)
            fragment.definition.templates.filter { it.format == FragmentTemplateFormat.LITERAL }.map { template ->
                template.output to FragmentTemplates.render(fragment, template.output, emptyMap())
            }
        }
        require(literals.map { it.first }.distinct().size == literals.size)
        val baselineOriginal = FragmentRecipes.inputs(FragmentRecipes.spec(inventory, name,
            forgejoRevision = if (selected.scope == "full-private") 5 else 4), inventory, password, pki)
        val baseline = if (freshFull) freshForgejoSelectedOrigin(baselineOriginal)
            else baselineOriginal
        val secrets = List(8) { password() }
        require(secrets.all { it.matches(Regex("[a-f0-9]{64}")) } && secrets.distinct().size == secrets.size &&
            secrets.none { secret -> baseline.values.any { it.contains(secret) } }) {
            "Shared cache and Planka credentials must be independent"
        }
        val (cache, migration, runtime, appKey, bootstrap) = secrets
        if (candidateRevision == 10) requireNotNull(freshPlankaActorGrant).also { grant ->
            require(grant.generation == name.substring(0, 14) &&
                bootstrap !in setOf(grant.ownerPassword, grant.outsiderPassword))
        } else require(freshPlankaActorGrant == null)
        val mariaRoot = secrets[5]
        val grafanaPassword = secrets[6]
        val grafanaSecret = secrets[7]
        val adminPassword = baseline.getValue("postgres-bootstrap.env").substringAfter("POSTGRES_PASSWORD=").trim()
        require(adminPassword.matches(Regex("[a-f0-9]{64}")))
        val ca = "NODE_EXTRA_CA_CERTS=/run/secrets/postgres-ca.pem\n"
        val pg = "PGHOST=postgres\nPGUSER=postgres\nPGDATABASE=postgres\nPGPASSWORD=$adminPassword\n" +
            "PGSSLMODE=verify-full\nPGSSLROOTCERT=/run/secrets/postgres-ca.pem\n"
        fun application(role: String, credential: String) = "NODE_ENV=production\nLOG_FILE=/tmp/planka.log\n" +
            "BASE_URL=http://planka:1337\nSECRET_KEY=$appKey\n" + ca +
            "DATABASE_URL=postgresql://$role:$credential@postgres:5432/planka?sslmode=verify-full\n" +
            "OUTGOING_PROXY=http://127.0.0.1:9\n"
        val hba = baseline.getValue("postgres-hba.conf")
        val anchor = "hostssl forgejo forgejo,forgejo_migrate ::/0 scram-sha-256\n"
        require(hba.count { it == '\n' } >= 5 && hba.split(anchor).size == 2 &&
            name.matches(Regex("q-[a-f0-9]{12}-[a-z][a-z0-9-]{0,23}")))
        val generation = name.substring(0, 14)
        if (freshFull) require(freshIngressRecord?.fileName?.toString() == "$generation.json") {
            "Fresh ingress grant custody must belong to the selected generation"
        }
        val full = selected.scope == "full-private"
        if (full) requireNotNull(freshIdentity).validate()
        val memberships = if (full) requireNotNull(freshIdentity).memberships() else null
        val oidcSecrets = if (full) List(8) { index ->
            val key = when (index) {
                3 -> requireNotNull(managedBrokerHost).secret(managedBrokerHost.agentSecret, generation)
                4 -> requireNotNull(managedBrokerHost).secret(managedBrokerHost.readerSecret, generation)
                else -> password()
            }
            require(key.matches(Regex("[a-f0-9]{64}")) && !baseline.values.any { key in it })
            key
        } else emptyList()
        require(oidcSecrets.distinct().size == oidcSecrets.size)
        val bookstackOidcSecret = oidcSecrets.getOrNull(0)
        val financeBrowserSecrets = if (freshFull) List(4) { password() } else emptyList()
        require(financeBrowserSecrets.distinct().size == financeBrowserSecrets.size &&
            financeBrowserSecrets.all { it.matches(Regex("[a-f0-9]{64}")) && it !in oidcSecrets })
        val importerClientId = if (freshFull) java.util.UUID.randomUUID().toString() else null
        val realmClients = mutableListOf(IdentityRuntime.canonicalOperatorClient(generation))
        val realmAccounts = mutableListOf<kotlinx.serialization.json.JsonObject>()
        var keeperAgentSubject: String? = null
        if (full) {
            realmClients += BookStackRuntime.releaseOidcClient(requireNotNull(bookstackOidcSecret))
            realmClients += MatrixIdentityRuntime.canonicalUpstreamClient(oidcSecrets[5])
            realmClients += CanonicalAuthGatewaySource.client(oidcSecrets[6])
            if (freshFull) {
                realmClients += FreshFinanceSsoSource.client("firefly-sso", "https://firefly.datamancy.net",
                    financeBrowserSecrets[0])
                realmClients += FreshFinanceSsoSource.client("firefly-importer-sso",
                    "https://firefly-importer.datamancy.net", financeBrowserSecrets[2])
            }
            realmClients += KeykeeperRuntime.canonicalClients(oidcSecrets[1], oidcSecrets[2], generation)
                .map { it as kotlinx.serialization.json.JsonObject }
            realmClients += KeykeeperRuntime.canonicalManagedLaneClient(oidcSecrets[3], generation)
            realmClients += KeykeeperRuntime.canonicalManagedLaneReaderClient(oidcSecrets[4], generation)
            fun account(factory: (String) -> kotlinx.serialization.json.JsonObject) =
                factory(java.util.UUID.randomUUID().toString())
            val agent = account(KeykeeperRuntime::canonicalServiceAccount)
            keeperAgentSubject = agent.getValue("id").toString().trim('"')
            realmAccounts += agent
            val laneSubject = requireNotNull(freshIdentity).let { fresh ->
                requireNotNull(managedLanesSubject).also { selected ->
                    require(selected !in setOf(fresh.ownerUuid, fresh.outsiderUuid,
                        fresh.appNonMemberUuid))
                }
            }
            realmAccounts += KeykeeperRuntime.canonicalManagedLaneServiceAccount(laneSubject)
            realmAccounts += KeykeeperRuntime.canonicalManagedLaneReaderServiceAccount(
                requireNotNull(managedReaderSubject).also { require(it != laneSubject &&
                    it !in setOf(freshIdentity.ownerUuid, freshIdentity.outsiderUuid,
                        freshIdentity.appNonMemberUuid)) })
            // Original-only scoped RESTORE controller: protected in the sealed
            // original realm input and inherited only by the isolated target.
            // Provider OAuth remains in the host broker; no target-human PKCE.
            val restoreControllerSubject = java.util.UUID.randomUUID().toString()
            require(restoreControllerSubject !in setOf(laneSubject, managedReaderSubject,
                keeperAgentSubject, freshIdentity.ownerUuid, freshIdentity.outsiderUuid,
                freshIdentity.appNonMemberUuid))
            realmClients += IdentityRuntime.canonicalRestoreControllerClient(password(), generation)
            realmAccounts += IdentityRuntime.canonicalRestoreControllerServiceAccount(restoreControllerSubject)
        }
        val identity = IdentityRuntime.canonicalInputs(adminPassword, identityPki, password,
            clients = kotlinx.serialization.json.JsonArray(realmClients),
            serviceAccounts = kotlinx.serialization.json.JsonArray(realmAccounts),
            originalOwnerId = freshIdentity?.ownerUuid, originalOutsiderId = freshIdentity?.outsiderUuid,
            originalMemberships = memberships,
            originalAppNonMemberId = if (freshFull) freshIdentity?.appNonMemberUuid else null)
        if (freshFull) FreshRequiredActionJourney.requireImportedSource(
            identity.getValue("identity-realm.json"), requireNotNull(freshIdentity))
        require(identity.keys == setOf("identity-db-admin.env", "identity-migration.env", "identity-runtime.env",
            "identity-realm.json", "identity-ca.pem", "identity-web.pem", "identity-web-key.pem") &&
            identity.values.none { it.contains(mariaRoot) || it.contains(cache) })
        val mariaOffice = if (full) CanonicalMariaOfficeSource.inputs(mariaRoot,
            requireNotNull(freshIdentity).ownerUuid, requireNotNull(bookstackOidcSecret), password,
            freshApi = if (freshFull) requireNotNull(freshIngressGrants).also {
                require(it.outsiderBookstackApiId != null && it.outsiderBookstackApiSecret != null)
            } else null,
            generation = if (freshFull) generation else null,
            outsiderUuid = if (freshFull) freshIdentity.outsiderUuid else null) else null
        val authSessionPassword = if (full) password() else ""
        val portalSource = if (full) {
            val routes = requireNotNull(portalRoutes)
            if (freshFull) require(routes.sortedBy { it.host } ==
                CanonicalGraphCaddyfile.siteRoutes(selected, spec)) {
                "Owned portal/dashboard hosts must be the full executable module ingress projection"
            }
            CanonicalPortalSource.inputs(routes, routes.map { it.host }.toSet(), selectedR9 = freshFull) + mapOf(
                "portal.env" to "LOG_TARGETS=stdout\nHOMEPAGE_ALLOWED_HOSTS=portal.datamancy.net,portal:3000\n")
        } else emptyMap()
        val baoSource = if ("openbao" in selectedCapabilities) OpenBaoRuntime.inputs() else emptyMap()
        val keeperSource = if (full) {
            val keeperPki=PrivateWebPki.generate("keeper")
            if (freshFull) {
                require(baoToken==null)
                CanonicalR9LateKeeperInputs.project(generation,oidcSecrets[2],
                    setOf(requireNotNull(keeperAgentSubject)),keeperPki,
                    identity.getValue("identity-ca.pem"),baoSource.getValue("ca.pem"))
            } else KeykeeperRuntime.canonicalInputs(requireNotNull(baoToken),oidcSecrets[2],
                setOf(requireNotNull(keeperAgentSubject)),generation,keeperPki,
                identity.getValue("identity-ca.pem"),baoSource.getValue("ca.pem"))
        } else emptyMap()
        require(!full || keeperSource.getValue("identity-ca.pem") == identity.getValue("identity-ca.pem") &&
            keeperSource.getValue("bao-ca.pem") == baoSource.getValue("ca.pem"))
        val rtcSource = if (full) MatrixRtcRuntime.canonicalInputs(mapOf(
            "postgres.env" to "POSTGRES_PASSWORD=$adminPassword\n",
            "postgres-admin.env" to pg), oidcSecrets[5], password) else emptyMap()
        val cacheSource = if (full) {
            val pair = requireNotNull(mariaOffice)
            val health = password(); val mastodonFront = password(); val mastodonBack = password()
            val bridge = password()
            val rules = listOf(CanonicalCachePrincipal("seafile", pair.seafileCachePassword),
                CanonicalCachePrincipal("erpnext", bridge))
            val credentials = listOf(health, mastodonFront, mastodonBack, authSessionPassword) + rules.map { it.password }
            require(credentials.all { it.matches(Regex("[a-f0-9]{64}")) } &&
                credentials.distinct().size == credentials.size)
            mapOf("valkey.conf" to "bind 0.0.0.0\nprotected-mode yes\nport 6379\ndir /data\nappendonly yes\nappendfsync everysec\naclfile /etc/valkey/users.acl\n",
                "valkey.acl" to "user default off\nuser health on >$health -@all +ping\n" +
                    rules.joinToString("") { it.aclRule() } +
                    // oauth2-proxy v7.15.2 ticket.go stores keys as the exact
                    // cookie name plus a random hex ID; lock.go appends .lock.
                    // DB2 is preserved from OLD; ACL keys, not DB alone, isolate
                    // this session principal from the other shared consumers.
                    "user auth-gateway on >$authSessionPassword ~_p0v3_edge-* -@all +ping +select +get +set +del +exists +eval +evalsha\n" +
                    MastodonRedisBridgeSource.acl(mastodonBack, generation),
                "valkey-health.env" to "VALKEY_HEALTH_PASSWORD=$health\n",
                "erp-provider-cache-password" to bridge,
                "mastodon-bridge-front-password" to mastodonFront,
                "mastodon-bridge-back-password" to mastodonBack)
        } else emptyMap()
        val authSource = if (full) CanonicalAuthGatewaySource.inputs(oidcSecrets[6], oidcSecrets[7],
            authSessionPassword) else emptyMap()
        val mastodonBridge = if (full) MastodonRedisBridgeSource.inputs(generation,
            inventory.images.single { it.product == "mastodon" }, "7.2.15",
            requireNotNull(mastodonRedisScripts),
            cacheSource.getValue("mastodon-bridge-front-password"),
            cacheSource.getValue("mastodon-bridge-back-password")) else emptyMap()
        val socialSource = if (full) CanonicalFreshMastodonSource.inputs(generation, adminPassword,
            cacheSource.getValue("mastodon-bridge-front-password"), password) else emptyMap()
        val erpSource = if (full) {
            val pair = requireNotNull(mariaOffice)
            val provider = cacheSource.getValue("erp-provider-cache-password")
            val client = password(); val admin = password()
            val erpActors = FreshErpActorGrant(password(),password())
            require(listOf(client, admin, provider, erpActors.ownerPassword,
                erpActors.outsiderPassword).all { it.matches(Regex("[a-f0-9]{64}")) } &&
                setOf(client, admin, provider, erpActors.ownerPassword,
                    erpActors.outsiderPassword).size == 5)
            val legacy = ErpNextRuntime.inputs()
            val service = mapOf("erp.env" to legacy.getValue("erp.env"),
                "erp-process-init.py" to legacy.getValue("process-init.py"),
                "erp-nginx.conf" to legacy.getValue("nginx.conf")
                    .replace("server_name erp;", "server_name erp.datamancy.net;")
                    .replace("https://erp:8443", "https://erp.datamancy.net"),
                "erp-ca.pem" to legacy.getValue("ca.pem"),
                "erp-web.pem" to legacy.getValue("web.pem"),
                "erp-web-key.pem" to legacy.getValue("web-key.pem"))
            service + ErpNextRuntime.releaseNativeSiteInputs(pair.erp, admin, client, generation,
                actors = erpActors) +
                ErpNextRuntime.releaseRedisBridgeInputs(client, provider) +
                ErpNextRuntime.releaseMariaCutoverInputs(pair.erp, pair.erpCutoverPassword, generation)
        } else emptyMap()
        val financeSource = if (full) {
            val runtime = password(); val migration = password()
            val key = "base64:" + java.util.Base64.getEncoder().encodeToString(
                java.util.HexFormat.of().parseHex(password()))
            val fresh = requireNotNull(freshIdentity)
            val original = FireflyOriginalSubjects(fresh.ownerUuid,
                fresh.outsiderUuid, password(), password(), generation)
            require(listOf(runtime, migration, original.ownerPassword, original.outsiderPassword).all {
                it.matches(Regex("[a-f0-9]{64}"))
            } && setOf(runtime, migration, original.ownerPassword, original.outsiderPassword).size == 4)
            FireflyCanonical.fragment(inventory, "postgres", "postgres", runtime, migration,
                baseline.getValue("postgres-ca.pem"), key,
                if (freshFull) "https://firefly.datamancy.net" else "https://finance.datamancy.net",
                original, freshRemoteSubjects = freshFull,
                freshImporterClientId = importerClientId).inputs +
                mapOf("firefly-db-admin.env" to pg + "FIREFLY_RUNTIME_PASSWORD=$runtime\n" +
                    "FIREFLY_MIGRATION_PASSWORD=$migration\n") +
                (if (freshFull) mapOf(
                    "firefly-sso.env" to FreshFinanceSsoSource.inputs("firefly-sso",
                        "https://firefly.datamancy.net", financeBrowserSecrets[0], financeBrowserSecrets[1],
                        "http://firefly:8080/"),
                    "firefly-importer-sso.env" to FreshFinanceSsoSource.inputs("firefly-importer-sso",
                        "https://firefly-importer.datamancy.net", financeBrowserSecrets[2], financeBrowserSecrets[3],
                        "http://firefly-importer:8080/"),
                    "firefly-importer.env" to FreshFinanceImporterSource.inputs(
                        requireNotNull(importerClientId), password(), generation)) +
                    PrivateWebPki.generate("finance", listOf("finance", "firefly.datamancy.net"))
                        .mapKeys { (key,_) -> when (key) {
                            "ca.pem" -> "finance-ingress-ca.pem"
                            "web.pem" -> "finance-ingress-web.pem"
                            "web-key.pem" -> "finance-ingress-web-key.pem"
                            else -> error("Unselected finance issuer output")
                        } } else emptyMap())
        } else emptyMap()
        val mailSource = if ("mailserver" in selectedCapabilities) MailRuntime.inputs() else emptyMap()
        val sharedMail = mailSource.mapKeys { (key, _) -> when (key) {
            "ca.pem" -> "mail-ca.pem"
            "users.json" -> "mail-users.json"
            "generation" -> "mail-generation"
            "bootstrap.env" -> "mail-bootstrap.env"
            else -> key
        } }
        val groupwareSource = if ("sogo" in selectedCapabilities) {
            val users = kotlinx.serialization.json.Json.parseToJsonElement(
                mailSource.getValue("users.json")).let { it as kotlinx.serialization.json.JsonObject }
                .mapValues { (_, credential) -> credential.toString().trim('"') }
            SogoRuntime.canonicalInputs(users, adminPassword, mapOf(
                "postgres-ca.pem" to baseline.getValue("postgres-ca.pem"),
                "postgres.pem" to baseline.getValue("postgres.pem"),
                "postgres-key.pem" to baseline.getValue("postgres-key.pem")))
        } else emptyMap()
        val fullSources = listOf(identity, baoSource.mapKeys { (key, _) ->
            if (key in setOf("ca.pem", "web.pem", "web-key.pem")) "bao-$key" else key
        }, keeperSource, sharedMail, groupwareSource, mariaOffice?.inputs.orEmpty(), rtcSource,
            financeSource, authSource, portalSource, socialSource,
            cacheSource.filterKeys { it !in setOf("erp-provider-cache-password", "mastodon-bridge-front-password",
                "mastodon-bridge-back-password") }, mastodonBridge, erpSource)
        if (full) fullSources.flatMap { it.entries }.groupBy { it.key }
            .filterValues { it.size > 1 }.forEach { (file, values) ->
                require(file in setOf("identity-ca.pem", "bao-ca.pem", "seafile-ca.pem") &&
                    values.map { it.value }.distinct().size == 1) {
                    "Full source producers conflict for $file"
                }
            }
        return (baseline + mapOf(
            "postgres-hba.conf" to hba.replace(anchor, anchor +
                "hostssl planka planka,planka_migrate 0.0.0.0/0 scram-sha-256\n" +
                "hostssl planka planka,planka_migrate ::/0 scram-sha-256\n" +
                "hostssl keycloak keycloak,keycloak_migrate 0.0.0.0/0 scram-sha-256\n" +
                "hostssl keycloak keycloak,keycloak_migrate ::/0 scram-sha-256\n" +
                (if (full) listOf(
                    "firefly firefly_runtime,firefly_migration", "synapse synapse",
                    "mas mas", "mastodon mastodon_runtime,mastodon_migration", "sogo sogo")
                    .joinToString("") { role -> "hostssl $role 0.0.0.0/0 scram-sha-256\n" +
                        "hostssl $role ::/0 scram-sha-256\n" } else "")), 
            "valkey.conf" to "bind 0.0.0.0\nprotected-mode yes\nport 6379\ndir /data\nappendonly yes\nappendfsync everysec\nrequirepass $cache\n",
            "planka-db-admin.env" to pg + "PLANKA_MIGRATION_PASSWORD=$migration\nPLANKA_RUNTIME_PASSWORD=$runtime\n",
            "planka-migration.env" to application("planka_migrate", migration) +
                "DEFAULT_ADMIN_EMAIL=bootstrap@localhost.invalid\nDEFAULT_ADMIN_USERNAME=p0v3_bootstrap\n" +
                "DEFAULT_ADMIN_NAME=Private bootstrap\nDEFAULT_ADMIN_PASSWORD=$bootstrap\n",
            "planka-runtime.env" to application("planka", runtime),
            "planka-database.js" to "module.exports = { datastores: { default: { ssl: { rejectUnauthorized: true, ca: require('fs').readFileSync('/run/secrets/postgres-ca.pem') } } } };\n",
            "fixture-terms.md" to PlankaRuntime.FIXTURE_TERMS,
            "mariadb-bootstrap.env" to "MARIADB_ROOT_PASSWORD=$mariaRoot\n",
            "grafana-runtime.env" to "GF_SECURITY_ADMIN_USER=p0v3_private_operator\n" +
                "GF_SECURITY_ADMIN_PASSWORD=$grafanaPassword\nGF_SECURITY_SECRET_KEY=$grafanaSecret\n" +
                "GF_SERVER_HTTP_ADDR=0.0.0.0\nGF_SERVER_ROOT_URL=http://grafana:3000\n" +
                "GF_USERS_ALLOW_SIGN_UP=false\nGF_AUTH_ANONYMOUS_ENABLED=false\n" +
                "GF_ANALYTICS_REPORTING_ENABLED=false\nGF_ANALYTICS_CHECK_FOR_UPDATES=false\n" +
                "GF_PLUGINS_CHECK_FOR_UPDATES=false\nGF_PLUGINS_PREINSTALL_DISABLED=true\n"
        ) + identity + literals.toMap() +
            (if (candidateRevision == 10) PlankaRuntime.freshActorEnrollmentInputs(
                requireNotNull(freshPlankaActorGrant), bootstrap) else emptyMap()) +
            (if (freshFull) CanonicalFreshNtfySource.inputs(
                requireNotNull(freshNtfy) { "Fresh scoped ntfy grants required" }) else emptyMap()) +
            (if ("caddy" in selectedCapabilities) {
                if (freshFull) CaddyRuntime.inputs() + ("caddy.json" to
                    CanonicalGraphCaddyfile.adaptFresh(selected, spec,
                        requireNotNull(freshIngressGrants).also { ingress ->
                            require(ingress.ntfySsoToken == requireNotNull(freshNtfy).ssoToken) {
                                "The Caddy browser token must be the same freshly provisioned ntfy read-only grant"
                            }
                        },
                        requireNotNull(freshCaddyCli) { "SHA-pinned exact Caddy CLI required" }, requireFeatureClosure = true,
                        controlSource = FreshControlIngressSource(generation,
                            ActivationInput(requireNotNull(freshIngressRecord).toString(),
                                ReleaseLocks.sha256(ReleasePrivateFiles.read(freshIngressRecord,4096))),
                            ActivationInput("/mnt/media/p0-v3/release-bootstrap-anchors/identity/ntfy-fresh/$generation.json",
                                ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(
                                    "/mnt/media/p0-v3/release-bootstrap-anchors/identity/ntfy-fresh/$generation.json"),4096))),
                            requireNotNull(managedBrokerHost))))
                else CaddyRuntime.inputs()
            } else emptyMap()) +
            (if ("donetick" in selectedCapabilities) {
                val serving = DonetickRuntime.canonicalInputs(password)
                val daemon = serving.mapKeys { (key, _) ->
                    if (key == "selfhosted.yaml") "donetick-selfhosted.yaml" else key
                }
                if (freshFull) {
                    val grant = FreshDonetickActorGrant(generation = generation,
                        ownerPassword = password(), outsiderPassword = password(), appNonMemberPassword = password())
                    daemon + DonetickRuntime.freshActorEnrollmentInputs(grant, serving.getValue("selfhosted.yaml"))
                } else daemon
            } else emptyMap()) +
            (if ("searxng" in selectedCapabilities) SearxngRuntime.canonicalInputs() else emptyMap()) +
            (if ("opensearch" in selectedCapabilities) {
                if (freshFull) OpenSearchRuntime.canonicalFreshInputs() else OpenSearchRuntime.canonicalInputs()
            } else emptyMap()) +
            (if ("jellyfin" in selectedCapabilities) JellyfinRuntime.canonicalInputs() else emptyMap()) +
            (if ("qbittorrent" in selectedCapabilities) {
                if (freshFull) QbittorrentRuntime.freshCanonicalInputs(
                    FreshNativeIngressCustody.qbittorrentPassword(requireNotNull(freshIngressRecord) {
                        "Original fresh ingress custody record required"
                    }, requireNotNull(freshIngressGrants)))
                else QbittorrentRuntime.canonicalInputs()
            } else emptyMap()) +
            (if ("crowdsec" in selectedCapabilities) CrowdsecRuntime.canonicalInputs() else emptyMap()) +
            (if ("homeassistant" in selectedCapabilities) HomeAssistantRuntime.canonicalInputs() else emptyMap()) +
            (if ("element" in selectedCapabilities) MatrixRuntime.canonicalInputs() else emptyMap()) +
            baoSource.mapKeys { (key, _) ->
                if (key in setOf("ca.pem", "web.pem", "web-key.pem")) "bao-$key" else key
            } + keeperSource +
            (if ("huly" in selectedCapabilities) HulyRuntime.canonicalInputs() else emptyMap()) +
            (if ("jupyter-notebook" in selectedCapabilities) NotebookRuntime.canonicalInputs() else emptyMap()) +
            sharedMail + groupwareSource + mariaOffice?.inputs.orEmpty() + rtcSource + financeSource + authSource + portalSource +
            cacheSource.filterKeys { it !in setOf("erp-provider-cache-password", "mastodon-bridge-front-password",
                "mastodon-bridge-back-password") } + mastodonBridge + socialSource + erpSource +
            (if ("jupyterhub" in selectedCapabilities) JupyterHubRuntime.canonicalInputs(
                onDemandGeneration = if (freshFull) generation else null) else emptyMap()))
            .also {
                val expected = PrivateDeployment.inputNames(spec).toSet()
                require(it.keys == expected) {
                    "Selected source input names differ: missing=${(expected - it.keys).sorted()} unexpected=${(it.keys - expected).sorted()}"
                }
                if (freshFull) CanonicalPrivateIngressTrust.requireSelectedCertificates(selected,spec,it)
            }
    }
}
