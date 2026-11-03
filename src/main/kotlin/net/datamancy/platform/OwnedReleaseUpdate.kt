package net.datamancy.platform

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** Immutable PREPARED update identity. The future bundle digest is deliberately not guessed. */
@Serializable internal data class ReleaseUpdateIntent(val source: ReleaseGeneration, val targetGeneration: String,
    val candidateSha256: String, val sitePolicySha256: String, val previousInventorySha256: String,
    val candidateInventorySha256: String, val transition: PlankaVersionTransition) {
    fun validate() {
        source.validate(); transition.validate()
        require(targetGeneration.matches(Regex("q-[a-f0-9]{12}")) && targetGeneration != source.id &&
            listOf(candidateSha256, sitePolicySha256, previousInventorySha256, candidateInventorySha256).all { it.matches(Regex("[a-f0-9]{64}")) })
    }
}
@Serializable internal data class OwnedUpdateLineage(val schemaVersion: Int = 1, val intent: ReleaseUpdateIntent,
    val snapshot: KopiaSnapshotReceipt,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val original: GenerationBundle? = null) {
    fun validate() {
        intent.validate(); KopiaGenerationStore.validate(snapshot)
        require(schemaVersion == 1 && snapshot.generation == intent.source.id && snapshot.bundleSha256 == intent.source.bundleSha256)
    }
}

/** Version-aware compiler for a fresh OWNED update, not a recovery-promotion escape hatch.
 * Cold restoration checks the exact old compiler before this narrowly supported image substitution.
 * Original state bytes and surviving credential hashes are retained. All initializer roles stay retired.
 */
internal object OwnedReleaseUpdates {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    fun compile(original: GenerationBundle, previousInventoryBytes: ByteArray, candidateInventoryBytes: ByteArray,
        intent: ReleaseUpdateIntent, snapshot: KopiaSnapshotReceipt): GenerationBundle {
        intent.validate()
        val lineage = OwnedUpdateLineage(intent = intent, snapshot = snapshot, original = original).also { it.validate() }
        require(original.request.id == intent.source.id && original.request.store == RuntimeStore.CANONICAL_V2 &&
            original.recoverySourceArchiveSha256 == null && original.recoverySourceKopia == null && original.ownedUpdate == null &&
            ReleaseLocks.sha256(json.encodeToString(original).toByteArray()) == intent.source.bundleSha256) {
            "Update requires the exact original owned source, never a recovery or unverified chained update"
        }
        SiteOwnerships.checkSealed(original)
        val sourceOwner = requireNotNull(original.ownership)
        require(ReleaseLocks.sha256(previousInventoryBytes) == intent.previousInventorySha256 &&
            ReleaseLocks.sha256(candidateInventoryBytes) == intent.candidateInventorySha256)
        val previous = json.decodeFromString<AcquiredInventory>(previousInventoryBytes.decodeToString())
        val candidate = json.decodeFromString<AcquiredInventory>(candidateInventoryBytes.decodeToString())
        require(previous.schemaVersion == 1 && candidate.schemaVersion == 1 &&
            previous.images.map { it.product }.distinct().size == previous.images.size &&
            candidate.images.map { it.product }.distinct().size == candidate.images.size)
        val old = previous.images.associateBy { it.product }; val next = candidate.images.associateBy { it.product }
        require(old.keys == next.keys && old.filterKeys { it != "planka" } == next.filterKeys { it != "planka" }) {
            "Only the reviewed Planka patch may change; unsupported provider or application updates refused"
        }
        val oldPlanka = old.getValue("planka"); val newPlanka = next.getValue("planka")
        require(oldPlanka.reference == "ghcr.io/plankanban/planka:2.2.0" && newPlanka.reference == "ghcr.io/plankanban/planka:2.2.1" &&
            oldPlanka.os == "linux" && newPlanka.os == "linux" && oldPlanka.architecture == "amd64" && newPlanka.architecture == "amd64" &&
            oldPlanka.pinnedImage != newPlanka.pinnedImage && oldPlanka.imageId != newPlanka.imageId)
        val restored = FoundationRestore.bundle(original, previous, intent.targetGeneration, KopiaGenerationStore.receiptHash(snapshot),
            ColdRestoreCohort.WHOLE_RELEASE, RuntimeStore.CANONICAL_V2)
        var replaced = 0
        val pins = restored.members.map { pin ->
            val spec = pin.spec.copy(processes = pin.spec.processes.map { process ->
                if (process.image == oldPlanka.pinnedImage && process.imageId == oldPlanka.imageId) {
                    require(process.id == "planka" && !process.oneShot && process.command == listOf("app.js", "--prod"))
                    replaced++
                    process.copy(image = newPlanka.pinnedImage, imageId = newPlanka.imageId)
                } else process
            }).also { PrivateDeployment.validate(it) }
            pin.copy(spec = spec, manifestSha256 = ReleaseLocks.sha256(Json.encodeToString(spec).toByteArray()),
                runtimeFingerprint = PrivateDeployment.expectedFingerprint(spec, pin.inputHashes))
        }
        require(replaced == 1) { "Exactly one compiled Planka daemon required" }
        val request = restored.request.copy(candidateSha256 = intent.candidateSha256, releaseCandidateSha256 = null)
        val assemblyRequest = sourceOwner.assembly.request.copy(id = intent.targetGeneration,
            candidateSha256 = intent.candidateSha256, inventorySha256 = intent.candidateInventorySha256,
            // Cold import raises disk reservation for authenticated extraction. Ownership must
            // bind that actual capacity policy, not silently project the smaller source policy.
            diskReservationMiB = request.diskReservationMiB, memoryHeadroomMiB = request.memoryHeadroomMiB,
            diskHeadroomMiB = request.diskHeadroomMiB, store = request.store)
        fun renamed(value: String): String {
            require(value.startsWith(original.request.id + "-")) { "Foreign ownership reference" }
            return intent.targetGeneration + value.removePrefix(original.request.id)
        }
        val summaries = pins.mapIndexed { index, pin ->
            val spec = pin.spec
            val source = sourceOwner.assembly.members[index]
            require(renamed(source.name) == pin.member.name)
            source.copy(name = spec.name, dependencies = pin.member.dependencies,
                specSha256 = ReleaseLocks.sha256(Json.encodeToString(spec).toByteArray()),
                images = spec.processes.associate { it.image to it.imageId },
                daemons = spec.processes.map { it.id }, initializers = emptyList(),
                state = spec.volumes.map { volume -> AssemblyState(volume.id, volume.userId,
                    spec.processes.filter { p -> p.volumes.any { it.volume == volume.id } }.map { it.id }.sorted()) },
                inputs = PrivateDeployment.inputNames(spec).map { file -> AssemblyInput(file,
                    spec.processes.filter { it.environmentFile == file || it.files.any { f -> f.file == file } }.map { it.id }.sorted()) })
        }
        val summary = sourceOwner.assembly.copy(request = assemblyRequest, members = summaries,
            globalIntegrationValidated = false, fullStackQualification = false, publicActivation = false)
        val specs = pins.map { it.spec }
        val plan = AssemblyPlan(summary, request, candidate, specs, emptyList())
        val processNames = specs.flatMap { s -> s.processes.map { "${s.name}/${it.id}" } }.toSet()
        val inputNames = specs.flatMap { s -> PrivateDeployment.inputNames(s).map { "${s.name}/$it" } }.toSet()
        val contract = sourceOwner.contract.copy(assemblySha256 = SiteOwnerships.assemblyDigest(plan),
            processes = sourceOwner.contract.processes.map { it.copy(process = renamed(it.process)) }.filter { it.process in processNames },
            state = sourceOwner.contract.state.map { it.copy(volume = renamed(it.volume)) },
            inputs = sourceOwner.contract.inputs.map { it.copy(input = renamed(it.input), consumers = it.consumers.map(::renamed).filter(processNames::contains)) }
                .filter { it.input in inputNames },
            routes = sourceOwner.contract.routes.map { it.copy(process = renamed(it.process)) })
        val ownership = SiteOwnerships.bind(plan, contract, sourceOwner.approvedHosts, lineage)
        val result = restored.copy(request = request, members = pins, assemblySha256 = contract.assemblySha256,
            recoverySourceArchiveSha256 = null, recoverySourceKopia = null, ownership = ownership, ownedUpdate = lineage)
        validate(result)
        return result
    }
    /** Authenticated source metadata, not a caller-selected list of roles to omit. No update chains. */
    fun original(lineage: OwnedUpdateLineage): GenerationBundle {
        lineage.validate()
        val source = requireNotNull(lineage.original) { "Owned update requires retained original ownership evidence" }
        require(source.ownedUpdate == null && source.recoverySourceKopia == null && source.recoverySourceArchiveSha256 == null &&
            source.ownership != null && source.request.id == lineage.intent.source.id &&
            source.request.store == RuntimeStore.CANONICAL_V2 &&
            ReleaseLocks.sha256(json.encodeToString(source).toByteArray()) == lineage.intent.source.bundleSha256) {
            "Owned update original evidence differs from the verified snapshot"
        }
        SiteOwnerships.checkSealed(source)
        return source
    }

    fun validate(bundle: GenerationBundle) {
        val lineage = requireNotNull(bundle.ownedUpdate).also { it.validate() }
        require(bundle.request.id == lineage.intent.targetGeneration && bundle.request.candidateSha256 == lineage.intent.candidateSha256 &&
            bundle.request.store == RuntimeStore.CANONICAL_V2 && bundle.recoverySourceArchiveSha256 == null && bundle.recoverySourceKopia == null &&
            bundle.ownership != null && bundle.members.all { it.spec.processes.none { process -> process.oneShot } }) {
            "Foreign owned-update lineage or initializer resurrection"
        }
        SiteOwnerships.checkSealed(bundle)
    }
}
