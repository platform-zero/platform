package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** Fixed controller-owned components, never arbitrary command or host-path registrations. */
@Serializable internal enum class ManagedComponentKind { RSS, LANES, CI }
@Serializable internal data class SiteManagedOwner(val component: ManagedComponentKind,
    val products: Set<String>, val stateRoot: String, val planSha256: String)

@Serializable internal data class ManagedRecoveryIndex(val schemaVersion: Int = 1,
    val generation: String, val captureId: String, val planSha256: String,
    val oracleSha256: String, val sourceManifestSha256: String,
    val archives: Map<String, ManagedLaneArchive>, val nativeCaptures: Map<ManagedLaneKind, ManagedLaneEvidence>)

@Serializable internal data class ManagedImportIntent(val sourceGeneration: String, val targetGeneration: String,
    val captureId: String, val sourceBundleSha256: String, val targetBundleSha256: String,
    val indexSha256: String, val oracleSha256: String, val targetPlanSha256: String,
    val maximumReadbackBytes: Long, val additionalDiskBytes: Long)
@Serializable internal data class ManagedImportResult(val intentSha256: String,
    val imports: Map<ManagedLaneKind, ManagedLaneEvidence>,
    val preparations: Map<ManagedLaneKind, ManagedLaneEvidence>)

/** Admission and custody orchestration; effects use only the fixed feature adapters. */
internal object GenerationManagedComponents {
    private val json = Json { encodeDefaults = true }
    private val laneProducts = setOf("worklane", "tuios", "pi")

    fun validate(request: GenerationRequest) {
        if (request.rssPlan == null && request.recoveredRssPlan == null &&
            request.managedLanes == null && request.forgejoCi == null && request.recoveredForgejoCi == null &&
            request.recoveredForgejoCiTarget == null && request.ciRecoveryGrant == null) return
        require(request.rssPlan == null || request.recoveredRssPlan == null) { "Live and inert RSS plans cannot coexist" }
        require(request.id.matches(Regex("q-[a-f0-9]{12}")) && request.store == RuntimeStore.CANONICAL_V2) {
            "Managed components require canonical generation isolation"
        }
        request.rssPlan?.validate()
        request.recoveredRssPlan?.validate()
        require(request.forgejoCi == null || request.recoveredForgejoCi == null) {
            "Live and inert Forgejo runner controls cannot coexist"
        }
        request.forgejoCi?.validate(request.id)
        request.recoveredForgejoCi?.let { prior ->
            require(prior.generation != request.id && request.recoveryStateReservationMiB != null &&
                request.store == RuntimeStore.CANONICAL_V2)
            prior.validate(prior.generation)
        }
        require((request.recoveredForgejoCiTarget == null) == (request.ciRecoveryGrant == null) &&
            (request.ciRecoveryGrant == null || request.recoveredForgejoCi != null && request.forgejoCi == null))
        request.ciRecoveryGrant?.let { grant ->
            val prior = requireNotNull(request.recoveredForgejoCi)
            grant.validate(prior, request.id)
            require(grant.targetPlan(prior) == request.recoveredForgejoCiTarget)
        }
        request.managedLanes?.let { plan ->
            plan.validate(request.id)
            require(plan.capabilities.isNotEmpty() && laneProducts.containsAll(plan.capabilities)) {
                "Unknown managed lane capability"
            }
            require(plan.memoryReservationMiB > 0 && plan.diskReservationMiB > 0) {
                "Managed lanes require explicit bounded reservations"
            }
        }
        // Exact arithmetic must fail before preparation rather than wrap into a smaller reservation.
        memoryReservationMiB(request)
        diskReservationMiB(request)
    }

    fun capabilities(request: GenerationRequest): Set<String> = request.managedLanes?.capabilities.orEmpty()

    fun memoryReservationMiB(request: GenerationRequest): Long = Math.addExact(
        if (request.rssPlan == null) 0L else GenerationRssPlan.MEMORY_MIB,
        Math.addExact(request.managedLanes?.memoryReservationMiB ?: 0L,
            if ((request.forgejoCi ?: request.recoveredForgejoCiTarget) == null) 0L else
                Math.addExact(requireNotNull(request.forgejoCi ?: request.recoveredForgejoCiTarget)
                    .enrollment.memoryMiB.toLong(), 640L)))

    fun diskReservationMiB(request: GenerationRequest): Long = Math.addExact(
        if (request.rssPlan == null && request.recoveredRssPlan == null) 0L else GenerationRssPlan.DISK_MIB,
        Math.addExact(request.managedLanes?.diskReservationMiB ?: 0L,
            (request.forgejoCi ?: request.recoveredForgejoCiTarget)?.let { ci ->
                val jobBytes = Math.addExact(ci.jobArchive.archiveBytes, ci.jobArchive.maximumUnpackedBytes)
                val runner = requireNotNull(ci.runnerImage)
                val runnerBytes = Math.addExact(runner.archiveBytes, runner.maximumUnpackedBytes)
                val transport = requireNotNull(ci.transportImage)
                val transportBytes = Math.addExact(transport.archiveBytes, transport.maximumUnpackedBytes)
                Math.addExact(ci.enrollment.diskMiB.toLong() + 256L,
                    Math.addExact(Math.addExact(Math.addExact(jobBytes, runnerBytes), transportBytes), 1048575L) / 1048576L)
            } ?: 0L))

    fun ownership(request: GenerationRequest): List<SiteManagedOwner> {
        validate(request)
        require(request.recoveredRssPlan == null && request.recoveryStateReservationMiB == null) {
            "Recovery state cannot acquire installation ownership"
        }
        return buildList {
            request.rssPlan?.let { plan ->
                add(SiteManagedOwner(ManagedComponentKind.RSS, setOf("mastodon"), "${request.id}/rss",
                    ReleaseLocks.sha256(json.encodeToString(plan).toByteArray())))
            }
            request.managedLanes?.let { plan ->
                add(SiteManagedOwner(ManagedComponentKind.LANES, plan.capabilities.toSortedSet(), "${request.id}/managed",
                    ReleaseLocks.sha256(json.encodeToString(plan).toByteArray())))
            }
            request.forgejoCi?.let { plan ->
                add(SiteManagedOwner(ManagedComponentKind.CI, setOf("forgejo"), "${request.id}/ci",
                    ReleaseLocks.sha256(json.encodeToString(plan).toByteArray())))
            }
        }
    }

    /** Managed payloads are a separate, exact partition; historical manifests have none. */
    fun validate(manifest: CapsuleManifest) {
        val declared = manifest.managedFiles
        val physical = manifest.files.filter { it.name.startsWith("managed/") }
        require(declared.size <= 2051 && declared.distinct() == declared &&
            declared.toSet() == physical.map { it.name }.toSet() &&
            physical.map { it.name }.distinct().size == physical.size &&
            declared.none { it in manifest.controllerFiles }) { "Unknown or aliased managed recovery payload" }
        if (declared.isEmpty()) return
        val metadata = setOf("managed/index.json", "managed/oracle.json", "managed/source-manifest.toml")
        val components = setOf("home", "workspace", "manifests", "transcripts")
        require(declared.containsAll(metadata) && physical.filter { it.name in metadata }.all {
            it.bytes in 1..1048576 && it.sha256.matches(Regex("[a-f0-9]{64}"))
        }) { "Missing managed original-identity or archive binding" }
        val expected = metadata.toMutableSet()
        for (component in components) {
            val name = "managed/$component/tree.tar"
            val segmented = manifest.volumes.singleOrNull { it.name == name }
            if (segmented == null) {
                val file = physical.singleOrNull { it.name == name }
                require(file != null && file.bytes in 1024..RecoveryCapsule.MAX_FILE && file.bytes % 512 == 0L &&
                    file.sha256.matches(Regex("[a-f0-9]{64}"))) { "Missing or invalid managed archive" }
                expected += name
            } else {
                require(segmented.segments.size in 2..512 && segmented.segments == segmented.segments.indices.map {
                    "$name.part-${it.toString().padStart(4, '0')}"
                }) { "Noncanonical managed archive framing" }
                expected += segmented.segments
            }
        }
        require(expected == declared.toSet()) { "Unrecognized managed recovery file or missing segment" }
    }

    /** Called under controller exclusion and every member's frozen lock. Physical export happens once. */
    fun capture(generationRoot: Path, captureRoot: Path, captureId: String,
        payloads: MutableMap<String, Path>, maximumBytes: Long,
        runtimeFactory: (Path, ManagedLanePlan) -> ManagedLaneRuntime = ManagedLaneRuntime::real): List<String> {
        ReleasePrivateFiles.directory(generationRoot)
        ReleasePrivateFiles.directory(captureRoot)
        val bundle = json.decodeFromString<GenerationBundle>(ReleasePrivateFiles.read(generationRoot.resolve("bundle.json"))
            .decodeToString(throwOnInvalidSequence = true))
        require(bundle.request.id == generationRoot.fileName.toString() && captureId.matches(Regex("cap-[a-f0-9]{12}")))
        val plan = bundle.request.managedLanes ?: run {
            require(payloads.keys.none { it.startsWith("managed/") })
            return emptyList()
        }
        validate(bundle.request)
        val destination = captureRoot.resolve("managed-export")
        require(!Files.exists(destination, NOFOLLOW_LINKS) && payloads.keys.none { it.startsWith("managed/") })
        val runtime = runtimeFactory(generationRoot, plan)
        val receipts = plan.lanes.associate { lane -> lane.kind to runtime.operate(lane,
            ManagedLaneOperation.CAPTURE, captureId, transfer = destination,
            deadlineEpochMillis = RecoveryDeadline.observedUtcDeadline().toEpochMilli(),
            maximumBytes = minOf(maximumBytes, RecoveryCapsule.MAX_TOTAL)) }
        val oracle = ManagedLaneRecovery.captureOracle(plan, generationRoot.resolve("managed"), destination)
        require(oracle.sourceManifestSha256 == plan.native.manifest.sha256 &&
            receipts.keys == ManagedLaneKind.entries.toSet() && receipts.values.all {
                it.generation == plan.generation && it.laneId == plan.lanes.first().laneId &&
                    it.operation == ManagedLaneOperation.CAPTURE && it.operationId == captureId && it.isolated
            }) { "Managed capture is not the sealed original cohort" }
        val oracleBytes = ReleasePrivateFiles.read(destination.resolve("oracle.json"))
        val index = ManagedRecoveryIndex(generation = plan.generation, captureId = captureId,
            planSha256 = ReleaseLocks.sha256(json.encodeToString(plan).toByteArray()),
            oracleSha256 = ReleaseLocks.sha256(oracleBytes), sourceManifestSha256 = oracle.sourceManifestSha256,
            archives = oracle.archives, nativeCaptures = receipts)
        val indexPath = captureRoot.resolve("managed-index.json")
        ReleasePrivateFiles.save(indexPath, json.encodeToString(index).toByteArray())
        val selected = linkedMapOf("managed/index.json" to indexPath,
            "managed/oracle.json" to destination.resolve("oracle.json"),
            "managed/source-manifest.toml" to destination.resolve("source-manifest.toml"))
        oracle.archives.keys.sorted().forEach { component ->
            selected["managed/$component/tree.tar"] = destination.resolve("$component.tar")
        }
        require(selected.values.fold(0L) { total, path -> Math.addExact(total, Files.size(path)) } <= maximumBytes) {
            "Managed capture exceeds remaining release budget"
        }
        payloads.putAll(selected)
        // Caller computes manifest.managedFiles AFTER shared RecoverySegments.prepare, not from this logical list.
        return selected.keys.toList()
    }

    /** Bind original managed metadata to the authenticated source plan and shared logical archive descriptors. */
    fun validateRecovered(bundle: GenerationBundle, manifest: CapsuleManifest, root: Path): ManagedRecoveryIndex? =
        validatePayload(bundle, manifest) { root.resolve(it) }

    fun validateCaptured(bundle: GenerationBundle, manifest: CapsuleManifest, captureRoot: Path): ManagedRecoveryIndex? =
        validatePayload(bundle, manifest) { name ->
            when (name) {
                "managed/index.json" -> captureRoot.resolve("managed-index.json")
                "managed/oracle.json" -> captureRoot.resolve("managed-export/oracle.json")
                "managed/source-manifest.toml" -> captureRoot.resolve("managed-export/source-manifest.toml")
                else -> {
                    require(name.matches(Regex("managed/(home|workspace|manifests|transcripts)/tree\\.tar")))
                    captureRoot.resolve("managed-export/${name.split('/')[1]}.tar")
                }
            }
        }

    private fun validatePayload(bundle: GenerationBundle, manifest: CapsuleManifest,
        path: (String) -> Path): ManagedRecoveryIndex? {
        validate(manifest)
        val plan = bundle.request.managedLanes
        require((plan == null) == manifest.managedFiles.isEmpty()) { "Managed source plan/payload mismatch" }
        if (plan == null) return null
        fun bytes(name: String) = ReleasePrivateFiles.read(path("managed/$name"), 1048576)
        val index = json.decodeFromString<ManagedRecoveryIndex>(bytes("index.json").decodeToString(throwOnInvalidSequence = true))
        val oracleBytes = bytes("oracle.json")
        val oracle = json.decodeFromString<ManagedLaneCaptureOracle>(oracleBytes.decodeToString(throwOnInvalidSequence = true))
        require(index.schemaVersion == 1 && index.generation == bundle.request.id && index.captureId == manifest.id &&
            index.planSha256 == ReleaseLocks.sha256(json.encodeToString(plan).toByteArray()) &&
            index.oracleSha256 == ReleaseLocks.sha256(oracleBytes) && index.archives == oracle.archives &&
            index.sourceManifestSha256 == oracle.sourceManifestSha256 &&
            index.sourceManifestSha256 == plan.native.manifest.sha256 &&
            ReleaseLocks.sha256(bytes("source-manifest.toml")) == index.sourceManifestSha256 &&
            oracle.sourceGeneration == plan.generation && oracle.sourceLaneId == plan.lanes.first().laneId &&
            oracle.sourceSession == plan.lanes.first().session &&
            index.nativeCaptures.keys == ManagedLaneKind.entries.toSet()) { "Managed original custody changed" }
        index.nativeCaptures.values.forEach { receipt ->
            require(receipt.generation == plan.generation && receipt.laneId == oracle.sourceLaneId &&
                receipt.operation == ManagedLaneOperation.CAPTURE && receipt.operationId == manifest.id && receipt.isolated &&
                listOf(receipt.intentSha256, receipt.ownershipSha256, receipt.resultSha256).all { it.matches(Regex("[a-f0-9]{64}")) })
        }
        require(index.archives.keys == setOf("home", "workspace", "manifests", "transcripts"))
        index.archives.forEach { (component, descriptor) ->
            val name = "managed/$component/tree.tar"
            val segmented = manifest.volumes.singleOrNull { it.name == name }
            val declared = manifest.files.singleOrNull { it.name == name }
            require((segmented?.sha256 ?: declared?.sha256) == descriptor.sha256 &&
                (segmented?.bytes ?: declared?.bytes) == descriptor.bytes &&
                ManagedLaneRecovery.archive(path(name)) == descriptor) { "Managed archive framing or metadata differs" }
        }
        return index
    }

    /** Caller holds the ordered source/target generation and native locks throughout this hook.
     * Recovered archives are already authenticated/materialized; import reads that single logical
     * layout directly. Neither an oracle nor a successful import authorizes running a lane.
     */
    fun importOwned(source: GenerationBundle, target: GenerationBundle, manifest: CapsuleManifest,
        recovered: Path, targetRoot: Path,
        runtimeFactory: (Path, ManagedLanePlan) -> ManagedLaneRuntime = ManagedLaneRuntime::real) =
        importCold(source, target, manifest, recovered, targetRoot, true, runtimeFactory)

    fun importRecovered(source: GenerationBundle, target: GenerationBundle, manifest: CapsuleManifest,
        recovered: Path, targetRoot: Path,
        runtimeFactory: (Path, ManagedLanePlan) -> ManagedLaneRuntime = ManagedLaneRuntime::real) =
        importCold(source, target, manifest, recovered, targetRoot, false, runtimeFactory)

    private fun importCold(source: GenerationBundle, target: GenerationBundle, manifest: CapsuleManifest,
        recovered: Path, targetRoot: Path, owned: Boolean,
        runtimeFactory: (Path, ManagedLanePlan) -> ManagedLaneRuntime) {
        ReleasePrivateFiles.directory(recovered)
        ReleasePrivateFiles.directory(targetRoot)
        require(targetRoot.fileName.toString() == target.request.id && source.request.id != target.request.id)
        val index = validateRecovered(source, manifest, recovered)
        if (index == null) {
            require(target.request.managedLanes == null) { "Unmanaged source cannot create managed recovery state" }
            return
        }
        if (owned) {
            OwnedReleaseUpdates.validate(target)
            require(OwnedReleaseUpdates.original(requireNotNull(target.ownedUpdate)) == source) {
                "Foreign managed owned-import source"
            }
        } else {
            val snapshot = requireNotNull(target.recoverySourceKopia)
            KopiaGenerationStore.validate(snapshot)
            require(target.ownedUpdate == null && target.ownership == null && target.assemblySha256 == null &&
                target.recoverySourceArchiveSha256 == null && snapshot.id == manifest.id &&
                snapshot.generation == source.request.id && snapshot.bundleSha256 == manifest.bundleSha256) {
                "Managed private recovery cannot acquire owned update or site authority"
            }
        }
        require(manifest.generation == source.request.id && manifest.bundleSha256 ==
            ReleaseLocks.sha256(json.encodeToString(source).toByteArray())) { "Foreign managed import source" }
        val sourcePlan = requireNotNull(source.request.managedLanes)
        val plan = requireNotNull(target.request.managedLanes)
        val sourceManifest = ReleasePrivateFiles.read(recovered.resolve("managed/source-manifest.toml"), 1048576)
        val image = requireNotNull(plan.native.imageArchive)
        val projection = ManagedLaneRecovery.projectPlan(sourcePlan, target.request.id, sourceManifest, image)
        require(projection.plan == plan) { "Target managed plan differs from authenticated cold projection" }
        val root = targetRoot.resolve("managed")
        require(!Files.exists(root, NOFOLLOW_LINKS)) { "Managed import already attempted; reconcile, do not replay" }
        val deadline = RecoveryDeadline.observedUtcDeadline().toEpochMilli()
        val archiveBytes = index.archives.values.fold(0L) { sum, archive -> Math.addExact(sum, archive.bytes) }
        val maximumReadback = Math.addExact(Math.multiplyExact(archiveBytes, 2L), ManagedLaneRecovery.METADATA_RESERVE_BYTES)
        require(maximumReadback in (ManagedLaneRecovery.METADATA_RESERVE_BYTES + 4096)..RecoveryCapsule.MAX_TOTAL)
        // Source tar byte counts alone do not bound tiny-file allocation on the target filesystem.
        // Charge a block plus metadata for every entry, including directories and hardlinks.
        val block = Files.getFileStore(targetRoot).blockSize
        require(block in 512L..(1024L * 1024L)) { "Unsupported managed target filesystem allocation unit" }
        val owner = com.sun.security.auth.module.UnixSystem().uid.toInt()
        var allocated = 0L
        index.archives.keys.sorted().forEach { component ->
            RecoveryDeadline.remainingSecondsIfBound()
            VolumeTar.inspect(recovered.resolve("managed/$component/tree.tar"), owner).forEach { entry ->
                val blocks = maxOf(1L, Math.addExact(entry.size, block - 1L) / block)
                allocated = Math.addExact(allocated, Math.addExact(Math.multiplyExact(blocks, block), 65536L))
            }
        }
        val additionalDisk = Math.addExact(Math.addExact(allocated, maximumReadback),
            Math.addExact(image.maximumUnpackedBytes, 512L * 1024L * 1024L))
        require(Files.getFileStore(targetRoot).usableSpace >= Math.addExact(additionalDisk,
            Math.multiplyExact(target.request.diskHeadroomMiB, 1024L * 1024L))) {
            "Insufficient managed import, readback, image and retained headroom capacity"
        }
        val intent = ManagedImportIntent(source.request.id, target.request.id, manifest.id,
            manifest.bundleSha256, ReleaseLocks.sha256(json.encodeToString(target).toByteArray()),
            ReleaseLocks.sha256(ReleasePrivateFiles.read(recovered.resolve("managed/index.json"))),
            index.oracleSha256, ReleaseLocks.sha256(json.encodeToString(plan).toByteArray()), maximumReadback, additionalDisk)
        val intentBytes = json.encodeToString(intent).toByteArray()
        ReleasePrivateFiles.save(targetRoot.resolve("managed-import.intent.json"), intentBytes)
        // All following writes are covered by the immutable intent. Partial output is retained.
        fun directory(path: Path) {
            ReleasePrivateFiles.directory(path.parent)
            Files.createDirectory(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(path.parent)
        }
        directory(root)
        listOf("inputs", "control", "control/home", "control/config", "control/data", "control/run",
            "control/leases", "control/podman-graph", "control/podman-run", "identity", "identity/revisions",
            "identity/native", "worklane", "tuios", "pi").forEach { directory(root.resolve(it)) }
        fun input(binding: ActivationInput, relative: String, bytes: ByteArray) {
            require(Path.of(binding.path) == root.resolve(relative) && ReleaseLocks.sha256(bytes) == binding.sha256)
            ReleasePrivateFiles.save(root.resolve(relative), bytes)
        }
        input(plan.native.manifest, "inputs/target-lane.toml", projection.targetManifestBytes)
        input(plan.native.storageConfig, "control/storage.conf", projection.targetStorageConfigBytes)
        input(requireNotNull(plan.native.broker).configuration, "inputs/broker.json", projection.targetBrokerConfigBytes)
        val runtime = runtimeFactory(targetRoot, plan)
        val ordered = ManagedLaneKind.entries.map { kind -> plan.lanes.single { it.kind == kind } }
        val imports = ordered.associate { lane -> lane.kind to runtime.operate(lane, ManagedLaneOperation.IMPORT,
            manifest.id, sourceCaptureSha256 = index.oracleSha256, transfer = recovered.resolve("managed"),
            deadlineEpochMillis = deadline, maximumBytes = maximumReadback) }
        require(imports.values.all { it.isolated }) { "Managed import must remain cold" }
        // Import original home first: PREPARE creates fresh registry/config, never copies source registry.
        val preparations = ordered.associate { lane -> lane.kind to runtime.operate(lane, ManagedLaneOperation.PREPARE,
            manifest.id, deadlineEpochMillis = deadline) }
        require(preparations.values.all { it.isolated }) { "Managed preparation unexpectedly started a lane" }
        val result = ManagedImportResult(ReleaseLocks.sha256(intentBytes), imports, preparations)
        ReleasePrivateFiles.save(targetRoot.resolve("managed-import.result.json"), json.encodeToString(result).toByteArray())
    }

    /** Native initial source preparation uses real pinned Worklane inputs and fresh graph. */
    fun prepareInitial(bundle: GenerationBundle, targetRoot: Path): ManagedInitialPreparation? =
        ManagedGenerationLifecycle.prepareInitial(bundle, targetRoot)

    /** Original installation also needs a fresh lane, supervised broker and native identity. */
    fun startInitial(bundle: GenerationBundle, targetRoot: Path): ManagedGenerationStartResult? =
        ManagedGenerationLifecycle.start(bundle, targetRoot, recovered = false, initial = true)

    /** Source backup/target isolation boundary: revoke broker before native lane stop. */
    fun isolate(bundle: GenerationBundle, generationRoot: Path, operationId: String): ManagedGenerationIsolationResult? =
        ManagedGenerationLifecycle.isolate(bundle, generationRoot, operationId)

    /** Caller must prove target isolation and bridge removal BEFORE source resume. */
    fun resumeOriginal(bundle: GenerationBundle, generationRoot: Path, isolatedOperationId: String,
        operationId: String): ManagedGenerationResumeResult? =
        ManagedGenerationLifecycle.resumeOriginal(bundle, generationRoot, isolatedOperationId, operationId)

    /** Owned-candidate first/second cycle is not an original-source site publication. */
    fun resumeOwnedCandidate(bundle: GenerationBundle, generationRoot: Path, isolatedOperationId: String,
        operationId: String): ManagedGenerationResumeResult? =
        ManagedGenerationLifecycle.resumeOwnedCandidate(bundle, generationRoot, isolatedOperationId, operationId)

    /** Only after imported native members have started. Failure retains start intent and fences retry. */
    fun startOwned(bundle: GenerationBundle, targetRoot: Path): ManagedGenerationStartResult? =
        ManagedGenerationLifecycle.start(bundle, targetRoot, recovered = false)

    /** Private, nonpromotable target: neither an import nor native lane readiness publishes a site. */
    fun startRecovered(bundle: GenerationBundle, targetRoot: Path): ManagedGenerationStartResult? =
        ManagedGenerationLifecycle.start(bundle, targetRoot, recovered = true)

    fun checkOwnership(request: GenerationRequest, contract: SiteOwnership) {
        require(contract.managed == ownership(request)) {
            "Managed component ownership differs from the compiled generation plan"
        }
    }
}
