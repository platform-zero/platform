package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Initial source-setting forecast, NOT an observed r9 RSS or permission to
 * overcommit. Unknown per-service heap/worker demand is conservatively charged
 * at its existing hard ceiling in the *forecast row*; the sum is diagnostic,
 * NEVER an INSTALL admission reservation. Original processes are serialized:
 * one unchanged next ceiling + owner margin + selected auxiliary work is
 * admitted against actual protected host floors, before/after EACH start.
 */
@Serializable internal data class GenerationWorkingForecastRow(val process: String, val oneShot: Boolean,
    val hardCeilingMiB: Long, val prospectiveMiB: Long, val basis: String)
@Serializable internal data class GenerationFirstStartEnvelope(val schemaVersion: Int = 1,
    val scope: String = "r9-complete-private-first-start-prospective-not-rss",
    val generation: String, val candidateSha256: String, val indexSha256: String,
    val manifestSha256: String, val selectedSpecSha256: String,
    val observedMemAvailableMiB: Long, val observedUsableDiskMiB: Long,
    val currentHostAndRootlessLoadIncludedInMemAvailable: Boolean = true,
    val priorFreshR9RssRequired: Boolean = false,
    val memoryFloorMiB: Long, val diskFloorMiB: Long,
    val prospectiveRows: List<GenerationWorkingForecastRow>,
    val diagnosticSumOfSteadyForecastMiBNotRssOrReservation: Long,
    val initialBothNotebookBootstrapMiB: Long,
    val largestNextOriginalCeilingPlusOwnerMarginMiB: Long,
    val selectedRssCiManagedAuxiliaryMiB: Long,
    val rootfulStateAndSelectedAuxiliaryDiskMiB: Long,
    val serializedOriginalDiskScratchMiB: Long = 512,
    val futureKopiaMemoryMinimumMiB: Long = 1024,
    val backupAndRestoreScratchDiskMiB: Long,
    val isolatedRestoreSourceAndTargetStateDiskMiB: Long,
    val oldStateUsedAsInput: Boolean = false,
    val nativeStageAndPhaseRecheckRequired: Boolean = true,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val predecessorDisposition: ActivationInput? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val memberPredecessorDisposition: ActivationInput? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val abandonedPreparation: AbandonedPreparationLineage? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val preparedNoStartPredecessor: ActivationInput? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val failedPreUnitStagePredecessor: ActivationInput? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val uncertainNativeImportPredecessor: ActivationInput? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val isolatedRootlessProbePredecessor: ActivationInput? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val qc3PreparedNoStartPredecessor: ActivationInput? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val q273UncertainImportPredecessor: ActivationInput? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val q583PreparedNoStartPredecessor: ActivationInput? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val isolatedFullWorklanePreparePredecessor: ActivationInput? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val q9bColdPreparedUninstalledPredecessor: ActivationInput? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val q07PartialInstalledPredecessor: ActivationInput? = null)

internal object GenerationWorkingEnvelopeIssuer {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    // AssemblySummary.specSha256 is produced with the assembly's default-field
    // serializer. Do not re-encode the same spec with envelope-only defaults.
    private val specJson = Json { ignoreUnknownKeys = false }
    private val perms = PosixFilePermissions.fromString("rwx------")
    private const val scope = "r9-full-private-incremental-first-start"
    private const val successorScope = "r10-full-private-incremental-first-start"
    private const val successor = "q-5712d9335843"
    private const val freshSuccessor = "q-dd36ebcf43ef"
    private const val afterPreUnit = "q-4d3c1cb287e5"
    private fun r10(generation:String)=generation==successor || generation==freshSuccessor ||
        generation==afterPreUnit || generation==GenerationAfterNativeImportLineage.generation ||
        generation==GenerationAfterCapacityRefusalLineage.generation ||
        generation==GenerationAfterQ273Lineage.generation ||
        generation==GenerationAfterQ583Lineage.generation ||
        generation==GenerationAfterQ9bLineage.generation ||
        generation==GenerationAfterQ07Lineage.generation
    private val anchor = Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/workload")
    private fun source(generation: String): Pair<String,String> {
        val revision = if (r10(generation)) "r10" else "r9"
        val index = javaClass.getResourceAsStream("/fragments/v3/canonical/$revision/index.yaml")?.readBytes()
            ?: error("Selected $revision index unavailable")
        val manifest = javaClass.getResourceAsStream("/fragments/v3/canonical/$revision/manifest.yaml")?.readBytes()
            ?: error("Selected $revision manifest unavailable")
        val parsed = FragmentYaml.parse(index).jsonObject
        require(parsed.getValue("manifestSha256").jsonPrimitive.content == ReleaseLocks.sha256(manifest))
        return ReleaseLocks.sha256(index) to ReleaseLocks.sha256(manifest)
    }
    internal fun forecastRows(spec: PrivateDeploymentSpec): List<GenerationWorkingForecastRow> =
        PrivateDeployment.validate(spec).map { process ->
            val cap = process.memoryMiB.toLong()
            val (value, basis) = when (process.id) {
                "huly-cockroach" -> 768L to "selected cache128+sql128+prospective512 runtime overhead; full 2048 cap retained"
                "huly-elastic" -> 1024L to "selected Xms=Xmx512m+prospective512 JVM/native overhead; full 1536 cap retained"
                "huly-redpanda" -> 1024L to "selected SMP1 memory512M+prospective512 native overhead; full 1024 cap retained"
                else -> cap to "selected unchanged hard ceiling as an unmeasured per-process conservative fallback, not RSS"
            }
            require(value in 64..cap)
            GenerationWorkingForecastRow("${spec.name}/${process.id}", process.oneShot, cap, value, basis)
        }
    private fun observedMemory(): Long {
        val row = Files.readAllLines(Path.of("/proc/meminfo")).single { it.startsWith("MemAvailable:") }
            .trim().split(Regex("\\s+"))
        require(row.size == 3 && row[2] == "kB")
        return row[1].toLong() / 1024
    }
    private fun model(plan: AssemblyPlan): GenerationFirstStartEnvelope {
        val request = plan.generation
        require(request.store == RuntimeStore.CANONICAL_V2 && request.releaseCandidateSha256 != null &&
            request.workingBudget == null && request.members.size == 1 && plan.specs.size == 1 &&
            plan.summary.missingCapabilities.isEmpty() && plan.summary.request.id == request.id &&
            request.memoryHeadroomMiB >= 16384 && request.diskHeadroomMiB >= 10240)
        val spec = plan.specs.single()
        val r10 = r10(request.id)
        require(spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2 &&
            spec.fragmentBinding?.recipe == CanonicalSharedYamlGraph.RECIPE &&
            spec.fragmentBinding?.resources?.containsKey("fragments/v3/canonical/${if (r10) "r10" else "r9"}/index.yaml") == true &&
            spec.processes.size == (if (r10) 134 else 133) &&
            spec.processes.count { !it.oneShot } == 79 &&
            NotebookSelectedGraph.selected(GenerationRuntime.BASE.resolve(request.id), spec) &&
            plan.summary.members.single().specSha256 == ReleaseLocks.sha256(specJson.encodeToString(spec).toByteArray()))
        val rows = forecastRows(spec)
        require(rows.map { it.process }.distinct().size == rows.size && rows.size == spec.processes.size &&
            listOf("alice", "bob").all { id -> rows.single { it.process.endsWith("/$id") }.prospectiveMiB == 2048L })
        val aux = GenerationManagedComponents.memoryReservationMiB(request)
        val extraDisk = GenerationManagedComponents.diskReservationMiB(request)
        val state = request.diskReservationMiB
        val scratch = maxOf(1024L, state) // Until a real bounded capture/import size is sealed.
        val available = observedMemory()
        val usable = Files.getFileStore(PrivateDeployment.BASE).usableSpace / 1048576L
        val next = rows.maxOf { Math.addExact(it.hardCeilingMiB, 512L) }
        // Reserve target and retained isolated source state, bounded backup/capture
        // scratch, selected auxiliary disk and owner margin before first use.
        // The later RESTORE phase still needs a fresh, separate native admission.
        val isolatedRestoreDisk = Math.multiplyExact(state, 2L)
        val prospectiveDiskOverlap = Math.addExact(isolatedRestoreDisk,
            Math.addExact(extraDisk, Math.addExact(scratch, 512L)))
        require(available >= Math.addExact(request.memoryHeadroomMiB, Math.addExact(next, aux)) &&
            usable >= Math.addExact(request.diskHeadroomMiB, prospectiveDiskOverlap)) {
            "Current host cannot safely admit the next full-family first-start step and source state; no eviction or cap cut"
        }
        val (index, manifest) = source(request.id)
        return GenerationFirstStartEnvelope(scope = if (r10) "r10-complete-private-first-start-prospective-not-rss" else
            "r9-complete-private-first-start-prospective-not-rss",
            generation = request.id, candidateSha256 = request.releaseCandidateSha256,
            indexSha256 = index, manifestSha256 = manifest,
            selectedSpecSha256 = ReleaseLocks.sha256(specJson.encodeToString(spec).toByteArray()),
            predecessorDisposition = request.predecessorDisposition,
            memberPredecessorDisposition = request.memberPredecessorDisposition,
            abandonedPreparation = request.abandonedPreparation,
            preparedNoStartPredecessor = if (request.id in setOf(afterPreUnit,GenerationAfterNativeImportLineage.generation,
                GenerationAfterCapacityRefusalLineage.generation,GenerationAfterQ273Lineage.generation,
                GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
                GenerationAfterQ07Lineage.generation)) request.preparedNoStartPredecessor else null,
            failedPreUnitStagePredecessor = if (request.id in setOf(afterPreUnit,GenerationAfterNativeImportLineage.generation,
                GenerationAfterCapacityRefusalLineage.generation,GenerationAfterQ273Lineage.generation,
                GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
                GenerationAfterQ07Lineage.generation)) request.failedPreUnitStagePredecessor else null,
            uncertainNativeImportPredecessor = if (request.id in setOf(GenerationAfterNativeImportLineage.generation,
                GenerationAfterCapacityRefusalLineage.generation,GenerationAfterQ273Lineage.generation,
                GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
                GenerationAfterQ07Lineage.generation)) request.uncertainNativeImportPredecessor else null,
            isolatedRootlessProbePredecessor = if (request.id in setOf(GenerationAfterNativeImportLineage.generation,
                GenerationAfterCapacityRefusalLineage.generation,GenerationAfterQ273Lineage.generation,
                GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
                GenerationAfterQ07Lineage.generation)) request.isolatedRootlessProbePredecessor else null,
            qc3PreparedNoStartPredecessor = if (request.id in setOf(GenerationAfterCapacityRefusalLineage.generation,
                GenerationAfterQ273Lineage.generation,GenerationAfterQ583Lineage.generation,
                GenerationAfterQ9bLineage.generation,GenerationAfterQ07Lineage.generation))
                request.qc3PreparedNoStartPredecessor else null,
            q273UncertainImportPredecessor = if (request.id in setOf(GenerationAfterQ273Lineage.generation,
                GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
                GenerationAfterQ07Lineage.generation)) request.q273UncertainImportPredecessor else null,
            q583PreparedNoStartPredecessor = if (request.id in setOf(GenerationAfterQ583Lineage.generation,
                GenerationAfterQ9bLineage.generation,GenerationAfterQ07Lineage.generation))
                request.q583PreparedNoStartPredecessor else null,
            isolatedFullWorklanePreparePredecessor = if (request.id in setOf(GenerationAfterQ583Lineage.generation,
                GenerationAfterQ9bLineage.generation,GenerationAfterQ07Lineage.generation))
                request.isolatedFullWorklanePreparePredecessor else null,
            q9bColdPreparedUninstalledPredecessor = if (request.id in setOf(GenerationAfterQ9bLineage.generation,
                GenerationAfterQ07Lineage.generation)) request.q9bColdPreparedUninstalledPredecessor else null,
            q07PartialInstalledPredecessor = if (request.id==GenerationAfterQ07Lineage.generation)
                request.q07PartialInstalledPredecessor else null,
            observedMemAvailableMiB = available, observedUsableDiskMiB = usable,
            memoryFloorMiB = request.memoryHeadroomMiB, diskFloorMiB = request.diskHeadroomMiB,
            prospectiveRows = rows,
            diagnosticSumOfSteadyForecastMiBNotRssOrReservation = rows.filterNot { it.oneShot }.sumOf { it.prospectiveMiB },
            initialBothNotebookBootstrapMiB = 4096,
            largestNextOriginalCeilingPlusOwnerMarginMiB = next,
            selectedRssCiManagedAuxiliaryMiB = aux,
            rootfulStateAndSelectedAuxiliaryDiskMiB = Math.addExact(state, extraDisk),
            backupAndRestoreScratchDiskMiB = scratch,
            isolatedRestoreSourceAndTargetStateDiskMiB = isolatedRestoreDisk)
    }
    /** One-use producer. Input plan has no budget; return value is inserted into
     * the SAME assembly request for subsequent owned preparation. No runtime
     * process, image, identity, old state or deployment is touched here. */
    fun issue(plan: AssemblyPlan): GenerationWorkingBudget = ReleasePrivateFiles.locked(anchor.parent) {
        val record = model(plan)
        if (!Files.exists(anchor, NOFOLLOW_LINKS)) {
            Files.createDirectory(anchor, PosixFilePermissions.asFileAttribute(perms))
            ReleasePrivateFiles.sync(anchor.parent)
        }
        ReleasePrivateFiles.directory(anchor)
        val root = anchor.resolve(record.generation)
        val previous=Files.exists(root,NOFOLLOW_LINKS)
        if (record.generation in setOf(GenerationAfterCapacityRefusalLineage.generation,
                GenerationAfterQ273Lineage.generation,GenerationAfterQ583Lineage.generation,
                GenerationAfterQ9bLineage.generation,GenerationAfterQ07Lineage.generation)) {
            require(!previous && record.abandonedPreparation!=null &&
                record.qc3PreparedNoStartPredecessor==GenerationAfterCapacityRefusalLineage.qc3 &&
                record.q273UncertainImportPredecessor==(if(record.generation in setOf(GenerationAfterQ273Lineage.generation,
                    GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
                    GenerationAfterQ07Lineage.generation)) GenerationAfterQ273Lineage.predecessor else null) &&
                record.q583PreparedNoStartPredecessor==(if(record.generation in setOf(GenerationAfterQ583Lineage.generation,
                    GenerationAfterQ9bLineage.generation,GenerationAfterQ07Lineage.generation))
                    GenerationAfterQ583Lineage.predecessor else null) &&
                record.isolatedFullWorklanePreparePredecessor==(if(record.generation in setOf(GenerationAfterQ583Lineage.generation,
                    GenerationAfterQ9bLineage.generation,GenerationAfterQ07Lineage.generation))
                    GenerationAfterQ583Lineage.isolatedFullPrepare else null) &&
                record.q9bColdPreparedUninstalledPredecessor==(if(record.generation in setOf(GenerationAfterQ9bLineage.generation,
                    GenerationAfterQ07Lineage.generation)) GenerationAfterQ9bLineage.predecessor else null) &&
                record.q07PartialInstalledPredecessor==(if(record.generation==GenerationAfterQ07Lineage.generation)
                    GenerationAfterQ07Lineage.predecessor else null) && record.prospectiveRows.size==134)
            Files.createDirectory(root,PosixFilePermissions.asFileAttribute(perms))
            ReleasePrivateFiles.sync(anchor)
            val file=root.resolve("envelope.json")
            val bytes=json.encodeToString(record).toByteArray()
            ReleasePrivateFiles.save(file,bytes)
            return@locked GenerationWorkingBudget(ActivationInput(file.toString(),ReleaseLocks.sha256(bytes)),
                record.prospectiveRows.associate { it.process to it.prospectiveMiB },successorScope)
        }
        if (record.generation == GenerationAfterNativeImportLineage.generation) {
            require(previous && record.abandonedPreparation!=null && record.prospectiveRows.size==134)
            ReleasePrivateFiles.directory(root)
            val oldBytes=ReleasePrivateFiles.read(root.resolve("envelope.json"),4194304)
            val prior=json.decodeFromString<GenerationFirstStartEnvelope>(oldBytes.decodeToString(throwOnInvalidSequence=true))
            require(ReleaseLocks.sha256(oldBytes)=="e4d9f447fb7807af3beb05e6e3773269cd50ff0d74552c2de8c10ae1a8f7998b" &&
                prior.generation==record.generation &&
                prior.candidateSha256=="fb612091f1709e885f8b6ace64f841a0f36b70ceb5e0ba37a5b04d1f06733408" &&
                prior.uncertainNativeImportPredecessor==record.uncertainNativeImportPredecessor &&
                prior.isolatedRootlessProbePredecessor==record.isolatedRootlessProbePredecessor &&
                record.candidateSha256!=prior.candidateSha256)
            val file=root.resolve("envelope-v2.json")
            require(!Files.exists(file,NOFOLLOW_LINKS) &&
                !Files.exists(GenerationRuntime.BASE.resolve(record.generation),NOFOLLOW_LINKS))
            val bytes=json.encodeToString(record).toByteArray()
            ReleasePrivateFiles.save(file,bytes)
            return@locked GenerationWorkingBudget(ActivationInput(file.toString(),ReleaseLocks.sha256(bytes)),
                record.prospectiveRows.associate { it.process to it.prospectiveMiB },successorScope)
        }
        if (record.generation == afterPreUnit) {
            require(!previous && record.abandonedPreparation!=null && record.prospectiveRows.size==134)
            Files.createDirectory(root,PosixFilePermissions.asFileAttribute(perms))
            ReleasePrivateFiles.sync(anchor)
            val file=root.resolve("envelope.json")
            val bytes=json.encodeToString(record).encodeToByteArray()
            ReleasePrivateFiles.save(file,bytes)
            return@locked GenerationWorkingBudget(ActivationInput(file.toString(),ReleaseLocks.sha256(bytes)),
                record.prospectiveRows.associate { it.process to it.prospectiveMiB },successorScope)
        }
        if (record.generation == freshSuccessor) {
            require(record.abandonedPreparation!=null && record.prospectiveRows.size==134)
            val file=if(previous) {
                ReleasePrivateFiles.directory(root)
                val v2=root.resolve("envelope-v2.json")
                val continued=Files.exists(v2,NOFOLLOW_LINKS)
                val priorBytes=ReleasePrivateFiles.read(if(continued) v2 else root.resolve("envelope.json"),4194304)
                val prior=json.decodeFromString<GenerationFirstStartEnvelope>(
                    priorBytes.decodeToString(throwOnInvalidSequence=true))
                require(prior.generation==freshSuccessor && prior.candidateSha256==
                    (if(continued) "913dbaa2970459116c513b4398d2f9ddd94e4b4b47da096101e9df8a7b7756c0" else
                        "ca5495b01a8192db33802f3131c5c6bd3be3512564ac999a6959c2aa5512f653") &&
                    prior.prospectiveRows.size==134 && prior.candidateSha256!=record.candidateSha256 &&
                    !Files.exists(root.resolve("envelope-v3.json"),NOFOLLOW_LINKS))
                root.resolve(if(continued) "envelope-v3.json" else "envelope-v2.json")
            } else {
                Files.createDirectory(root,PosixFilePermissions.asFileAttribute(perms))
                ReleasePrivateFiles.sync(anchor)
                root.resolve("envelope.json")
            }
            val bytes=json.encodeToString(record).toByteArray()
            ReleasePrivateFiles.save(file,bytes)
            return@locked GenerationWorkingBudget(ActivationInput(file.toString(),ReleaseLocks.sha256(bytes)),
                record.prospectiveRows.associate { it.process to it.prospectiveMiB },successorScope)
        }
        if (record.generation == successor) {
            require(previous) { "Successor requires its retained r9 source envelope" }
            ReleasePrivateFiles.directory(root)
            val v2 = root.resolve("envelope-v2.json")
            val continued = Files.exists(v2, NOFOLLOW_LINKS)
            val file = root.resolve(if (continued) "envelope-v3.json" else "envelope-v2.json")
            require(!Files.exists(file, NOFOLLOW_LINKS)) { "Successor envelope revision already attempted" }
            val oldBytes = ReleasePrivateFiles.read(if (continued) v2 else root.resolve("envelope.json"), 4194304)
            val prior = json.decodeFromString<GenerationFirstStartEnvelope>(oldBytes.decodeToString(throwOnInvalidSequence=true))
            require(ReleaseLocks.sha256(oldBytes) == (if (continued)
                "02b4ef3543a991789344e93959c4e68e3999dae98dfff2650f0d60fb6916680c" else
                "553df60a8d355488bd7b3b32119da6e9b42acc6295d1d9a44b958d4158b1dce8"))
            require(prior.generation == successor && prior.candidateSha256 == (if (continued)
                "453cb671b681aa65b35e0d699882eced9ee73a9c1c0bed1e6f07d480aa65a245" else
                "3703b5fcfbfdf2ee1a66944e4d62c14b341a9a38f0f7d312901ef9f6942f5c78"))
            require(prior.scope == (if (continued) "r10-complete-private-first-start-prospective-not-rss" else
                "r9-complete-private-first-start-prospective-not-rss"))
            require(prior.prospectiveRows.size == (if (continued) 134 else 133))
            require(record.abandonedPreparation != null &&
                prior.abandonedPreparation?.copy(correctedOwnershipSourceSha256 =
                    record.abandonedPreparation.correctedOwnershipSourceSha256) == record.abandonedPreparation &&
                record.candidateSha256 != prior.candidateSha256 && record.prospectiveRows.size == 134)
            val bytes = json.encodeToString(record).toByteArray()
            ReleasePrivateFiles.save(file, bytes)
            return@locked GenerationWorkingBudget(ActivationInput(file.toString(), ReleaseLocks.sha256(bytes)),
                record.prospectiveRows.associate { it.process to it.prospectiveMiB }, successorScope)
        }
        val continuation = previous && Files.exists(root.resolve("envelope-v2.json"), NOFOLLOW_LINKS)
        val nextRevision = continuation && Files.exists(root.resolve("envelope-v3.json"), NOFOLLOW_LINKS)
        val memberRevision = nextRevision && Files.exists(root.resolve("envelope-v4.json"),NOFOLLOW_LINKS)
        if (previous) {
            ReleasePrivateFiles.directory(root)
            val prior=json.decodeFromString<GenerationFirstStartEnvelope>(ReleasePrivateFiles.read(root.resolve(
                if (memberRevision) "envelope-v4.json" else if (nextRevision) "envelope-v3.json" else if (continuation) "envelope-v2.json" else "envelope.json"),4194304)
                .decodeToString(throwOnInvalidSequence=true))
            if (continuation) {
                require(prior.generation==record.generation &&
                    prior.candidateSha256==(if (memberRevision)
                        "49ea46615e661cbc31394e9e97187685f5918951989eb8fe297975efbb7d5e9a"
                    else if (nextRevision) "91520dae277383db91239a00467b7d936c755a78e373786e6715e1d0d93b00de"
                    else GenerationCiPreEffectContinuation.ORIGINAL_CONTROLLER) &&
                    record.candidateSha256!=prior.candidateSha256 &&
                    record.predecessorDisposition != null &&
                    (!memberRevision || record.memberPredecessorDisposition != null) &&
                    !Files.exists(root.resolve(if (memberRevision) "envelope-v5.json" else if (nextRevision) "envelope-v4.json" else "envelope-v3.json"),NOFOLLOW_LINKS))
                GenerationCiPreEffectContinuation.verify(
                    GenerationRuntime.BASE.resolve(record.generation), record.predecessorDisposition)
                if (memberRevision) GenerationCiMemberPreEffectContinuation.verify(
                    GenerationRuntime.BASE.resolve(record.generation), requireNotNull(record.memberPredecessorDisposition))
            } else require(prior.generation==record.generation &&
                prior.candidateSha256=="e07b40bcd887512cc1e2628621a3aed117688027a49d347cb92286837a63929f" &&
                record.candidateSha256!=prior.candidateSha256 &&
                record.predecessorDisposition == null &&
                !Files.exists(root.resolve("envelope-v2.json"),NOFOLLOW_LINKS)) {
                "Prior envelope remains immutable; one distinct candidate revision only"
            }
        } else {
            Files.createDirectory(root, PosixFilePermissions.asFileAttribute(perms))
            ReleasePrivateFiles.sync(anchor)
        }
        val file = root.resolve(if(memberRevision) "envelope-v5.json" else if(nextRevision) "envelope-v4.json" else if(continuation) "envelope-v3.json" else if(previous) "envelope-v2.json" else "envelope.json")
        val bytes = json.encodeToString(record).toByteArray()
        ReleasePrivateFiles.save(file, bytes)
        GenerationWorkingBudget(ActivationInput(file.toString(), ReleaseLocks.sha256(bytes)),
            record.prospectiveRows.associate { it.process to it.prospectiveMiB }, scope)
    }
    /** Admission reopens the original evidence; a caller cannot supply a map
     * of unexplained lower numbers or change source pins after issuance. Current
     * host measurements are *rechecked* at actual owner stage, never replayed. */
    fun verify(request: GenerationRequest, specs: List<PrivateDeploymentSpec>) {
        val budget = requireNotNull(request.workingBudget)
        require(budget.scope == (if (r10(request.id)) successorScope else scope))
        require(budget.evidence.path in (if (request.id == afterPreUnit)
            setOf(anchor.resolve(request.id).resolve("envelope.json").toString()) else if (request.id == freshSuccessor)
            setOf(anchor.resolve(request.id).resolve("envelope.json").toString(),
                anchor.resolve(request.id).resolve("envelope-v2.json").toString(),
                anchor.resolve(request.id).resolve("envelope-v3.json").toString()) else if (request.id == successor)
            setOf(anchor.resolve(request.id).resolve("envelope-v2.json").toString(),
                anchor.resolve(request.id).resolve("envelope-v3.json").toString()) else setOf(
            anchor.resolve(request.id).resolve("envelope.json").toString(),
            anchor.resolve(request.id).resolve("envelope-v2.json").toString(),
            anchor.resolve(request.id).resolve("envelope-v3.json").toString(),
            anchor.resolve(request.id).resolve("envelope-v4.json").toString(),
            anchor.resolve(request.id).resolve("envelope-v5.json").toString())))
        val bytes = ReleasePrivateFiles.read(Path.of(budget.evidence.path), 4194304)
        val evidence = json.decodeFromString<GenerationFirstStartEnvelope>(bytes.decodeToString(throwOnInvalidSequence = true))
        val (index, manifest) = source(request.id)
        require(ReleaseLocks.sha256(bytes) == budget.evidence.sha256 &&
            evidence.schemaVersion == 1 && evidence.scope == (if (r10(request.id))
                "r10-complete-private-first-start-prospective-not-rss" else
                "r9-complete-private-first-start-prospective-not-rss") &&
            evidence.generation == request.id && evidence.candidateSha256 == request.releaseCandidateSha256 &&
            evidence.predecessorDisposition == request.predecessorDisposition &&
            evidence.memberPredecessorDisposition == request.memberPredecessorDisposition &&
            evidence.abandonedPreparation == request.abandonedPreparation &&
            evidence.preparedNoStartPredecessor == (if (request.id in setOf(afterPreUnit,GenerationAfterNativeImportLineage.generation,
                GenerationAfterCapacityRefusalLineage.generation,GenerationAfterQ273Lineage.generation,
                GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
                GenerationAfterQ07Lineage.generation)) request.preparedNoStartPredecessor else null) &&
            evidence.failedPreUnitStagePredecessor == (if (request.id in setOf(afterPreUnit,GenerationAfterNativeImportLineage.generation,
                GenerationAfterCapacityRefusalLineage.generation,GenerationAfterQ273Lineage.generation,
                GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
                GenerationAfterQ07Lineage.generation)) request.failedPreUnitStagePredecessor else null) &&
            evidence.uncertainNativeImportPredecessor == (if (request.id in setOf(GenerationAfterNativeImportLineage.generation,
                GenerationAfterCapacityRefusalLineage.generation,GenerationAfterQ273Lineage.generation,
                GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
                GenerationAfterQ07Lineage.generation)) request.uncertainNativeImportPredecessor else null) &&
            evidence.isolatedRootlessProbePredecessor == (if (request.id in setOf(GenerationAfterNativeImportLineage.generation,
                GenerationAfterCapacityRefusalLineage.generation,GenerationAfterQ273Lineage.generation,
                GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
                GenerationAfterQ07Lineage.generation)) request.isolatedRootlessProbePredecessor else null) &&
            evidence.qc3PreparedNoStartPredecessor == (if (request.id in setOf(GenerationAfterCapacityRefusalLineage.generation,
                GenerationAfterQ273Lineage.generation,GenerationAfterQ583Lineage.generation,
                GenerationAfterQ9bLineage.generation,GenerationAfterQ07Lineage.generation))
                request.qc3PreparedNoStartPredecessor else null) &&
            evidence.q273UncertainImportPredecessor == (if (request.id in setOf(GenerationAfterQ273Lineage.generation,
                GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
                GenerationAfterQ07Lineage.generation)) request.q273UncertainImportPredecessor else null) &&
            evidence.q583PreparedNoStartPredecessor == (if (request.id in setOf(GenerationAfterQ583Lineage.generation,
                GenerationAfterQ9bLineage.generation,GenerationAfterQ07Lineage.generation))
                request.q583PreparedNoStartPredecessor else null) &&
            evidence.isolatedFullWorklanePreparePredecessor == (if (request.id in setOf(GenerationAfterQ583Lineage.generation,
                GenerationAfterQ9bLineage.generation,GenerationAfterQ07Lineage.generation))
                request.isolatedFullWorklanePreparePredecessor else null) &&
            evidence.q9bColdPreparedUninstalledPredecessor == (if (request.id in setOf(GenerationAfterQ9bLineage.generation,
                GenerationAfterQ07Lineage.generation)) request.q9bColdPreparedUninstalledPredecessor else null) &&
            evidence.q07PartialInstalledPredecessor == (if (request.id==GenerationAfterQ07Lineage.generation)
                request.q07PartialInstalledPredecessor else null) &&
            evidence.indexSha256 == index && evidence.manifestSha256 == manifest && specs.size == 1 &&
            evidence.selectedSpecSha256 == ReleaseLocks.sha256(specJson.encodeToString(specs.single()).toByteArray()) &&
            evidence.prospectiveRows == forecastRows(specs.single()) &&
            evidence.prospectiveRows.associate { it.process to it.prospectiveMiB } == budget.workingMiB &&
            evidence.memoryFloorMiB == request.memoryHeadroomMiB && evidence.diskFloorMiB == request.diskHeadroomMiB &&
            evidence.selectedRssCiManagedAuxiliaryMiB == GenerationManagedComponents.memoryReservationMiB(request) &&
            evidence.rootfulStateAndSelectedAuxiliaryDiskMiB == Math.addExact(request.diskReservationMiB,
                GenerationManagedComponents.diskReservationMiB(request)) &&
            evidence.largestNextOriginalCeilingPlusOwnerMarginMiB == specs.single().processes.maxOf {
                Math.addExact(it.memoryMiB.toLong(), 512L) } &&
            evidence.initialBothNotebookBootstrapMiB == 4096L &&
            evidence.futureKopiaMemoryMinimumMiB >= 1024 &&
            evidence.backupAndRestoreScratchDiskMiB >= request.diskReservationMiB &&
            evidence.isolatedRestoreSourceAndTargetStateDiskMiB == Math.multiplyExact(request.diskReservationMiB,2L) &&
            evidence.observedMemAvailableMiB >= request.memoryHeadroomMiB +
                evidence.largestNextOriginalCeilingPlusOwnerMarginMiB + evidence.selectedRssCiManagedAuxiliaryMiB &&
            evidence.observedUsableDiskMiB >= request.diskHeadroomMiB +
                evidence.rootfulStateAndSelectedAuxiliaryDiskMiB + evidence.backupAndRestoreScratchDiskMiB + 512 &&
            evidence.currentHostAndRootlessLoadIncludedInMemAvailable && !evidence.priorFreshR9RssRequired &&
            !evidence.oldStateUsedAsInput && evidence.nativeStageAndPhaseRecheckRequired)
    }
}
