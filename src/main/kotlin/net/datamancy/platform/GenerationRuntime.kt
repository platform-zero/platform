package net.datamancy.platform

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions
import com.sun.security.auth.module.UnixSystem
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

@Serializable internal data class GenerationMember(val name: String, val dependencies: List<String> = emptyList())
@Serializable internal data class GenerationRequest(val schemaVersion: Int = 1, val id: String,
    val candidateSha256: String, val members: List<GenerationMember>, val diskReservationMiB: Long,
    val memoryHeadroomMiB: Long = 16384, val diskHeadroomMiB: Long = 10240,
    val purpose: String = "private-component-integration",
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val store: RuntimeStore = RuntimeStore.LEGACY,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val releaseCandidateSha256: String? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val rssPlan: GenerationRssPlan? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val managedLanes: ManagedLanePlan? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val forgejoCi: ForgejoCiSourcePlan? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val baoBootstrapOperation: GenerationFreshBaoOperation? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val recoveredBaoOriginal: ActivationInput? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val recoveredForgejoCi: ForgejoCiSourcePlan? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val ciRecoveryGrant: ForgejoCiRecoveryGrant? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val recoveredForgejoCiTarget: ForgejoCiSourcePlan? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val recoveredRssPlan: GenerationRssPlan? = null,
    /** Original payload budget, distinct from retained import/readback scratch. Never compounds on recovery. */
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val recoveryStateReservationMiB: Long? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val gatewayDenialProducer: OriginalGatewayDenialProducer? = null,
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
    val q07PartialInstalledPredecessor: ActivationInput? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val freshPlankaActorGrant: ActivationInput? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val workingBudget: GenerationWorkingBudget? = null)
@Serializable internal data class GenerationPin(val member: GenerationMember, val manifestSha256: String,
    val inputHashes: Map<String, String>, val runtimeFingerprint: String, val spec: PrivateDeploymentSpec)
@Serializable internal data class GenerationBundle(val request: GenerationRequest, val members: List<GenerationPin>,
    val memoryReservationMiB: Long, val assemblySha256: String? = null, val recoverySourceArchiveSha256: String? = null,
    val ownership: BoundSiteOwnership? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val recoverySourceKopia: KopiaSnapshotReceipt? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val ownedUpdate: OwnedUpdateLineage? = null)
@Serializable internal data class GenerationIntent(val action: String, val bundleSha256: String,
    val priorIntentSha256: String? = null)
@Serializable internal data class GenerationOutcome(val action: String, val bundleSha256: String,
    val passed: Boolean, val failureType: String? = null, val fences: Map<String, String> = emptyMap(),
    val priorIntentSha256: String? = null)
@Serializable internal data class GenerationCapacity(val availableMemoryMiB: Long, val usableDiskMiB: Long,
    val availableRuntimeLocks: Long = Long.MAX_VALUE)
@Serializable internal data class GenerationInspection(val id: String, val bundleSha256: String,
    val memoryReservationMiB: Long, val members: List<RuntimeAudit>, val publicActivation: Boolean = false,
    val fullStackQualification: Boolean = false)

internal object GenerationColdCaptureAdmission {
    fun requireSupported(bundle: GenerationBundle) {
        require(bundle.members.isNotEmpty() && bundle.members.all {
            it.spec.executionBackend == RuntimeExecutionBackend.DIRECT_PODMAN_V1
        }) { "Quadlet cold capture backend unavailable; no Kopia pending operation created" }
    }
}

internal interface GenerationBackend {
    fun audit(spec: PrivateDeploymentSpec, pristine: Boolean): RuntimeAudit
    fun apply(spec: PrivateDeploymentSpec): List<RuntimeStatus>
    fun isolate(spec: PrivateDeploymentSpec): String
}

/**
 * Live private-generation lifecycle, NOT the complete release transaction backend.
 * It never deletes volumes, releases historical isolation fences, enables boot units or publishes routes/outbound jobs.
 * Routine backup can release only its own freshly acquired temporary fences under an operation lease.
 */
internal class GenerationRuntime(private val base: Path, private val runtimeBase: Path,
    private val backend: (Map<String, String>) -> GenerationBackend,
    private val capacity: (RuntimeStore) -> GenerationCapacity,
    private val rssSchedule: (Path) -> RssSchedule = { RssSchedule.real(it) },
    private val retiredCensus: RuntimeCapacityCensus = RuntimeCapacityCensus()) {
    companion object {
        val BASE: Path = Path.of("/mnt/media/p0-v3/release-generations")
        private val json = Json { ignoreUnknownKeys = false; encodeDefaults = true }
        private val id = Regex("q-[a-f0-9]{12}")
        private val hash = Regex("[a-f0-9]{64}")
        private val privateDir = PosixFilePermissions.fromString("rwx------")
        private val privateFile = PosixFilePermissions.fromString("rw-------")
        fun real() = GenerationRuntime(BASE, PrivateDeployment.BASE, { bindings -> NativeGenerationBackend(bindings) }, { store ->
            val mem = Files.readAllLines(Path.of("/proc/meminfo")).single { it.startsWith("MemAvailable:") }
                .trim().split(Regex("\\s+"))
            require(mem.size == 3 && mem[2] == "kB") { "Unknown available-memory measurement" }
            GenerationCapacity(mem[1].toLong() / 1024, Files.getFileStore(PrivateDeployment.BASE).usableSpace / 1048576,
                RuntimeLockBudget.available(PrivateRootfulCommands(store = store), store))
        })
        fun validateScope(request: GenerationRequest): List<GenerationMember> = Scope.ordered(request)
        fun request(path: Path): GenerationRequest = json.decodeFromString(privateInput(path).decodeToString(throwOnInvalidSequence = true))
        fun privateInput(path: Path): ByteArray {
            val file = path.toAbsolutePath().normalize()
            require(file.toRealPath() == file && (Files.getAttribute(file, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == UnixSystem().uid &&
                (Files.getAttribute(file, "unix:nlink", NOFOLLOW_LINKS) as Number).toInt() == 1) { "Owned single-link request required" }
            return ReleaseLocks.privateBytes(file)
        }
    }

    private fun directory(path: Path) {
        require(path.isAbsolute && path.normalize() == path && path.toRealPath() == path &&
            Files.isDirectory(path, NOFOLLOW_LINKS) && Files.getPosixFilePermissions(path) == privateDir &&
            (Files.getAttribute(path, "unix:uid") as Number).toLong() == UnixSystem().uid) { "Owned private generation directory required" }
    }
    private fun data(path: Path): ByteArray {
        require(path.toRealPath() == path && (Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == UnixSystem().uid &&
            (Files.getAttribute(path, "unix:nlink", NOFOLLOW_LINKS) as Number).toInt() == 1) { "Owned unlinked generation input required" }
        return ReleaseLocks.privateBytes(path)
    }
    private fun save(path: Path, text: String) = save(path, text.toByteArray())
    private fun save(path: Path, encoded: ByteArray) {
        require(encoded.size in 1..1048576) { "Generation record exceeds bound" }
        FileChannel.open(path, setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS), PosixFilePermissions.asFileAttribute(privateFile)).use {
            val bytes = ByteBuffer.wrap(encoded)
            while (bytes.hasRemaining()) it.write(bytes)
            it.force(true)
        }
        FileChannel.open(path.parent, READ).use { it.force(true) }
    }
    private val generationLockHeld = ThreadLocal.withInitial { false }
    private val mutationHeld = ThreadLocal.withInitial { false }
    private fun <T> locked(action: () -> T): T {
        require(base.isAbsolute && base.normalize() == base && base.parent.toRealPath() == base.parent &&
            (Files.getAttribute(base.parent, "unix:uid") as Number).toLong() == UnixSystem().uid &&
            Files.getPosixFilePermissions(base.parent).none { it.name == "GROUP_WRITE" || it.name == "OTHERS_WRITE" }) {
            "Protected generation parent required"
        }
        if (!Files.exists(base, NOFOLLOW_LINKS)) Files.createDirectory(base, PosixFilePermissions.asFileAttribute(privateDir))
        directory(base)
        if (generationLockHeld.get()) return action() // Same instance/thread, never a second file lock.
        val lock = base.resolve("generation.lock")
        return JvmNativeLockGate.with(lock) {
            FileChannel.open(lock, setOf(CREATE, READ, WRITE, NOFOLLOW_LINKS), PosixFilePermissions.asFileAttribute(privateFile)).use { channel ->
                require(Files.getPosixFilePermissions(lock) == privateFile &&
                    (Files.getAttribute(lock, "unix:uid") as Number).toLong() == UnixSystem().uid &&
                    (Files.getAttribute(lock, "unix:nlink") as Number).toInt() == 1) { "Unsafe generation lock" }
                channel.lock().use {
                    generationLockHeld.set(true)
                    try { action() } finally { generationLockHeld.remove() }
                }
            }
        }
    }
    private fun <T> mutating(action: () -> T): T {
        if (mutationHeld.get()) {
            require(generationLockHeld.get()) { "Nested mutation lost its generation exclusion lock" }
            return action() // RSS + generation lock and original deadline remain held by this thread.
        }
        require(!generationLockHeld.get()) { "Cannot acquire RSS exclusion beneath an observation-only generation lock" }
        return RecoveryDeadline.within {
            GenerationRssOperations(base, rssSchedule).withExclusion {
                locked {
                    mutationHeld.set(true)
                    try { action() } finally { mutationHeld.remove() }
                }
            }
        }
    }

    /** Read-only locked preflight. A native observation is NOT a terminal ACK. */
    fun observeFailedPreparation(generation:String,census:ActivationInput):PreparationTerminalDisposition = mutating {
        require(base==BASE && runtimeBase==PrivateDeployment.BASE && generation.matches(id) &&
            census.sha256.matches(hash))
        val root=base.resolve(generation)
        directory(root)
        GenerationPreparationTerminalDisposition.observe(root,census)
    }

    /** Differential read-only terminal observation, no attempted effect. */
    fun observeFailedPreparationPair(generation:String,census:ActivationInput):
        Pair<PreparationTerminalDisposition,PreparationTerminalDisposition> = mutating {
        require(base==BASE && runtimeBase==PrivateDeployment.BASE && generation.matches(id) &&
            census.sha256.matches(hash))
        val root=base.resolve(generation)
        directory(root)
        GenerationPreparationTerminalDisposition.observePair(root,census)
    }

    /** Independently close an unsealed failed preparation. This is a native
     * read-only absence census and a one-use disposition, not a preparation
     * retry, successful result or permission to transplant member inputs. */
    fun terminalizeFailedPreparation(generation:String,census:ActivationInput):PreparationTerminalDisposition = mutating {
        require(base==BASE && runtimeBase==PrivateDeployment.BASE && generation.matches(id) &&
            census.sha256.matches(hash))
        val root=base.resolve(generation)
        directory(root)
        GenerationPreparationTerminalDisposition.record(root,census)
    }

    /** Separately records an attempted v2 pre-effect refusal. NOT terminal
     * success: this cannot un-fence inventory, identity or a fresh request. */
    fun recordFailedPreparationV2PreEffect(generation:String,census:ActivationInput,
        refusalLog:ActivationInput):PreparationTerminalV2PreEffectRefusal = mutating {
        require(base==BASE && runtimeBase==PrivateDeployment.BASE && generation.matches(id) &&
            listOf(census,refusalLog).all { it.sha256.matches(hash) })
        val root=base.resolve(generation)
        directory(root)
        GenerationPreparationTerminalDisposition.recordV2PreEffectRefusal(root,census,refusalLog)
    }

    /** Independent locked read-only verification of a separately passed
     * terminal record. Cannot create or amend any historical receipt. */
    fun verifyFailedPreparationTerminal(generation:String,census:ActivationInput,
        terminal:ActivationInput):PreparationTerminalDisposition = mutating {
        require(base==BASE && runtimeBase==PrivateDeployment.BASE && generation.matches(id) &&
            listOf(census,terminal).all { it.sha256.matches(hash) })
        val root=base.resolve(generation)
        directory(root)
        GenerationPreparationTerminalDisposition.verify(root,census,terminal)
    }

    /** Distinct one-use v3 journal after source+native-checked v2 refusal
     * disposition. No old member/controller/result is rewritten or retried. */
    fun terminalizeAfterV2PreEffect(generation:String,census:ActivationInput,
        refusal:ActivationInput):PreparationTerminalDisposition = mutating {
        require(base==BASE && runtimeBase==PrivateDeployment.BASE && generation.matches(id) &&
            listOf(census,refusal).all { it.sha256.matches(hash) })
        val root=base.resolve(generation)
        directory(root)
        GenerationPreparationTerminalDisposition.terminalizeAfterV2Refusal(root,census,refusal)
    }

    /** A *distinct* terminal operation after a separately evidenced false
     * original terminal result. Never replays the first intent. */
    fun reconcileFailedPreparationTerminal(generation:String,census:ActivationInput,
        priorIntent:ActivationInput,priorResult:ActivationInput):PreparationTerminalDisposition = mutating {
        require(base==BASE && runtimeBase==PrivateDeployment.BASE && generation.matches(id) &&
            listOf(census,priorIntent,priorResult).all { it.sha256.matches(hash) })
        val root=base.resolve(generation)
        directory(root)
        GenerationPreparationTerminalDisposition.reconcileFailed(root,census,priorIntent,priorResult)
    }

    fun issueManagedPiSubscriptionCustody(generation: String): String = mutating {
        require(base == BASE && generation == "q-5962a9fda75b" &&
            !Files.exists(base.resolve(generation), NOFOLLOW_LINKS))
        ManagedPiSubscriptionCustody.issue().also { require(ManagedPiSubscriptionCustody.verify() == it) }
    }
    fun issueManagedPiScriptRevision(generation: String): String = mutating {
        require(base == BASE && generation == "q-5962a9fda75b" &&
            !Files.exists(base.resolve(generation), NOFOLLOW_LINKS))
        ManagedPiSubscriptionCustody.issueScriptRevision()
    }
    fun verifyManagedPiSubscriptionCustody(generation: String): String = locked {
        require(base == BASE && generation == "q-5962a9fda75b")
        ManagedPiSubscriptionCustody.verify()
    }
    fun issueManagedPiRecoveryAuthority(source: String, target: String): ActivationInput = mutating {
        require(base == BASE && source == "q-5962a9fda75b" && target.matches(id))
        GenerationR9ManagedRecoveryAuthority.issue(source,target)
    }
    fun issueManagedPiSubscriptionPlan(generation: String, controller: String): ActivationInput = mutating {
        require(base == BASE && generation.matches(id))
        if (Files.exists(base.resolve(generation), NOFOLLOW_LINKS)) {
            val root = base.resolve(generation)
            if (Files.exists(root.resolve(GenerationCiMemberPreEffectContinuation.FILE),NOFOLLOW_LINKS))
                GenerationCiMemberPreEffectContinuation.verify(root,GenerationCiMemberPreEffectContinuation.binding(root),
                    beforeEffects=true)
            else GenerationCiPreEffectContinuation.verify(root, GenerationCiPreEffectContinuation.binding(root), beforeEffects = true)
        }
        GenerationR9ManagedPlan.issue(generation, controller)
    }

    /** Local-only age recipient is authorized before first Bao startup. This
     * never implies off-host owner receipt or an acknowledged Bao export. */
    fun issueLocalBaoRecipient(generation: String): ActivationInput = mutating {
        require(base == BASE && generation == "q-5962a9fda75b" &&
            !Files.exists(base.resolve(generation), NOFOLLOW_LINKS))
        OwnerRecoveryAgeIdentity.issue(generation).also {
            require(OwnerRecoveryAgeIdentity.verifyLocal(generation) == it)
        }
    }
    fun issueLocalBaoRecipientAfterInvalidRedirect(generation: String): ActivationInput = mutating {
        require(base == BASE && generation == "q-5962a9fda75b" &&
            !Files.exists(base.resolve(generation), NOFOLLOW_LINKS))
        OwnerRecoveryAgeIdentity.issueAfterInvalidRedirect(generation).also {
            require(OwnerRecoveryAgeIdentity.verifyLocal(generation) == it)
        }
    }
    /** First original local-only owner age source for a successor, not the
     * abandoned preparation's already-attempted v1 or v2 identity. */
    fun issueFreshLocalBaoRecipient(generation: String): ActivationInput = mutating {
        require(base == BASE && generation in setOf("q-5712d9335843", "q-dd36ebcf43ef", "q-4d3c1cb287e5", GenerationAfterNativeImportLineage.generation,
            GenerationAfterCapacityRefusalLineage.generation,GenerationAfterQ273Lineage.generation,
            GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
            GenerationAfterQ07Lineage.generation) &&
            !Files.exists(base.resolve(generation), NOFOLLOW_LINKS))
        GenerationPreparationTerminalDisposition.requireClosedForNewSource(generation)
        GenerationAfterNativeImportLineage.beforeSourceIssue(generation)
        GenerationAfterCapacityRefusalLineage.beforeSourceIssue(generation)
        GenerationAfterQ273Lineage.beforeSourceIssue(generation)
        GenerationAfterQ583Lineage.beforeSourceIssue(generation)
        GenerationAfterQ9bLineage.beforeSourceIssue(generation)
        GenerationAfterQ07Lineage.beforeSourceIssue(generation)
        OwnerRecoveryAgeIdentity.issueFreshV3(generation).also {
            require(OwnerRecoveryAgeIdentity.verifyLocal(generation) == it)
        }
    }
    fun verifyLocalBaoRecipient(generation: String): ActivationInput = locked {
        require(base == BASE && generation in setOf("q-5962a9fda75b", "q-5712d9335843", "q-dd36ebcf43ef", "q-4d3c1cb287e5", GenerationAfterNativeImportLineage.generation,
            GenerationAfterCapacityRefusalLineage.generation,GenerationAfterQ273Lineage.generation,
            GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
            GenerationAfterQ07Lineage.generation))
        OwnerRecoveryAgeIdentity.verifyLocal(generation)
    }

    /** Shared parent-controller exclusion for independently supervised managed-lane
     * operations. Never acquire an ad-hoc broker lock instead of the release's RSS,
     * generation and ordered native member locks. This does NOT grant an operation:
     * the caller must independently attest active ownership, identity and capacity.
     */
    fun <T> withManagedLaneControlLocks(bundle: GenerationBundle, action: () -> T): T = mutating {
        val generation = bundle.request.id
        require(id.matches(generation) && bundle.request.managedLanes != null &&
            base == BASE && bundle.request.store == RuntimeStore.CANONICAL_V2)
        val root = base.resolve(generation)
        require(root.toRealPath() == root && ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"))) ==
            ReleaseLocks.sha256(json.encodeToString(bundle).toByteArray()))
        GenerationRssOperations(base, rssSchedule).requireWritableGeneration(root)
        SiteOwnerships.checkSealed(bundle)
        PrivateDeployment.withOrderedNativeLocks(bundle.request.members.map { it.name }, runtimeBase) { action() }
    }

    /** Safe terminal-observation callback for a LOST Kopia outcome. The immutable
     * original worker create ACK is mandatory; the callback may produce separate
     * read-only evidence, never rewrite the original result or clear a pending fence.
     * Missing historical create ACKs remain unresolved, not reconstructed from ps.
     */
    fun <T> withKopiaTerminalReferenceExclusion(generation: String, expected: String,
        operationId: String, kind: String, action: (KopiaTerminalExclusion) -> T): T = mutating {
        require(base == BASE && runtimeBase == PrivateDeployment.BASE && kind in setOf("snapshot", "retention"))
        val (bundle, specs) = load(generation, expected, checkLiveInputs = false)
        require(bundle.request.store == RuntimeStore.CANONICAL_V2 && specs.isNotEmpty())
        PrivateDeployment.withOrderedNativeLocks(specs.map { it.name }, runtimeBase) {
            GenerationKopiaTerminalExclusion.withExcludedWriters(base.resolve(generation), generation,
                expected, operationId, kind,
                { RuntimeCapacityCensus().snapshot(RuntimeStore.CANONICAL_V2) }, action)
        }
    }

    private fun ordered(request: GenerationRequest): List<GenerationMember> = validateScope(request)

    private fun admitRecoveryScratch(request: GenerationRequest, measured: GenerationCapacity, copies: Int) {
        require(measured.usableDiskMiB >= request.diskHeadroomMiB) { "Insufficient protected recovery headroom" }
        // The helper includes the absolute floor; preserve any stricter caller headroom too.
        val extraHeadroom = maxOf(0L, Math.subtractExact(request.diskHeadroomMiB,
            RecoveryCapsule.PROTECTED_HEADROOM / 1048576L))
        val available = Math.multiplyExact(Math.subtractExact(measured.usableDiskMiB, extraHeadroom), 1048576L)
        RecoveryCapsule.admitScratch(request.recoveryStateReservationMiB ?: request.diskReservationMiB, copies, available)
    }

    internal object Scope {
    fun ordered(request: GenerationRequest): List<GenerationMember> {
        request.baoBootstrapOperation?.also { operation ->
            operation.validate(request.id)
            require(request.store == RuntimeStore.CANONICAL_V2 &&
                request.recoveryStateReservationMiB == null && request.recoveredBaoOriginal == null) {
                "Fresh Bao init authority cannot be projected into an isolated RESTORE target"
            }
        }
        request.recoveredBaoOriginal?.also { source ->
            require(request.baoBootstrapOperation == null && request.recoveryStateReservationMiB != null &&
                source.sha256.matches(Regex("[a-f0-9]{64}")) &&
                Path.of(source.path).normalize() == Path.of(source.path) &&
                source.path.matches(Regex("/mnt/media/p0-v3/release-generations/q-[a-f0-9]{12}/bao-custody/q-[a-f0-9]{12}-original-issuer\\.result\\.json"))) {
                "RESTORE Bao may reference only an original sealed result, never reinit"
            }
        }
        GenerationManagedComponents.validate(request)
        require(request.schemaVersion == 1 && id.matches(request.id) && hash.matches(request.candidateSha256) &&
            (request.releaseCandidateSha256 == null || hash.matches(request.releaseCandidateSha256)) &&
            request.purpose == "private-component-integration" && request.members.size in 1..64 &&
            request.memoryHeadroomMiB in 16384..1048576 && request.diskHeadroomMiB in 10240..10485760 &&
            request.diskReservationMiB in 1024..10485760) { "Invalid private generation scope or capacity policy" }
        require(request.recoveryStateReservationMiB == null ||
            request.recoveryStateReservationMiB in 1024..request.diskReservationMiB) { "Invalid original recovery payload reservation" }
        val members = request.members.associateBy { it.name }
        require(members.size == request.members.size && members.keys.all {
            it.startsWith("${request.id}-") && it.matches(Regex("q-[a-f0-9]{12}-[a-z][a-z0-9-]{0,23}")) && it.length <= 40
        }) { "Only fresh q-generation member namespaces are permitted" }
        val result = mutableListOf<GenerationMember>()
        val active = mutableSetOf<String>()
        val done = mutableSetOf<String>()
        fun visit(name: String) {
            if (name in done) return
            require(active.add(name)) { "Generation dependency cycle" }
            val member = members.getValue(name)
            require(member.dependencies.distinct().size == member.dependencies.size &&
                member.dependencies.all { it in members && it != name }) { "Invalid generation dependency" }
            member.dependencies.sorted().forEach(::visit)
            active.remove(name); done.add(name); result += member
        }
        members.keys.sorted().forEach(::visit)
        return result
    }
    }
    private fun pin(member: GenerationMember): Pair<GenerationPin, PrivateDeploymentSpec> {
        directory(runtimeBase)
        val manifest = data(runtimeBase.resolve("${member.name}.json"))
        val spec = Json.decodeFromString<PrivateDeploymentSpec>(manifest.decodeToString(throwOnInvalidSequence = true))
        require(spec.name == member.name) { "Foreign deployment manifest" }
        PrivateDeployment.validate(spec)
        val root = runtimeBase.resolve(spec.name)
        directory(root)
        val hashes = PrivateDeployment.inputNames(spec).associateWith { ReleaseLocks.sha256(data(root.resolve(it))) }
        return GenerationPin(member, ReleaseLocks.sha256(manifest), hashes, PrivateDeployment.expectedFingerprint(spec, hashes), spec) to spec
    }
    private fun reservation(specs: List<PrivateDeploymentSpec>, request: GenerationRequest): Long {
        val budget = request.workingBudget
        if (budget == null) return specs.sumOf { spec ->
            spec.processes.filterNot { it.oneShot }.sumOf { it.memoryMiB.toLong() } +
                (spec.processes.filter { it.oneShot }.maxOfOrNull { it.memoryMiB } ?: 0)
        }
        require(request.store == RuntimeStore.CANONICAL_V2 && request.releaseCandidateSha256 != null &&
            budget.evidence.path in setOf(
                "/mnt/media/p0-v3/release-bootstrap-anchors/workload/${request.id}/envelope.json",
                "/mnt/media/p0-v3/release-bootstrap-anchors/workload/${request.id}/envelope-v2.json",
                "/mnt/media/p0-v3/release-bootstrap-anchors/workload/${request.id}/envelope-v3.json",
                "/mnt/media/p0-v3/release-bootstrap-anchors/workload/${request.id}/envelope-v4.json",
                "/mnt/media/p0-v3/release-bootstrap-anchors/workload/${request.id}/envelope-v5.json") &&
            ReleaseLocks.sha256(privateInput(Path.of(budget.evidence.path))) == budget.evidence.sha256) {
            "Unsealed fresh whole-generation workload evidence"
        }
        if (budget.scope in setOf("r9-full-private-incremental-first-start",
                "r10-full-private-incremental-first-start"))
            GenerationWorkingEnvelopeIssuer.verify(request, specs)
        return GenerationCapacityPlanner.plan(specs,request.diskReservationMiB,budget).install.memoryMiB
    }
    private fun load(generation: String, expected: String, checkLiveInputs: Boolean = true): Pair<GenerationBundle, List<PrivateDeploymentSpec>> {
        require(id.matches(generation) && hash.matches(expected)) { "Invalid generation binding" }
        val root = base.resolve(generation); directory(root)
        val bytes = data(root.resolve("bundle.json"))
        require(ReleaseLocks.sha256(bytes) == expected) { "Generation bundle changed" }
        val bundle = json.decodeFromString<GenerationBundle>(bytes.decodeToString(throwOnInvalidSequence = true))
        if (checkLiveInputs && bundle.assemblySha256 != null) {
            val predecessor = bundle.request.predecessorDisposition
            val memberPredecessor = bundle.request.memberPredecessorDisposition
            val resultFile = if (memberPredecessor != null) GenerationCiMemberPreEffectContinuation.RESULT else
                if (predecessor == null) "assembly.result.json" else GenerationCiPreEffectContinuation.RESULT
            val intentFile = if (memberPredecessor != null) GenerationCiMemberPreEffectContinuation.INTENT else
                if (predecessor == null) "assembly.intent.json" else GenerationCiPreEffectContinuation.INTENT
            if (predecessor != null) GenerationCiPreEffectContinuation.verify(root, predecessor)
            if (memberPredecessor != null) GenerationCiMemberPreEffectContinuation.verify(root,memberPredecessor)
            val result = json.decodeFromString<AssemblyPreparationOutcome>(data(root.resolve(resultFile)).decodeToString())
            require(result.passed && result.bundleSha256 == expected && result.assemblySha256 == bundle.assemblySha256 &&
                bundle.assemblySha256 == ReleaseLocks.sha256(data(root.resolve(intentFile)))) { "Incomplete or foreign assembly preparation" }
        }
        require(bundle.request.id == generation) { "Foreign generation bundle" }
        bundle.request.abandonedPreparation?.let { lineage ->
            AbandonedPreparationLineages.inspect(generation,requireNotNull(bundle.request.releaseCandidateSha256),lineage)
        }
        if (generation == "q-4d3c1cb287e5") {
            val prior=ManagedPreUnitNoStartTerminal.verify(requireNotNull(bundle.request.failedPreUnitStagePredecessor))
            val image=GenerationNormalizedWorklaneImage.requireSelected(bundle.request.managedLanes?.native?.imageArchive)
            require(prior.predecessorPreparedNoStartSha256==
                requireNotNull(bundle.request.preparedNoStartPredecessor).sha256 &&
                prior.priorFailedPreparationTerminalSha256==
                requireNotNull(bundle.request.abandonedPreparation).terminal.sha256 &&
                image==bundle.request.managedLanes?.native?.imageArchive)
        } else if (generation !in setOf(GenerationAfterNativeImportLineage.generation,
                GenerationAfterCapacityRefusalLineage.generation,GenerationAfterQ273Lineage.generation,
                GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
                GenerationAfterQ07Lineage.generation))
            require(bundle.request.failedPreUnitStagePredecessor==null)
        if (generation in setOf(GenerationAfterNativeImportLineage.generation,
                GenerationAfterCapacityRefusalLineage.generation,GenerationAfterQ273Lineage.generation,
                GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
                GenerationAfterQ07Lineage.generation)) {
            GenerationAfterNativeImportLineage.verify(
                requireNotNull(bundle.request.uncertainNativeImportPredecessor),
                requireNotNull(bundle.request.isolatedRootlessProbePredecessor))
            val prior=ManagedPreUnitNoStartTerminal.verify(requireNotNull(bundle.request.failedPreUnitStagePredecessor))
            require(prior.predecessorPreparedNoStartSha256==
                requireNotNull(bundle.request.preparedNoStartPredecessor).sha256 &&
                prior.priorFailedPreparationTerminalSha256==
                requireNotNull(bundle.request.abandonedPreparation).terminal.sha256 &&
                GenerationNormalizedWorklaneImage.requireSelected(bundle.request.managedLanes?.native?.imageArchive)==
                    bundle.request.managedLanes?.native?.imageArchive)
        } else require(bundle.request.uncertainNativeImportPredecessor==null &&
            bundle.request.isolatedRootlessProbePredecessor==null)
        if (generation in setOf(GenerationAfterCapacityRefusalLineage.generation,
                GenerationAfterQ273Lineage.generation,GenerationAfterQ583Lineage.generation,
                GenerationAfterQ9bLineage.generation,GenerationAfterQ07Lineage.generation))
            GenerationAfterCapacityRefusalLineage.verify(
                requireNotNull(bundle.request.qc3PreparedNoStartPredecessor),
                requireNotNull(bundle.request.uncertainNativeImportPredecessor),
                requireNotNull(bundle.request.isolatedRootlessProbePredecessor))
        else require(bundle.request.qc3PreparedNoStartPredecessor==null)
        if (generation in setOf(GenerationAfterQ273Lineage.generation,
                GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
                GenerationAfterQ07Lineage.generation)) {
            GenerationAfterQ273Lineage.verify(requireNotNull(bundle.request.q273UncertainImportPredecessor),
                requireNotNull(bundle.request.qc3PreparedNoStartPredecessor),
                requireNotNull(bundle.request.uncertainNativeImportPredecessor),
                requireNotNull(bundle.request.isolatedRootlessProbePredecessor))
            WorklaneLateBrokerImportProof.verifySelected(requireNotNull(bundle.request.managedLanes).native.worklane)
        } else require(bundle.request.q273UncertainImportPredecessor==null)
        if (generation in setOf(GenerationAfterQ583Lineage.generation,
                GenerationAfterQ9bLineage.generation,GenerationAfterQ07Lineage.generation)) {
            GenerationAfterQ583Lineage.verify(requireNotNull(bundle.request.q583PreparedNoStartPredecessor),
                requireNotNull(bundle.request.isolatedFullWorklanePreparePredecessor),
                requireNotNull(bundle.request.q273UncertainImportPredecessor),
                requireNotNull(bundle.request.qc3PreparedNoStartPredecessor),
                requireNotNull(bundle.request.uncertainNativeImportPredecessor),
                requireNotNull(bundle.request.isolatedRootlessProbePredecessor))
            WorklaneLateBrokerImportProof.verifySelected(requireNotNull(bundle.request.managedLanes).native.worklane)
        } else require(bundle.request.q583PreparedNoStartPredecessor==null &&
            bundle.request.isolatedFullWorklanePreparePredecessor==null)
        if (generation in setOf(GenerationAfterQ9bLineage.generation,GenerationAfterQ07Lineage.generation))
            GenerationAfterQ9bLineage.verify(requireNotNull(bundle.request.q9bColdPreparedUninstalledPredecessor),
                requireNotNull(bundle.request.q583PreparedNoStartPredecessor),
                requireNotNull(bundle.request.isolatedFullWorklanePreparePredecessor),
                requireNotNull(bundle.request.q273UncertainImportPredecessor),
                requireNotNull(bundle.request.qc3PreparedNoStartPredecessor),
                requireNotNull(bundle.request.uncertainNativeImportPredecessor),
                requireNotNull(bundle.request.isolatedRootlessProbePredecessor))
        else require(bundle.request.q9bColdPreparedUninstalledPredecessor==null)
        if (generation==GenerationAfterQ07Lineage.generation)
            GenerationAfterQ07Lineage.verify(requireNotNull(bundle.request.q07PartialInstalledPredecessor),
                requireNotNull(bundle.request.q9bColdPreparedUninstalledPredecessor),
                requireNotNull(bundle.request.q583PreparedNoStartPredecessor),
                requireNotNull(bundle.request.isolatedFullWorklanePreparePredecessor),
                requireNotNull(bundle.request.q273UncertainImportPredecessor),
                requireNotNull(bundle.request.qc3PreparedNoStartPredecessor),
                requireNotNull(bundle.request.uncertainNativeImportPredecessor),
                requireNotNull(bundle.request.isolatedRootlessProbePredecessor))
        else require(bundle.request.q07PartialInstalledPredecessor==null)
        if (generation == "q-dd36ebcf43ef") {
            val predecessor=PreparedNoStartTerminal.verify(requireNotNull(bundle.request.preparedNoStartPredecessor))
            require(predecessor.earlierFailedPreparationTerminalSha256 ==
                requireNotNull(bundle.request.abandonedPreparation).terminal.sha256 &&
                bundle.request.forgejoCi?.runnerBinary?.sha256 == predecessor.runnerBinarySha256 &&
                requireNotNull(bundle.request.forgejoCi).runnerBinary.path ==
                    "/mnt/media/p0-v3/ci-runner/bin/forgejo-runner-v3.5.1")
        }
        // Capture, restore, retired capacity and terminal readback MUST all
        // authenticate sealed ownership, including historical V3 bindings.
        // Historical provenance is checked against its original packaged
        // revision, never silently skipped because a newer index exists.
        SiteOwnerships.checkSealed(bundle)
        if (checkLiveInputs) {
            val intent = root.resolve(if (bundle.request.memberPredecessorDisposition != null) GenerationCiMemberPreEffectContinuation.OWNERSHIP else
                if (bundle.request.predecessorDisposition == null) "ownership.intent.json" else GenerationCiPreEffectContinuation.OWNERSHIP)
            require(Files.exists(intent, NOFOLLOW_LINKS) == (bundle.ownership != null)) { "Missing or foreign ownership preparation intent" }
            bundle.ownership?.let { require(data(intent).contentEquals(json.encodeToString(it).toByteArray())) { "Ownership preparation intent changed" } }
        }
        val order = ordered(bundle.request)
        require(bundle.members.map { it.member } == order && bundle.members.all {
            it.spec.name == it.member.name && hash.matches(it.manifestSha256) &&
                PrivateDeployment.expectedFingerprint(it.spec, it.inputHashes) == it.runtimeFingerprint
        }) { "Invalid sealed member definition" }
        val specs = bundle.members.map { it.spec }
        require(specs.all { it.store == bundle.request.store }) { "Generation runtime-store binding differs" }
        require(Math.addExact(reservation(specs,bundle.request), GenerationManagedComponents.memoryReservationMiB(bundle.request)) == bundle.memoryReservationMiB &&
            bundle.request.diskReservationMiB >= specs.sumOf { it.volumes.size.toLong() * 1024 } +
                GenerationManagedComponents.diskReservationMiB(bundle.request) &&
            (!checkLiveInputs || order.map { pin(it).first } == bundle.members)) { "Generation input binding changed" }
        return bundle to specs
    }
    fun seal(request: GenerationRequest): String = mutating {
        val pins = ordered(request).map(::pin)
        require(request.store == RuntimeStore.LEGACY && pins.all { it.first.spec.store == request.store }) {
            "Canonical store installation requires ownership-bound preparation"
        }
        require(request.diskReservationMiB >= pins.sumOf { it.second.volumes.size.toLong() * 1024 }) { "Disk reservation below per-volume minimum" }
        val bundle = GenerationBundle(request, pins.map { it.first }, reservation(pins.map { it.second },request))
        val root = base.resolve(request.id)
        Files.createDirectory(root, PosixFilePermissions.asFileAttribute(privateDir))
        val text = json.encodeToString(bundle)
        save(root.resolve("bundle.json"), text)
        FileChannel.open(base, READ).use { it.force(true) }
        ReleaseLocks.sha256(text.toByteArray())
    }
    /** Prepares fresh synthetic inputs only. No runtime backend, unseal, provisioning or startup is invoked. */
    fun prepareAssembly(plan: AssemblyPlan): String = prepareAssembly(plan, null)
    fun prepareOwnedAssembly(plan: AssemblyPlan, contract: SiteOwnership, approvedHosts: Set<String>): String {
        val binding = SiteOwnerships.bind(plan, contract, approvedHosts) // Before registry locks/directories or credentials.
        return if (plan.generation.memberPredecessorDisposition != null) prepareCiMemberPreEffectRemainder(plan,binding)
            else if (plan.generation.predecessorDisposition == null) prepareAssembly(plan, binding)
            else prepareCiPreEffectRemainder(plan, binding)
    }
    /** Distinct read-only reconciliation of the one diagnosed, failed original, under the same
     * RSS/generation exclusion as preparation. It neither acknowledges nor replays that original.
     */
    fun issueCiPreEffectDisposition(generation: String): ActivationInput = mutating {
        require(generation == GenerationCiPreEffectContinuation.GENERATION)
        val root = base.resolve(generation); directory(root); directory(runtimeBase)
        val original = GenerationCiPreEffectContinuation.original(root)
        val summary = json.decodeFromString<AssemblySummary>(data(root.resolve("assembly.intent.json")).decodeToString())
        require(summary.members.isNotEmpty() && summary.members.all { member ->
            !Files.exists(runtimeBase.resolve(member.name), NOFOLLOW_LINKS) &&
                !Files.exists(runtimeBase.resolve("${member.name}.json"), NOFOLLOW_LINKS)
        }) { "Original member input effect may have occurred; no continuation" }
        save(root.resolve(GenerationCiPreEffectContinuation.FILE), json.encodeToString(original))
        GenerationCiPreEffectContinuation.binding(root)
    }
    /** Read-only reconciliation of the second failed preparation, under the original member's
     * namespace lock. The separate disposition binds exact CI/grant outputs and lock-only
     * member state; the original v2 attempt remains failed and is never resumed in place.
     */
    fun issueCiMemberPreEffectDisposition(generation: String): ActivationInput = mutating {
        require(base == BASE && runtimeBase == PrivateDeployment.BASE &&
            generation == GenerationCiPreEffectContinuation.GENERATION)
        val root=base.resolve(generation); directory(root)
        val member="${generation}-v2"
        PrivateDeployment.withOrderedNativeLocks(listOf(member), runtimeBase) {
            val first=GenerationCiPreEffectContinuation.binding(root)
            val observation=GenerationCiMemberPreEffectContinuation.inspect(root,runtimeBase.resolve(member),first,true)
            save(root.resolve(GenerationCiMemberPreEffectContinuation.FILE),json.encodeToString(observation))
            GenerationCiMemberPreEffectContinuation.binding(root)
        }
    }
    /** Third, separate one-use operation: both earlier preparation results stay false.
     * Exact original CI/issuer bytes are adopted, and a lock-only member is admitted
     * under its SAME native namespace lock only after an independent disposition.
     */
    private fun prepareCiMemberPreEffectRemainder(plan: AssemblyPlan, ownership: BoundSiteOwnership): String = mutating {
        val root=base.resolve(plan.generation.id); directory(root); directory(runtimeBase)
        val first=requireNotNull(plan.generation.predecessorDisposition)
        val second=requireNotNull(plan.generation.memberPredecessorDisposition)
        require(plan.summary.request.predecessorDisposition == first &&
            plan.summary.request.memberPredecessorDisposition == second &&
            plan.generation.id == GenerationCiPreEffectContinuation.GENERATION &&
            plan.summary.request.releaseCandidateSha256 == plan.summary.request.quadletControllerSha256 &&
            plan.summary.request.releaseCandidateSha256 != GenerationCiPreEffectContinuation.ORIGINAL_CONTROLLER)
        GenerationCiMemberPreEffectContinuation.verify(root,second,beforeEffects=true)
        val original=json.decodeFromString<AssemblySummary>(data(root.resolve("assembly.intent.json")).decodeToString())
        val revised=original.request.copy(candidateSha256=plan.summary.request.candidateSha256,
            releaseCandidateSha256=plan.summary.request.releaseCandidateSha256,
            quadletControllerSha256=plan.summary.request.quadletControllerSha256,
            rssPlan=plan.summary.request.rssPlan, managedLanes=plan.summary.request.managedLanes,
            predecessorDisposition=first, memberPredecessorDisposition=second,
            workingBudget=plan.summary.request.workingBudget)
        require(revised == plan.summary.request && original.members.size == 1 && plan.specs.size == 1 &&
            plan.recipes.size == 1 && plan.summary.members.single().name == original.members.single().name &&
            plan.generation.forgejoCi == original.request.forgejoCi &&
            plan.generation.rssPlan != null && plan.generation.managedLanes != null &&
            !Files.exists(root.resolve("bundle.json"),NOFOLLOW_LINKS) &&
            !Files.exists(runtimeBase.resolve("${plan.specs.single().name}.json"),NOFOLLOW_LINKS)) {
            "Foreign candidate or member input has already been attempted"
        }
        GenerationCiPreEffectContinuation.unchangedInputs(root,plan.generation.managedLanes)
        val member=ordered(plan.generation).single()
        require(member.name == plan.specs.single().name && member.name == original.members.single().name)
        val encoded=json.encodeToString(plan.summary)
        val assemblyHash=ReleaseLocks.sha256(encoded.toByteArray())
        save(root.resolve(GenerationCiMemberPreEffectContinuation.INTENT),encoded)
        fun failed(error:Exception):Nothing {
            val interrupted=Thread.interrupted() || error is InterruptedException
            try { save(root.resolve(GenerationCiMemberPreEffectContinuation.RESULT),json.encodeToString(
                AssemblyPreparationOutcome(assemblyHash,false,failureType=error.javaClass.name))) }
            finally { if (interrupted) Thread.currentThread().interrupt() }
            throw error
        }
        try {
            save(root.resolve(GenerationCiMemberPreEffectContinuation.OWNERSHIP),json.encodeToString(ownership))
            val expectedSpec=plan.summary.members.single().specSha256
            save(root.resolve("${member.name}.prepare-ci-member-v3.intent.json"),json.encodeToString(
                AssemblyMemberIntent(assemblyHash,member.name,expectedSpec)))
            val adapter=plan.recipes.single()
            val path=adapter.prepareWithRequest?.invoke(plan.inventory,runtimeBase,plan.specs.single(),plan.summary.request)
                ?: adapter.prepareBound?.invoke(plan.inventory,runtimeBase,plan.specs.single())
                ?: adapter.prepare(plan.inventory,runtimeBase,member.name,plan.generation.store)
            require(path == runtimeBase.resolve("${member.name}.json"))
            val (pin,spec)=pin(member)
            require(spec == plan.specs.single() && pin.manifestSha256 == expectedSpec)
            save(root.resolve("${member.name}.prepare-ci-member-v3.result.json"),json.encodeToString(pin))
            val bundle=GenerationBundle(plan.generation,listOf(pin),
                reservation(plan.specs,plan.generation)+GenerationManagedComponents.memoryReservationMiB(plan.generation),
                assemblyHash,ownership=ownership)
            SiteOwnerships.checkSealed(bundle)
            val bundleBytes=json.encodeToString(bundle)
            save(root.resolve("bundle.json"),bundleBytes)
            val hash=ReleaseLocks.sha256(bundleBytes.toByteArray())
            save(root.resolve(GenerationCiMemberPreEffectContinuation.RESULT),json.encodeToString(
                AssemblyPreparationOutcome(assemblyHash,true,hash)))
            hash
        } catch(error:InterruptedException) { failed(error) }
        catch(error:Exception) { failed(error) }
    }
    /** A new intent/result and new candidate, not another call to the failed original operation.
     * Existing managed/RSS bytes are validated/adopted unchanged; only CI and the unattempted
     * member recipe execute. Any attempted remainder is fenced even when its ACK is missing.
     */
    private fun prepareCiPreEffectRemainder(plan: AssemblyPlan, ownership: BoundSiteOwnership): String = mutating {
        val root = base.resolve(plan.generation.id); directory(root); directory(runtimeBase)
        val disposition = requireNotNull(plan.generation.predecessorDisposition)
        require(plan.summary.request.predecessorDisposition == disposition &&
            plan.generation.id == GenerationCiPreEffectContinuation.GENERATION &&
            plan.summary.request.quadletControllerSha256 != GenerationCiPreEffectContinuation.ORIGINAL_CONTROLLER &&
            plan.summary.request.releaseCandidateSha256 == plan.summary.request.quadletControllerSha256)
        GenerationCiPreEffectContinuation.verify(root, disposition, beforeEffects = true)
        val original = json.decodeFromString<AssemblySummary>(data(root.resolve("assembly.intent.json")).decodeToString())
        val updated = original.request.copy(candidateSha256 = plan.summary.request.candidateSha256,
            releaseCandidateSha256 = plan.summary.request.releaseCandidateSha256,
            quadletControllerSha256 = plan.summary.request.quadletControllerSha256,
            rssPlan = plan.summary.request.rssPlan, managedLanes = plan.summary.request.managedLanes,
            predecessorDisposition = disposition, workingBudget = plan.summary.request.workingBudget)
        require(updated == plan.summary.request && original.members.map { it.name } == plan.summary.members.map { it.name } &&
            original.members.size == 1 && plan.recipes.size == 1 && plan.specs.size == 1 &&
            !Files.exists(root.resolve("ci"), NOFOLLOW_LINKS) && !Files.exists(root.resolve("bundle.json"), NOFOLLOW_LINKS) &&
            plan.generation.rssPlan != null && plan.generation.managedLanes != null &&
            plan.generation.forgejoCi == original.request.forgejoCi &&
            plan.generation.diskReservationMiB >= plan.specs.sumOf { it.volumes.size.toLong() * 1024 } +
                GenerationManagedComponents.diskReservationMiB(plan.generation)) { "Candidate changed unrelated original inputs or partial effect is uncertain" }
        GenerationCiPreEffectContinuation.unchangedInputs(root, plan.generation.managedLanes)
        val order = ordered(plan.generation)
        require(order.size == 1 && order.single().name == plan.summary.members.single().name &&
            order.single().name == original.members.single().name &&
            !Files.exists(runtimeBase.resolve(order.single().name), NOFOLLOW_LINKS) &&
            !Files.exists(runtimeBase.resolve("${order.single().name}.json"), NOFOLLOW_LINKS)) {
            "One-member original recipe may have been attempted"
        }
        val text = json.encodeToString(plan.summary)
        val assemblyHash = ReleaseLocks.sha256(text.toByteArray())
        save(root.resolve(GenerationCiPreEffectContinuation.INTENT), text)
        fun failed(error: Exception): Nothing {
            val interrupted = Thread.interrupted() || error is InterruptedException
            try { save(root.resolve(GenerationCiPreEffectContinuation.RESULT), json.encodeToString(
                AssemblyPreparationOutcome(assemblyHash, false, failureType = error.javaClass.name))) }
            finally { if (interrupted) Thread.currentThread().interrupt() }
            throw error
        }
        try {
            save(root.resolve(GenerationCiPreEffectContinuation.OWNERSHIP), json.encodeToString(ownership))
            // No call to managed/RSS materialize or initialize: their exact immutable original
            // outputs have been checked against the new plan above.
            ForgejoCiSourcePlan.prepare(root, requireNotNull(plan.generation.forgejoCi))
            val member = order.single(); val expectedSpec = plan.summary.members.single().specSha256
            save(root.resolve("${member.name}.prepare-ci-pre-effect-v2.intent.json"), json.encodeToString(
                AssemblyMemberIntent(assemblyHash, member.name, expectedSpec)))
            val adapter = plan.recipes.single()
            val path = adapter.prepareWithRequest?.invoke(plan.inventory, runtimeBase, plan.specs.single(), plan.summary.request)
                ?: adapter.prepareBound?.invoke(plan.inventory, runtimeBase, plan.specs.single())
                ?: adapter.prepare(plan.inventory, runtimeBase, member.name, plan.generation.store)
            require(path == runtimeBase.resolve("${member.name}.json")) { "Recipe returned foreign input path" }
            val (pin, spec) = pin(member)
            require(spec == plan.specs.single() && pin.manifestSha256 == expectedSpec) { "Prepared recipe changed" }
            save(root.resolve("${member.name}.prepare-ci-pre-effect-v2.result.json"), json.encodeToString(pin))
            val bundle = GenerationBundle(plan.generation, listOf(pin),
                reservation(plan.specs, plan.generation) + GenerationManagedComponents.memoryReservationMiB(plan.generation),
                assemblyHash, ownership = ownership)
            SiteOwnerships.checkSealed(bundle)
            val encoded = json.encodeToString(bundle)
            save(root.resolve("bundle.json"), encoded)
            val hash = ReleaseLocks.sha256(encoded.toByteArray())
            save(root.resolve(GenerationCiPreEffectContinuation.RESULT), json.encodeToString(
                AssemblyPreparationOutcome(assemblyHash, true, hash)))
            hash
        } catch (error: InterruptedException) { failed(error) }
        catch (error: Exception) { failed(error) }
    }
    private fun prepareAssembly(plan: AssemblyPlan, ownership: BoundSiteOwnership?): String = mutating {
        // All failed pre-bundle generations must remain fenced before another
        // original r9 preparation. Reobserve terminal absence under the global
        // RSS/generation owner lock plus the old native member lock; never
        // interpret a fresh name as permission to reuse a historical input.
        if(plan.summary.request.selections.any { it.recipe in setOf(CanonicalSharedYamlGraph.R9_ASSEMBLY_RECIPE,
                CanonicalSharedYamlGraph.R10_ASSEMBLY_RECIPE) }) {
            val known=Files.list(base).use { entries -> entries.filter { candidate ->
                candidate.fileName.toString().matches(id) && candidate.fileName.toString()!=plan.generation.id &&
                    Files.isDirectory(candidate,NOFOLLOW_LINKS)
            }.toList() }
            val failed=known.filter { candidate ->
                val result=candidate.resolve("assembly.result.json")
                Files.isRegularFile(result,NOFOLLOW_LINKS) && !Files.exists(candidate.resolve("bundle.json"),NOFOLLOW_LINKS) &&
                    !json.decodeFromString<AssemblyPreparationOutcome>(data(result).decodeToString(throwOnInvalidSequence=true)).passed
            }.map { it.fileName.toString() }.toSet()
            val prior=known.filter { candidate ->
                (Files.isRegularFile(candidate.resolve(GenerationPreparationTerminalDisposition.NAME),NOFOLLOW_LINKS) ||
                    Files.isRegularFile(candidate.resolve(GenerationPreparationTerminalDisposition.V2_NAME),NOFOLLOW_LINKS) ||
                    Files.isRegularFile(candidate.resolve(GenerationPreparationTerminalDisposition.V3_NAME),NOFOLLOW_LINKS))
            }.map { it.fileName.toString() }.toSet()
            require(failed==prior) { "Unclosed failed original generation; issue an independent terminal disposition first" }
            val lineage=plan.generation.abandonedPreparation
            require((prior.isEmpty() && lineage==null) ||
                (lineage!=null && prior==setOf(lineage.priorGeneration))) {
                "Abandoned original preparation requires explicit terminal history; no renaming around the fence"
            }
            if(lineage!=null) AbandonedPreparationLineages.verifyLive(plan.generation.id,
                requireNotNull(plan.summary.request.quadletControllerSha256),lineage)
        }
        val order = ordered(plan.generation)
        plan.generation.rssPlan?.let {
            require(ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(it.artifactClosure.path))) == it.artifactClosure.sha256) {
                "RSS artifact closure unavailable or changed before preparation"
            }
        }
        require(plan.specs.all { it.store == plan.generation.store } &&
            (plan.generation.store == RuntimeStore.LEGACY || ownership != null)) {
            "Canonical store installation requires matching store bindings and explicit ownership"
        }
        require(order.map { it.name } == plan.specs.map { it.name } && order.size == plan.recipes.size &&
            order == plan.summary.members.map { GenerationMember(it.name, it.dependencies) }) { "Assembly ordering mismatch" }
        require(plan.generation.diskReservationMiB >= plan.specs.sumOf { it.volumes.size.toLong() * 1024 } +
            GenerationManagedComponents.diskReservationMiB(plan.generation)) { "Insufficient controller state reservation" }
        directory(runtimeBase)
        for (member in order) require(!Files.exists(runtimeBase.resolve(member.name), NOFOLLOW_LINKS) &&
            !Files.exists(runtimeBase.resolve("${member.name}.json"), NOFOLLOW_LINKS)) { "Assembly requires fresh input namespaces; no credential regeneration" }
        val root = base.resolve(plan.generation.id)
        Files.createDirectory(root, PosixFilePermissions.asFileAttribute(privateDir))
        FileChannel.open(base, READ).use { it.force(true) }
        val text = json.encodeToString(plan.summary)
        val assemblyHash = ReleaseLocks.sha256(text.toByteArray())
        save(root.resolve("assembly.intent.json"), text)
        fun failed(error: Exception): Nothing {
            val interrupted = Thread.interrupted() || error is InterruptedException
            try { save(root.resolve("assembly.result.json"), json.encodeToString(
                AssemblyPreparationOutcome(assemblyHash, false, failureType = error.javaClass.name))) }
            finally { if (interrupted) Thread.currentThread().interrupt() }
            throw error
        }
        try {
            ownership?.let { save(root.resolve("ownership.intent.json"), json.encodeToString(it)) }
            if (plan.generation.baoBootstrapOperation != null && plan.generation.managedLanes != null)
                GenerationR9ManagedPlan.materialize(plan.generation.managedLanes,root)
            plan.generation.rssPlan?.let { GenerationRssPlan.prepare(root) }
            plan.generation.forgejoCi?.let { ForgejoCiSourcePlan.prepare(root, it) }
            val pins = order.indices.map { index ->
                val member = order[index]
                val expectedSpec = plan.summary.members[index].specSha256
                save(root.resolve("${member.name}.prepare.intent.json"), json.encodeToString(
                    AssemblyMemberIntent(assemblyHash, member.name, expectedSpec)))
                val adapter = plan.recipes[index]
                val path = adapter.prepareWithRequest?.invoke(plan.inventory, runtimeBase,
                    plan.specs[index], plan.summary.request)
                    ?: adapter.prepareBound?.invoke(plan.inventory, runtimeBase, plan.specs[index])
                    ?: adapter.prepare(plan.inventory, runtimeBase, member.name, plan.generation.store)
                require(path == runtimeBase.resolve("${member.name}.json")) { "Recipe returned foreign input path" }
                val (actual, spec) = pin(member)
                require(spec == plan.specs[index] && actual.manifestSha256 == expectedSpec) { "Prepared recipe differs from planned definition" }
                save(root.resolve("${member.name}.prepare.result.json"), json.encodeToString(actual))
                actual
            }
            val bundle = GenerationBundle(plan.generation, pins, reservation(plan.specs,plan.generation) +
                GenerationManagedComponents.memoryReservationMiB(plan.generation), assemblyHash, ownership = ownership)
            SiteOwnerships.checkSealed(bundle)
            val encoded = json.encodeToString(bundle)
            save(root.resolve("bundle.json"), encoded)
            val hash = ReleaseLocks.sha256(encoded.toByteArray())
            save(root.resolve("assembly.result.json"), json.encodeToString(AssemblyPreparationOutcome(assemblyHash, true, hash)))
            hash
        } catch (error: InterruptedException) { failed(error) }
        catch (error: Exception) { failed(error) }
    }
    private fun backend(bundle: GenerationBundle) = backend(bundle.members.associate { it.member.name to it.runtimeFingerprint })
    /** Append-only read-only native disposition for a successful owned PREPARE
     * that never entered Quadlet START. This is not a failed preparation or a
     * substitute INSTALL result; a future generation must pin it explicitly. */
    fun terminalizePreparedNoStart(generation: String, expected: String): ActivationInput = mutating {
        require(generation == "q-5712d9335843")
        val (bundle, specs) = load(generation, expected)
        require(specs.size == 1 && bundle.ownership != null)
        PrivateDeployment.withOrderedNativeLocks(listOf(specs.single().name), runtimeBase) {
            require(load(generation, expected).first == bundle)
            PreparedNoStartTerminal.observe(bundle, expected)
        }
    }
    /** Different from a passed-preparation no-start: this original serve has
     * stage and managed-initial intents, but no result or native unit/CID. */
    fun terminalizeFailedPreUnitServe(generation:String,expected:String):ActivationInput = mutating {
        require(generation=="q-dd36ebcf43ef")
        val (bundle,specs)=load(generation,expected)
        require(specs.size==1 && bundle.ownership!=null)
        PrivateDeployment.withOrderedNativeLocks(listOf(specs.single().name),runtimeBase) {
            require(load(generation,expected).first==bundle)
            ManagedPreUnitNoStartTerminal.observe(bundle,expected)
        }
    }
    /** Original qc3 owned prepare, one pre-effect capacity refusal. This
     * terminal does not release q4d's image or reconstruct either native ACK. */
    fun terminalizeQc3PreparedNoStart(generation:String,expected:String):ActivationInput = mutating {
        require(generation=="q-c3a7a9e29391")
        val (bundle,specs)=load(generation,expected)
        require(specs.size==1 && bundle.ownership!=null)
        PrivateDeployment.withOrderedNativeLocks(listOf(specs.single().name),runtimeBase) {
            require(load(generation,expected).first==bundle)
            Qc3PreparedNoStartTerminal.observe(bundle,expected)
        }
    }
    /** Read-only original native import observation under owner/member locks; the
     * unacknowledged PREPARE intent remains terminally fenced. */
    fun terminalizeUncertainManagedImport(generation:String,expected:String):ActivationInput = mutating {
        require(generation=="q-4d3c1cb287e5")
        val (bundle,specs)=load(generation,expected)
        require(specs.size==1 && bundle.ownership!=null)
        PrivateDeployment.withOrderedNativeLocks(listOf(specs.single().name),runtimeBase) {
            require(load(generation,expected).first==bundle)
            ManagedUncertainImageImportTerminal.observe(bundle,expected)
        }
    }
    /** q273 is NOT pre-native: its old imported image, manifest and home remain
     * physical, while its three original native results remain missing. */
    fun terminalizeQ273UncertainImport(generation:String,expected:String):ActivationInput = mutating {
        require(generation==Q273UncertainManagedImportTerminal.generation)
        val (bundle,specs)=load(generation,expected)
        require(specs.size==1 && bundle.ownership!=null)
        PrivateDeployment.withOrderedNativeLocks(listOf(specs.single().name),runtimeBase) {
            require(load(generation,expected).first==bundle)
            Q273UncertainManagedImportTerminal.observe(bundle,expected)
        }
    }
    /** q07's original disabled INSTALL copied files but missed its audit result;
     * record the root-read-only actual installed/inactive state, never retry. */
    fun terminalizeQ07PartialInstalled(generation:String,expected:String):ActivationInput = mutating {
        require(generation==Q07PartialInstalledUnitTerminal.generation)
        val (bundle,specs)=load(generation,expected)
        require(specs.size==1 && bundle.ownership!=null)
        PrivateDeployment.withOrderedNativeLocks(listOf(specs.single().name),runtimeBase) {
            require(load(generation,expected).first==bundle)
            Q07PartialInstalledUnitTerminal.observe(bundle,expected)
        }
    }
    /** q9b completed three original PREPAREs, but no unit installation or
     * application stage. Retain its entire imported graph and original results. */
    fun terminalizeQ9bColdPreparedUninstalled(generation:String,expected:String):ActivationInput = mutating {
        require(generation==Q9bColdPreparedUninstalledTerminal.generation)
        val (bundle,specs)=load(generation,expected)
        require(specs.size==1 && bundle.ownership!=null)
        PrivateDeployment.withOrderedNativeLocks(listOf(specs.single().name),runtimeBase) {
            require(load(generation,expected).first==bundle)
            Q9bColdPreparedUninstalledTerminal.observe(bundle,expected)
        }
    }
    /** q583 prepared inputs remain frozen; no original serve or import was tried.
     * A predicted semantic refusal is NOT an uncertain native effect. */
    fun terminalizeQ583PreparedNoStart(generation:String,expected:String):ActivationInput = mutating {
        require(generation==Q583PreparedNoStartTerminal.generation)
        val (bundle,specs)=load(generation,expected)
        require(specs.size==1 && bundle.ownership!=null)
        PrivateDeployment.withOrderedNativeLocks(listOf(specs.single().name),runtimeBase) {
            require(load(generation,expected).first==bundle)
            Q583PreparedNoStartTerminal.observe(bundle,expected)
        }
    }
    fun inspect(generation: String, expected: String): GenerationInspection = locked {
        val (bundle, specs) = load(generation, expected)
        val runtime = backend(bundle)
        GenerationInspection(generation, expected, bundle.memoryReservationMiB, specs.map { runtime.audit(it, false) })
    }
    /** Read-only actual installed Quadlet audit. This is neither admission nor a StartUnit
     * authorization. Re-load protected inputs *after* acquiring the same native member lock
     * used by preparations, so observations cannot straddle input replacement.
     */
    fun auditInstalledQuadlet(generation: String, expected: String, member: String, process: String): String = RecoveryDeadline.within { locked {
        require(member.matches(Regex("q-[a-f0-9]{12}-[a-z][a-z0-9-]{0,39}")))
        val preliminary = load(generation, expected).first
        require(preliminary.members.any { it.member.name == member &&
            it.spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2 }) { "No bound Quadlet member" }
        PrivateDeployment.withOrderedNativeLocks(listOf(member), runtimeBase) {
            val (bundle, specs) = load(generation, expected)
            require(bundle.members.singleOrNull { it.member.name == member }?.spec?.executionBackend ==
                RuntimeExecutionBackend.QUADLET_V2) { "No bound Quadlet member" }
            val spec = specs.single { it.name == member }
            val selected = spec.processes.single { it.id == process }
            RuntimeQuadletInstalledAudit().audit(spec, selected)
        }
    } }
    /** Failed original systemd stage with no native launch: terminal observation only.
     * A retained intent/ACK is never turned into a new launch capability.
     */
    fun reconcileQuadletStage(generation: String, expected: String): QuadletStageTerminalObservation =
        RecoveryDeadline.within { locked {
            // Terminal-only readback must remain possible after a new packaged
            // manifest supersedes the failed generation. Never recompile it
            // against today's recipe or require its old runtime credentials.
            val (bundle, specs) = load(generation, expected, checkLiveInputs = false)
            require(bundle.members.size == 1 && specs.singleOrNull()?.executionBackend == RuntimeExecutionBackend.QUADLET_V2)
            val spec = specs.single()
            PrivateDeployment.withOrderedNativeLocks(listOf(spec.name), runtimeBase) {
                require(load(generation, expected, checkLiveInputs = false).first == bundle)
                RuntimeQuadletStageReconcile(base, runtimeBase).terminal(generation, expected, spec)
            }
        } }
    /** Read-only revalidation of a FAILED original stage. Checks original sealed
     * site ownership, archived resource pins, missing ACKs, fence, native labels,
     * exact retained CIDs and quiescence under the member lock. It saves nothing. */
    fun auditFailedQuadletStageTerminal(generation: String, expected: String): QuadletStageTerminalObservation =
        RecoveryDeadline.within { locked {
            val (bundle, specs) = load(generation, expected, checkLiveInputs = false)
            require(bundle.members.size == 1 && specs.size == 1 &&
                specs.single().executionBackend == RuntimeExecutionBackend.QUADLET_V2 &&
                bundle.request.store == RuntimeStore.CANONICAL_V2)
            val pin = bundle.members.single()
            val root = base.resolve(generation)
            PrivateDeployment.withOrderedNativeLocks(listOf(pin.spec.name), runtimeBase) {
                val (fence, cids) = requireNotNull(RuntimeQuadletCapacityTerminal.failedStage(root, bundle, expected))
                val observed = retiredCensus.snapshot(bundle.request.store)
                require(retiredCensus.quiescent(listOf(RuntimeCapacityCensus.Member(pin.spec, pin.runtimeFingerprint)), observed) &&
                    RuntimeQuadletCapacityTerminal.matchesOriginalCids(pin.spec.name, cids, observed) &&
                    RuntimeMaintenance.read(runtimeBase.resolve(pin.spec.name), pin.runtimeFingerprint)?.id == fence) {
                    "Failed-stage terminal is not quiescent under its original fence and exact CIDs"
                }
                json.decodeFromString<QuadletStageTerminalObservation>(
                    data(root.resolve("quadlet-stage.terminal.json")).decodeToString())
            }
        } }
    /** Separate one-use owner-death containment of a still-running failed StartUnit CID.
     * Missing original launch/stop ACKs remain missing; this never releases capacity.
     */
    fun emergencyContainFailedQuadlet(generation: String, expected: String): QuadletEmergencyContainment =
        RecoveryDeadline.within { locked {
            val (bundle, specs) = load(generation, expected, checkLiveInputs = false)
            require(bundle.members.size == 1 && specs.size == 1 && bundle.ownership != null &&
                specs.single().executionBackend == RuntimeExecutionBackend.QUADLET_V2)
            val pin = bundle.members.single()
            PrivateDeployment.withOrderedNativeLocks(listOf(pin.spec.name), runtimeBase) {
                require(load(generation, expected, checkLiveInputs = false).first == bundle)
                RuntimeQuadletEmergencyContainment.contain(generation, expected, pin.spec,
                    pin.runtimeFingerprint, base, runtimeBase)
            }
        } }
    /** Separate terminal observation of an interrupted original install. Neither the
     * installed policy digest nor this receipt is the missing original install ACK.
     */
    fun reconcileQuadletInstall(generation: String, expected: String, member: String): QuadletInstallTerminalObservation =
        RecoveryDeadline.within { locked {
            val (bundle, specs) = load(generation, expected)
            require(bundle.members.singleOrNull()?.spec?.name == member &&
                specs.singleOrNull()?.executionBackend == RuntimeExecutionBackend.QUADLET_V2)
            PrivateDeployment.withOrderedNativeLocks(listOf(member), runtimeBase) {
                require(load(generation, expected).first == bundle)
                RuntimeQuadletInstallReconcile().terminal(base.resolve(generation), generation, expected, specs.single())
            }
        } }
    /** Diagnostic only: the same admission calculation as install, without an
     * install intent, source copy or StartUnit. Never substitutes for rechecking
     * capacity beneath the original installer lock immediately before effects.
     */
    /** Post-start ORIGINAL trusted Forgejo job, never a source-seal or issuer-start prerequisite. */
    internal fun produceOriginalCiJob(generation: String, expected: String): ForgejoCiJobResult = mutating {
        val (bundle, _) = load(generation, expected)
        ForgejoCiOriginalJob.produce(bundle, base.resolve(generation), expected)
    }

    fun auditQuadletCapacity(generation: String, expected: String): GenerationCapacity = RecoveryDeadline.within { locked {
        val (bundle, specs) = load(generation, expected)
        require(bundle.ownership != null && specs.any { it.executionBackend == RuntimeExecutionBackend.QUADLET_V2 } &&
            !Files.exists(base.resolve(generation).resolve("stage.intent.json"), NOFOLLOW_LINKS))
        admit(bundle)
        capacity(bundle.request.store)
    } }
    /** Install disabled, immutable Quadlet sources for a sealed, fresh member. This action is
     * deliberately separate from stage: no systemd start or direct-Podman fallback occurs.
     * Hold RSS/generation and native member locks across privilege effects and live audit.
     */
    internal class QuadletInstallGateFailure(val stage: String, cause: Exception) :
        IllegalStateException("Quadlet install $stage rejected", cause)
    fun installQuadlet(generation: String, expected: String, member: String,
        installer: RuntimeQuadletInstaller = RuntimeQuadletInstaller()): QuadletInstallResult = mutating {
        fun <T> gate(stage: String, effect: () -> T): T = try { effect() }
        catch (failure: Exception) { throw QuadletInstallGateFailure(stage, failure) }
        val (bundle, specs) = gate("sealed-bundle") { load(generation, expected) }
        require(bundle.request.store == RuntimeStore.CANONICAL_V2 &&
            bundle.recoverySourceArchiveSha256 == null && bundle.recoverySourceKopia == null &&
            bundle.ownedUpdate == null && bundle.ownership != null &&
            !Files.exists(base.resolve(generation).resolve("stage.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(base.resolve(generation).resolve("isolate.intent.json"), NOFOLLOW_LINKS)) {
            "Quadlet install requires an owned, unattempted fresh generation"
        }
        require(specs.any { it.name == member && it.executionBackend == RuntimeExecutionBackend.QUADLET_V2 })
        // Capacity walks other retired generations under the generation lock. Their
        // independent native member locks cannot be acquired beneath THIS member lock.
        gate("capacity") { admit(bundle) }
        PrivateDeployment.withOrderedNativeLocks(listOf(member), runtimeBase) {
            val (checked, bound) = gate("locked-inputs") { load(generation, expected) }
            require(checked == bundle && bound == specs) { "Generation changed before unit installation" }
            val spec = bound.single { it.name == member }
            gate("native-store-images-absence") { RuntimeQuadletPreflight.verify(spec) }
            gate("privileged-install-and-audit") { installer.install(base.resolve(generation), generation, expected, spec) }
        }
    }
    /** This signal deliberately does NOT take the generation lock: the genuine owner
     * must retain that lock for the whole serving interval. A request cannot start,
     * stop, or replace a process by itself; the held owner verifies it before StopUnit.
     */
    /** Terminal readback only. This cannot invent an isolate.result, resume a
     * source, authorize another initializer or assert a functional restore.
     */
    fun terminalQuadletCapacity(generation: String, expected: String): QuadletCapacityTerminalObservation = mutating {
        val (bundle, specs) = load(generation, expected)
        require(base == BASE && runtimeBase == PrivateDeployment.BASE && specs.size == 1 &&
            bundle.members.size == 1 && bundle.members.single().spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2)
        RuntimeQuadletCapacityTerminal.record(base.resolve(generation), bundle, expected, runtimeBase)
    }
    /** Independent physical terminal disposition when an original serving/stop
     * result is absent. Read-only native evidence; never an original ACK or replay.
     */
    fun separateQuadletTerminal(generation: String, expected: String): QuadletSeparateTerminalDisposition = mutating {
        val (bundle, specs) = load(generation,expected)
        require(base == BASE && runtimeBase == PrivateDeployment.BASE && specs.size == 1 &&
            bundle.members.size == 1 && bundle.members.single().spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2)
        RuntimeQuadletTerminalDisposition.record(base.resolve(generation),bundle,expected,runtimeBase)
    }
    fun checkSeparateQuadletTerminal(generation: String, expected: String): QuadletSeparateTerminalDisposition =
        RecoveryDeadline.within(360_000L) { locked {
            val (bundle, specs) = load(generation,expected)
            require(base == BASE && runtimeBase == PrivateDeployment.BASE && specs.size == 1 &&
                bundle.members.size == 1 && bundle.members.single().spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2)
            RuntimeQuadletTerminalDisposition.record(base.resolve(generation),bundle,expected,runtimeBase,persist=false)
        } }
    fun verifySeparateQuadletTerminal(generation: String, expected: String): QuadletSeparateTerminalDisposition =
        RecoveryDeadline.within(360_000L) { locked {
            val (bundle,specs)=load(generation,expected)
            require(base == BASE && runtimeBase == PrivateDeployment.BASE && specs.size == 1)
            val pin=bundle.members.single()
            PrivateDeployment.withOrderedNativeLocks(listOf(pin.spec.name),runtimeBase) {
                val receipt=requireNotNull(RuntimeQuadletTerminalDisposition.read(base.resolve(generation),
                    bundle,expected,runtimeBase))
                RuntimeQuadletTerminalDisposition.requireCurrentUnits(base.resolve(generation),bundle,receipt)
                val census=RuntimeCapacityCensus()
                val observed=census.snapshot(pin.spec.store)
                require(census.quiescent(listOf(RuntimeCapacityCensus.Member(pin.spec,pin.runtimeFingerprint)),observed) &&
                    RuntimeQuadletCapacityTerminal.matchesOriginalCids(pin.spec.name,receipt.originalCids,observed) &&
                    observed.filter { it.member == pin.spec.name }.all { it.state == "exited" }) {
                    "Separate terminal receipt no longer matches the native CID state"
                }
                receipt
            }
        } }
    fun requestQuadletServeStop(generation: String, expected: String): QuadletServeStopRequest {
        require(id.matches(generation) && hash.matches(expected))
        val root = base.resolve(generation)
        directory(root)
        val bytes = data(root.resolve("bundle.json"))
        require(ReleaseLocks.sha256(bytes) == expected &&
            !Files.exists(root.resolve("quadlet-serve-stop.intent.json"), NOFOLLOW_LINKS))
        val bundle = json.decodeFromString<GenerationBundle>(bytes.decodeToString(throwOnInvalidSequence = true))
        val member = bundle.members.single()
        require(bundle.request.id == generation && member.spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2 &&
            Files.exists(root.resolve("stage.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("quadlet-serve.result.json"), NOFOLLOW_LINKS))
        val request = QuadletServeStopRequest(generation = generation, member = member.spec.name,
            bundleSha256 = expected, reason = "operator-controlled")
        save(root.resolve("quadlet-serve-stop.intent.json"), json.encodeToString(request))
        return request
    }
    /** Dedicated persistent owner process. Unlike stageQuadlet it never releases the
     * native generation/member locks while any serving systemd unit remains active.
     */
    fun serveQuadlet(generation: String, expected: String): QuadletServeResult = mutating {
        val (bundle, specs) = load(generation, expected)
        require(bundle.ownership != null && bundle.request.store == RuntimeStore.CANONICAL_V2 &&
            bundle.members.size == 1 && specs.size == 1 &&
            specs.single().executionBackend == RuntimeExecutionBackend.QUADLET_V2 &&
            bundle.recoverySourceArchiveSha256 == null && bundle.recoverySourceKopia == null &&
            !Files.exists(base.resolve(generation).resolve("stage.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(base.resolve(generation).resolve("isolate.intent.json"), NOFOLLOW_LINKS)) {
            "Serving requires fresh owned single-member Quadlet generation"
        }
        // The persistent foreground owner must execute from the exact immutable
        // distribution named by the installed Quadlet helper, not a development
        // classpath that could change between the first and last StartUnit.
        PinnedBackupController.verify(requireNotNull(specs.single().fragmentBinding?.controllerSha256))
        admit(bundle) // Never audit other generations under this member's native lock.
        bundle.request.forgejoCi?.let { ForgejoCiNativeSourceAdmission.check(it,base.resolve(generation)) }
        val pin = bundle.members.single()
        val spec = specs.single()
        if (spec.fragmentBinding?.phase == FragmentPhase.INSTALL.name &&
            spec.fragmentBinding.resources.containsKey("fragments/v3/canonical/r9/index.yaml"))
            GenerationR9ImageStore.verifySelected(generation,spec)
        PrivateDeployment.withOrderedNativeLocks(listOf(spec.name), runtimeBase) {
            require(load(generation, expected).first == bundle)
            RuntimeQuadletPreflight.verify(spec)
            val root = base.resolve(generation)
            val installIntent=root.resolve("quadlet-install-${spec.name}.intent.json")
            val installResult=root.resolve("quadlet-install-${spec.name}.result.json")
            // The installed-unit producer belongs to this same retained owner,
            // before the first stage/PREPARE intent. It installs only this
            // generation's disabled sources, reloads systemd, and audits the
            // generated/effective units; it never starts or enables them.
            if (!Files.exists(installIntent,NOFOLLOW_LINKS) &&
                !Files.exists(installResult,NOFOLLOW_LINKS))
                RuntimeQuadletInstaller().install(root,generation,expected,spec)
            val originalInstall=json.decodeFromString<QuadletInstallIntent>(
                data(installIntent).decodeToString(throwOnInvalidSequence=true))
            val originalResult=json.decodeFromString<QuadletInstallResult>(
                data(installResult).decodeToString(throwOnInvalidSequence=true))
            val rendered=RuntimeQuadlets.render(spec)
            val expectedFiles=rendered.files.mapKeys { (relative,_) ->
                (if (relative.endsWith(".container")) Path.of("/etc/containers/systemd/p0-v3")
                 else Path.of("/etc/systemd/system")).resolve(relative).toString()
            }.mapValues { ReleaseLocks.sha256(it.value.toByteArray()) }
            require(originalInstall.generation==generation && originalInstall.member==spec.name &&
                originalInstall.bundleSha256==expected &&
                originalInstall.specSha256==rendered.specSha256 &&
                originalInstall.filesSha256==expectedFiles &&
                originalInstall.stagedDestinations==expectedFiles.keys.toList() &&
                originalResult.intentSha256==ReleaseLocks.sha256(data(installIntent)) &&
                originalResult.installedAuditSha256.keys==spec.processes.map { it.id }.toSet()) {
                "Incomplete original installed-unit producer result"
            }
            // Hold the native member lock continuously through re-audit and
            // START; a dry-run is never an installed-unit result.
            val installed=RuntimeQuadletInstalledAudit()
            spec.processes.forEach { p ->
                require(installed.audit(spec,p)==originalResult.installedAuditSha256.getValue(p.id))
            }
            val stopPath = root.resolve("quadlet-serve-stop.intent.json")
            require(!Files.exists(stopPath, NOFOLLOW_LINKS))
            save(root.resolve("stage.intent.json"), json.encodeToString(GenerationIntent("stage", expected)))
            if (bundle.request.managedLanes != null) {
                val managed=root.resolve("managed")
                if (!Files.exists(managed,NOFOLLOW_LINKS)) {
                    Files.createDirectory(managed,PosixFilePermissions.asFileAttribute(privateDir))
                    FileChannel.open(root,READ).use { it.force(true) }
                }
                directory(managed)
                requireNotNull(GenerationManagedComponents.prepareInitial(bundle,root))
            }
            val memberRoot = runtimeBase.resolve(spec.name)
            val onDemandNotebook = NotebookSelectedGraph.selected(root,spec)
            var notebookSocket: NotebookParentControlSocket? = null
            var notebookActor: NotebookParentActuator? = null
            try {
                lateinit var actor: NotebookParentActuator
                val owner = RuntimeQuadletOwnerStage(root, runtimeBase, beforeProcessStart = { p ->
                    if (p.id == "keeper" && bundle.request.baoBootstrapOperation != null) {
                        val controller=Path.of("/mnt/media/p0-v3/runtime-supervision/releases/" +
                            requireNotNull(spec.fragmentBinding?.controllerSha256) + "/bin/p0-v3-platform")
                        GenerationFreshBaoStage.issueBeforeKeeper(bundle,expected,controller)
                    }
                    if (onDemandNotebook && p.id == "hub-controller") {
                        actor.retireOriginals()
                        notebookSocket = NotebookParentControlSocket(root,spec.name,
                            pin.inputHashes.getValue("jupyterhub-hub-settings.json"),actor,runtimeBase)
                        requireNotNull(notebookSocket).start()
                    }
                })
                if (onDemandNotebook) actor = NotebookParentActuator(bundle,pin,root,expected,owner,
                    runtimeRoot=runtimeBase).also { notebookActor = it }
                val statuses = owner.stage(bundle, expected, pin)
                require(statuses.size == spec.processes.size)
                save(root.resolve("${spec.name}.stage.result.json"), json.encodeToString(statuses))
                save(root.resolve("stage.result.json"), json.encodeToString(GenerationOutcome("stage", expected, true)))
                if (spec.processes.singleOrNull { it.id == "caddy" }?.files?.any {
                    it.file == "onlyoffice-office-web.pem" && it.target == "/run/secrets/office-web.pem"
                } == true) {
                    val selected=PackagedGraphFragment.pendingV3R9().first
                    CanonicalCaddyInternalCaCustody(root,bundle,expected,selected).record()
                    CanonicalCaddyServedLeafReadback(root,bundle,expected,selected).record(
                        CanonicalPrivateIngressTrust.project(selected,spec).keys)
                    CanonicalCaddyCaseTlsBundle(root,bundle,expected,selected).sealAll()
                }
                bundle.request.forgejoCi?.let { ci ->
                    // Only after original Caddy issuer/current SNI readback. The
                    // pending source plan contains no future CA, IP or token ACK.
                    ForgejoCiNativeAccountOwner.provision()
                    ForgejoCiNativeSourceAdmission.requirePristineAccountNamespace(ci)
                    ForgejoCiNativeSystemd.start(bundle,root)
                }
                if (bundle.request.managedLanes != null) {
                    val controller=Path.of("/mnt/media/p0-v3/runtime-supervision/releases/" +
                        requireNotNull(spec.fragmentBinding?.controllerSha256) + "/bin/p0-v3-platform")
                    ManagedOriginalIdentityEnrollment.provision(bundle,root,expected,controller)
                    requireNotNull(GenerationManagedComponents.startInitial(bundle,root))
                }
                // A monotonic deadline is inherited by every native subprocess. Budget
                // the last 180 seconds for a bounded, original controlled StopUnit.
                while (!Files.exists(stopPath, NOFOLLOW_LINKS) && RecoveryDeadline.remainingMillis() > 180_000L) {
                    Thread.sleep(500)
                }
                if (!Files.exists(stopPath, NOFOLLOW_LINKS)) save(stopPath, json.encodeToString(
                    QuadletServeStopRequest(generation = generation, member = spec.name,
                        bundleSha256 = expected, reason = "monotonic-deadline")))
                val request = json.decodeFromString<QuadletServeStopRequest>(data(stopPath).decodeToString(throwOnInvalidSequence = true))
                require(request.schemaVersion == 1 && request.generation == generation &&
                    request.bundleSha256 == expected && request.member == spec.name &&
                    request.reason in setOf("operator-controlled", "monotonic-deadline"))
                notebookSocket?.close()
                notebookSocket = null
                notebookActor?.retireForShutdown()
                if (bundle.request.managedLanes != null)
                    requireNotNull(GenerationManagedComponents.isolate(bundle,root,"serve-stop"))
                if (bundle.request.forgejoCi != null)
                    require(ForgejoCiNativeSystemd.stopIfOwned(bundle,root))
                val stopped = owner.stop(bundle, expected, pin)
                RuntimeMaintenance.create(memberRoot, pin.runtimeFingerprint, "update", null)
                QuadletServeResult(bundleSha256 = expected, stoppedCids = stopped, fenced = true).also {
                    save(root.resolve("quadlet-serve.result.json"), json.encodeToString(it))
                }
            } catch (failure: Exception) {
                val interrupted = Thread.interrupted() || failure is InterruptedException
                // Only a completed original managed START may receive one original
                // isolation attempt. Missing result is uncertain, never inferred
                // from a live broker socket or used to replay a partial START.
                if (Files.exists(root.resolve("managed-start.result.json"),NOFOLLOW_LINKS) &&
                    !Files.exists(root.resolve("managed-isolate-serve-failure.intent.json"),NOFOLLOW_LINKS) &&
                    !Files.exists(root.resolve("managed-isolate-serve-stop.intent.json"),NOFOLLOW_LINKS))
                    try { requireNotNull(GenerationManagedComponents.isolate(bundle,root,"serve-failure")) }
                    catch (isolation: Exception) { failure.addSuppressed(isolation) }
                if (Files.exists(root.resolve("stage.result.json"),NOFOLLOW_LINKS) &&
                    bundle.request.forgejoCi != null)
                    try { require(ForgejoCiNativeSystemd.stopIfOwned(bundle,root)) }
                    catch (isolation: Exception) { failure.addSuppressed(isolation) }
                try { RuntimeMaintenance.create(memberRoot, pin.runtimeFingerprint, "update", null) }
                catch (fence: Exception) { failure.addSuppressed(fence) }
                // A failed stage performs its own one-shot stop attempts. Never replay
                // any of them here; absence of a result is a retained uncertainty.
                if (interrupted) Thread.currentThread().interrupt()
                throw failure
            } finally {
                notebookSocket?.close()
            }
        }
    }
    /** Read-only installed-unit, original import, resource and fence gate for
     * a restored Quadlet target. No fence removal or systemd StartUnit here.
     */
    fun auditImportedQuadletServing(generation: String, expected: String): String =
        RecoveryDeadline.within { locked {
            val (bundle, specs) = load(generation, expected)
            val pin = bundle.members.single()
            val spec = specs.single()
            val snapshot = requireNotNull(bundle.recoverySourceKopia)
            val root = base.resolve(generation)
            val outcome = json.decodeFromString<GenerationOutcome>(data(root.resolve("import.result.json")).decodeToString())
            val receipt = json.decodeFromString<KopiaSnapshotReceipt>(data(root.resolve("recovery.source.json")).decodeToString())
            val volumes = json.decodeFromString<List<QuadletColdImportVolumeResult>>(
                data(root.resolve("quadlet-import-member.result.json")).decodeToString())
            require(bundle.ownership == null && bundle.request.store == RuntimeStore.CANONICAL_V2 &&
                spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2 && spec.processes.none { it.oneShot } &&
                outcome.action == "restore-import" && outcome.passed && outcome.bundleSha256 == expected &&
                receipt == snapshot && volumes.map { it.volume } == spec.volumes.map { it.id } &&
                !Files.exists(root.resolve("stage.intent.json"), NOFOLLOW_LINKS))
            val fence = requireNotNull(RuntimeMaintenance.read(runtimeBase.resolve(spec.name), pin.runtimeFingerprint))
            require(fence.reason == "restore" && fence.id == outcome.fences[spec.name])
            admit(bundle)
            RuntimeQuadletResources(root, runtimeBase).auditProvisioned(spec, pin.runtimeFingerprint, pin.inputHashes)
            val installed = RuntimeQuadletInstalledAudit()
            spec.processes.forEach { installed.audit(spec, it) }
            fence.id
        } }
    /** Serve only an independently volume-verified recovered target through the
     * same installed systemd units and retained foreground CID owner as a fresh
     * installation. The source initializer is never invoked on this target.
     */
    fun serveImportedQuadlet(generation: String, expected: String): QuadletServeResult = mutating {
        val (bundle, specs) = load(generation, expected)
        val snapshot = requireNotNull(bundle.recoverySourceKopia)
        require(bundle.request.store == RuntimeStore.CANONICAL_V2 && bundle.ownership == null &&
            bundle.recoverySourceArchiveSha256 == null && bundle.members.size == 1 && specs.size == 1 &&
            specs.single().executionBackend == RuntimeExecutionBackend.QUADLET_V2 &&
            specs.single().processes.none { it.oneShot })
        val root = base.resolve(generation)
        // The foreground owner and the effective unit helpers must execute the
        // SAME immutable controller. Reject a development binary BEFORE the
        // first one-use delegation or restore-fence release intent.
        PinnedBackupController.verify(requireNotNull(specs.single().fragmentBinding?.controllerSha256))
        val imported = json.decodeFromString<GenerationOutcome>(data(root.resolve("import.result.json")).decodeToString())
        val intent = json.parseToJsonElement(data(root.resolve("import.intent.json")).decodeToString()).jsonObject
        val verificationId = requireNotNull(intent["verificationId"])?.jsonPrimitive?.content ?: error("Missing scratch verification")
        val original = snapshot.generation
        val sourceRoot = base.resolve(original)
        val sourceBundle = snapshot.bundleSha256
        val originalBundle = load(original, sourceBundle).first
        val terminal = requireNotNull(RuntimeQuadletCapacityTerminal.read(sourceRoot, originalBundle, sourceBundle))
        val verified = GenerationRecovery.validateKopia(sourceRoot.resolve("kopia-verifications/$verificationId/recovered"), snapshot)
        require(imported.action == "restore-import" && imported.passed && imported.bundleSha256 == expected &&
            imported.fences[specs.single().name] != null && verified.bundle == originalBundle &&
            json.decodeFromString<GenerationRecoveryCheck>(data(root.resolve("recovery.check.json")).decodeToString()) == verified.check &&
            !Files.exists(root.resolve("stage.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("quadlet-serve-stop.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("isolate.intent.json"), NOFOLLOW_LINKS))
        admit(bundle)
        val pin = bundle.members.single()
        val spec = specs.single()
        PrivateDeployment.withOrderedNativeLocks(listOf(originalBundle.members.single().spec.name, spec.name), runtimeBase) {
            require(RuntimeQuadletColdCapture(sourceRoot, originalBundle, sourceBundle, runtimeBase)
                .audit(originalBundle.members.single().spec, false).maintenanceId == terminal.fenceId)
            val memberRoot = runtimeBase.resolve(spec.name)
            val fence = requireNotNull(RuntimeMaintenance.read(memberRoot, pin.runtimeFingerprint))
            require(fence.id == imported.fences.getValue(spec.name) && fence.reason == "restore" &&
                fence.stageTarget == null)
            // Original release intent precedes removing the native restore fence.
            // A failed/unknown release must not be repeated or made into a new initializer.
            save(root.resolve("quadlet-import-release.intent.json"), json.encodeToString(mapOf(
                "bundleSha256" to expected, "member" to spec.name, "fenceId" to fence.id,
                "importResultSha256" to ReleaseLocks.sha256(data(root.resolve("import.result.json"))))))
            val stopPath = root.resolve("quadlet-serve-stop.intent.json")
            save(root.resolve("stage.intent.json"), json.encodeToString(GenerationIntent("stage", expected)))
            val onDemandNotebook = NotebookSelectedGraph.selected(root,spec)
            var notebookSocket: NotebookParentControlSocket? = null
            var notebookActor: NotebookParentActuator? = null
            try {
                RuntimeMaintenance.remove(memberRoot, pin.runtimeFingerprint, fence.id)
                require(RuntimeMaintenance.read(memberRoot, pin.runtimeFingerprint) == null)
                save(root.resolve("quadlet-import-release.result.json"), json.encodeToString(mapOf(
                    "bundleSha256" to expected, "fenceId" to fence.id, "released" to "true")))
                lateinit var actor: NotebookParentActuator
                val owner = RuntimeQuadletOwnerStage(root, runtimeBase, beforeProcessStart = { p ->
                    if (p.id == "keeper" && bundle.request.recoveredBaoOriginal != null) {
                        val controller=Path.of("/mnt/media/p0-v3/runtime-supervision/releases/" +
                            requireNotNull(spec.fragmentBinding?.controllerSha256) + "/bin/p0-v3-platform")
                        GenerationBaoColdRestore.startAfterImportedBao(bundle,expected,controller)
                    }
                    if (onDemandNotebook && p.id == "hub-controller") {
                        actor.retireOriginals()
                        notebookSocket = NotebookParentControlSocket(root,spec.name,
                            pin.inputHashes.getValue("jupyterhub-hub-settings.json"),actor,runtimeBase)
                        requireNotNull(notebookSocket).start()
                    }
                })
                if (onDemandNotebook) actor = NotebookParentActuator(bundle,pin,root,expected,owner,
                    runtimeRoot=runtimeBase).also { notebookActor = it }
                val statuses = owner.stage(bundle, expected, pin)
                require(statuses.size == spec.processes.size)
                save(root.resolve("${spec.name}.stage.result.json"), json.encodeToString(statuses))
                save(root.resolve("stage.result.json"), json.encodeToString(GenerationOutcome("stage", expected, true)))
                if (spec.processes.singleOrNull { it.id == "caddy" }?.files?.any {
                    it.file == "onlyoffice-office-web.pem" && it.target == "/run/secrets/office-web.pem"
                } == true) {
                    val selected=PackagedGraphFragment.pendingV3R9().first
                    CanonicalCaddyInternalCaCustody(root,bundle,expected,selected).record()
                    CanonicalCaddyServedLeafReadback(root,bundle,expected,selected).record(
                        CanonicalPrivateIngressTrust.project(selected,spec).keys)
                    CanonicalCaddyCaseTlsBundle(root,bundle,expected,selected).sealAll()
                }
                bundle.request.recoveredForgejoCiTarget?.let {
                    // Isolated target gets its own issuer/leaf and private IP;
                    // original source trust is never reused in RESTORE.
                    ForgejoCiNativeSystemd.start(bundle,root,recovered=true)
                }
                if (bundle.request.managedLanes != null) {
                    // PKCE owner authorization is issued ONLY by the now-running
                    // isolated target Keycloak, not captured source sessions. Hold
                    // this original foreground owner while awaiting its bounded
                    // operator grant; no managed credential effect is attempted.
                    val deadline=System.nanoTime()+java.util.concurrent.TimeUnit.MINUTES.toNanos(5)
                    val anchor=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/$generation")
                    while (!Files.exists(anchor.resolve("recovery-admin-grant.json"),NOFOLLOW_LINKS) ||
                        !Files.exists(anchor.resolve("recovery-owner-bearer"),NOFOLLOW_LINKS)) {
                        require(System.nanoTime()<deadline && !Files.exists(stopPath,NOFOLLOW_LINKS)) {
                            "Isolated target owner PKCE grant absent; no issuer revision attempted"
                        }
                        Thread.sleep(250)
                    }
                    val controller=Path.of("/mnt/media/p0-v3/runtime-supervision/releases/" +
                        requireNotNull(spec.fragmentBinding?.controllerSha256) + "/bin/p0-v3-platform")
                    ManagedOriginalIdentityEnrollment.provision(bundle,root,expected,controller)
                    requireNotNull(GenerationManagedComponents.startRecovered(bundle,root))
                }
                while (!Files.exists(stopPath, NOFOLLOW_LINKS) && RecoveryDeadline.remainingMillis() > 180_000L) Thread.sleep(500)
                if (!Files.exists(stopPath, NOFOLLOW_LINKS)) save(stopPath, json.encodeToString(
                    QuadletServeStopRequest(generation = generation, member = spec.name,
                        bundleSha256 = expected, reason = "monotonic-deadline")))
                val request = json.decodeFromString<QuadletServeStopRequest>(data(stopPath).decodeToString())
                require(request.schemaVersion == 1 && request.generation == generation && request.member == spec.name &&
                    request.bundleSha256 == expected && request.reason in setOf("operator-controlled", "monotonic-deadline"))
                notebookSocket?.close()
                notebookSocket = null
                notebookActor?.retireForShutdown()
                if (bundle.request.managedLanes != null)
                    requireNotNull(GenerationManagedComponents.isolate(bundle,root,"serve-stop"))
                if (bundle.request.recoveredForgejoCiTarget != null)
                    require(ForgejoCiNativeSystemd.stopIfOwned(bundle,root))
                val stopped = owner.stop(bundle, expected, pin)
                RuntimeMaintenance.create(memberRoot, pin.runtimeFingerprint, "update", null)
                QuadletServeResult(bundleSha256 = expected, stoppedCids = stopped, fenced = true).also {
                    save(root.resolve("quadlet-serve.result.json"), json.encodeToString(it))
                }
            } catch (failure: Exception) {
                val interrupted = Thread.interrupted() || failure is InterruptedException
                if (Files.exists(root.resolve("managed-start.result.json"),NOFOLLOW_LINKS) &&
                    !Files.exists(root.resolve("managed-isolate-serve-failure.intent.json"),NOFOLLOW_LINKS) &&
                    !Files.exists(root.resolve("managed-isolate-serve-stop.intent.json"),NOFOLLOW_LINKS))
                    try { requireNotNull(GenerationManagedComponents.isolate(bundle,root,"serve-failure")) }
                    catch (isolation: Exception) { failure.addSuppressed(isolation) }
                if (Files.exists(root.resolve("stage.result.json"),NOFOLLOW_LINKS) &&
                    bundle.request.recoveredForgejoCiTarget != null)
                    try { require(ForgejoCiNativeSystemd.stopIfOwned(bundle,root)) }
                    catch (isolation: Exception) { failure.addSuppressed(isolation) }
                if (Files.exists(root.resolve("stage.result.json"),NOFOLLOW_LINKS) &&
                    !Files.exists(root.resolve("quadlet-serve.result.json"),NOFOLLOW_LINKS) &&
                    pin.spec.processes.none { Files.exists(root.resolve(
                        "quadlet-stop-${spec.name}-${it.id}.intent.json"),NOFOLLOW_LINKS) })
                    try { RuntimeQuadletOwnerStage(root,runtimeBase).stop(bundle,expected,pin) }
                    catch (isolation: Exception) { failure.addSuppressed(isolation) }
                try { RuntimeMaintenance.create(memberRoot, pin.runtimeFingerprint, "update", null) }
                catch (fenceFailure: Exception) { failure.addSuppressed(fenceFailure) }
                if (interrupted) Thread.currentThread().interrupt()
                throw failure
            } finally {
                notebookSocket?.close()
            }
        }
    }
    /** Single owned private development member: systemd/Quadlet owns process starts.
     * No direct-Podman backend is selected. A failed/uncertain original retains its
     * reservation and fences; the owner never calls stage() as a fallback.
     */
    fun stageQuadlet(generation: String, expected: String): GenerationOutcome = mutating {
        val (bundle, specs) = load(generation, expected)
        require(bundle.ownership != null && bundle.request.store == RuntimeStore.CANONICAL_V2 &&
            bundle.members.size == 1 && specs.size == 1 &&
            specs.single().executionBackend == RuntimeExecutionBackend.QUADLET_V2 &&
            bundle.recoverySourceArchiveSha256 == null && bundle.recoverySourceKopia == null &&
            !Files.exists(base.resolve(generation).resolve("stage.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(base.resolve(generation).resolve("isolate.intent.json"), NOFOLLOW_LINKS)) {
            "Quadlet stage requires a fresh owned single-member private generation"
        }
        val pin = bundle.members.single()
        val spec = specs.single()
        require(spec.processes.all { it.oneShot }) {
            "Native serving-unit foreground custody is not implemented; do not start even an initializer"
        }
        admit(bundle) // Retired-generation audits must precede this member's native lock.
        PrivateDeployment.withOrderedNativeLocks(listOf(spec.name), runtimeBase) {
            require(load(generation, expected).first == bundle)
            RuntimeQuadletPreflight.verify(spec)
            val root = base.resolve(generation)
            save(root.resolve("stage.intent.json"), json.encodeToString(GenerationIntent("stage", expected)))
            try {
                val statuses = RuntimeQuadletOwnerStage(root, runtimeBase).stage(bundle, expected, pin)
                require(statuses.size == spec.processes.size)
                save(root.resolve("${spec.name}.stage.result.json"), json.encodeToString(statuses))
                GenerationOutcome("stage", expected, true).also {
                    save(root.resolve("stage.result.json"), json.encodeToString(it))
                }
            } catch (failure: Exception) {
                val interrupted = Thread.interrupted() || failure is InterruptedException
                try {
                    GenerationOutcome("stage", expected, false, failure.javaClass.name).also {
                        save(root.resolve("stage.result.json"), json.encodeToString(it))
                    }
                } finally { if (interrupted) Thread.currentThread().interrupt() }
            }
        }
    }
    /** BEFORE any successor seal: exactly the serving owner's live retained-
     * generation capacity planner and native-lock census, not a source budget.
     * The synthetic prospective pins are never saved or treated as an ACK. */
    fun prospectiveLiveAdmission(plan:AssemblyPlan,contract:SiteOwnership,approvedHosts:Set<String>):String = mutating {
        require(base==BASE && runtimeBase==PrivateDeployment.BASE &&
            !Files.exists(base.resolve(plan.generation.id),NOFOLLOW_LINKS) &&
            plan.generation.id==GenerationAfterQ07Lineage.generation &&
            plan.specs.size==1 && plan.specs.single().processes.size==134 &&
            plan.generation.members.size==1)
        val qc3=base.resolve("q-c3a7a9e29391/qc3-pre-native-capacity-no-start-v1.disposition.json")
        GenerationAfterCapacityRefusalLineage.verify(
            requireNotNull(plan.generation.qc3PreparedNoStartPredecessor),
            requireNotNull(plan.generation.uncertainNativeImportPredecessor),
            requireNotNull(plan.generation.isolatedRootlessProbePredecessor))
        Qc3PreparedNoStartTerminal.verify(ActivationInput(qc3.toString(),
            ReleaseLocks.sha256(ReleasePrivateFiles.read(qc3,1048576))))
        GenerationAfterQ273Lineage.verify(requireNotNull(plan.generation.q273UncertainImportPredecessor),
            requireNotNull(plan.generation.qc3PreparedNoStartPredecessor),
            requireNotNull(plan.generation.uncertainNativeImportPredecessor),
            requireNotNull(plan.generation.isolatedRootlessProbePredecessor))
        WorklaneLateBrokerImportProof.verifySelected(requireNotNull(plan.generation.managedLanes).native.worklane)
        GenerationAfterQ583Lineage.verify(requireNotNull(plan.generation.q583PreparedNoStartPredecessor),
            requireNotNull(plan.generation.isolatedFullWorklanePreparePredecessor),
            requireNotNull(plan.generation.q273UncertainImportPredecessor),
            requireNotNull(plan.generation.qc3PreparedNoStartPredecessor),
            requireNotNull(plan.generation.uncertainNativeImportPredecessor),
            requireNotNull(plan.generation.isolatedRootlessProbePredecessor))
        WorklaneFullPrepareReturnProbe.verifyLive(
            requireNotNull(plan.generation.isolatedFullWorklanePreparePredecessor))
        GenerationAfterQ9bLineage.verify(requireNotNull(plan.generation.q9bColdPreparedUninstalledPredecessor),
            requireNotNull(plan.generation.q583PreparedNoStartPredecessor),
            requireNotNull(plan.generation.isolatedFullWorklanePreparePredecessor),
            requireNotNull(plan.generation.q273UncertainImportPredecessor),
            requireNotNull(plan.generation.qc3PreparedNoStartPredecessor),
            requireNotNull(plan.generation.uncertainNativeImportPredecessor),
            requireNotNull(plan.generation.isolatedRootlessProbePredecessor))
        GenerationAfterQ07Lineage.verify(requireNotNull(plan.generation.q07PartialInstalledPredecessor),
            requireNotNull(plan.generation.q9bColdPreparedUninstalledPredecessor),
            requireNotNull(plan.generation.q583PreparedNoStartPredecessor),
            requireNotNull(plan.generation.isolatedFullWorklanePreparePredecessor),
            requireNotNull(plan.generation.q273UncertainImportPredecessor),
            requireNotNull(plan.generation.qc3PreparedNoStartPredecessor),
            requireNotNull(plan.generation.uncertainNativeImportPredecessor),
            requireNotNull(plan.generation.isolatedRootlessProbePredecessor))
        val bound=SiteOwnerships.bind(plan,contract,approvedHosts)
        val request=plan.generation
        PinnedBackupController.verifyDistribution(Path.of("/mnt/media/p0-v3/runtime-supervision/releases/"+
            requireNotNull(request.releaseCandidateSha256)),requireNotNull(request.releaseCandidateSha256),
            "p0-v3-platform")
        val selected=plan.specs.single()
        GenerationR9ImageStore.verifySelected(request.id,selected)
        ForgejoCiNativeSourceAdmission.checkProspective(requireNotNull(request.forgejoCi))
        RuntimeQuadletPreflight.verify(selected)
        val specSha=ReleaseLocks.sha256(json.encodeToString(selected).toByteArray())
        val resource=GenerationCapacityPlanner.plan(plan.specs,request.diskReservationMiB,request.workingBudget)
        val provisional=GenerationBundle(request,
            listOf(GenerationPin(request.members.single(),specSha,emptyMap(),specSha,selected)),
            resource.install.memoryMiB,ownership=bound)
        admit(provisional)
        "same-live-admit-passed:old-q4d-q273-q9b-q07-physical-disk-retained:synthetic-prospective-pins-not-sealed"
    }
    private fun admit(bundle: GenerationBundle, workers: Int = 0) {
        val measured = capacity(bundle.request.store)
        RuntimeLockBudget.requireAvailable(measured.availableRuntimeLocks, bundle.members.map { it.spec }, workers)
        var reservedMemory = 0L
        var reservedDisk = 0L
        val retired = mutableListOf<Triple<GenerationBundle, List<PrivateDeploymentSpec>, List<GenerationOutcome>>>()
        val quadletTerminalCids = mutableMapOf<String, Map<String, String>>()
        val separatelyDisposedMembers = mutableSetOf<String>()
        val retainedUncertainImports = mutableListOf<GenerationBundle>()
        val retainedPartialInstalled = mutableListOf<GenerationBundle>()
        Files.list(base).use { paths ->
            val entries = paths.filter { it.fileName.toString() != "generation.lock" }.limit(4097).toList()
            require(entries.size <= 4096) { "Generation registry bound reached; no automatic evidence deletion" }
            for (path in entries) {
                require(id.matches(path.fileName.toString())) { "Unknown generation registry entry" }
                directory(path)
                val begin = path.resolve("stage.intent.json")
                if (base==BASE && path.fileName.toString()==Q07PartialInstalledUnitTerminal.generation &&
                    Files.exists(path.resolve("quadlet-install-q-083e9b7d2a64-v2.intent.json"),NOFOLLOW_LINKS)) {
                    require(!Files.exists(begin,NOFOLLOW_LINKS))
                    val bytes=data(path.resolve("bundle.json"))
                    val existing=json.decodeFromString<GenerationBundle>(bytes.decodeToString())
                    ordered(existing.request)
                    val record=path.resolve("partial-disabled-quadlet-install-umask-v1.disposition.json")
                    val terminal=Q07PartialInstalledUnitTerminal.verify(ActivationInput(
                        record.toString(),ReleaseLocks.sha256(ReleasePrivateFiles.read(record,262144))))
                    require(existing.request.id==terminal.generation &&
                        ReleaseLocks.sha256(bytes)==terminal.bundleSha256 &&
                        existing.members.single().spec.name==terminal.member)
                    retainedPartialInstalled+=existing
                    reservedDisk=Math.addExact(reservedDisk,existing.request.diskReservationMiB)
                    continue
                }
                if (!Files.exists(begin, NOFOLLOW_LINKS)) continue
                val intent = json.decodeFromString<GenerationIntent>(data(begin).decodeToString())
                require(intent.action in setOf("stage", "restore-import")) { "Invalid capacity reservation intent" }
                val bytes = data(path.resolve("bundle.json"))
                require(ReleaseLocks.sha256(bytes) == intent.bundleSha256) { "Reserved generation changed" }
                val existing = json.decodeFromString<GenerationBundle>(bytes.decodeToString())
                ordered(existing.request)
                require(existing.request.id == path.fileName.toString() && existing.memoryReservationMiB > 0) { "Invalid reservation" }
                // Imported startup is admitted against the existing sealed target, not charged twice.
                // The caller validates its completed import before reaching this admission boundary.
                if (existing.request.id == bundle.request.id) {
                    require(existing == bundle) { "Existing target reservation differs from sealed startup" }
                    continue
                }
                if (base==BASE && existing.request.id==Q9bColdPreparedUninstalledTerminal.generation) {
                    val record=path.resolve("cold-three-lane-prepare-uninstalled-stage-v1.disposition.json")
                    val terminal=Q9bColdPreparedUninstalledTerminal.verify(ActivationInput(
                        record.toString(),ReleaseLocks.sha256(ReleasePrivateFiles.read(record,1048576))))
                    require(terminal.bundleSha256==intent.bundleSha256 &&
                        existing.members.single().spec.name==terminal.member &&
                        !Files.exists(path.resolve("stage.result.json"),NOFOLLOW_LINKS))
                    retainedUncertainImports+=existing
                    reservedDisk=Math.addExact(reservedDisk,existing.request.diskReservationMiB)
                    continue
                }
                if (base==BASE && existing.request.id==Q273UncertainManagedImportTerminal.generation) {
                    val terminal=Q273UncertainManagedImportTerminal.verify(ActivationInput(
                        path.resolve("uncertain-native-worklane-manifest-import-v1.disposition.json").toString(),
                        ReleaseLocks.sha256(ReleasePrivateFiles.read(path.resolve(
                            "uncertain-native-worklane-manifest-import-v1.disposition.json"),1048576))))
                    require(terminal.bundleSha256==intent.bundleSha256 &&
                        existing.members.single().spec.name==terminal.member &&
                        !Files.exists(path.resolve("stage.result.json"),NOFOLLOW_LINKS))
                    // Its manifest and VFS image are NOT a completed PREPARE.
                    // Only inactive RAM may be unreserved; all disk stays charged.
                    retainedUncertainImports+=existing
                    reservedDisk=Math.addExact(reservedDisk,existing.request.diskReservationMiB)
                    continue
                }
                if (base==BASE && existing.request.id=="q-4d3c1cb287e5") {
                    val terminal=ManagedUncertainImageImportTerminal.verify(ActivationInput(
                        path.resolve("uncertain-native-worklane-import-v1.disposition.json").toString(),
                        "d731a2136e435d3e1bfa5b183a0c74a6cf987788376c7f5df292c4315c7451bb"))
                    require(terminal.bundleSha256==intent.bundleSha256 &&
                        existing.members.single().spec.name==terminal.member &&
                        !Files.exists(path.resolve("stage.result.json"),NOFOLLOW_LINKS))
                    // Physical original graph/state and the FULL old disk reservation
                    // remain charged. Only inactive process RAM is eligible for release.
                    retainedUncertainImports+=existing
                    reservedDisk=Math.addExact(reservedDisk,existing.request.diskReservationMiB)
                    continue
                }
                val outcomes = isolationOutcomes(path, intent.bundleSha256).filter { it.passed }.toMutableList()
                if (base == BASE && existing.members.size == 1 &&
                    existing.members.single().spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2) {
                    val terminal = RuntimeQuadletCapacityTerminal.read(path, existing, intent.bundleSha256)
                    val failedStage = RuntimeQuadletCapacityTerminal.failedStage(path, existing, intent.bundleSha256)
                    val separate = RuntimeQuadletTerminalDisposition.read(path,existing,intent.bundleSha256)
                    require(listOfNotNull(terminal,failedStage,separate).size <= 1) {
                        "Conflicting Quadlet original and separate terminal observations"
                    }
                    val observed = terminal?.let { it.fenceId to it.stoppedCids } ?:
                        failedStage ?: separate?.let { it.fenceId to it.originalCids }
                    if (observed != null) {
                        val member = existing.members.single().spec.name
                        quadletTerminalCids[member] = observed.second
                        if (separate != null) separatelyDisposedMembers += member
                        outcomes += GenerationOutcome(if (separate != null)
                            "quadlet-separate-physical-terminal-disposition" else "quadlet-capacity-observation",
                            intent.bundleSha256, true, fences = mapOf(member to observed.first))
                        // A separate physical disposition releases only capacity after
                        // fresh locked readback; it is NEVER an original serve/stop ACK.
                    }
                }
                if (outcomes.isNotEmpty()) {
                    val (sealed, specs) = load(existing.request.id, intent.bundleSha256, checkLiveInputs = false)
                    retired += Triple(sealed, specs, outcomes)
                    continue
                }
                reservedMemory = Math.addExact(reservedMemory, existing.memoryReservationMiB)
                reservedDisk = Math.addExact(reservedDisk, existing.request.diskReservationMiB)
            }
        }
        for (old in retainedPartialInstalled) {
            PrivateDeployment.withOrderedNativeLocks(listOf(old.members.single().spec.name),runtimeBase) {
                val record=base.resolve(old.request.id).resolve("partial-disabled-quadlet-install-umask-v1.disposition.json")
                Q07PartialInstalledUnitTerminal.verifyLive(old,ActivationInput(
                    record.toString(),ReleaseLocks.sha256(ReleasePrivateFiles.read(record,262144))))
            }
        }
        for (old in retainedUncertainImports) {
            PrivateDeployment.withOrderedNativeLocks(listOf(old.members.single().spec.name),runtimeBase) {
                val physical=when(old.request.id) {
                    Q9bColdPreparedUninstalledTerminal.generation -> {
                        val record=base.resolve(old.request.id)
                            .resolve("cold-three-lane-prepare-uninstalled-stage-v1.disposition.json")
                        Q9bColdPreparedUninstalledTerminal.verifyLive(old,ActivationInput(
                            record.toString(),ReleaseLocks.sha256(ReleasePrivateFiles.read(record,1048576))))
                            .graphAllocatedBytes
                    }
                    Q273UncertainManagedImportTerminal.generation ->
                        Q273UncertainManagedImportTerminal.verifyLiveInactive(old)
                    else -> ManagedUncertainImageImportTerminal.verifyLiveInactive(old)
                }
                require(physical>=4294967296L &&
                    Math.multiplyExact(old.request.diskReservationMiB,1048576L)>=physical)
            }
        }
        if (retired.isNotEmpty() && base != BASE) {
            // Isolated unit fixtures inject a fake backend, not the real Podman store.
            // Preserve their per-resource audit contract; production below uses the
            // bounded native census and still checks every original fence.
            for ((sealed, specs, outcomes) in retired) {
                val runtime = backend(sealed)
                val audits = specs.map { runtime.audit(it, false) }
                require(outcomes.any { result -> result.fences.keys == specs.map { it.name }.toSet() && audits.all { audit ->
                    audit.maintenanceId == result.fences[audit.name] && audit.maintenanceId != null &&
                        audit.statuses.none { it.state in setOf("running", "paused", "restarting") }
                } }) { "Isolation evidence is stale; reservation cannot be released" }
            }
        } else if (retired.isNotEmpty()) {
            val members = retired.flatMap { it.second.map(PrivateDeploymentSpec::name) }
            // Acquire every retired member's native locks in order before a single
            // per-store census. No current target lock is held at this boundary.
            PrivateDeployment.withOrderedNativeLocks(members, runtimeBase) {
                val census = retiredCensus
                val stores = retired.map { it.first.request.store }.distinct()
                    .associateWith(census::snapshot)
                val ownership = retired.flatMap { (sealed, specs, _) ->
                    val pins = sealed.members.associateBy { it.spec.name }
                    specs.map { spec -> sealed.request.store to RuntimeCapacityCensus.Member(
                        spec, requireNotNull(pins[spec.name]).runtimeFingerprint) }
                }.groupBy({ it.first }, { it.second })
                require(stores.all { (store, observed) ->
                    census.quiescent(ownership.getValue(store), observed) &&
                        quadletTerminalCids.all { (member, cids) ->
                            val owner = ownership[store]?.singleOrNull { it.spec.name == member }
                            owner == null || RuntimeQuadletCapacityTerminal.matchesOriginalCids(member, cids, observed) &&
                                (member !in separatelyDisposedMembers || observed.filter {
                                    it.member == member || it.name.startsWith("p0v3-live-$member-")
                                }.all { it.state == "exited" })
                        }
                }) { "Native namespace, label, exact original CID or process state disagrees with retired capacity evidence" }
                for ((sealed, specs, outcomes) in retired) {
                    if (outcomes.any { it.action == "quadlet-separate-physical-terminal-disposition" }) {
                        val generationRoot=base.resolve(sealed.request.id)
                        val evidence=RuntimeQuadletTerminalDisposition.read(generationRoot,sealed,
                            ReleaseLocks.sha256(data(generationRoot.resolve("bundle.json"))))
                        RuntimeQuadletTerminalDisposition.requireCurrentUnits(generationRoot,sealed,requireNotNull(evidence))
                    }
                    val pins = sealed.members.associateBy { it.spec.name }
                    require(outcomes.any { result ->
                        result.fences.keys == specs.map { it.name }.toSet() && specs.all { spec ->
                            val pin = pins[spec.name] ?: return@all false
                            val fence = RuntimeMaintenance.read(runtimeBase.resolve(spec.name), pin.runtimeFingerprint)
                            fence != null && fence.id == result.fences[spec.name]
                        }
                    }) { "Isolation evidence is stale; reservation cannot be released" }
                }
            }
        }
        // Runtime apply is serial and topological. Do not add every completed initializer to the
        // serving peak, but keep historical sealed reservation bytes and conservative reservations
        // for other active/uncertain generations unchanged. Import still reserves startup capacity.
        val resources = GenerationCapacityPlanner.plan(bundle.members.map { it.spec }, bundle.request.diskReservationMiB,
            bundle.request.workingBudget)
        require(!resources.incrementalFirstStart ||
            (bundle.recoverySourceKopia == null && bundle.recoverySourceArchiveSha256 == null &&
                bundle.ownedUpdate == null)) {
            "Provisional original first-start budget cannot authorize RESTORE or update overlap"
        }
        val phase = GenerationCapacityPlanner.phase(resources, GenerationPhase.INSTALL,
            work = GenerationResources(Math.addExact(workers * 1024L, GenerationManagedComponents.memoryReservationMiB(bundle.request)),
                0, workers.toLong()),
            retained = GenerationResources(reservedMemory, reservedDisk, 0),
            memoryHeadroomMiB = bundle.request.memoryHeadroomMiB, diskHeadroomMiB = bundle.request.diskHeadroomMiB)
        GenerationCapacityPlanner.admit(phase, measured.availableMemoryMiB, measured.usableDiskMiB, measured.availableRuntimeLocks)
    }
    /** Imports only the compiled foundation/SQL-cache cohort into new namespaces. Leaves every target fenced and stopped. */
    fun restoreFoundation(inventory: AcquiredInventory, source: String, sourceBundle: String, captureId: String, target: String,
        custody: Path = Path.of("/mnt/media/p0-v3/generation-custody")): GenerationOutcome =
        restoreCold(inventory, source, sourceBundle, captureId, target, custody, ColdRestoreCohort.FOUNDATION)

    fun restoreApplications(inventory: AcquiredInventory, source: String, sourceBundle: String, captureId: String, target: String,
        custody: Path = Path.of("/mnt/media/p0-v3/generation-custody")): GenerationOutcome =
        restoreCold(inventory, source, sourceBundle, captureId, target, custody, ColdRestoreCohort.APPLICATIONS)

    fun restoreCanonicalCore(inventory: AcquiredInventory, source: String, sourceBundle: String, captureId: String, target: String,
        custody: Path = Path.of("/mnt/media/p0-v3/generation-custody")): GenerationOutcome =
        restoreCold(inventory, source, sourceBundle, captureId, target, custody, ColdRestoreCohort.CANONICAL_CORE)

    private fun restoreCold(inventory: AcquiredInventory, source: String, sourceBundle: String, captureId: String, target: String,
        custody: Path, cohort: ColdRestoreCohort, kopia: GenerationSnapshotStore? = null,
        targetStore: RuntimeStore = RuntimeStore.LEGACY): GenerationOutcome = mutating {
        require(id.matches(target) && captureId.matches(Regex("cap-[a-f0-9]{12}")))
        val (original, _) = load(source, sourceBundle, checkLiveInputs = false)
        val captureRoot = base.resolve(source).resolve("${if (kopia == null) "captures" else "kopia-captures"}/$captureId"); directory(captureRoot)
        val archive = captureRoot.resolve("state.cap"); val key = custody.resolve(if (kopia == null) "$captureId.key" else "$source.env")
        val verified: CapsuleVerification?
        val snapshot: KopiaSnapshotReceipt?
        if (kopia == null) {
            val prior = json.decodeFromString<GenerationCaptureOutcome>(data(captureRoot.resolve("capture.result.json")).decodeToString())
            require(prior.passed && prior.id == captureId && prior.bundleSha256 == sourceBundle)
            verified = RecoveryCapsule.verify(archive, key, captureId, source, sourceBundle)
            require(verified == prior.verification) { "Capture differs from retained verification" }
            snapshot = null
        } else {
            val prior = json.decodeFromString<KopiaCaptureOutcome>(data(captureRoot.resolve("capture.result.json")).decodeToString())
            snapshot = requireNotNull(prior.snapshot)
            require(prior.passed && prior.id == captureId && prior.bundleSha256 == sourceBundle && snapshot.id == captureId &&
                snapshot.generation == source && snapshot.bundleSha256 == sourceBundle) { "Kopia capture binding mismatch" }
            KopiaGenerationStore.validate(snapshot)
            verified = null
        }
        val stateHash = verified?.archiveSha256 ?: KopiaGenerationStore.receiptHash(requireNotNull(snapshot))
        val ciGrant = (original.request.forgejoCi ?: original.request.recoveredForgejoCiTarget)?.let { sourcePlan ->
            require(kopia != null && cohort == ColdRestoreCohort.WHOLE_RELEASE &&
                targetStore == RuntimeStore.CANONICAL_V2) { "CI requires complete private Kopia recovery" }
            val grant = json.decodeFromString<ForgejoCiRecoveryGrant>(privateInput(
                ForgejoCiRecoveryGrant.path(target)).decodeToString(throwOnInvalidSequence = true))
            grant.validate(sourcePlan, target)
            val registered = json.decodeFromString<ForgejoCiRegistrationResult>(data(base.resolve(source)
                .resolve("ci/registration.result.json")).decodeToString(throwOnInvalidSequence = true))
            require(grant.sourceBundleSha256 == sourceBundle && grant.originalRunnerId == registered.runnerId)
            for (input in listOf(grant.managementToken, grant.newRegistrationToken)) {
                val bytes = privateInput(Path.of(input.path))
                require(bytes.size in 20..4096 && ReleaseLocks.sha256(bytes) == input.sha256)
                bytes.fill(0)
            }
            grant
        }
        // A managed plan requires the authenticated ORIGINAL manifest embedded in the
        // Kopia payload before a target plan can be purely compiled. Publish the fixed
        // import reference and scratch budget BEFORE this repository read, not a dummy
        // target bundle or an invented fresh identity from the source home.
        val managedPrecompile = original.request.managedLanes != null
        val root = base.resolve(target)
        val recovered = root.resolve("recovered")
        val earlyChecked: RecoveredGeneration? = if (managedPrecompile) {
            require(kopia != null && snapshot != null && cohort == ColdRestoreCohort.WHOLE_RELEASE &&
                targetStore == RuntimeStore.CANONICAL_V2 && !Files.exists(root, NOFOLLOW_LINKS))
            val capacity = capacity(RuntimeStore.CANONICAL_V2)
            require(capacity.availableMemoryMiB >= original.memoryReservationMiB +
                original.request.memoryHeadroomMiB + 2048 && capacity.usableDiskMiB >=
                Math.addExact(original.request.diskHeadroomMiB,
                    Math.addExact(Math.multiplyExact(3L, original.request.diskReservationMiB), 512L))) {
                "Managed cold projection and import budget must precede its first repository effect"
            }
            admitRecoveryScratch(original.request, capacity, 4)
            RuntimeLockBudget.requireAvailable(capacity.availableRuntimeLocks, workers = 3)
            RecoveryReferenceOperations.protect(base, snapshot, "import", target)
            Files.createDirectory(root, PosixFilePermissions.asFileAttribute(privateDir))
            FileChannel.open(base, READ).use { it.force(true) }
            save(root.resolve("managed-precompile.intent.json"), json.encodeToString(snapshot))
            kopia.restore(base.resolve(source).resolve("kopia-store/repository"), key, root, snapshot, recovered)
            GenerationRecovery.validateKopia(recovered, snapshot).also { require(it.bundle == original) }
        } else null
        val managedSourceManifest = earlyChecked?.let { data(recovered.resolve("managed/source-manifest.toml")) }
        val compiled = FoundationRestore.bundle(original, inventory, target, stateHash, cohort, targetStore,
            managedSourceManifest, original.request.managedLanes?.native?.imageArchive, ciRecoveryGrant = ciGrant)
        val bundle = if (snapshot == null) compiled else compiled.copy(recoverySourceArchiveSha256 = null, recoverySourceKopia = snapshot)
        directory(runtimeBase)
        for (pin in bundle.members) require(!Files.exists(runtimeBase.resolve(pin.spec.name), NOFOLLOW_LINKS) &&
            !Files.exists(runtimeBase.resolve("${pin.spec.name}.json"), NOFOLLOW_LINKS)) { "Restore requires fresh input namespaces" }
        val runtime = backend(bundle)
        val importer = runtime as? GenerationImportBackend ?: error("Native import backend unavailable")
        admit(bundle, workers = if (kopia == null) 0 else 2)
        if (earlyChecked == null) {
            Files.createDirectory(root, PosixFilePermissions.asFileAttribute(privateDir))
            FileChannel.open(base, READ).use { it.force(true) }
        } else directory(root)
        val text = json.encodeToString(bundle); val expected = ReleaseLocks.sha256(text.toByteArray())
        save(root.resolve("bundle.json"), text)
        save(root.resolve("stage.intent.json"), json.encodeToString(GenerationIntent("restore-import", expected)))
        save(root.resolve("recovery.source.json"), if (snapshot == null) json.encodeToString(requireNotNull(verified)) else json.encodeToString(snapshot))
        val fences = linkedMapOf<String, String>()
        fun failed(error: Exception): GenerationOutcome {
            var interrupted = Thread.interrupted() || error is InterruptedException
            val result = GenerationOutcome("restore-import", expected, false, error.javaClass.name, fences)
            var recordingFailure: Exception? = null
            fun retain(failure: Exception) {
                interrupted = Thread.interrupted() || failure is InterruptedException || interrupted
                if (recordingFailure == null) recordingFailure = failure else recordingFailure!!.addSuppressed(failure)
            }
            try {
                try { save(root.resolve("stage.result.json"), json.encodeToString(result)) }
                catch (failure: InterruptedException) { retain(failure) }
                catch (failure: Exception) { retain(failure) }
                // Independent immutable isolation intent/outcome: a failed result write must not skip cleanup.
                // Missing/changed inputs fail closed; never regenerate credentials just to make isolation pass.
                try { isolateLocked(target, expected) }
                catch (failure: InterruptedException) { retain(failure) }
                catch (failure: Exception) { retain(failure) }
                recordingFailure?.let { it.addSuppressed(error); throw it }
                return result
            } finally { if (interrupted) Thread.currentThread().interrupt() }
        }
        try {
            val checked = if (earlyChecked != null) earlyChecked else if (kopia == null) {
                RecoveryCapsule.extract(archive, key, captureId, source, sourceBundle, recovered)
                GenerationRecovery.validate(recovered, requireNotNull(verified))
            } else {
                RecoveryReferenceOperations.protect(base, requireNotNull(snapshot), "import", target)
                kopia.restore(base.resolve(source).resolve("kopia-store/repository"), key, root, snapshot, recovered)
                GenerationRecovery.validateKopia(recovered, snapshot)
            }
            require(checked.bundle == original)
            save(root.resolve("recovery.check.json"), json.encodeToString(checked.check))
            // Only the authenticated, hash-bound original capsule may supply bounded
            // controller/actor custody. Import before native member/volume allocation;
            // CREATE_NEW retains uncertainty on interruption, never reissues a grant.
            if (checked.manifest.controllerFiles.isNotEmpty()) {
                require(base == BASE && runtimeBase == PrivateDeployment.BASE && snapshot != null &&
                    targetStore == RuntimeStore.CANONICAL_V2)
                RecoveryControllerPayloads.restore(checked, root)
            }
            if (managedPrecompile) GenerationManagedComponents.importRecovered(original, bundle,
                checked.manifest, recovered, root)
            for (index in bundle.members.indices) {
                val pin = bundle.members[index]; val old = original.members[index]
                RuntimePreparation.prepare(pin.spec, runtimeBase) {
                    pin.inputHashes.mapValues { (file, _) ->
                        val bytes = data(recovered.resolve("${old.spec.name}/inputs/$file"))
                        require(ReleaseLocks.sha256(bytes) == pin.inputHashes.getValue(file))
                        bytes.decodeToString(throwOnInvalidSequence = true)
                    }
                }
                require(this.pin(pin.member).first == pin) { "Prepared restoration inputs differ from sealed definitions" }
            }
            bundle.members.forEach { runtime.audit(it.spec, true) } // All member/image audits before allocation.
            if (checked.manifest.credentialFiles.isNotEmpty()) {
                require(base == BASE && runtimeBase == PrivateDeployment.BASE && snapshot != null &&
                    targetStore == RuntimeStore.CANONICAL_V2)
                PrivateDeployment.withOrderedNativeLocks((original.members + bundle.members)
                    .map { it.spec.name }.distinct(), runtimeBase) {
                    requireNotNull(NativeCredentialRevision.importOriginal(original, bundle,
                        checked.manifest, recovered, root))
                }
            }
            for (index in bundle.members.indices) {
                val pin = bundle.members[index]; val old = original.members[index]
                save(root.resolve("${pin.spec.name}.import.intent.json"), json.encodeToString(GenerationIntent("import-member", expected)))
                val verification = root.resolve("verify-${pin.spec.name}")
                Files.createDirectory(verification, PosixFilePermissions.asFileAttribute(privateDir))
                FileChannel.open(root, READ).use { it.force(true) }
                val inputs = pin.spec.volumes.associate { it.id to recovered.resolve("${old.spec.name}/volumes/${it.id}.tar") }
                val expectedHashes = pin.spec.volumes.associate { volume ->
                    val name = "${old.spec.name}/volumes/${volume.id}.tar"
                    volume.id to (checked.manifest.volumes.singleOrNull { it.name == name }?.sha256
                        ?: checked.manifest.files.single { it.name == name }.sha256)
                }
                fences[pin.spec.name] = importer.importCold(pin.spec, inputs, stateHash, verification, expectedHashes).id
                save(root.resolve("${pin.spec.name}.import.result.json"), json.encodeToString(runtime.audit(pin.spec, false)))
            }
            val result = GenerationOutcome("restore-import", expected, true, fences = fences)
            save(root.resolve("stage.result.json"), json.encodeToString(result))
            result
        } catch (error: InterruptedException) { failed(error); throw error }
        catch (error: Exception) { failed(error) }
    }
    /** The only owned Planka update import. Read the PREPARED RAW inventory pins: decoding and
     * reserializing an AcquiredInventory is not evidence for the frozen inventory SHA. Restored
     * target state remains private and fenced; this does not adopt a site or recovery authority. */
    fun importOwnedUpdate(preparation: ReleaseUpdatePreparation, captureId: String, transactionId: String,
        custody: Path = Path.of("/mnt/media/p0-v3/kopia-custody"), store: GenerationSnapshotStore? = null): GenerationOutcome = mutating {
        val intent = preparation.intent
        preparation.validate(intent.source, intent.targetGeneration, base)
        require(captureId.matches(Regex("cap-[a-f0-9]{12}")) &&
            transactionId.matches(Regex("[a-z][a-z0-9-]{0,63}")))
        val oldBytes = ReleasePrivateFiles.read(Path.of(preparation.previousInventory.path))
        val newBytes = ReleasePrivateFiles.read(Path.of(preparation.candidateInventory.path))
        require(ReleaseLocks.sha256(oldBytes) == intent.previousInventorySha256 &&
            ReleaseLocks.sha256(newBytes) == intent.candidateInventorySha256)
        val (oldInventory, _) = OwnedReleaseUpdates.preflight(oldBytes, newBytes, intent)
        val (original, oldSpecs) = load(intent.source.id, intent.source.bundleSha256)
        require(original.ownedUpdate == null && original.recoverySourceKopia == null &&
            original.recoverySourceArchiveSha256 == null && original.ownership != null &&
            original.request.store == RuntimeStore.CANONICAL_V2 &&
            !Files.exists(base.resolve(intent.targetGeneration), NOFOLLOW_LINKS))
        val access = RuntimeBackupAccess(intent.source.id, captureId, intent.source.bundleSha256)
        val held = json.decodeFromString<GenerationHeldCapture>(data(base.resolve(intent.source.id)
            .resolve("backups/$captureId/held.json")).decodeToString()).also { it.validate() }
        val snapshot = held.snapshot
        require(held.access == access && snapshot.id == captureId &&
            snapshot.generation == intent.source.id && snapshot.bundleSha256 == intent.source.bundleSha256)
        val capture = json.decodeFromString<KopiaCaptureOutcome>(data(base.resolve(intent.source.id)
            .resolve("kopia-captures/$captureId/capture.result.json")).decodeToString())
        require(capture.passed && capture.snapshot == snapshot && capture.id == captureId &&
            capture.bundleSha256 == intent.source.bundleSha256)
        RecoveryReferences(base.resolve(intent.source.id).resolve("recovery-references"))
            .requireProtected("import", transactionId, snapshot)
        val oldRuntime = backend(original)
        oldSpecs.forEach { spec ->
            val audit = oldRuntime.audit(spec, false)
            require(audit.name == spec.name && audit.fingerprint == original.members.single {
                it.spec.name == spec.name }.runtimeFingerprint && audit.maintenanceId == held.fences[spec.name] &&
                audit.maintenanceId != null && audit.statuses.none { it.state in setOf("running", "paused", "restarting") }) {
                "Original update source must be natively held before target repository effects"
            }
        }
        val measured = capacity(RuntimeStore.CANONICAL_V2)
        RuntimeLockBudget.requireAvailable(measured.availableRuntimeLocks, workers = 3)
        require(measured.availableMemoryMiB >= original.memoryReservationMiB +
            original.request.memoryHeadroomMiB + 2048 && measured.usableDiskMiB >=
            Math.addExact(original.request.diskHeadroomMiB,
                Math.addExact(Math.multiplyExact(3L, original.request.diskReservationMiB), 512L))) {
            "Full owned cold import resource and scratch budget must be admitted before repository effects"
        }
        admitRecoveryScratch(original.request, measured, 4)
        val root = base.resolve(intent.targetGeneration)
        Files.createDirectory(root, PosixFilePermissions.asFileAttribute(privateDir))
        FileChannel.open(base, READ).use { it.force(true) }
        // A crash after this intent, even before bundle materialization, is NOT a retry slot.
        save(root.resolve("owned-import.intent.json"), json.encodeToString(preparation))
        val recovered = root.resolve("recovered")
        val repository = base.resolve(intent.source.id).resolve("kopia-store/repository")
        val kopia = store ?: KopiaGenerationStore.real(oldInventory, RuntimeStore.CANONICAL_V2)
        var expected: String? = null
        val fences = linkedMapOf<String, String>()
        try {
            kopia.restore(repository, custody.resolve("${intent.source.id}.env"), root, snapshot, recovered)
            val checked = GenerationRecovery.validateKopia(recovered, snapshot)
            require(checked.bundle == original)
            val managedManifest = if (original.request.managedLanes == null) null else
                data(recovered.resolve("managed/source-manifest.toml"))
            val bundle = OwnedReleaseUpdates.compile(original, oldBytes, newBytes, intent, snapshot, managedManifest)
            OwnedReleaseUpdates.validate(bundle)
            val text = json.encodeToString(bundle)
            val targetHash = ReleaseLocks.sha256(text.toByteArray())
            expected = targetHash
            require(bundle.request.id == intent.targetGeneration && bundle.members.all {
                it.spec.ingress == null && it.spec.nativeIngress == null &&
                    it.spec.processes.none(RuntimeProcess::oneShot) })
            admit(bundle, workers = 2)
            save(root.resolve("bundle.json"), text)
            save(root.resolve("stage.intent.json"), json.encodeToString(GenerationIntent("restore-import", targetHash)))
            save(root.resolve("recovery.source.json"), json.encodeToString(snapshot))
            save(root.resolve("recovery.check.json"), json.encodeToString(checked.check))
            // Owned succession still imports ONLY the protected original controller
            // payload at its authenticated target point, never a new actor issuance.
            if (checked.manifest.controllerFiles.isNotEmpty()) {
                require(base == BASE && runtimeBase == PrivateDeployment.BASE &&
                    bundle.request.store == RuntimeStore.CANONICAL_V2)
                RecoveryControllerPayloads.restore(checked, root)
            }
            save(root.resolve("ownership.intent.json"), json.encodeToString(requireNotNull(bundle.ownership)))
            val assembly = requireNotNull(bundle.ownership).assembly
            save(root.resolve("assembly.intent.json"), json.encodeToString(assembly))
            require(ReleaseLocks.sha256(data(root.resolve("assembly.intent.json"))) == bundle.assemblySha256)
            directory(runtimeBase)
            for (pin in bundle.members) require(!Files.exists(runtimeBase.resolve(pin.spec.name), NOFOLLOW_LINKS) &&
                !Files.exists(runtimeBase.resolve("${pin.spec.name}.json"), NOFOLLOW_LINKS))
            // Fixed managed state is imported as source data, never as old live identities.
            GenerationManagedComponents.importOwned(original, bundle, checked.manifest, recovered, root)
            for (index in bundle.members.indices) {
                val pin = bundle.members[index]; val old = original.members[index]
                RuntimePreparation.prepare(pin.spec, runtimeBase) {
                    pin.inputHashes.mapValues { (file, _) ->
                        val bytes = data(recovered.resolve("${old.spec.name}/inputs/$file"))
                        require(ReleaseLocks.sha256(bytes) == pin.inputHashes.getValue(file));
                        bytes.decodeToString(throwOnInvalidSequence = true)
                    }
                }
                require(this.pin(pin.member).first == pin)
            }
            save(root.resolve("assembly.result.json"), json.encodeToString(AssemblyPreparationOutcome(
                requireNotNull(bundle.assemblySha256), true, targetHash)))
            val runtime = backend(bundle)
            val importer = runtime as? GenerationImportBackend ?: error("Native owned import backend unavailable")
            bundle.members.forEach { runtime.audit(it.spec, true) }
            if (checked.manifest.credentialFiles.isNotEmpty()) {
                require(base == BASE && runtimeBase == PrivateDeployment.BASE)
                PrivateDeployment.withOrderedNativeLocks((original.members + bundle.members)
                    .map { it.spec.name }.distinct(), runtimeBase) {
                    requireNotNull(NativeCredentialRevision.importOriginal(original, bundle,
                        checked.manifest, recovered, root))
                }
            }
            val receiptHash = KopiaGenerationStore.receiptHash(snapshot)
            for (index in bundle.members.indices) {
                val pin = bundle.members[index]; val old = original.members[index]
                save(root.resolve("${pin.spec.name}.import.intent.json"), json.encodeToString(
                    GenerationIntent("import-member", targetHash)))
                val verify = root.resolve("verify-${pin.spec.name}")
                Files.createDirectory(verify, PosixFilePermissions.asFileAttribute(privateDir))
                val archives = pin.spec.volumes.associate { volume ->
                    volume.id to recovered.resolve("${old.spec.name}/volumes/${volume.id}.tar") }
                val hashes = pin.spec.volumes.associate { volume ->
                    val name = "${old.spec.name}/volumes/${volume.id}.tar"
                    volume.id to (checked.manifest.volumes.singleOrNull { it.name == name }?.sha256
                        ?: checked.manifest.files.single { it.name == name }.sha256) }
                fences[pin.spec.name] = importer.importCold(pin.spec, archives, receiptHash, verify, hashes).id
                save(root.resolve("${pin.spec.name}.import.result.json"), json.encodeToString(runtime.audit(pin.spec, false)))
            }
            val result = GenerationOutcome("restore-import", targetHash, true, fences = fences)
            save(root.resolve("stage.result.json"), json.encodeToString(result))
            result
        } catch (error: Exception) {
            val interrupted = Thread.interrupted() || error is InterruptedException
            try {
                expected?.let { digest ->
                    val result = GenerationOutcome("restore-import", digest, false, error.javaClass.name, fences)
                    try { save(root.resolve("stage.result.json"), json.encodeToString(result)) }
                    catch (record: Exception) { error.addSuppressed(record) }
                    try { isolateLocked(intent.targetGeneration, digest) }
                    catch (isolation: Exception) { error.addSuppressed(isolation) }
                }
                // An import that never sealed a target still has durable owned-import.intent,
                // a protected source receipt and no target runtime effects. Explicit typed
                // reconciliation, never an implicit no-target success, is required.
                throw error
            } finally { if (interrupted) Thread.currentThread().interrupt() }
        }
    }

    /** Start ONLY the original-data imported Postgres under its restore fence. No Planka
     * daemon, source identity, public listener or egress writer is permitted before migration. */
    fun prepareOwnedMigration(inventory: AcquiredInventory, generation: String, expected: String): GenerationOutcome = mutating {
        val (bundle, specs) = load(generation, expected)
        OwnedReleaseUpdates.validate(bundle)
        val root = base.resolve(generation)
        val preparation = json.decodeFromString<ReleaseUpdatePreparation>(data(root.resolve("owned-import.intent.json")).decodeToString())
        preparation.validate(preparation.intent.source, generation, base)
        val sourceBytes = ReleasePrivateFiles.read(Path.of(preparation.candidateInventory.path))
        require(ReleaseLocks.sha256(sourceBytes) == preparation.intent.candidateInventorySha256 &&
            json.decodeFromString<AcquiredInventory>(sourceBytes.decodeToString()) == inventory)
        val imported = json.decodeFromString<GenerationOutcome>(data(root.resolve("stage.result.json")).decodeToString())
        require(imported.action == "restore-import" && imported.passed && imported.failureType == null &&
            imported.bundleSha256 == expected && imported.fences.keys == specs.map { it.name }.toSet() &&
            bundle.ownedUpdate?.intent == preparation.intent)
        require(!Files.exists(root.resolve("owned-migration-prep.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("owned-migration-prep.result.json"), NOFOLLOW_LINKS)) {
            "Migration database startup already attempted; reconcile without replay"
        }
        val spec = specs.single { member -> member.processes.any { it.id == "planka" } }
        require(spec.processes.single { it.id == "postgres" }.dependencies.isEmpty() &&
            spec.processes.none { it.oneShot } && spec.ingress == null)
        val runtime = backend(bundle)
        val starter = runtime as? OwnedMigrationGenerationBackend ?: error("Native owned migration backend unavailable")
        specs.forEach { member ->
            val audit = runtime.audit(member, false)
            require(audit.fingerprint == bundle.members.single { it.spec.name == member.name }.runtimeFingerprint &&
                audit.maintenanceId == imported.fences[member.name] && audit.statuses.size == member.processes.size &&
                audit.statuses.all { it.state == "absent" && it.exitCode == null }) {
                "Owned target import not pristine and natively fenced"
            }
        }
        admit(bundle)
        save(root.resolve("owned-migration-prep.intent.json"), json.encodeToString(GenerationIntent("owned-migration-prep", expected)))
        try {
            val statuses = starter.startMigrationDatabase(spec, imported.fences.getValue(spec.name))
            require(statuses.single { it.id == "postgres" }.state == "running" &&
                statuses.filterNot { it.id == "postgres" }.all { it.state in setOf("absent", "configured", "created") })
            val audit = runtime.audit(spec, false)
            require(audit.maintenanceId == imported.fences.getValue(spec.name) && audit.statuses.single {
                it.id == "postgres" }.state == "running" &&
                audit.statuses.filterNot { it.id == "postgres" }.none { it.state == "running" })
            val result = GenerationOutcome("owned-migration-prep", expected, true, fences = imported.fences)
            save(root.resolve("owned-migration-prep.result.json"), json.encodeToString(result))
            result
        } catch (error: Exception) {
            val interrupted = Thread.interrupted() || error is InterruptedException
            try {
                val result = GenerationOutcome("owned-migration-prep", expected, false, error.javaClass.name,
                    imported.fences)
                try { save(root.resolve("owned-migration-prep.result.json"), json.encodeToString(result)) }
                catch (record: Exception) { error.addSuppressed(record) }
                try { isolateLocked(generation, expected) }
                catch (isolation: Exception) { error.addSuppressed(isolation) }
                throw error
            } finally { if (interrupted) Thread.currentThread().interrupt() }
        }
    }

    /** Explicit Planka-only owned startup AFTER native Knex and migration-role NOLOGIN readback.
     * Generic private recovered targets cannot enter this branch or gain site authority. */
    fun startOwnedUpdate(inventory: AcquiredInventory, generation: String, expected: String): GenerationOutcome = mutating {
        val (bundle, specs) = load(generation, expected)
        OwnedReleaseUpdates.validate(bundle)
        val root = base.resolve(generation)
        val preparation = json.decodeFromString<ReleaseUpdatePreparation>(data(root.resolve("owned-import.intent.json")).decodeToString())
        preparation.validate(preparation.intent.source, generation, base)
        val inventoryBytes = ReleasePrivateFiles.read(Path.of(preparation.candidateInventory.path))
        require(ReleaseLocks.sha256(inventoryBytes) == preparation.intent.candidateInventorySha256 &&
            json.decodeFromString<AcquiredInventory>(inventoryBytes.decodeToString()) == inventory)
        val imported = json.decodeFromString<GenerationOutcome>(data(root.resolve("stage.result.json")).decodeToString())
        val prepared = json.decodeFromString<GenerationOutcome>(data(root.resolve("owned-migration-prep.result.json")).decodeToString())
        val native = json.decodeFromString<PlankaMigrationResult>(data(root.resolve(
            "planka-migration/${preparation.migrationOperation}.result.json")).decodeToString())
        val requestBytes = data(root.resolve("planka-migration/pending.json"))
        val migration = json.decodeFromString<PlankaMigrationRequest>(requestBytes.decodeToString())
        val spec = specs.single { it.processes.any { p -> p.id == "planka" } }
        require(imported.action == "restore-import" && imported.passed && imported.bundleSha256 == expected &&
            prepared.action == "owned-migration-prep" && prepared.passed && prepared.bundleSha256 == expected &&
            imported.fences == prepared.fences && native.passed && native.migrationRoleRetired && native.failureType == null &&
            native.operation == preparation.migrationOperation && native.requestSha256 == ReleaseLocks.sha256(requestBytes) &&
            migration.operation == preparation.migrationOperation && migration.generation == generation &&
            migration.bundleSha256 == expected && migration.transition == preparation.intent.transition &&
            migration.snapshotId == requireNotNull(bundle.ownedUpdate).snapshot.id &&
            migration.fenceId == imported.fences.getValue(spec.name) &&
            migration.manifest.path == runtimeBase.resolve("${spec.name}.json").toString() &&
            migration.manifest.sha256 == bundle.members.single { it.spec.name == spec.name }.manifestSha256 &&
            ReleaseLocks.sha256(data(runtimeBase.resolve("${spec.name}.json"))) == migration.manifest.sha256 &&
            migration.image.reference == spec.processes.single { it.id == "planka" }.image &&
            migration.image.imageId == spec.processes.single { it.id == "planka" }.imageId &&
            specs.all { it.ingress == null && it.nativeIngress == null && it.processes.none(RuntimeProcess::oneShot) } &&
            !Files.exists(root.resolve("owned-start.intent.json"), NOFOLLOW_LINKS)) {
            "Native migration, role retirement or owned target startup already uncertain"
        }
        val runtime = backend(bundle)
        val starter = runtime as? GenerationRestoreStartupBackend ?: error("Native imported startup backend unavailable")
        val owned = runtime as? OwnedMigrationGenerationBackend ?: error("Native Planka startup backend unavailable")
        specs.forEach { member ->
            val audit = runtime.audit(member, false)
            require(audit.fingerprint == bundle.members.single { it.spec.name == member.name }.runtimeFingerprint &&
                audit.maintenanceId == imported.fences.getValue(member.name) &&
                if (member.name == spec.name) audit.statuses.single { it.id == "postgres" }.state == "running" &&
                    audit.statuses.filterNot { it.id == "postgres" }.none { it.state == "running" }
                else audit.statuses.all { it.state == "absent" })
        }
        admit(bundle)
        save(root.resolve("owned-start.intent.json"), json.encodeToString(GenerationIntent("owned-start", expected)))
        try {
            for (member in specs) {
                load(generation, expected)
                save(root.resolve("${member.name}.owned-start.intent.json"), json.encodeToString(
                    GenerationIntent("start-owned-member", expected)))
                val statuses = if (member.name == spec.name) owned.startOwnedAfterMigration(member,
                    imported.fences.getValue(member.name)) else starter.startImported(member, imported.fences.getValue(member.name))
                require(statuses.size == member.processes.size && member.processes.all { process ->
                    statuses.singleOrNull { it.id == process.id }?.state == "running" })
                requireRunning(member, runtime.audit(member, false))
                save(root.resolve("${member.name}.owned-start.result.json"), json.encodeToString(statuses))
            }
            if (bundle.request.managedLanes != null) requireNotNull(GenerationManagedComponents.startOwned(bundle, root)) {
                "Managed owned candidate startup needs native broker, identity and revision result"
            }
            val result = GenerationOutcome("owned-start", expected, true)
            save(root.resolve("owned-start.result.json"), json.encodeToString(result))
            result
        } catch (error: Exception) {
            val interrupted = Thread.interrupted() || error is InterruptedException
            try {
                try { save(root.resolve("owned-start.result.json"), json.encodeToString(
                    GenerationOutcome("owned-start", expected, false, error.javaClass.name))) }
                catch (record: Exception) { error.addSuppressed(record) }
                try { isolateLocked(generation, expected) }
                catch (isolation: Exception) { error.addSuppressed(isolation) }
                throw error
            } finally { if (interrupted) Thread.currentThread().interrupt() }
        }
    }

    /** Starts a complete, private Kopia import once. This does not confer site or promotion authority.
     * All cohort audits and capacity admission precede the first fence release. The native member
     * actuator holds its runtime lock across exact import checks, fence release and daemon startup. */
    fun startRestored(inventory: AcquiredInventory, generation: String, expected: String): GenerationOutcome = mutating {
        val (bundle, specs) = backupSource(inventory, generation, expected)
        require(bundle.request.recoveredForgejoCi == null ||
            bundle.request.recoveredForgejoCiTarget != null && bundle.request.ciRecoveryGrant != null) {
            "Restored CI needs new target-scoped credential and original source custody"
        }
        require(bundle.recoverySourceKopia != null && bundle.ownedUpdate == null &&
            specs.all { it.ingress == null && it.nativeIngress == null && it.processes.none { p -> p.oneShot } }) {
            "Restricted restored startup requires a private initializer-free Kopia import"
        }
        val root = base.resolve(generation)
        val intent = root.resolve("restore-start.intent.json")
        require(!Files.exists(intent, NOFOLLOW_LINKS)) { "Restored startup already attempted; reconcile, never replay" }
        val imported = json.decodeFromString<GenerationOutcome>(data(root.resolve("stage.result.json")).decodeToString())
        val runtime = backend(bundle)
        val starter = runtime as? GenerationRestoreStartupBackend ?: error("Native imported startup backend unavailable")
        specs.forEach { spec ->
            val audit = runtime.audit(spec, false)
            require(audit.name == spec.name && audit.fingerprint == bundle.members.single { it.spec.name == spec.name }.runtimeFingerprint &&
                audit.maintenanceId == imported.fences.getValue(spec.name) && audit.statuses.size == spec.processes.size &&
                audit.statuses.map { it.id }.toSet() == spec.processes.map { it.id }.toSet() &&
                audit.statuses.all { it.state == "absent" && it.exitCode == null }) { "Imported target is not pristine and fenced" }
        }
        admit(bundle)
        save(intent, json.encodeToString(GenerationIntent("restore-start", expected)))
        try {
            bundle.request.recoveredForgejoCiTarget?.let { targetPlan ->
                ForgejoCiSourcePlan.prepare(root, targetPlan)
                ForgejoCiNativeSourceAdmission.check(targetPlan, root)
                ForgejoCiNativeAccountOwner.provision()
                ForgejoCiNativeSourceAdmission.requirePristineAccountNamespace(targetPlan)
                ForgejoCiNativeRecovery.revoke(bundle, root)
            }
            specs.forEach { spec ->
                load(generation, expected)
                save(root.resolve("${spec.name}.restore-start.intent.json"), json.encodeToString(GenerationIntent("start-imported-member", expected)))
                val statuses = starter.startImported(spec, imported.fences.getValue(spec.name))
                require(statuses.size == spec.processes.size && spec.processes.all { process ->
                    statuses.singleOrNull { it.id == process.id }?.state == "running"
                }) { "Restored member readiness incomplete" }
                requireRunning(spec, runtime.audit(spec, false))
                save(root.resolve("${spec.name}.restore-start.result.json"), json.encodeToString(statuses))
            }
            if (bundle.request.managedLanes != null) requireNotNull(GenerationManagedComponents.startRecovered(bundle, root)) {
                "Private managed functional RESTORE needs native isolated lanes and fresh identity result"
            }
            if (bundle.request.recoveredForgejoCiTarget != null) ForgejoCiNativeSystemd.start(bundle, root, recovered = true)
            val result = GenerationOutcome("restore-start", expected, true)
            save(root.resolve("restore-start.result.json"), json.encodeToString(result))
            result
        } catch (error: Exception) {
            var interrupted = Thread.interrupted() || error is InterruptedException
            val result = GenerationOutcome("restore-start", expected, false, error.javaClass.name)
            var recordingFailure: Exception? = null
            fun retain(failure: Exception) {
                interrupted = Thread.interrupted() || failure is InterruptedException || interrupted
                if (recordingFailure == null) recordingFailure = failure else recordingFailure!!.addSuppressed(failure)
            }
            try {
                try { save(root.resolve("restore-start.result.json"), json.encodeToString(result)) } catch (failure: Exception) { retain(failure) }
                // A missing result must not skip stop/fence of members already started.
                try { isolateLocked(generation, expected) } catch (failure: Exception) { retain(failure) }
                recordingFailure?.let { it.addSuppressed(error); throw it }
                if (interrupted) throw error
                result
            } finally { if (interrupted) Thread.currentThread().interrupt() }
        }
    }

    fun stage(generation: String, expected: String): GenerationOutcome = mutating {
        val (bundle, specs) = load(generation, expected)
        require(bundle.recoverySourceArchiveSha256 == null && bundle.recoverySourceKopia == null) { "Restore generations cannot run clean-install staging" }
        require(bundle.ownedUpdate == null) { "Update generations cannot run clean-install staging" }
        val root = base.resolve(generation)
        require(!Files.exists(root.resolve("stage.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("isolate.intent.json"), NOFOLLOW_LINKS)) { "Generation already attempted; reconcile, do not replay" }
        val runtime = backend(bundle)
        // Audit every member/image before the FIRST process or resource creation.
        specs.forEach { runtime.audit(it, true) }
        bundle.request.forgejoCi?.let { ForgejoCiNativeSourceAdmission.check(it, root) }
        admit(bundle)
        save(root.resolve("stage.intent.json"), json.encodeToString(GenerationIntent("stage", expected)))
        try {
            bundle.request.forgejoCi?.let { ci ->
                ForgejoCiNativeAccountOwner.provision()
                ForgejoCiNativeSourceAdmission.requirePristineAccountNamespace(ci)
            }
            for (spec in specs) {
                load(generation, expected) // Immutable member manifests are also checked between effects.
                save(root.resolve("${spec.name}.stage.intent.json"), json.encodeToString(GenerationIntent("stage-member", expected)))
                val result = runtime.apply(spec)
                require(spec.processes.all { process -> result.singleOrNull { it.id == process.id }?.let {
                    if (process.oneShot) it.state in setOf("completed", "exited") && it.exitCode == 0 else it.state == "running"
                } == true }) { "Generation member not ready" }
                save(root.resolve("${spec.name}.stage.result.json"), json.encodeToString(result))
            }
            if (bundle.members.any { pin -> pin.spec.processes.any { it.id == "mastodon-rss-feature" } }) {
                FreshRssFeatureCustody.adopt(bundle, root)
            }
            if (bundle.request.forgejoCi != null) {
                ForgejoCiNativeSystemd.start(bundle, root)
            }
            val result = GenerationOutcome("stage", expected, true)
            save(root.resolve("stage.result.json"), json.encodeToString(result))
            result
        } catch (interrupted: InterruptedException) {
            stageFailure(generation, expected, interrupted)
            throw interrupted
        } catch (failure: Exception) {
            stageFailure(generation, expected, failure)
        }
    }
    private fun stageFailure(generation: String, expected: String, failure: Exception): GenerationOutcome {
        val interrupted = Thread.interrupted() || failure is InterruptedException
        try {
            val result = GenerationOutcome("stage", expected, false, failure.javaClass.name)
            save(base.resolve(generation).resolve("stage.result.json"), json.encodeToString(result))
            // Isolation has its own intent and retained result. Never release any fence on failure.
            isolateLocked(generation, expected)
            if (interrupted) throw failure
            return result
        } finally { if (interrupted) Thread.currentThread().interrupt() }
    }
    private fun isolationOutcomes(root: Path, expected: String): List<GenerationOutcome> {
        val paths = Files.list(root).use { files -> files.filter {
            it.fileName.toString() == "isolate.result.json" ||
                (it.fileName.toString().startsWith("isolate-reconcile-") && it.fileName.toString().endsWith(".result.json"))
        }.limit(130).toList() }
        require(paths.size <= 129) { "Isolation reconciliation bound reached" }
        return paths.map { path ->
            val stem = path.fileName.toString().removeSuffix(".result.json")
            require(stem == "isolate" || stem.matches(Regex("isolate-reconcile-r-[a-f0-9]{12}"))) { "Invalid isolation record" }
            val intent = json.decodeFromString<GenerationIntent>(data(root.resolve("$stem.intent.json")).decodeToString())
            val result = json.decodeFromString<GenerationOutcome>(data(path).decodeToString())
            require(result.bundleSha256 == expected && intent.bundleSha256 == expected && result.action == intent.action &&
                result.priorIntentSha256 == intent.priorIntentSha256 &&
                if (stem == "isolate") result.action == "isolate" && intent.priorIntentSha256 == null
                else result.action == "reconcile-isolation" && intent.priorIntentSha256 ==
                    ReleaseLocks.sha256(data(root.resolve("isolate.intent.json")))) { "Foreign isolation result" }
            result
        }
    }
    private fun isolateLocked(generation: String, expected: String, reconciliationId: String? = null,
        priorIntent: String? = null, runtimeOverride: GenerationBackend? = null): GenerationOutcome {
        // Sealed definitions permit stopping other members even if a live manifest has drifted.
        // Each runtime still checks actual input fingerprints and ownership under its own lock.
        val (bundle, specs) = load(generation, expected, checkLiveInputs = false)
        val root = base.resolve(generation)
        val stem = if (reconciliationId == null) "isolate" else "isolate-reconcile-$reconciliationId"
        val action = if (reconciliationId == null) "isolate" else "reconcile-isolation"
        if (reconciliationId != null) {
            require(reconciliationId.matches(Regex("r-[a-f0-9]{12}")) && priorIntent != null && hash.matches(priorIntent)) { "Invalid reconciliation identity" }
            val original = data(root.resolve("isolate.intent.json"))
            val intent = json.decodeFromString<GenerationIntent>(original.decodeToString())
            require(ReleaseLocks.sha256(original) == priorIntent && intent.action == "isolate" &&
                intent.bundleSha256 == expected && intent.priorIntentSha256 == null) { "Isolation predecessor mismatch" }
            isolationOutcomes(root, expected) // Corrupt history cannot be bypassed with another action ID.
        }
        save(root.resolve("$stem.intent.json"), json.encodeToString(GenerationIntent(action, expected, priorIntent)))
        val runtime = runtimeOverride ?: backend(bundle)
        val fences = linkedMapOf<String, String>()
        var failure: Exception? = null
        var interrupted = false
        try {
            try { ForgejoCiNativeSystemd.stopIfOwned(bundle, root) }
            catch (error: InterruptedException) {
                Thread.interrupted(); interrupted = true; failure = failure ?: error
            } catch (error: Exception) {
                interrupted = Thread.interrupted() || interrupted
                failure = failure ?: error
            }
            for (spec in specs.asReversed()) try {
                fences[spec.name] = runtime.isolate(spec)
            } catch (error: InterruptedException) {
                Thread.interrupted(); interrupted = true; failure = failure ?: error
            } catch (error: Exception) {
                interrupted = Thread.interrupted() || interrupted
                failure = failure ?: error
            }
            val result = GenerationOutcome(action, expected, failure == null, failure?.javaClass?.name, fences, priorIntent)
            save(root.resolve("$stem.result.json"), json.encodeToString(result))
            if (interrupted) throw InterruptedException("Generation isolation interrupted; outcomes retained")
            return result
        } finally { if (interrupted) Thread.currentThread().interrupt() }
    }
    fun restoreKopiaCanonicalCore(inventory: AcquiredInventory, source: String, sourceBundle: String, captureId: String, target: String,
        custody: Path = Path.of("/mnt/media/p0-v3/kopia-custody"), store: GenerationSnapshotStore? = null,
        targetStore: RuntimeStore = RuntimeStore.LEGACY): GenerationOutcome =
        restoreCold(inventory, source, sourceBundle, captureId, target, custody, ColdRestoreCohort.CANONICAL_CORE,
            store ?: KopiaGenerationStore.real(inventory, targetStore), targetStore)

    fun restoreKopiaWholeRelease(inventory: AcquiredInventory, source: String, sourceBundle: String, captureId: String, target: String,
        custody: Path = Path.of("/mnt/media/p0-v3/kopia-custody"), store: GenerationSnapshotStore? = null,
        targetStore: RuntimeStore = RuntimeStore.CANONICAL_V2): GenerationOutcome =
        restoreCold(inventory, source, sourceBundle, captureId, target, custody, ColdRestoreCohort.WHOLE_RELEASE,
            store ?: KopiaGenerationStore.real(inventory, targetStore), targetStore)

    fun retainKopia(inventory: AcquiredInventory, generation: String, expected: String, operation: String): KopiaRetentionResult = mutating {
        val bundle = load(generation, expected, checkLiveInputs = false).first
        val measured = capacity(bundle.request.store)
        RuntimeLockBudget.requireAvailable(measured.availableRuntimeLocks, workers = 1)
        require(measured.availableMemoryMiB >= bundle.request.memoryHeadroomMiB + 1024 &&
            measured.usableDiskMiB >= bundle.request.diskHeadroomMiB) { "Insufficient retention worker headroom" }
        RecoveryReferenceOperations.retain(base, inventory, generation, expected, operation)
    }

    private fun backupRuntime(bundle: GenerationBundle, access: RuntimeBackupAccess): BackupGenerationBackend =
        (backend(bundle) as? BackupGenerationFactory ?: error("Routine backup backend unavailable")).forBackup(access)
    private fun requireRunning(spec: PrivateDeploymentSpec, audit: RuntimeAudit) {
        require(audit.name == spec.name && audit.maintenanceId == null && spec.processes.all { p ->
            audit.statuses.singleOrNull { it.id == p.id }?.let {
                if (p.oneShot) it.state in setOf("completed", "exited") && it.exitCode == 0 else it.state == "running"
            } == true
        }) { "Routine backup requires a fully running unfenced cohort" }
    }
    /** Activation observation only: never promotes a recovery, replays jobs or releases a maintenance/backup fence. */
    fun checkActivationSource(deployment: ReleaseDeploymentBinding, candidate: kotlinx.serialization.json.JsonObject,
        imagePins: Set<Pair<String, String>>): List<CaddyUpstream> = locked {
        deployment.validate()
        val (bundle, specs) = load(deployment.generationId, deployment.bundleSha256)
        val fields = listOf("implementationSha256", "artifactsSha256", "configurationSha256", "acceptanceSha256", "sitePolicySha256")
        require(candidate.keys == fields.toSet())
        val normalized = kotlinx.serialization.json.JsonObject(fields.associateWith { candidate.getValue(it) })
        require(bundle.request.candidateSha256 == ReleaseLocks.sha256(normalized.toString().toByteArray()) &&
            bundle.request.store == RuntimeStore.CANONICAL_V2 && bundle.recoverySourceArchiveSha256 == null && bundle.recoverySourceKopia == null)
        bundle.ownedUpdate?.let { owned ->
            OwnedReleaseUpdates.validate(bundle)
            val source = OwnedReleaseUpdates.original(owned)
            val held = json.decodeFromString<GenerationHeldCapture>(data(base.resolve(source.request.id)
                .resolve("backups/${owned.snapshot.id}/held.json")).decodeToString()).also { it.validate() }
            require(held.snapshot == owned.snapshot && held.access.generation == source.request.id &&
                held.access.bundleSha256 == owned.intent.source.bundleSha256)
            val originalRuntime = backend(source)
            source.members.forEach { pin ->
                val observed = originalRuntime.audit(pin.spec, false)
                require(observed.fingerprint == pin.runtimeFingerprint &&
                    observed.maintenanceId == held.fences[pin.member.name] &&
                    observed.statuses.none { it.state in setOf("running", "paused", "restarting") }) {
                    "Original Planka update source can still write: activation forbidden"
                }
            }
        }
        require(imagePins.isNotEmpty() && specs.flatMap { it.processes }.all { (it.image to it.imageId) in imagePins }) {
            "Runtime image differs from frozen artifact closure"
        }
        val owned = requireNotNull(bundle.ownership) { "Activation requires original site ownership, not recovery lineage" }
        val capabilities = owned.assembly.members.flatMap { it.primaryCapabilities }
        require(capabilities.size == capabilities.distinct().size && capabilities.toSet() ==
            ProductSelection.bundled().products.toSet() + setOf("openbao", "keykeeper", "worklane", "tuios", "pi")) { "Complete canonical activation cohort required" }
        val root = base.resolve(bundle.request.id)
        require(!Files.exists(root.resolve("isolate.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("kopia-store/snapshot.pending.json"), NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("kopia-store/retention.pending.json"), NOFOLLOW_LINKS)) { "Retired or uncertain activation source" }
        completedCaptureSource(bundle, deployment.bundleSha256, allowRecovered = false)
        val backups = root.resolve("backups")
        if (Files.exists(backups, NOFOLLOW_LINKS)) {
            directory(backups)
            val attempts = Files.list(backups).use { it.limit(129).toList() }
            require(attempts.size <= 128)
            for (attempt in attempts) {
                directory(attempt)
                val result = json.decodeFromString<GenerationBackupOutcome>(data(attempt.resolve("result.json")).decodeToString())
                require(result.passed && result.sourceResumed && result.failureType == null && result.access.generation == bundle.request.id &&
                    result.access.bundleSha256 == deployment.bundleSha256) { "Uncertain backup blocks activation" }
            }
        }
        val runtime = backend(bundle)
        specs.forEach { spec ->
            require(!Files.exists(runtimeBase.resolve(spec.name).resolve("runtime.backup"), NOFOLLOW_LINKS)) { "Backup operation still owns source" }
            requireRunning(spec, runtime.audit(spec, false))
        }
        val caddyPin = bundle.members.single { pin -> pin.spec.processes.any { it.id == "caddy" } }
        val caddyProcess = caddyPin.spec.processes.single { it.id == "caddy" }
        owned.contract.routes.map { route ->
            val dial = "p0v3-live-${route.process.replace('/', '-')}:${route.port}"
            if (route.host == "notebooks.datamancy.net") {
                val hubPin = bundle.members.single { pin -> pin.spec.processes.any { it.id == "hub" } }
                val hubProcess = hubPin.spec.processes.single { it.id == "hub" }
                require(route.port == 8443 && route.process == "${hubPin.spec.name}/hub" &&
                    hubProcess.networks.contains("hub-web") && caddyProcess.networks.contains("hub-web") &&
                    hubProcess.files.singleOrNull { it.file == "jupyterhub-ca.pem" &&
                        it.target == "/run/secrets/hub-ca.pem" } != null &&
                    caddyProcess.files.singleOrNull { it.file == "hub-ca.pem" &&
                        it.target == "/run/secrets/hub-ca.pem" } != null &&
                    caddyPin.inputHashes["hub-ca.pem"] == hubPin.inputHashes["jupyterhub-ca.pem"]) {
                    "Hub native HTTPS requires an actual sealed Caddy CA input"
                }
                val ca = requireNotNull(caddyPin.inputHashes["hub-ca.pem"])
                require(ReleaseLocks.sha256(data(runtimeBase.resolve(caddyPin.spec.name)
                    .resolve("hub-ca.pem"))) == ca &&
                    ReleaseLocks.sha256(data(runtimeBase.resolve(hubPin.spec.name)
                        .resolve("jupyterhub-ca.pem"))) == ca) {
                    "Caddy native Hub trust must be the exact originally minted Hub CA"
                }
                CaddyUpstream(route.host, dial, tlsServerName = "hub",
                    trustedCaFile = "/run/secrets/hub-ca.pem", trustedCaSha256 = ca,
                    forwardOriginalHost = true)
            } else {
                require(route.port !in setOf(443, 8443)) {
                    "Every private native HTTPS upstream needs an exact sealed CA and SNI profile"
                }
                CaddyUpstream(route.host, dial)
            }
        }
    }

    /** Append one effective public Caddy certificate revision under the SAME generation/RSS
     * exclusion and native Caddy/LiveKit member locks as capture. The fixed one-use intent
     * precedes every native observation; uncertain adoption cannot be retried. */
    fun publishEffectivePublicCertificate(operation: String, generation: String, expected: String,
        host: String, approvedHosts: Set<String>, trust: ActivationInput,
        originalBundle: GenerationBundle? = null, originalManifest: CapsuleManifest? = null,
        recovered: Path? = null): ActivationInput = mutating {
        require(base == BASE && runtimeBase == PrivateDeployment.BASE &&
            operation.matches(Regex("r-[a-f0-9]{12}")) && expected.matches(hash) &&
            host in approvedHosts && approvedHosts.isNotEmpty())
        val (bundle, specs) = load(generation, expected)
        val adoptingOriginal = originalBundle != null && originalManifest != null && recovered != null
        require((originalBundle == null && originalManifest == null && recovered == null) || adoptingOriginal)
        val owner = if (adoptingOriginal) requireNotNull(originalBundle?.ownership)
            else requireNotNull(bundle.ownership)
        require(approvedHosts == owner.approvedHosts &&
            (bundle.recoverySourceKopia == null || adoptingOriginal) &&
            (bundle.ownedUpdate == null || adoptingOriginal))
        if (adoptingOriginal && bundle.ownedUpdate != null) {
            val owned = requireNotNull(bundle.ownedUpdate)
            require(requireNotNull(originalManifest).id == owned.snapshot.id &&
                originalManifest.bundleSha256 == owned.snapshot.bundleSha256 &&
                originalBundle == OwnedReleaseUpdates.original(owned))
        }
        val caddy = specs.single { it.processes.any { process -> process.id == "caddy" } }
        require(caddy.store == RuntimeStore.CANONICAL_V2 &&
            (adoptingOriginal && caddy.ingress == null && caddy.nativeIngress == null ||
                !adoptingOriginal && bundle.recoverySourceKopia == null && bundle.ownedUpdate == null &&
                    caddy.ingress != null)) {
            "Native public issuance needs original ingress; private RESTORE/owned update adopts exact original bytes"
        }
        val memberNames = specs.filter { spec -> spec.processes.any { it.id in setOf("caddy", "livekit") } }
            .map { it.name }.sorted()
        require(memberNames.isNotEmpty() && memberNames.size <= 2)
        val root = base.resolve(generation)
        val intent = GenerationCertificatePublishIntent(operation = operation,
            generation = ReleaseGeneration(generation, expected), host = host,
            approvedHosts = approvedHosts, trust = trust,
            originalBundleSha256 = originalBundle?.let { ReleaseLocks.sha256(json.encodeToString(it).toByteArray()) },
            originalManifestSha256 = originalManifest?.let { ReleaseLocks.sha256(json.encodeToString(it).toByteArray()) },
            recoveredRoot = recovered?.toString())
        require(!Files.exists(root.resolve("credential-publish-$operation.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("credential-publish-$operation.result.json"), NOFOLLOW_LINKS) &&
            trust.sha256 == ReleaseLocks.sha256(data(Path.of(trust.path))))
        save(root.resolve("credential-publish-$operation.intent.json"), json.encodeToString(intent))
        for (path in listOf(root.resolve("credential-revisions"),
            root.resolve("credential-revisions/public"),
            root.resolve("credential-revisions/public/observations"))) {
            if (!Files.exists(path, NOFOLLOW_LINKS)) {
                Files.createDirectory(path, PosixFilePermissions.asFileAttribute(privateDir))
                FileChannel.open(path.parent, READ).use { it.force(true) }
            }
            ReleasePrivateFiles.directory(path)
        }
        PrivateDeployment.withOrderedNativeLocks(memberNames, runtimeBase) {
            val native = backend(bundle)
            memberNames.forEach { name ->
                val spec = specs.single { it.name == name }
                val audit = native.audit(spec, false)
                require(audit.fingerprint == bundle.members.single { it.spec.name == name }.runtimeFingerprint &&
                    audit.maintenanceId == null && audit.existingResources > 0 &&
                    spec.processes.filter { it.id in setOf("caddy", "livekit") }.all { process ->
                        audit.statuses.singleOrNull { it.id == process.id }?.state == "running"
                    }) { "Certificate collection requires actual original/target native Caddy and RTC identity"
                }
            }
            val pin = NativeCredentialRevision.publish(bundle, host, approvedHosts, trust,
                NativeCaddyCertificateCollector(Path.of(trust.path), trust.sha256),
                originalBundle, originalManifest, recovered)
            require(Path.of(pin.path).parent == root.resolve("credential-revisions/public") &&
                ReleaseLocks.sha256(data(Path.of(pin.path))) == pin.sha256)
            save(root.resolve("credential-publish-$operation.result.json"), json.encodeToString(pin))
            pin
        }
    }
    /** INSTALL qualification child and all its controller callbacks retain the original
     * RSS, generation and sorted member locks on this one owner thread. RESTORE needs the
     * source+target cohort and is deliberately not admitted through this entry point. */
    fun <T> withInstallQualificationScope(generation: String, expected: String, action: () -> T): T = mutating {
        require(base == BASE && runtimeBase == PrivateDeployment.BASE)
        val (bundle, specs) = load(generation, expected)
        require(bundle.request.store == RuntimeStore.CANONICAL_V2 && bundle.ownedUpdate == null &&
            bundle.recoverySourceKopia == null && bundle.recoverySourceArchiveSha256 == null)
        SiteOwnerships.checkSealed(bundle)
        QualificationCanonicalTopology.require(bundle)
        val root = base.resolve(generation)
        val stage = json.decodeFromString<GenerationOutcome>(data(root.resolve("stage.result.json")).decodeToString())
        require(stage.action == "stage" && stage.passed && stage.failureType == null && stage.bundleSha256 == expected)
        val names = specs.map { it.name }.sorted()
        require(names.size == names.toSet().size)
        PrivateDeployment.withOrderedNativeLocks(names, runtimeBase) { action() }
    }
    /** Check original actor grants against the sealed one-shot signup inputs, without
     * minting credentials or confusing a completed initializer with native account
     * readback. Called before the first original INSTALL case under the held cohort. */
    fun requireOriginalDonetickActorsUnderHeldScope(scope: QualificationControlScope) {
        require(base == BASE && runtimeBase == PrivateDeployment.BASE &&
            generationLockHeld.get() && mutationHeld.get() && scope.operation == "execute-staged")
        val (bundle, _) = load(scope.generationId, scope.bundleSha256)
        GenerationOriginalActorInputs.requireOriginalDonetick(scope, bundle, base.resolve(scope.generationId), runtimeBase)
    }

    /** First-use Forgejo accounts MUST exist before the original repository journey.
     * Its sole effect is journalled by the app-owned issuer before POST; a lost ACK
     * is never replayed. The bootstrap password is read from the NEW original
     * owner-init volume, not from OLD or regenerated here. */
    fun enrollOriginalForgejoActorsUnderHeldScope(scope: QualificationControlScope) {
        require(base == BASE && runtimeBase == PrivateDeployment.BASE &&
            generationLockHeld.get() && mutationHeld.get() && scope.operation == "execute-staged")
        val (bundle, _) = load(scope.generationId, scope.bundleSha256)
        require(bundle.request.store == RuntimeStore.CANONICAL_V2 && bundle.recoverySourceKopia == null &&
            bundle.recoverySourceArchiveSha256 == null && bundle.ownedUpdate == null)
        val root = base.resolve(scope.generationId)
        val manifest = PackagedGraphFragment.pendingV3R9().first
        val host = "forgejo.datamancy.net"
        val owner = GenerationOriginalActorInputs.credential(scope, "forgejo", "owner")
        val outsider = GenerationOriginalActorInputs.credential(scope, "forgejo", "outsider")
        require(owner.getValue("username").jsonPrimitive.content == "owner" &&
            outsider.getValue("username").jsonPrimitive.content == "outsider" &&
            owner.getValue("password") != outsider.getValue("password"))
        val client = GenerationOriginalActorHttp.client(root, bundle, scope.bundleSha256, manifest, host)
        val bootstrap = ForgejoCiFreshIssuer.credential(bundle, root)
        try {
            val journal = root.resolve("qualification-actor-enrollment")
            require(!Files.exists(journal, NOFOLLOW_LINKS)) {
                "Fresh actor enrollment journal already exists; original effect must not be replayed"
            }
            Files.createDirectory(journal, PosixFilePermissions.asFileAttribute(privateDir))
            ReleasePrivateFiles.sync(root)
            val issued = ForgejoRuntime.enrollFreshActors(client, java.net.URI("https://$host"),
                journal, scope.generationId,
                bootstrap.decodeToString(throwOnInvalidSequence = true),
                owner.getValue("password").jsonPrimitive.content,
                outsider.getValue("password").jsonPrimitive.content)
            require(issued["owner"] == "owner" && issued["outsider"] == "outsider")
        } finally { bootstrap.fill(0) }
    }

    /** Original INSTALL grants are sealed only after genuine enrollment readbacks, while
     * owner/RSS/generation and all native member locks remain held. This never issues users,
     * copies historical identities or turns a source fixture into native evidence. */
    fun stageOriginalQualificationActors(generation: String, expected: String,
        originalContexts: ActivationInput, issuanceReadbacks: Map<String, ActivationInput>): RecoveryActorCustodyManifest =
        withInstallQualificationScope(generation, expected) {
            stageOriginalQualificationActorsUnderHeldScope(generation, expected, originalContexts, issuanceReadbacks)
        }

    /** Reuses the lexical INSTALL owner/native-lock cohort. Never reacquire the
     * member file locks from the completed qualification callback. */
    fun stageOriginalQualificationActorsUnderHeldScope(generation: String, expected: String,
        originalContexts: ActivationInput, issuanceReadbacks: Map<String, ActivationInput>): RecoveryActorCustodyManifest {
        require(generationLockHeld.get() && mutationHeld.get() && base == BASE &&
            runtimeBase == PrivateDeployment.BASE && id.matches(generation) && hash.matches(expected))
        val (bundle, _) = load(generation, expected)
        require(bundle.request.store == RuntimeStore.CANONICAL_V2 && bundle.ownedUpdate == null &&
            bundle.recoverySourceKopia == null && bundle.recoverySourceArchiveSha256 == null)
        val contextPath = Path.of(originalContexts.path)
        require(contextPath.isAbsolute && contextPath.normalize() == contextPath &&
            (contextPath.startsWith(base.resolve(generation)) || contextPath.startsWith(ReleaseDispatch.BASE)) &&
            issuanceReadbacks.values.all { input ->
                val path = Path.of(input.path)
                path.isAbsolute && path.normalize() == path && path.startsWith(base.resolve(generation))
            }) {
            "Original actor issuance must be generation-owned, not caller-supplied external files"
        }
        return RecoveryActorCustody.stage(base.resolve(generation), expected, originalContexts, issuanceReadbacks)
    }

    /** Called ONLY within withRestoredIsolationLocks on the same owner thread.
     * This projects authenticated original actor bytes, never mints replacement grants.
     * RESTORE's source and target cohort locks must not be reacquired here. */
    fun projectRestoredQualificationActors(source: ReleaseGeneration, target: ReleaseGeneration,
        service: String, originalContextsSha256: String,
        originalContext: JsonObject): Pair<JsonObject, List<ActivationInput>> {
        require(generationLockHeld.get() && mutationHeld.get() && base == BASE &&
            runtimeBase == PrivateDeployment.BASE && source.id != target.id) {
            "RESTORE actor projection requires held original source/target owner scope"
        }
        source.validate(); target.validate()
        val (original, sourceSpecs) = load(source.id, source.bundleSha256, checkLiveInputs = false)
        val (restored, targetSpecs) = load(target.id, target.bundleSha256, checkLiveInputs = false)
        QualificationCanonicalTopology.require(original, allowOwnedUpdateSource = original.ownedUpdate != null)
        QualificationCanonicalTopology.require(restored, restoredTarget = true)
        require(restored.recoverySourceKopia?.let { it.generation == source.id &&
            it.bundleSha256 == source.bundleSha256 } == true &&
            sourceSpecs.map { it.name }.toSet().intersect(targetSpecs.map { it.name }.toSet()).isEmpty())
        val sourceRoot = base.resolve(source.id); val targetRoot = base.resolve(target.id)
        val stage = json.decodeFromString<GenerationOutcome>(data(targetRoot.resolve("stage.result.json")).decodeToString())
        require(stage.action == "restore-import" && stage.passed && stage.bundleSha256 == target.bundleSha256)
        // Stopped-source proof is native, not a RESTORE flag or a copied certificate.
        val sourceNative = backend(original)
        require(sourceSpecs.all { spec ->
            val observed = sourceNative.audit(spec, false)
            observed.name == spec.name && observed.statuses.size == spec.processes.size &&
                observed.statuses.all { it.state in setOf("stopped", "exited", "completed") }
        }) { "Original source is not natively stopped under RESTORE cohort locks" }
        require(originalContextsSha256.matches(hash))
        GenerationNativeActorIssuance.verifyOriginal(sourceRoot, source.id, source.bundleSha256,
            originalContextsSha256, service)
        return RecoveryActorCustody.project(sourceRoot, targetRoot, source.bundleSha256,
            service, originalContextsSha256, originalContext)
    }

    /** Direct RestoreTest has no held-capture lease. Quiesce the entire existing source once
     * with an operation-bound backup lease; do not mint another snapshot or replay onboarding.
     * Caller must retain withRestoredIsolationLocks across this and the matching resume. */
    fun directRestoreQuiesce(inventory: AcquiredInventory, source: ReleaseGeneration, target: ReleaseGeneration,
        captureId: String, suiteId: String, route: RestoredOriginalRouteAuthority): ActivationInput = mutating {
        require(base == BASE && runtimeBase == PrivateDeployment.BASE && source.id != target.id &&
            suiteId.matches(Regex("[a-f0-9]{24}")) && captureId.matches(Regex("cap-[a-f0-9]{12}")))
        val (original, specs) = backupSource(inventory, source.id, source.bundleSha256)
        QualificationCanonicalTopology.require(original,
            allowOwnedUpdateSource = original.ownedUpdate != null)
        require(specs.size == 1 && original.ownership != null)
        val (restored, _) = load(target.id, target.bundleSha256)
        require(restored.recoverySourceKopia?.let { it.generation == source.id &&
            it.bundleSha256 == source.bundleSha256 && it.id == captureId } == true)
        val snapshotBytes = data(base.resolve(source.id).resolve("kopia-captures/$captureId/capture.result.json"))
        val snapshot = json.decodeFromString<KopiaCaptureOutcome>(snapshotBytes.decodeToString(throwOnInvalidSequence = true))
        require(snapshot.passed && snapshot.failureType == null && snapshot.snapshot == restored.recoverySourceKopia)
        val access = RuntimeBackupAccess(source.id, captureId, source.bundleSha256).also { it.validate() }
        val parent = privateControlDirectory(base.resolve(source.id).resolve("qualification-direct"))
        val root = privateControlDirectory(parent.resolve(suiteId))
        val path = root.resolve("quiesce.result.json")
        route.recheck()
        require(route.source == source && route.site == original.ownership?.contract?.site &&
            route.approvedHosts == original.ownership?.approvedHosts)
        val routeBytes = json.encodeToString(route).encodeToByteArray()
        ReleasePrivateFiles.save(root.resolve("original-route.json"), routeBytes)
        save(root.resolve("quiesce.intent.json"), json.encodeToString(buildJsonObject {
            put("source", json.encodeToJsonElement(source)); put("target", json.encodeToJsonElement(target))
            put("snapshotSha256", ReleaseLocks.sha256(snapshotBytes))
        }))
        val worker = backupRuntime(original, access)
        specs.forEach { spec -> requireRunning(spec, worker.audit(spec, false)) }
        val claimed = specs.map { it.name to it }.toMap()
        val fences = linkedMapOf<String, String>()
        for (name in claimed.keys.sorted()) {
            val spec = claimed.getValue(name)
            save(root.resolve("claim-$name.intent.json"), json.encodeToString(access))
            worker.claim(spec)
            save(root.resolve("claim-$name.result.json"), json.encodeToString(access))
        }
        for (name in claimed.keys.sortedDescending()) {
            val spec = claimed.getValue(name)
            save(root.resolve("quiesce-$name.intent.json"), json.encodeToString(access))
            fences[name] = worker.quiesce(spec)
            val audit = worker.audit(spec, false)
            require(audit.maintenanceId == fences[name] && audit.statuses.all {
                val process = spec.processes.single { p -> p.id == it.id }
                if (process.oneShot) it.state in setOf("completed", "exited") && it.exitCode == 0
                else it.state == "exited" && it.exitCode in setOf(0, 143)
            })
            save(root.resolve("quiesce-$name.result.json"), json.encodeToString(audit))
        }
        if (original.request.managedLanes != null) {
            val stopped = requireNotNull(GenerationManagedComponents.isolate(original,
                base.resolve(source.id), "restore-$suiteId"))
            require(stopped.brokerSocketAbsent && stopped.lanes.values.all { it.isolated })
        }
        val record = RestoredDirectSourceQuiesce(suiteId = suiteId, source = source, target = target,
            captureId = captureId, fences = fences, snapshotSha256 = ReleaseLocks.sha256(snapshotBytes),
            originalRouteSha256 = ReleaseLocks.sha256(routeBytes))
        save(path, json.encodeToString(record))
        ActivationInput(path.toString(), ReleaseLocks.sha256(data(path)))
    }
    /** One-use direct-source resume only after a real target isolate result and frozen
     * stopped-source leases. A lost acknowledgement never authorizes a second restart. */
    fun directRestoreResume(inventory: AcquiredInventory, quiescence: ActivationInput,
        finalIsolation: ActivationInput): ActivationInput = mutating {
        require(base == BASE && runtimeBase == PrivateDeployment.BASE)
        val path = Path.of(quiescence.path)
        val bytes = data(path)
        require(ReleaseLocks.sha256(bytes) == quiescence.sha256)
        val record = json.decodeFromString<RestoredDirectSourceQuiesce>(bytes.decodeToString(throwOnInvalidSequence = true))
        val routeBytes = data(path.parent.resolve("original-route.json"))
        val route = json.decodeFromString<RestoredOriginalRouteAuthority>(routeBytes
            .decodeToString(throwOnInvalidSequence = true)).also { it.recheck() }
        require(route.source == record.source && record.originalRouteSha256 == ReleaseLocks.sha256(routeBytes))
        require(record.schemaVersion == 2 && path == base.resolve(record.source.id)
            .resolve("qualification-direct/${record.suiteId}/quiesce.result.json") &&
            finalIsolation.path == base.resolve(record.target.id).resolve("isolate.result.json").toString())
        val isolatedBytes = data(Path.of(finalIsolation.path))
        require(ReleaseLocks.sha256(isolatedBytes) == finalIsolation.sha256)
        val isolated = json.decodeFromString<GenerationOutcome>(isolatedBytes.decodeToString(throwOnInvalidSequence = true))
        val (target, targetSpecs) = load(record.target.id, record.target.bundleSha256)
        val (original, specs) = backupSource(inventory, record.source.id, record.source.bundleSha256)
        require(target.recoverySourceKopia?.id == record.captureId &&
            target.recoverySourceKopia?.generation == record.source.id &&
            isolated.action == "isolate" && isolated.passed && isolated.failureType == null &&
            isolated.bundleSha256 == record.target.bundleSha256 &&
            isolated.fences.keys == targetSpecs.map { it.name }.toSet())
        val targetRuntime = backend(target)
        targetSpecs.forEach { spec ->
            val audit = targetRuntime.audit(spec, false)
            require(audit.maintenanceId == isolated.fences[spec.name] && audit.statuses.all {
                it.state == "exited" && it.exitCode in setOf(0, 143)
            })
        }
        val access = RuntimeBackupAccess(record.source.id, record.captureId, record.source.bundleSha256)
        val worker = backupRuntime(original, access)
        require(record.fences.keys == specs.map { it.name }.toSet())
        for (spec in specs) {
            val audit = worker.audit(spec, false)
            require(audit.maintenanceId == record.fences[spec.name] && audit.statuses.all {
                val process = spec.processes.single { p -> p.id == it.id }
                if (process.oneShot) it.state in setOf("completed", "exited") && it.exitCode == 0
                else it.state == "exited" && it.exitCode in setOf(0, 143)
            })
        }
        val root = path.parent
        val available = capacity(original.request.store)
        require(available.availableMemoryMiB - original.memoryReservationMiB >= 16384 &&
            available.usableDiskMiB >= 10240)
        save(root.resolve("resume.intent.json"), json.encodeToString(buildJsonObject {
            put("quiescenceSha256", quiescence.sha256); put("isolationSha256", finalIsolation.sha256)
        }))
        for (spec in specs) {
            save(root.resolve("resume-${spec.name}.intent.json"), json.encodeToString(access))
            worker.resume(spec, record.fences.getValue(spec.name))
            requireRunning(spec, worker.audit(spec, false))
            save(root.resolve("resume-${spec.name}.result.json"), json.encodeToString(access))
        }
        if (original.request.managedLanes != null) {
            val resumed = requireNotNull(GenerationManagedComponents.resumeOriginal(original,
                base.resolve(record.source.id), "restore-${record.suiteId}", "restore-${record.suiteId}"))
            require(resumed.lanes.values.all { !it.isolated } && resumed.brokerMainPid > 1)
        }
        val audits = specs.map { worker.audit(it, false).also { audit -> requireRunning(it, audit) } }
        val auditBytes = json.encodeToString(GenerationInspection(record.source.id, record.source.bundleSha256,
            original.memoryReservationMiB, audits)).encodeToByteArray()
        ReleasePrivateFiles.save(root.resolve("resume.audit.json"), auditBytes)
        for (spec in specs) {
            save(root.resolve("release-${spec.name}.intent.json"), json.encodeToString(access))
            worker.finish(spec)
            save(root.resolve("release-${spec.name}.result.json"), json.encodeToString(access))
        }
        val resultPath = root.resolve("resume.result.json")
        val result = RestoredDirectSourceResume(suiteId = record.suiteId, source = record.source,
            target = record.target, quiescenceSha256 = quiescence.sha256,
            finalIsolationSha256 = finalIsolation.sha256, resumed = true,
            sourceAuditSha256 = ReleaseLocks.sha256(auditBytes))
        save(resultPath, json.encodeToString(result))
        ActivationInput(resultPath.toString(), ReleaseLocks.sha256(data(resultPath)))
    }
    /** Production RESTORE actor keeps its complete source+target member namespace cohort
     * and generation/RSS exclusion across per-case bridge effects, target isolation and
     * actual source resume. Nested runtime operations reenter ONLY this same thread's locks. */
    fun <T> withRestoredIsolationLocks(source: ReleaseGeneration, target: ReleaseGeneration,
        action: () -> T): T = mutating {
        require(base == BASE && runtimeBase == PrivateDeployment.BASE && source.id != target.id)
        source.validate(); target.validate()
        val (original, sourceSpecs) = load(source.id, source.bundleSha256, checkLiveInputs = false)
        val (restored, targetSpecs) = load(target.id, target.bundleSha256, checkLiveInputs = false)
        QualificationCanonicalTopology.require(original,
            allowOwnedUpdateSource = original.ownedUpdate != null)
        QualificationCanonicalTopology.require(restored, restoredTarget = true)
        require(sourceSpecs.isNotEmpty() && targetSpecs.isNotEmpty() &&
            (restored.recoverySourceKopia?.let { it.generation == source.id && it.bundleSha256 == source.bundleSha256 } == true ||
                restored.ownedUpdate?.let { it.intent.source == source && OwnedReleaseUpdates.original(it) == original } == true) &&
            targetSpecs.all { it.ingress == null && it.nativeIngress == null && it.processes.none { p -> p.oneShot } })
        val names = (sourceSpecs + targetSpecs).map { it.name }
        require(names.size == names.toSet().size)
        PrivateDeployment.withOrderedNativeLocks(names, runtimeBase) { action() }
    }
    /** Native TURN adoption is a distinct one-use effect AFTER an actual effective public
     * Caddy revision, BEFORE A13 is permitted to expose :5349. Retain the source and target
     * native lock cohort through native secret replacement and A15's independent TLS proof. */
    fun adoptEffectiveTurn(operation: String, generation: String, expected: String,
        revision: ActivationInput, approvedHosts: Set<String>, trust: ActivationInput): PublicTurnAdoptionResult = mutating {
        require(base == BASE && runtimeBase == PrivateDeployment.BASE &&
            operation.matches(Regex("[a-z0-9-]{1,64}")) && expected.matches(hash) &&
            Path.of(trust.path).isAbsolute && trust.sha256.matches(hash))
        val (bundle, specs) = load(generation, expected)
        require(bundle.request.store == RuntimeStore.CANONICAL_V2 &&
            specs.count { it.processes.any { process -> process.id == "caddy" } } == 1 &&
            specs.count { it.processes.any { process -> process.id == "livekit" } } == 1)
        val original = when {
            bundle.ownedUpdate != null -> OwnedReleaseUpdates.original(requireNotNull(bundle.ownedUpdate))
            bundle.recoverySourceKopia != null -> {
                val receipt = requireNotNull(bundle.recoverySourceKopia)
                val bytes = data(base.resolve(receipt.generation).resolve("bundle.json"))
                require(ReleaseLocks.sha256(bytes) == receipt.bundleSha256)
                json.decodeFromString<GenerationBundle>(bytes.decodeToString(throwOnInvalidSequence = true))
            }
            else -> bundle
        }
        val owner = requireNotNull(original.ownership)
        SiteOwnerships.checkSealed(original)
        require(approvedHosts == owner.approvedHosts && "rtc.datamancy.net" in approvedHosts &&
            ReleaseLocks.sha256(data(Path.of(trust.path))) == trust.sha256 &&
            revision.sha256.matches(hash))
        val measured = capacity(RuntimeStore.CANONICAL_V2)
        RuntimeLockBudget.requireAvailable(measured.availableRuntimeLocks, specs, workers = 2)
        require(measured.availableMemoryMiB >= bundle.request.memoryHeadroomMiB + 2048 &&
            measured.usableDiskMiB >= bundle.request.diskHeadroomMiB + 512)
        val names = (bundle.members + original.members).filter { pin ->
            pin.spec.processes.any { it.id in setOf("caddy", "livekit") }
        }.map { it.spec.name }.distinct().sorted()
        PrivateDeployment.withOrderedNativeLocks(names, runtimeBase) {
            val runtime = backend(bundle)
            specs.filter { it.processes.any { process -> process.id in setOf("caddy", "livekit") } }
                .forEach { spec ->
                    val audit = runtime.audit(spec, false)
                    require(audit.fingerprint == bundle.members.single { it.spec.name == spec.name }.runtimeFingerprint &&
                        audit.maintenanceId == null && spec.processes.filter { it.id in setOf("caddy", "livekit") }
                            .all { p -> audit.statuses.singleOrNull { it.id == p.id }?.state == "running" })
                }
            NativeCredentialRevision.adoptTurn(bundle, revision, approvedHosts, trust,
                NativeCaddyCertificateCollector(Path.of(trust.path), trust.sha256),
                NativePrivateTurnCredentialActuator(), operation)
        }
    }
    /** Read-only eligibility for enrollment; the backup itself repeats these checks under the operation lock. */
    fun checkBackupSource(inventory: AcquiredInventory, generation: String, expected: String) = locked {
        val (bundle, specs) = backupSource(inventory, generation, expected)
        val runtime = backend(bundle)
        specs.forEach { requireRunning(it, runtime.audit(it, false)) }
    }
    /** A recovered source remains private. Its import proof is not site promotion or a functional acceptance receipt. */
    private fun completedCaptureSource(bundle: GenerationBundle, expected: String, allowRecovered: Boolean) {
        val root = base.resolve(bundle.request.id)
        val stage = json.decodeFromString<GenerationOutcome>(data(root.resolve("stage.result.json")).decodeToString())
        require(stage.passed && stage.failureType == null && stage.bundleSha256 == expected) { "Capture requires completed source staging" }
        val lineage = bundle.recoverySourceKopia
        if (lineage == null) {
            if (bundle.ownedUpdate != null) {
                // Explicitly OWNED import+native migration+startup; never a generic recovered
                // target promoted by a stage.success callback or initializer stripping.
                OwnedReleaseUpdates.validate(bundle)
                val source = requireNotNull(bundle.ownedUpdate)
                require(stage.action == "restore-import" && stage.fences.keys ==
                    bundle.members.map { it.member.name }.toSet() && bundle.recoverySourceArchiveSha256 == null)
                val intent = json.decodeFromString<GenerationIntent>(data(root.resolve("stage.intent.json")).decodeToString())
                require(intent == GenerationIntent("restore-import", expected) &&
                    json.decodeFromString<KopiaSnapshotReceipt>(data(root.resolve("recovery.source.json")).decodeToString()) == source.snapshot)
                val original = load(source.intent.source.id, source.intent.source.bundleSha256,
                    checkLiveInputs = false).first
                require(original == OwnedReleaseUpdates.original(source))
                val held = json.decodeFromString<GenerationHeldCapture>(data(base.resolve(original.request.id)
                    .resolve("backups/${source.snapshot.id}/held.json")).decodeToString()).also { it.validate() }
                require(held.snapshot == source.snapshot && held.access.bundleSha256 == source.intent.source.bundleSha256)
                val receiptHash = KopiaGenerationStore.receiptHash(source.snapshot)
                for (pin in bundle.members) {
                    require(pin.spec.processes.none { it.oneShot })
                    val memberIntent = json.decodeFromString<GenerationIntent>(data(root.resolve(
                        "${pin.member.name}.import.intent.json")).decodeToString())
                    val memberResult = json.decodeFromString<RuntimeAudit>(data(root.resolve(
                        "${pin.member.name}.import.result.json")).decodeToString())
                    require(memberIntent == GenerationIntent("import-member", expected) &&
                        memberResult.name == pin.member.name && memberResult.fingerprint == pin.runtimeFingerprint &&
                        memberResult.maintenanceId == stage.fences[pin.member.name])
                    val marker = "p0v3-native-volume-import-v1\n${pin.runtimeFingerprint}\n$receiptHash\n".toByteArray()
                    for (file in listOf("runtime.import.intent", "runtime.import.complete"))
                        require(data(runtimeBase.resolve(pin.member.name).resolve(file)).contentEquals(marker))
                }
                val started = json.decodeFromString<GenerationOutcome>(data(root.resolve("owned-start.result.json")).decodeToString())
                require(started.action == "owned-start" && started.passed && started.failureType == null &&
                    started.bundleSha256 == expected)
            } else require(bundle.recoverySourceArchiveSha256 == null && stage.action == "stage") {
                "Capture requires a clean installation or explicitly owned update"
            }
            return
        }
        require(allowRecovered && bundle.recoverySourceArchiveSha256 == null && bundle.ownership == null && bundle.assemblySha256 == null &&
            stage.action == "restore-import" && stage.fences.keys == bundle.members.map { it.member.name }.toSet()) { "Private recovered backup authority required" }
        KopiaGenerationStore.validate(lineage)
        require(lineage.generation != bundle.request.id)
        val intent = json.decodeFromString<GenerationIntent>(data(root.resolve("stage.intent.json")).decodeToString())
        require(intent == GenerationIntent("restore-import", expected) && stage.priorIntentSha256 == null)
        require(json.decodeFromString<KopiaSnapshotReceipt>(data(root.resolve("recovery.source.json")).decodeToString()) == lineage) { "Recovery lineage changed" }
        val receiptHash = KopiaGenerationStore.receiptHash(lineage)
        val check = json.decodeFromString<GenerationRecoveryCheck>(data(root.resolve("recovery.check.json")).decodeToString())
        val parent = load(lineage.generation, lineage.bundleSha256, checkLiveInputs = false).first
        require(check.generation == lineage.generation && check.capsule == lineage.id && check.bundleSha256 == lineage.bundleSha256 &&
            check.archiveSha256.isEmpty() && check.kopiaSnapshotId == lineage.snapshotId && check.kopiaReceiptSha256 == receiptHash &&
            !check.functionalRestoreVerified && !check.runtimeImported && check.members.map { it.name } == parent.members.map { it.member.name } &&
            check.members.zip(parent.members).all { (checked, pin) -> checked.fingerprint == pin.runtimeFingerprint &&
                checked.retiredInitializers == pin.spec.processes.filter { it.oneShot }.map { it.id }.toSet() }) { "Recovered source verification differs from lineage" }
        for (pin in bundle.members) {
            require(pin.spec.processes.none { it.oneShot }) { "Recovered backup cannot regain bootstrap processes" }
            val memberIntent = json.decodeFromString<GenerationIntent>(data(root.resolve("${pin.member.name}.import.intent.json")).decodeToString())
            val memberResult = json.decodeFromString<RuntimeAudit>(data(root.resolve("${pin.member.name}.import.result.json")).decodeToString())
            require(memberIntent == GenerationIntent("import-member", expected) && memberResult.name == pin.member.name &&
                memberResult.fingerprint == pin.runtimeFingerprint && memberResult.maintenanceId == stage.fences.getValue(pin.member.name)) {
                "Incomplete or foreign member import history"
            }
            val marker = "p0v3-native-volume-import-v1\n${pin.runtimeFingerprint}\n$receiptHash\n".toByteArray()
            for (file in listOf("runtime.import.intent", "runtime.import.complete"))
                require(data(runtimeBase.resolve(pin.member.name).resolve(file)).contentEquals(marker)) { "Native imported source lineage changed" }
        }
    }
    private fun backupSource(inventory: AcquiredInventory, generation: String, expected: String): Pair<GenerationBundle, List<PrivateDeploymentSpec>> {
        val (bundle, specs) = load(generation, expected)
        require(bundle.recoverySourceArchiveSha256 == null &&
            ((bundle.ownership != null && bundle.recoverySourceKopia == null) || (bundle.ownership == null && bundle.recoverySourceKopia != null))) {
            "Routine backup requires an owned canonical installation or private Kopia recovery"
        }
        if (bundle.ownedUpdate == null) FoundationRestore.bundle(bundle, inventory,
            if (generation == "q-000000000000") "q-111111111111" else "q-000000000000",
            "0".repeat(64), ColdRestoreCohort.WHOLE_RELEASE)
        else {
            OwnedReleaseUpdates.validate(bundle)
            val preparation = json.decodeFromString<ReleaseUpdatePreparation>(data(base.resolve(generation)
                .resolve("owned-import.intent.json")).decodeToString())
            preparation.validate(preparation.intent.source, generation, base)
            require(bundle.ownedUpdate?.intent == preparation.intent &&
                json.decodeFromString<AcquiredInventory>(ReleasePrivateFiles.read(Path.of(
                    preparation.candidateInventory.path)).decodeToString()) == inventory)
        }
        val generationRoot = base.resolve(generation)
        require(!Files.exists(generationRoot.resolve("isolate.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(generationRoot.resolve("kopia-store/snapshot.pending.json"), NOFOLLOW_LINKS) &&
            !Files.exists(generationRoot.resolve("kopia-store/retention.pending.json"), NOFOLLOW_LINKS)) { "Retired or uncertain source cannot be resumed by backup" }
        completedCaptureSource(bundle, expected, allowRecovered = true)
        return bundle to specs
    }
    /** New canonical source only. No permanent isolation history, unknown prior backup or bootstrap replay. */
    fun backupKopia(inventory: AcquiredInventory, generation: String, expected: String, captureId: String,
        custody: Path = Path.of("/mnt/media/p0-v3/kopia-custody"), store: GenerationSnapshotStore? = null): GenerationBackupOutcome =
        requireNotNull(coordinatedBackup(inventory, generation, expected, captureId, custody, store, hold = false).first)

    fun holdKopiaForRestore(inventory: AcquiredInventory, generation: String, expected: String, captureId: String,
        custody: Path = Path.of("/mnt/media/p0-v3/kopia-custody"), store: GenerationSnapshotStore? = null,
        reference: PendingRecoveryOperation? = null): GenerationHeldCapture =
        requireNotNull(coordinatedBackup(inventory, generation, expected, captureId, custody, store, hold = true,
            reference = reference).second) {
            "Source hold failed; retained isolation must be reconciled, never retried"
        }

    private fun coordinatedBackup(inventory: AcquiredInventory, generation: String, expected: String, captureId: String,
        custody: Path, store: GenerationSnapshotStore?, hold: Boolean,
        reference: PendingRecoveryOperation? = null): Pair<GenerationBackupOutcome?, GenerationHeldCapture?> = mutating {
        val access = RuntimeBackupAccess(generation, captureId, expected); access.validate()
        val (bundle, specs) = backupSource(inventory, generation, expected)
        val generationRoot = base.resolve(generation)
        require(!Files.exists(generationRoot.resolve("kopia-captures/$captureId"), NOFOLLOW_LINKS)) { "Capture namespace already exists" }
        val runtime = backupRuntime(bundle, access)
        specs.forEach { requireRunning(it, runtime.audit(it, false)) }
        val measured = capacity(bundle.request.store)
        RuntimeLockBudget.requireAvailable(measured.availableRuntimeLocks, workers = 3)
        require(measured.availableMemoryMiB >= bundle.request.memoryHeadroomMiB + 1024) { "Insufficient routine backup headroom" }
        admitRecoveryScratch(bundle.request, measured, 4)
        val backups = generationRoot.resolve("backups")
        if (!Files.exists(backups, NOFOLLOW_LINKS)) {
            Files.createDirectory(backups, PosixFilePermissions.asFileAttribute(privateDir))
            FileChannel.open(generationRoot, READ).use { it.force(true) }
        }
        directory(backups)
        Files.list(backups).use { entries ->
            val prior = entries.limit(129).toList(); require(prior.size < 128) { "Backup history bound reached; no automatic evidence deletion" }
            for (path in prior) {
                directory(path); require(path.fileName.toString().matches(Regex("cap-[a-f0-9]{12}")))
                val intent = json.decodeFromString<RuntimeBackupAccess>(data(path.resolve("intent.json")).decodeToString())
                val result = json.decodeFromString<GenerationBackupOutcome>(data(path.resolve("result.json")).decodeToString())
                require(intent == RuntimeBackupAccess(generation, path.fileName.toString(), expected) && result.access == intent &&
                    result.passed && result.sourceResumed) { "Incomplete or failed backup requires reconciliation, not another operation ID" }
            }
        }
        val requestedReference = reference ?: PendingRecoveryOperation(if (hold) "held" else "backup", captureId, access)
        require(requestedReference.access == access && (hold || reference == null)) { "Recovery reference access mismatch" }
        val pendingReference = RecoveryReferenceOperations.beginCapture(base, access, requestedReference.kind, requestedReference.id)
        val root = backups.resolve(captureId)
        Files.createDirectory(root, PosixFilePermissions.asFileAttribute(privateDir))
        FileChannel.open(backups, READ).use { it.force(true) }
        save(root.resolve("intent.json"), json.encodeToString(access))
        fun <T> effect(name: String, action: () -> T): T {
            save(root.resolve("$name.intent.json"), json.encodeToString(access))
            return action().also { save(root.resolve("$name.result.json"), json.encodeToString(access)) }
        }
        var snapshot: KopiaSnapshotReceipt? = null
        fun failed(error: Exception): GenerationBackupOutcome {
            var interrupted = Thread.interrupted() || error is InterruptedException
            val result = GenerationBackupOutcome(access, false, snapshot, false, error.javaClass.name)
            var recording: Exception? = null
            fun retain(e: Exception) {
                interrupted = Thread.interrupted() || e is InterruptedException || interrupted
                if (recording == null) recording = e else recording!!.addSuppressed(e)
            }
            try {
                try { save(root.resolve("result.json"), json.encodeToString(result)) }
                catch (e: InterruptedException) { retain(e) }
                catch (e: Exception) { retain(e) }
                // Independent stop/fence result, even if backup result persistence failed.
                try { isolateLocked(generation, expected, runtimeOverride = runtime) }
                catch (e: InterruptedException) { retain(e) }
                catch (e: Exception) { retain(e) }
                recording?.let { it.addSuppressed(error); throw it }
                return result
            } finally { if (interrupted) Thread.currentThread().interrupt() }
        }
        try {
            for (spec in specs) effect("claim-${spec.name}") { runtime.claim(spec) }
            val fences = linkedMapOf<String, String>()
            for (spec in specs.asReversed()) fences[spec.name] = effect("quiesce-${spec.name}") { runtime.quiesce(spec) }
            save(root.resolve("quiesced.json"), json.encodeToString(fences))
            if (bundle.request.managedLanes != null) {
                require(base == BASE && runtimeBase == PrivateDeployment.BASE)
                PrivateDeployment.withOrderedNativeLocks(specs.map { it.name }, runtimeBase) {
                    val stopped = requireNotNull(GenerationManagedComponents.isolate(bundle, generationRoot,
                        "backup-$captureId"))
                    require(stopped.brokerSocketAbsent && stopped.lanes.values.all { it.isolated })
                }
            }
            snapshot = effect("capture") { requireNotNull(captureLocked(generation, expected, captureId, custody, store ?: KopiaGenerationStore.real(inventory, bundle.request.store), runtime, fences).kopia) }
            require(snapshot.id == captureId && snapshot.generation == generation && snapshot.bundleSha256 == expected)
            RecoveryReferenceOperations.bindCaptured(base, pendingReference, snapshot)
            if (hold) {
                val held = GenerationHeldCapture(access, snapshot, fences).also { it.validate() }
                if (pendingReference.kind != "held")
                    RecoveryReferenceOperations.protect(base, snapshot, "unknown", "held-$captureId")
                save(root.resolve("held.json"), json.encodeToString(held))
                return@mutating null to held // No resumed/success outcome and no lease release while the restore target is active.
            }
            val available = capacity(bundle.request.store)
            require(available.availableMemoryMiB >= bundle.memoryReservationMiB + bundle.request.memoryHeadroomMiB &&
                available.usableDiskMiB >= bundle.request.diskHeadroomMiB) { "Insufficient safe resume capacity; source remains fenced" }
            for (spec in specs) effect("resume-${spec.name}") {
                completedCaptureSource(load(generation, expected).first, expected, allowRecovered = true)
                runtime.resume(spec, fences.getValue(spec.name))
                requireRunning(spec, runtime.audit(spec, false))
            }
            val resumedAudits = specs.map { spec -> runtime.audit(spec, false).also { requireRunning(spec, it) } }
            if (bundle.request.managedLanes != null) {
                PrivateDeployment.withOrderedNativeLocks(specs.map { it.name }, runtimeBase) {
                    val managed = requireNotNull(GenerationManagedComponents.resumeOriginal(bundle, generationRoot,
                        "backup-$captureId", "backup-$captureId"))
                    require(managed.lanes.values.all { !it.isolated } && managed.brokerMainPid > 1)
                }
            }
            save(root.resolve("resume.audit.json"), json.encodeToString(GenerationInspection(generation, expected,
                bundle.memoryReservationMiB, resumedAudits)))
            save(root.resolve("resume.verified.json"), json.encodeToString(access))
            for (spec in specs) effect("release-${spec.name}") { runtime.finish(spec) }
            val result = GenerationBackupOutcome(access, true, snapshot, true)
            save(root.resolve("result.json"), json.encodeToString(result))
            RecoveryReferenceOperations.completeBackup(base, access)
            result to null
        } catch (e: InterruptedException) { failed(e); throw e }
        catch (e: Exception) { failed(e) to null }
    }

    /** Resume only this still-held source while the exact imported target is locked, stopped and fenced. */
    fun resumeHeldSourceAfterIsolation(inventory: AcquiredInventory, generation: String, expected: String, captureId: String,
        expectedHeldSha256: String, target: String, targetExpected: String): GenerationBackupOutcome = mutating {
        val access = RuntimeBackupAccess(generation, captureId, expected).also { it.validate() }
        require(hash.matches(expectedHeldSha256) && hash.matches(targetExpected) && id.matches(target) && target != generation)
        val root = base.resolve(generation).resolve("backups/$captureId"); directory(root)
        require(!Files.exists(root.resolve("result.json"), NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("resume.authority.json"), NOFOLLOW_LINKS)) { "Held-source resume already attempted; no replay" }
        val bytes = data(root.resolve("held.json"))
        require(ReleaseLocks.sha256(bytes) == expectedHeldSha256)
        val held = json.decodeFromString<GenerationHeldCapture>(bytes.decodeToString()).also { it.validate() }
        require(held.access == access && held.sha256 == expectedHeldSha256 &&
            json.decodeFromString<RuntimeBackupAccess>(data(root.resolve("intent.json")).decodeToString()) == access)
        val capture = json.decodeFromString<KopiaCaptureOutcome>(data(base.resolve(generation)
            .resolve("kopia-captures/$captureId/capture.result.json")).decodeToString())
        require(capture.passed && capture.failureType == null && capture.id == captureId &&
            capture.bundleSha256 == expected && capture.snapshot == held.snapshot) { "Held snapshot lineage changed" }
        val (bundle, specs) = backupSource(inventory, generation, expected)
        require(held.fences.keys == specs.map { it.name }.toSet())
        val (targetBundle, targets) = load(target, targetExpected)
        require((targetBundle.recoverySourceKopia == held.snapshot ||
            targetBundle.ownedUpdate?.let { owned ->
                owned.snapshot == held.snapshot && OwnedReleaseUpdates.original(owned) == bundle &&
                    owned.intent.source == ReleaseGeneration(generation, expected)
            } == true) && targets.none { it.name in held.fences } &&
            targets.all { spec -> spec.processes.none { it.oneShot } }) { "Exact initializer-free imported or owned-update target required" }
        completedCaptureSource(targetBundle, targetExpected, allowRecovered = true)
        val targetRuntime = backend(targetBundle)
        val cold = targetRuntime as? ColdGenerationBackend ?: error("Target isolation observer unavailable")
        val observations = targets.associate { it.name to targetRuntime.audit(it, false) }
        val isolation = isolationOutcomes(base.resolve(target), targetExpected).firstOrNull { outcome ->
            outcome.passed && outcome.failureType == null && outcome.fences.keys == targets.map { it.name }.toSet() &&
                observations.all { (name, observed) -> observed.maintenanceId == outcome.fences[name] &&
                    observed.statuses.all { it.state == "exited" && it.exitCode in setOf(0, 143) } }
        } ?: error("Target isolation must be verified before source resume")
        val runtime = backupRuntime(bundle, access)
        val frozenTargets = mutableListOf<FrozenRuntimeObservation>()
        fun frozen(index: Int): GenerationBackupOutcome {
            if (index < targets.size) return cold.withFrozen(targets[index], isolation.fences.getValue(targets[index].name)) { observed ->
                val pin = targetBundle.members[index]
                require(observed.name == pin.member.name && observed.fingerprint == pin.runtimeFingerprint &&
                    observed.fenceId == isolation.fences[observed.name] && observed.completedInitializers.isEmpty() &&
                    observed.statuses.map { it.id }.toSet() == pin.spec.processes.map { it.id }.toSet() &&
                    observed.statuses.size == pin.spec.processes.size && observed.statuses.all { it.state == "exited" && it.exitCode in setOf(0, 143) })
                frozenTargets += observed
                frozen(index + 1)
            }
            // All target runtime locks stay held through every source resume and lease release.
            val available = capacity(bundle.request.store)
            require(available.availableMemoryMiB >= bundle.memoryReservationMiB + bundle.request.memoryHeadroomMiB &&
                available.usableDiskMiB >= bundle.request.diskHeadroomMiB) { "Insufficient safe resume capacity; source remains fenced" }
            RuntimeLockBudget.requireAvailable(available.availableRuntimeLocks, specs + targets, workers = 0)
            specs.forEach { spec ->
                val observed = runtime.audit(spec, false)
                require(observed.name == spec.name && observed.fingerprint == bundle.members.single { it.member.name == spec.name }.runtimeFingerprint &&
                    observed.statuses.size == spec.processes.size && observed.statuses.map { it.id }.toSet() == spec.processes.map { it.id }.toSet() &&
                    observed.maintenanceId == held.fences.getValue(spec.name) && observed.statuses.all {
                    if (spec.processes.single { p -> p.id == it.id }.oneShot) it.state in setOf("completed", "exited") && it.exitCode == 0
                    else it.state == "exited" && it.exitCode in setOf(0, 143)
                }) { "Held source changed before resume" }
            }
            save(root.resolve("resume.authority.json"), json.encodeToString(HeldSourceResumeAuthority(expectedHeldSha256, target, targetExpected, isolation.fences)))
            fun effect(name: String, action: () -> Unit) {
                if (Thread.currentThread().isInterrupted) throw InterruptedException("Held-source resume interrupted")
                save(root.resolve("$name.intent.json"), json.encodeToString(access)); action()
                save(root.resolve("$name.result.json"), json.encodeToString(access))
            }
            try {
                for (spec in specs) effect("resume-${spec.name}") {
                    completedCaptureSource(load(generation, expected).first, expected, allowRecovered = true)
                    runtime.resume(spec, held.fences.getValue(spec.name)); requireRunning(spec, runtime.audit(spec, false))
                }
                specs.forEach { requireRunning(it, runtime.audit(it, false)) }
                if (bundle.request.managedLanes != null) {
                    require(base == BASE && runtimeBase == PrivateDeployment.BASE)
                    val managed = requireNotNull(if (bundle.ownedUpdate == null)
                        GenerationManagedComponents.resumeOriginal(bundle,
                            base.resolve(generation), "backup-$captureId", "restore-$captureId")
                    else GenerationManagedComponents.resumeOwnedCandidate(bundle,
                        base.resolve(generation), "backup-$captureId", "restore-$captureId"))
                    require(managed.lanes.values.all { !it.isolated } && managed.brokerMainPid > 1)
                }
                save(root.resolve("resume.verified.json"), json.encodeToString(access))
                for (spec in specs) effect("release-${spec.name}") { runtime.finish(spec) }
                val result = GenerationBackupOutcome(access, true, held.snapshot, true)
                val sourceObservations = specs.map { spec -> runtime.audit(spec, false).also { requireRunning(spec, it) } }
                save(root.resolve("result.json"), json.encodeToString(result))
                val proof = GenerationCompletionProof(access = access, heldSha256 = expectedHeldSha256,
                    snapshotId = held.snapshot.snapshotId, target = target, targetBundleSha256 = targetExpected,
                    targetFences = isolation.fences,
                    sourceResultSha256 = ReleaseLocks.sha256(data(root.resolve("result.json"))),
                    resumeAuthoritySha256 = ReleaseLocks.sha256(data(root.resolve("resume.authority.json"))),
                    sourceObservations = sourceObservations, targetObservations = frozenTargets.toList())
                proof.validate()
                save(root.resolve("completion.proof.json"), json.encodeToString(proof))
                RecoveryReferenceOperations.authority(base, generation, expected)
                    .retireHeldSource(captureId, target, targetExpected)
                return result
            } catch (failure: Exception) {
                val interrupted = Thread.interrupted() || failure is InterruptedException
                try {
                    try { save(root.resolve("result.json"), json.encodeToString(GenerationBackupOutcome(access, false, held.snapshot, false, failure.javaClass.name))) }
                    finally { isolateLocked(generation, expected, runtimeOverride = runtime) }
                    throw failure
                } finally { if (interrupted) Thread.currentThread().interrupt() }
            }
        }
        if (runtimeBase == PrivateDeployment.BASE)
            PrivateDeployment.withOrderedNativeLocks((specs + targets).map { it.name }, runtimeBase) { frozen(0) }
        else frozen(0) // Unit-only injected transports provide their own native isolation.
    }
    /** Read and independently re-observe a controller-written held recovery completion.
     * This grants neither functional acceptance nor publication, and never resumes anything.
     */
    fun completionProof(generation: String, expected: String, captureId: String,
        target: String, targetExpected: String): GenerationCompletionReceipt = locked {
        completionProofLocked(generation, expected, captureId, target, targetExpected)
    }
    private fun completionProofLocked(generation: String, expected: String, captureId: String,
        target: String, targetExpected: String): GenerationCompletionReceipt {
        val access = RuntimeBackupAccess(generation, captureId, expected).also { it.validate() }
        require(id.matches(target) && target != generation && hash.matches(targetExpected))
        val root = base.resolve(generation).resolve("backups/$captureId")
        val path = root.resolve("completion.proof.json")
        val bytes = data(path)
        val proof = try { json.decodeFromString<GenerationCompletionProof>(bytes.decodeToString(throwOnInvalidSequence = true)) }
            catch (_: Exception) { error("Invalid private generation completion proof") }
        proof.validate()
        require(proof.access == access && proof.target == target && proof.targetBundleSha256 == targetExpected &&
            proof.sourceResultSha256 == ReleaseLocks.sha256(data(root.resolve("result.json"))) &&
            proof.resumeAuthoritySha256 == ReleaseLocks.sha256(data(root.resolve("resume.authority.json"))) &&
            proof.heldSha256 == ReleaseLocks.sha256(data(root.resolve("held.json")))) { "Completion proof lineage changed" }
        val result = json.decodeFromString<GenerationBackupOutcome>(data(root.resolve("result.json")).decodeToString())
        val authority = json.decodeFromString<HeldSourceResumeAuthority>(data(root.resolve("resume.authority.json")).decodeToString())
        require(result.access == access && result.passed && result.sourceResumed && result.failureType == null &&
            result.snapshot?.snapshotId == proof.snapshotId && authority.heldSha256 == proof.heldSha256 &&
            authority.target == target && authority.targetBundleSha256 == targetExpected && authority.targetFences == proof.targetFences)
        val (sourceBundle, sources) = load(generation, expected)
        val (restoredBundle, restored) = load(target, targetExpected)
        require((restoredBundle.recoverySourceKopia == result.snapshot ||
            restoredBundle.ownedUpdate?.let { owned ->
                owned.snapshot == result.snapshot && OwnedReleaseUpdates.original(owned) == sourceBundle &&
                    owned.intent.source == ReleaseGeneration(generation, expected)
            } == true) &&
            proof.sourceObservations.map { it.name } == sources.map { it.name } &&
            proof.targetObservations.map { it.name } == restored.map { it.name }) { "Foreign completion cohort" }
        val sourceRuntime = backend(sourceBundle)
        sources.forEach { requireRunning(it, sourceRuntime.audit(it, false)) }
        val targetRuntime = backend(restoredBundle)
        val cold = targetRuntime as? ColdGenerationBackend ?: error("Native target isolation observer unavailable")
        fun observe(index: Int) {
            if (index == restored.size) return
            val spec = restored[index]
            cold.withFrozen(spec, proof.targetFences.getValue(spec.name)) { observed ->
                require(observed == proof.targetObservations[index]) { "Target isolation changed after completion" }
                observe(index + 1)
            }
        }
        observe(0)
        return GenerationCompletionReceipt(proof, ActivationInput(path.toString(), ReleaseLocks.sha256(bytes)))
    }

    /** Controller-ordered first-install reference terminal. Keep the source generation lock
     * through both native completion readbacks and append-only site protection retirement. */
    /** Candidate isolation before rollback when there is no sealed candidate to inspect. */
    fun proveOwnedTargetAbsent(preparation: ReleaseUpdatePreparation,
        transactionId: String): NativeOwnedTargetAbsence = mutating {
        val intent = preparation.intent
        preparation.validate(intent.source, intent.targetGeneration, base)
        val tx = base.parent.resolve("release-transactions").resolve(transactionId)
        val request = json.decodeFromString<ReleaseTransactionRequest>(data(tx.resolve("request.json")).decodeToString())
        val journal = TransactionJournal.verify(tx.resolve("transaction.jsonl"))
        require(request.updatePreparation == preparation && request.snapshotId.matches(Regex("cap-[a-f0-9]{12}")) &&
            journal.last().phase == Phase.RECOVERY_REQUIRED &&
            journal.none { it.phase in setOf(Phase.STAGED, Phase.CUTOVER_RESTRICTED, Phase.ACCEPTED,
                Phase.ACTIVATION_STARTED, Phase.COMMITTED) })
        val target = base.resolve(intent.targetGeneration)
        require(!Files.exists(target.resolve("bundle.json"), NOFOLLOW_LINKS) &&
            !Files.exists(target.resolve("stage.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(target.resolve("stage.result.json"), NOFOLLOW_LINKS) &&
            !Files.exists(target.resolve("no-target.isolate.json"), NOFOLLOW_LINKS))
        if (Files.exists(target.resolve("owned-import.intent.json"), NOFOLLOW_LINKS))
            require(json.decodeFromString<ReleaseUpdatePreparation>(data(target.resolve(
                "owned-import.intent.json")).decodeToString()) == preparation)
        val (source, _) = load(intent.source.id, intent.source.bundleSha256)
        val held = json.decodeFromString<GenerationHeldCapture>(data(base.resolve(intent.source.id)
            .resolve("backups/${request.snapshotId}/held.json")).decodeToString()).also { it.validate() }
        RecoveryReferences(base.resolve(intent.source.id).resolve("recovery-references"))
            .requireBound("rollback", transactionId, held.snapshot)
        val targetMembers = source.members.map { pin ->
            require(pin.spec.name.startsWith("${intent.source.id}-"))
            intent.targetGeneration + pin.spec.name.removePrefix(intent.source.id)
        }
        PrivateDeployment.withOrderedNativeLocks(targetMembers, runtimeBase) {
            val probe = PrivateDeployment.observeAbsentOwnedTarget(source, intent.source.bundleSha256,
                intent.targetGeneration, runtimeRoot = runtimeBase)
            if (!Files.exists(target, NOFOLLOW_LINKS)) directory(target)
            save(target.resolve("no-target.isolate.json"), json.encodeToString(probe))
            probe
        }
    }
    /** Early owned PREPARED import never sealed a target. A native Podman namespace census,
     * not missing files or an import callback, authorizes original source resume. No retry of
     * an uncertain native write is possible; the original snapshot stays protected. */
    fun resumeOwnedWithoutTarget(preparation: ReleaseUpdatePreparation, capture: String,
        transactionId: String): OwnedUpdateNoTargetRollbackResult = mutating {
        val intent = preparation.intent
        preparation.validate(intent.source, intent.targetGeneration, base)
        require(transactionId.matches(Regex("[a-z][a-z0-9-]{0,63}")) && capture.matches(Regex("cap-[a-f0-9]{12}")))
        val txRoot = base.parent.resolve("release-transactions").resolve(transactionId)
        val request = json.decodeFromString<ReleaseTransactionRequest>(data(txRoot.resolve("request.json")).decodeToString())
        val journal = TransactionJournal.verify(txRoot.resolve("transaction.jsonl"))
        require(request.updatePreparation == preparation && request.snapshotId == capture &&
            journal.last().phase == Phase.RECOVERY_REQUIRED &&
            journal.none { it.phase in setOf(Phase.STAGED, Phase.CUTOVER_RESTRICTED, Phase.ACCEPTED,
                Phase.ACTIVATION_STARTED, Phase.COMMITTED) }) {
            "No-target rollback is confined to the pre-public-effect PREPARED failure"
        }
        val targetRoot = base.resolve(intent.targetGeneration)
        require(!Files.exists(targetRoot.resolve("bundle.json"), NOFOLLOW_LINKS) &&
            !Files.exists(targetRoot.resolve("stage.result.json"), NOFOLLOW_LINKS) &&
            !Files.exists(targetRoot.resolve("stage.intent.json"), NOFOLLOW_LINKS)) {
            "An attempted owned target requires full native isolation/reconciliation"
        }
        if (Files.exists(targetRoot.resolve("owned-import.intent.json"), NOFOLLOW_LINKS))
            require(json.decodeFromString<ReleaseUpdatePreparation>(data(targetRoot.resolve(
                "owned-import.intent.json")).decodeToString()) == preparation)
        val (source, specs) = load(intent.source.id, intent.source.bundleSha256)
        val backupRoot = base.resolve(intent.source.id).resolve("backups/$capture")
        val heldBytes = data(backupRoot.resolve("held.json"))
        val held = json.decodeFromString<GenerationHeldCapture>(heldBytes.decodeToString()).also { it.validate() }
        require(held.access == RuntimeBackupAccess(intent.source.id, capture, intent.source.bundleSha256) &&
            held.snapshot.id == capture && held.fences.keys == specs.map { it.name }.toSet() &&
            !Files.exists(backupRoot.resolve("result.json"), NOFOLLOW_LINKS) &&
            !Files.exists(backupRoot.resolve("no-target.resume.intent.json"), NOFOLLOW_LINKS))
        RecoveryReferences(base.resolve(intent.source.id).resolve("recovery-references"))
            .requireBound("rollback", transactionId, held.snapshot)
        val captureResult = json.decodeFromString<KopiaCaptureOutcome>(data(base.resolve(intent.source.id)
            .resolve("kopia-captures/$capture/capture.result.json")).decodeToString())
        require(captureResult.passed && captureResult.snapshot == held.snapshot)
        val available = capacity(RuntimeStore.CANONICAL_V2)
        require(available.availableMemoryMiB >= source.memoryReservationMiB + source.request.memoryHeadroomMiB &&
            available.usableDiskMiB >= source.request.diskHeadroomMiB)
        RuntimeLockBudget.requireAvailable(available.availableRuntimeLocks, specs + specs, workers = 0)
        val originalRuntime = backupRuntime(source, held.access)
        specs.forEach { spec ->
            val observed = originalRuntime.audit(spec, false)
            require(observed.name == spec.name && observed.existingResources > 0 &&
                observed.fingerprint == source.members.single { it.spec.name == spec.name }.runtimeFingerprint &&
                observed.maintenanceId == held.fences[spec.name] &&
                observed.statuses.map { it.id }.toSet() == spec.processes.map { it.id }.toSet() &&
                observed.statuses.size == spec.processes.size && observed.statuses.all { status ->
                    if (spec.processes.single { it.id == status.id }.oneShot)
                        status.state in setOf("exited", "completed") && status.exitCode == 0
                    else status.state == "exited" && status.exitCode in setOf(0, 143)
                }) { "Original native source changed while the no-target import was uncertain" }
        }
        val siteId = requireNotNull(source.ownership).contract.site
        val siteHead = ActiveSiteRegistry.BASE.resolve(ReleaseLocks.sha256(siteId.toByteArray())).resolve("head.json")
        val siteHeadBytes = data(siteHead)
        val ownerHead = json.decodeFromString<ActiveSiteHead>(siteHeadBytes.decodeToString())
        val ownerBytes = data(siteHead.parent.resolve(if (ownerHead.ordinal == 0) "bootstrap.json"
            else "rev-${ownerHead.ordinal}.json"))
        require(ReleaseLocks.sha256(ownerBytes) == ownerHead.revisionSha256 && ownerHead.ordinal in 0..256 &&
            (if (ownerHead.ordinal == 0) {
                val approved = json.decodeFromString<ActiveSiteBootstrap>(ownerBytes.decodeToString())
                ActiveSiteRegistry.real(txRoot.resolve("transaction.jsonl"), siteId,
                    requireNotNull(source.ownership).approvedHosts, intent.source,
                    Path.of("/mnt/media/p0-v3/release-activation-consumptions")
                        .resolve("${intent.source.id}.consumed.json"))
                    .validateBootstrap(approved, siteHead.parent)
                approved.source == intent.source && approved.siteId == siteId
            } else json.decodeFromString<ActiveSiteSelection>(ownerBytes.decodeToString()).deployment.let {
                it.generationId == intent.source.id && it.bundleSha256 == intent.source.bundleSha256
            })) { "Original site ceased to own its exact public identity; no unsafe source resume" }
        val isolated = json.decodeFromString<NativeOwnedTargetAbsence>(data(targetRoot.resolve(
            "no-target.isolate.json")).decodeToString())
        require(isolated.source == intent.source && isolated.targetGeneration == intent.targetGeneration &&
            isolated.runtimeMemberDirectoriesEmpty && isolated.targetMembers == source.members.map {
                intent.targetGeneration + it.spec.name.removePrefix(intent.source.id)
            }.sorted()) { "Native no-target isolation must precede original source resume" }
        val restoreBytes = data(base.resolve(request.restoreTarget).resolve("bundle.json"))
        val restoreHash = ReleaseLocks.sha256(restoreBytes)
        val (functional, functionalSpecs) = load(request.restoreTarget, restoreHash)
        require(functional.recoverySourceKopia == held.snapshot && functional.ownership == null &&
            functionalSpecs.none { it.ingress != null || it.nativeIngress != null || it.processes.any(RuntimeProcess::oneShot) }) {
            "Original functional RESTORE target must remain private and exact before source resume"
        }
        val functionalIsolation = json.decodeFromString<GenerationOutcome>(data(base.resolve(request.restoreTarget)
            .resolve("isolate.result.json")).decodeToString())
        require(functionalIsolation.action == "isolate" && functionalIsolation.passed &&
            functionalIsolation.bundleSha256 == restoreHash &&
            functionalIsolation.fences.keys == functionalSpecs.map { it.name }.toSet())
        val functionalCold = backend(functional) as? ColdGenerationBackend ?: error("Original restore isolation unavailable")
        val absenceIntent = backupRoot.resolve("no-target.resume.intent.json")
        save(absenceIntent, json.encodeToString(preparation))
        fun resumeLocked(): OwnedUpdateNoTargetRollbackResult {
        val absence = PrivateDeployment.observeAbsentOwnedTarget(source, intent.source.bundleSha256,
            intent.targetGeneration, runtimeRoot = runtimeBase)
        val absencePath = targetRoot.resolve("no-target.native.json")
        if (!Files.exists(targetRoot, NOFOLLOW_LINKS)) directory(targetRoot)
        val absenceBytes = json.encodeToString(absence).toByteArray()
        save(absencePath, absenceBytes)
        val nativePin = ActivationInput(absencePath.toString(), ReleaseLocks.sha256(absenceBytes))
        // No target resource can be prepared through this controller while the global generation
        // mutation/RSS operation exclusion is held; an independent native census is captured.
        fun effect(spec: PrivateDeploymentSpec) {
            save(backupRoot.resolve("no-target.resume-${spec.name}.intent.json"), json.encodeToString(held.access))
            completedCaptureSource(source, intent.source.bundleSha256, allowRecovered = false)
            originalRuntime.resume(spec, held.fences.getValue(spec.name))
            requireRunning(spec, originalRuntime.audit(spec, false))
            save(backupRoot.resolve("no-target.resume-${spec.name}.result.json"), json.encodeToString(held.access))
        }
        return try {
            specs.sortedBy { it.name }.forEach(::effect)
            if (source.request.managedLanes != null) {
                require(base == BASE && runtimeBase == PrivateDeployment.BASE)
                val managed = requireNotNull(GenerationManagedComponents.resumeOriginal(source,
                    base.resolve(intent.source.id), "backup-$capture", "early-$capture"))
                require(managed.lanes.values.all { !it.isolated } && managed.brokerMainPid > 1)
            }
            val audit = GenerationInspection(intent.source.id, intent.source.bundleSha256,
                source.memoryReservationMiB, specs.map { spec -> originalRuntime.audit(spec, false).also {
                    requireRunning(spec, it)
                } })
            val auditBytes = json.encodeToString(audit).toByteArray()
            val auditPath = backupRoot.resolve("no-target.resume.audit.json")
            save(auditPath, auditBytes)
            specs.sortedBy { it.name }.forEach { spec ->
                save(backupRoot.resolve("no-target.finish-${spec.name}.intent.json"), json.encodeToString(held.access))
                originalRuntime.finish(spec)
                save(backupRoot.resolve("no-target.finish-${spec.name}.result.json"), json.encodeToString(held.access))
            }
            val native = GenerationBackupOutcome(held.access, true, held.snapshot, true)
            val nativeBytes = json.encodeToString(native).toByteArray()
            save(backupRoot.resolve("no-target.resume.result.json"), nativeBytes)
            val proof = OwnedUpdateNoTargetSourceResumeProof(originalHeldSha256 = ReleaseLocks.sha256(heldBytes),
                nativeAbsenceSha256 = nativePin.sha256, resumedMembers = specs.map { it.name }.sorted(),
                resumeResultSha256 = ReleaseLocks.sha256(nativeBytes), sourceAuditSha256 = ReleaseLocks.sha256(auditBytes))
            val proofBytes = json.encodeToString(proof).toByteArray()
            val proofPath = backupRoot.resolve("no-target.resume.proof.json")
            save(proofPath, proofBytes)
            val result = OwnedUpdateNoTargetRollbackResult(transactionId = transactionId, source = intent.source,
                originalHeldSha256 = ReleaseLocks.sha256(heldBytes), targetGeneration = intent.targetGeneration,
                nativeAbsence = nativePin, sourceResumeAudit = ActivationInput(auditPath.toString(),
                    ReleaseLocks.sha256(auditBytes)), sourceResumeProof = ActivationInput(proofPath.toString(),
                    ReleaseLocks.sha256(proofBytes)), originalSiteHead = ActivationInput(siteHead.toString(),
                    ReleaseLocks.sha256(siteHeadBytes)))
            save(backupRoot.resolve("no-target.rollback.result.json"), json.encodeToString(result))
            result
        } catch (failure: Exception) {
            val interrupted = Thread.interrupted() || failure is InterruptedException
            try { save(backupRoot.resolve("no-target.resume.failure.json"), json.encodeToString(
                GenerationOutcome("no-target-resume", intent.source.bundleSha256, false,
                    failure.javaClass.name))) }
            finally { if (interrupted) Thread.currentThread().interrupt() }
            throw failure
        }
        }
        fun withFunctionalIsolation(index: Int): OwnedUpdateNoTargetRollbackResult {
            if (index == functionalSpecs.size) return resumeLocked()
            val spec = functionalSpecs[index]
            return functionalCold.withFrozen(spec, functionalIsolation.fences.getValue(spec.name)) { observed ->
                require(observed.name == spec.name && observed.fenceId == functionalIsolation.fences[spec.name] &&
                    observed.statuses.all { it.state == "exited" && it.exitCode in setOf(0, 143) }) {
                    "Functional RESTORE target could write during original no-target rollback"
                }
                withFunctionalIsolation(index + 1)
            }
        }
        val locks = specs.map { it.name } + isolated.targetMembers + functionalSpecs.map { it.name }
        return@mutating if (runtimeBase == PrivateDeployment.BASE)
            PrivateDeployment.withOrderedNativeLocks(locks, runtimeBase) { withFunctionalIsolation(0) }
        else withFunctionalIsolation(0) // Unit-only injected transports supply their own native isolation.
    }
    /** No sealed candidate existed; release only the already protected original claims
     * after A04's distinct RSS completion and independently repeated native readback. */
    fun retireOwnedEarlyRollback(result: OwnedUpdateNoTargetRollbackResult) = mutating {
        result.source.validate()
        val (original, specs) = load(result.source.id, result.source.bundleSha256)
        require(!Files.exists(base.resolve(result.targetGeneration).resolve("bundle.json"), NOFOLLOW_LINKS))
        val transaction = json.decodeFromString<ReleaseTransactionRequest>(data(base.parent
            .resolve("release-transactions/${result.transactionId}/request.json")).decodeToString())
        require(transaction.snapshotId.matches(Regex("cap-[a-f0-9]{12}")))
        val restoredBytes = data(base.resolve(transaction.restoreTarget).resolve("bundle.json"))
        val (restored, restoredSpecs) = load(transaction.restoreTarget, ReleaseLocks.sha256(restoredBytes))
        val isolation = json.decodeFromString<GenerationOutcome>(data(base.resolve(transaction.restoreTarget)
            .resolve("isolate.result.json")).decodeToString())
        require(isolation.action == "isolate" && isolation.passed &&
            isolation.bundleSha256 == ReleaseLocks.sha256(restoredBytes) &&
            isolation.fences.keys == restoredSpecs.map { it.name }.toSet())
        val restoredCold = backend(restored) as? ColdGenerationBackend ?: error("Original restore isolation unavailable")
        fun close(): Unit {
        val observed = specs.map { backend(original).audit(it, false) }
        require(observed.size == original.members.size && observed.zip(original.members).all { (audit, pin) ->
            audit.name == pin.spec.name && audit.fingerprint == pin.runtimeFingerprint &&
                audit.maintenanceId == null && audit.existingResources > 0 &&
                pin.spec.processes.filterNot(RuntimeProcess::oneShot).all { process ->
                    audit.statuses.singleOrNull { it.id == process.id }?.state == "running"
                }
        }) { "No-target original source is not actually running after held operation completion" }
        val present = PrivateDeployment.observeAbsentOwnedTarget(original, result.source.bundleSha256,
            result.targetGeneration, runtimeRoot = runtimeBase)
        require(present.source == result.source && present.targetGeneration == result.targetGeneration &&
            present.runtimeMemberDirectoriesEmpty && present.targetMembers.isNotEmpty())
        RecoveryReferences(base.resolve(result.source.id).resolve("recovery-references"))
            .retireEarlyOwned(result)
        }
        fun withRestored(index: Int) {
            if (index == restoredSpecs.size) { close(); return }
            val spec = restoredSpecs[index]
            restoredCold.withFrozen(spec, isolation.fences.getValue(spec.name)) { observed ->
                require(observed.name == spec.name && observed.fenceId == isolation.fences[spec.name] &&
                    observed.statuses.all { it.state == "exited" && it.exitCode in setOf(0, 143) })
                withRestored(index + 1)
            }
        }
        val targetMembers = original.members.map { result.targetGeneration +
            it.spec.name.removePrefix(result.source.id) }
        val all = specs.map { it.name } + targetMembers + restoredSpecs.map { it.name }
        if (runtimeBase == PrivateDeployment.BASE)
            PrivateDeployment.withOrderedNativeLocks(all, runtimeBase) { withRestored(0) }
        else withRestored(0)
    }
    /** Close four exact owned operation claims, not the former site's selected snapshot.
     * All frozen members remain isolated across both reference ledgers. */
    fun retireOwnedReferences(terminals: List<OwnedUpdateReferenceTerminal>) {
        require(terminals.map { it.kind }.toSet() == setOf("rollback", "import", "qualification", "activation") &&
            terminals.size == 4 && terminals.map { it.transactionId }.toSet().size == 1 &&
            terminals.map { it.source }.toSet().size == 1 &&
            terminals.map { it.targetGeneration to it.targetBundleSha256 }.toSet().size == 1 &&
            terminals.map { it.original }.toSet().size == 1 &&
            terminals.map { it.activeSite != null }.toSet().size == 1)
        val first = terminals.first()
        val committed = first.activeSite != null
        mutating {
            val (source, sourceSpecs) = load(first.source.id, first.source.bundleSha256)
            val (candidate, candidateSpecs) = load(first.targetGeneration, first.targetBundleSha256)
            require(candidate.ownedUpdate?.original == source && candidate.ownedUpdate?.snapshot == first.original)
            val primaryFences = if (committed) {
                val original = json.decodeFromString<GenerationHeldCapture>(data(base.resolve(first.source.id)
                    .resolve("backups/${first.original.id}/held.json")).decodeToString()).also { it.validate() }
                require(original.snapshot == first.original)
                original.fences
            } else {
                val isolated = json.decodeFromString<GenerationOutcome>(data(base.resolve(first.targetGeneration)
                    .resolve("isolate.result.json")).decodeToString())
                require(isolated.passed && isolated.bundleSha256 == first.targetBundleSha256)
                isolated.fences
            }
            val request = json.decodeFromString<ReleaseTransactionRequest>(data(base.parent
                .resolve("release-transactions/${first.transactionId}/request.json")).decodeToString())
            val stageBytes = data(base.resolve(request.restoreTarget).resolve("bundle.json"))
            val (originalFunctional, originalFunctionalSpecs) = load(request.restoreTarget, ReleaseLocks.sha256(stageBytes))
            require(originalFunctional.recoverySourceKopia == first.original && originalFunctional.ownership == null)
            val stagedIsolation = json.decodeFromString<GenerationOutcome>(data(base.resolve(request.restoreTarget)
                .resolve("isolate.result.json")).decodeToString())
            require(stagedIsolation.action == "isolate" && stagedIsolation.passed &&
                stagedIsolation.bundleSha256 == ReleaseLocks.sha256(stageBytes) &&
                stagedIsolation.fences.keys == originalFunctionalSpecs.map { it.name }.toSet())
            val frozen = ((if (committed) sourceSpecs.map { Triple(source, it, primaryFences.getValue(it.name)) }
                else candidateSpecs.map { Triple(candidate, it, primaryFences.getValue(it.name)) }) +
                (if (first.qualifiedSnapshot != null) {
                    val (qualified, qualifiedSpecs) = load(requireNotNull(first.qualifiedTargetGeneration),
                        requireNotNull(first.qualifiedTargetBundleSha256))
                    require(qualified.recoverySourceKopia == first.qualifiedSnapshot)
                    val proof = requireNotNull(first.qualifiedCompletion).proof
                    qualifiedSpecs.map { Triple(qualified, it, proof.targetFences.getValue(it.name)) }
                } else emptyList()) + originalFunctionalSpecs.map { spec ->
                    Triple(originalFunctional, spec, stagedIsolation.fences.getValue(spec.name))
                }).sortedBy { it.second.name }
            require(frozen.map { it.second.name }.distinct().size == frozen.size)
            val (running, runningSpecs) = if (committed) candidate to candidateSpecs else source to sourceSpecs
            fun terminal(index: Int) {
                if (index == frozen.size) {
                    // New site's functional snapshot must be protected before dropping original
                    // rollback claims. The old site's selection claim is NOT retired here.
                    terminals.sortedBy { if (it.kind == "qualification") 0 else 1 }.forEach { proof ->
                        val owner = if (proof.kind == "qualification") first.targetGeneration else first.source.id
                        RecoveryReferences(base.resolve(owner).resolve("recovery-references")).retireOwned(proof)
                    }
                } else {
                    val (owner, spec, fence) = frozen[index]
                    val cold = backend(owner) as? ColdGenerationBackend ?: error("Owned target isolation unavailable")
                    cold.withFrozen(spec, fence) { terminal(index + 1) }
                }
            }
            fun close(): Unit {
                val runtime = backend(running)
                val observed = runningSpecs.map { runtime.audit(it, false) }
                require(observed.size == running.members.size && observed.zip(running.members).all { (audit, pin) ->
                    audit.name == pin.spec.name && audit.fingerprint == pin.runtimeFingerprint &&
                        audit.maintenanceId == null && pin.spec.processes.filterNot(RuntimeProcess::oneShot).all { process ->
                        audit.statuses.singleOrNull { it.id == process.id }?.state == "running"
                    }
                }) { "Owned reference closure requires actual native selected source running" }
                terminal(0)
            }
            val locks = frozen.map { it.second.name } + runningSpecs.map { it.name }
            if (runtimeBase == PrivateDeployment.BASE)
                PrivateDeployment.withOrderedNativeLocks(locks, runtimeBase, ::close)
            else close()
        }
    }
    /** A later COMMITTED owned successor retires the former site's selected functional point
     * only after the candidate site snapshot is itself ledger-protected and old source is
     * still natively fenced. External unsigned legacy bootstrap has no old claim to retire. */
    fun retirePriorSiteSelection(transactionId: String, source: ReleaseGeneration,
        successor: ReleaseGeneration, siteId: String, selected: ActiveSiteSelection) = mutating {
        source.validate(); successor.validate()
        require(selected.source == source && selected.deployment.generationId == successor.id &&
            selected.deployment.bundleSha256 == successor.bundleSha256 &&
            selected.transactionId == transactionId && selected.siteId == siteId)
        require(selected.ordinal >= 1 && !selected.fresh &&
            selected.previousHeadSha256 != "0".repeat(64)) {
            "Owned succession can only follow a selected site or signed original bootstrap"
        }
        val siteDir = ActiveSiteRegistry.BASE.resolve(ReleaseLocks.sha256(siteId.toByteArray()))
        val head = json.decodeFromString<ActiveSiteHead>(data(siteDir.resolve("head.json")).decodeToString())
        require(head.ordinal == selected.ordinal && head.revisionSha256 == ReleaseLocks.sha256(
            data(siteDir.resolve("rev-${head.ordinal}.json"))))
        val previousBytes = data(siteDir.resolve(if (head.ordinal == 1) "bootstrap.json"
            else "rev-${head.ordinal - 1}.json"))
        val priorSha = ReleaseLocks.sha256(previousBytes)
        val prior = if (head.ordinal == 1) null else
            json.decodeFromString<ActiveSiteSelection>(previousBytes.decodeToString())
        require((prior == null || prior.deployment.generationId == source.id &&
            prior.deployment.bundleSha256 == source.bundleSha256 && prior.siteId == siteId) &&
            selected.previousHeadSha256 == ReleaseLocks.sha256(json.encodeToString(
                ActiveSiteHead(head.ordinal - 1, priorSha)).toByteArray()))
        val (original, originalSpecs) = load(source.id, source.bundleSha256)
        val (candidate, candidateSpecs) = load(successor.id, successor.bundleSha256)
        require(candidate.ownedUpdate?.original == original)
        fun held(generation: String, capture: String): GenerationHeldCapture =
            json.decodeFromString<GenerationHeldCapture>(data(base.resolve(generation)
                .resolve("backups/$capture/held.json")).decodeToString()).also { it.validate() }
        val update = held(source.id, requireNotNull(candidate.ownedUpdate).snapshot.id)
        val oldSnapshot = if (prior == null) update.snapshot else held(source.id, prior.qualificationSnapshotId).snapshot
        val newSnapshot = held(successor.id, selected.qualificationSnapshotId).snapshot
        require(update.snapshot == candidate.ownedUpdate.snapshot &&
            (prior == null || oldSnapshot.id == prior.qualificationSnapshotId) &&
            newSnapshot.id == selected.qualificationSnapshotId)
        val completionPath = siteDir.resolve("${head.revisionSha256}.completed.json")
        val completion = ActivationInput(completionPath.toString(), ReleaseLocks.sha256(data(completionPath)))
        val tx = ActiveSiteRegistry.BASE.parent.resolve(transactionId)
        val transaction = json.decodeFromString<ReleaseTransactionRequest>(data(tx.resolve("request.json")).decodeToString())
        require(transaction.updatePreparation?.intent?.source == source && transaction.transactionId == transactionId)
        val priorPublication = requireNotNull(transaction.previousPublication)
        val auditPath = tx.resolve("previous-site-held.audit.json")
        val originalCold = backend(original) as? ColdGenerationBackend ?: error("No native original isolation")
        val members = originalSpecs.sortedBy { it.name }
        fun fenced(index: Int) {
            if (index != members.size) {
                val spec = members[index]
                originalCold.withFrozen(spec, update.fences.getValue(spec.name)) { fenced(index + 1) }
                return
            }
            require(candidateSpecs.map { backend(candidate).audit(it, false) }.zip(candidate.members).all { (audit, pin) ->
                audit.name == pin.spec.name && audit.fingerprint == pin.runtimeFingerprint &&
                    audit.maintenanceId == null && pin.spec.processes.filterNot(RuntimeProcess::oneShot).all { process ->
                        audit.statuses.singleOrNull { it.id == process.id }?.state == "running"
                    }
            }) { "Owned successor stopped before former site reference retirement" }
            val inspection = GenerationInspection(source.id, source.bundleSha256,
                original.memoryReservationMiB, originalSpecs.map { backend(original).audit(it, false) })
            val auditBytes = json.encodeToString(inspection).toByteArray()
            save(auditPath, auditBytes)
            val protection = RecoveryReferences(base.resolve(successor.id).resolve("recovery-references"))
                .siteSelectionEvent(siteId, head.revisionSha256, newSnapshot)
            val terminal = SiteSuccessionTerminal(transactionId = transactionId, siteId = siteId,
                source = source, successor = successor, priorRevisionSha256 = priorSha,
                successorRevisionSha256 = head.revisionSha256, oldSnapshot = oldSnapshot,
                successorSnapshot = newSnapshot, originalHeld = ActivationInput(
                    base.resolve(source.id).resolve("backups/${update.snapshot.id}/held.json").toString(), update.sha256),
                oldNativeAudit = ActivationInput(auditPath.toString(), ReleaseLocks.sha256(auditBytes)),
                priorPublication = priorPublication, successorClaimEvent = protection,
                successorCompletion = completion)
            RecoveryReferences(base.resolve(source.id).resolve("recovery-references"))
                .retireSupersededSite(terminal)
        }
        if (runtimeBase == PrivateDeployment.BASE)
            PrivateDeployment.withOrderedNativeLocks((originalSpecs + candidateSpecs).map { it.name }, runtimeBase) {
                fenced(0)
            }
        else fenced(0)
    }
    fun retireInstallReferences(transactionId: String, source: ReleaseGeneration,
        firstCapture: String, firstTarget: String, firstTargetHash: String,
        secondCapture: String, secondTarget: String, secondTargetHash: String,
        activeSite: ActivationInput, selectedTrialId: String, committedHead: String): Unit = mutating {
        source.validate()
        val first = completionProofLocked(source.id, source.bundleSha256, firstCapture, firstTarget, firstTargetHash)
        val second = completionProofLocked(source.id, source.bundleSha256, secondCapture, secondTarget, secondTargetHash)
        val heldFirst = json.decodeFromString<GenerationHeldCapture>(data(base.resolve(source.id).resolve(
            "backups/$firstCapture/held.json")).decodeToString()).also { it.validate() }
        val heldSecond = json.decodeFromString<GenerationHeldCapture>(data(base.resolve(source.id).resolve(
            "backups/$secondCapture/held.json")).decodeToString()).also { it.validate() }
        val terminal = InstallReferenceTerminal(transactionId = transactionId, source = source,
            first = heldFirst.snapshot, second = heldSecond.snapshot,
            firstCompletion = first, secondCompletion = second,
            activeSite = activeSite, committedJournalSha256 = committedHead, selectedTrialId = selectedTrialId)
        val targets = listOf(first, second).flatMap { receipt ->
            val (bundle, specs) = load(receipt.proof.target, receipt.proof.targetBundleSha256)
            val cold = backend(bundle) as? ColdGenerationBackend ?: error("Target isolation locks unavailable")
            specs.mapIndexed { index, spec -> Triple(cold, spec, receipt.proof.targetObservations[index]) }
        }.sortedBy { it.second.name }
        fun protect(index: Int) {
            if (index == targets.size) {
                RecoveryReferences(base.resolve(source.id).resolve("recovery-references")).retireInstall(terminal)
                return
            }
            val (cold, spec, prior) = targets[index]
            val fence = if (spec.name.startsWith(firstTarget + "-")) first.proof.targetFences.getValue(spec.name)
                else second.proof.targetFences.getValue(spec.name)
            cold.withFrozen(spec, fence) { current ->
                require(current == prior) { "Target isolation changed before first-install site reference protection" }
                protect(index + 1)
            }
        }
        val (selectedSource, selectedSpecs) = load(source.id, source.bundleSha256)
        fun retire(): Unit {
            val runtime = backend(selectedSource)
            require(selectedSpecs.map { runtime.audit(it, false) }.zip(selectedSource.members).all { (audit, pin) ->
                audit.name == pin.spec.name && audit.fingerprint == pin.runtimeFingerprint &&
                    audit.maintenanceId == null && pin.spec.processes.filterNot(RuntimeProcess::oneShot).all { process ->
                        audit.statuses.singleOrNull { it.id == process.id }?.state == "running"
                    }
            }) { "Selected first-install source is not natively running under retirement lock" }
            protect(0)
        }
        if (runtimeBase == PrivateDeployment.BASE)
            PrivateDeployment.withOrderedNativeLocks(targets.map { it.second.name } + selectedSpecs.map { it.name },
                runtimeBase, ::retire)
        else retire()
    }

    /** Never resumes or re-submits a snapshot. Retains leases and original backup/capture outcomes. */
    fun reconcileBackup(generation: String, expected: String, captureId: String, reconciliationId: String, priorIntentSha256: String): GenerationOutcome = mutating {
        val access = RuntimeBackupAccess(generation, captureId, expected); access.validate()
        require(reconciliationId.matches(Regex("r-[a-f0-9]{12}")) && hash.matches(priorIntentSha256))
        val root = base.resolve(generation).resolve("backups/$captureId"); directory(root)
        val original = data(root.resolve("intent.json"))
        require(ReleaseLocks.sha256(original) == priorIntentSha256 && json.decodeFromString<RuntimeBackupAccess>(original.decodeToString()) == access)
        val result = root.resolve("result.json")
        if (Files.exists(result, NOFOLLOW_LINKS)) require(!json.decodeFromString<GenerationBackupOutcome>(data(result).decodeToString()).passed) {
            "Completed backup is not interruption recovery authority"
        }
        val (bundle, _) = load(generation, expected, checkLiveInputs = false)
        save(root.resolve("reconcile-$reconciliationId.intent.json"), json.encodeToString(GenerationIntent("backup-stop-only", expected, priorIntentSha256)))
        val prior = base.resolve(generation).resolve("isolate.intent.json")
        val outcome = if (Files.exists(prior, NOFOLLOW_LINKS)) isolateLocked(generation, expected, reconciliationId,
            ReleaseLocks.sha256(data(prior)), backupRuntime(bundle, access))
        else isolateLocked(generation, expected, runtimeOverride = backupRuntime(bundle, access))
        save(root.resolve("reconcile-$reconciliationId.result.json"), json.encodeToString(outcome))
        outcome
    }

    private data class CapturedPayload(val kopia: KopiaSnapshotReceipt)
    /** Legacy verification/extraction remains supported; new production storage belongs exclusively to Kopia. */
    fun capture(generation: String, expected: String, captureId: String,
        custody: Path = Path.of("/mnt/media/p0-v3/generation-custody")): GenerationCaptureOutcome {
        require(id.matches(generation) && hash.matches(expected) && captureId.matches(Regex("cap-[a-f0-9]{12}")))
        require(custody.isAbsolute && custody.normalize() == custody)
        error("New production backups require Kopia; historical capsule verification and extraction remain available")
    }
    fun captureKopia(inventory: AcquiredInventory, generation: String, expected: String, captureId: String,
        custody: Path = Path.of("/mnt/media/p0-v3/kopia-custody"), store: GenerationSnapshotStore? = null): KopiaCaptureOutcome = mutating {
        val source = load(generation, expected).first
        // The historical cold backend requires DIRECT_PODMAN_V1 and its native
        // runtime.jobs ledger. A successful Quadlet serve ACK is NOT that ledger.
        // Reject before beginCapture creates an irreversible Kopia pending fence;
        // Quadlet sources need a separate systemd-owned cold capture/import path.
        GenerationColdCaptureAdmission.requireSupported(source)
        require(!Files.exists(base.resolve(generation).resolve("kopia-store/snapshot.pending.json"), NOFOLLOW_LINKS)) {
            "Uncertain Kopia snapshot retained; no new capture namespace or resubmission"
        }
        // Exact supported cohort before repository initialization, custody or native worker effects.
        FoundationRestore.bundle(source, inventory, if (generation == "q-000000000000") "q-111111111111" else "q-000000000000",
            "0".repeat(64), ColdRestoreCohort.WHOLE_RELEASE)
        val access = RuntimeBackupAccess(generation, captureId, expected).also { it.validate() }
        val pending = RecoveryReferenceOperations.beginCapture(base, access, "capture", captureId)
        val snapshot = captureLocked(generation, expected, captureId, custody,
            store ?: KopiaGenerationStore.real(inventory, source.request.store)).kopia
        RecoveryReferenceOperations.bindCaptured(base, pending, snapshot)
        KopiaCaptureOutcome(captureId, expected, true, snapshot)
    }
    /** Read-only original-state and pinned backup-artifact preflight. Capture
     * rechecks these conditions before its first original intent and effect.
     */
    fun auditQuadletCapture(inventory: AcquiredInventory, generation: String, expected: String): GenerationInspection =
        RecoveryDeadline.within { locked {
            val (source, specs) = load(generation, expected)
            require(source.request.store == RuntimeStore.CANONICAL_V2 && source.ownership != null &&
                specs.size == 1 && specs.single().executionBackend == RuntimeExecutionBackend.QUADLET_V2 &&
                !Files.exists(base.resolve(generation).resolve("kopia-store/snapshot.pending.json"), NOFOLLOW_LINKS))
            FoundationRestore.bundle(source, inventory,
                if (generation == "q-000000000000") "q-111111111111" else "q-000000000000",
                "0".repeat(64), ColdRestoreCohort.WHOLE_RELEASE, RuntimeStore.CANONICAL_V2)
            val kopia = inventory.images.single { it.product == "kopia" }
            val observed = PrivateRootfulCommands(35, RuntimeStore.CANONICAL_V2).run(listOf("image", "inspect", kopia.pinnedImage))
            require(observed.exitCode == 0 && observed.output.toByteArray().size in 1..65536)
            val image = json.parseToJsonElement(observed.output).jsonArray.single().jsonObject
            require(image.getValue("Id").jsonPrimitive.content.removePrefix("sha256:") == kopia.imageId &&
                image.getValue("Digest").jsonPrimitive.content == kopia.selectedManifestDigest) {
                "Pinned legacy-store Kopia worker image changed"
            }
            val terminal = requireNotNull(RuntimeQuadletCapacityTerminal.read(base.resolve(generation), source, expected))
            val audit = RuntimeQuadletColdCapture(base.resolve(generation), source, expected, runtimeBase)
                .audit(specs.single(), false)
            require(audit.maintenanceId == terminal.fenceId)
            specs.single().volumes.forEach { ColdVolumeExport.rootMetadata(specs.single(), it, base.resolve(generation)) }
            GenerationInspection(generation, expected, source.memoryReservationMiB, listOf(audit))
        } }
    /** New-production Kopia on the ORIGINAL stopped Quadlet CIDs. The backup
     * worker uses a separately pinned, networkless container in the canonical
     * store; application processes remain exclusively in systemd units.
     */
    fun captureQuadletKopia(inventory: AcquiredInventory, generation: String, expected: String, captureId: String,
        custody: Path = Path.of("/mnt/media/p0-v3/kopia-custody"), store: GenerationSnapshotStore? = null): KopiaCaptureOutcome = mutating {
        require(captureId.matches(Regex("cap-[a-f0-9]{12}")) &&
            inventory.images.map { it.product }.toSet().containsAll(setOf("postgres-timescale", "forgejo", "kopia")))
        auditQuadletCapture(inventory, generation, expected)
        val (source, specs) = load(generation, expected)
        require(source.request.store == RuntimeStore.CANONICAL_V2 && source.ownership != null &&
            source.members.size == 1 && specs.single().executionBackend == RuntimeExecutionBackend.QUADLET_V2 &&
            !Files.exists(base.resolve(generation).resolve("kopia-store/snapshot.pending.json"), NOFOLLOW_LINKS)) {
            "Original Quadlet source or Kopia attempt is not uniquely recoverable"
        }
        FoundationRestore.bundle(source, inventory,
            if (generation == "q-000000000000") "q-111111111111" else "q-000000000000",
            "0".repeat(64), ColdRestoreCohort.WHOLE_RELEASE, RuntimeStore.CANONICAL_V2)
        val root = base.resolve(generation)
        val terminal = requireNotNull(RuntimeQuadletCapacityTerminal.read(root, source, expected)) {
            "Quadlet cold capture requires its separate exact-CID terminal observation"
        }
        val backend = RuntimeQuadletColdCapture(root, source, expected, runtimeBase)
        backend.audit(specs.single(), false) // Entire original cohort, fence and CIDs before any pending operation.
        val access = RuntimeBackupAccess(generation, captureId, expected).also { it.validate() }
        val intent = root.resolve("quadlet-kopia-$captureId.intent.json")
        require(!Files.exists(intent, NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("kopia-captures/$captureId"), NOFOLLOW_LINKS)) {
            "Original Quadlet Kopia capture exists; never resubmit an uncertain effect"
        }
        save(intent, json.encodeToString(mapOf("generation" to generation, "bundleSha256" to expected,
            "captureId" to captureId, "terminalSha256" to ReleaseLocks.sha256(data(root.resolve("quadlet-capacity.terminal.json"))),
            "workerStore" to RuntimeStore.CANONICAL_V2.name, "backend" to "quadlet-cold-cid-v1")))
        val pending = RecoveryReferenceOperations.beginCapture(base, access, "capture", captureId)
        val snapshot = captureLocked(generation, expected, captureId, custody,
            store ?: KopiaGenerationStore.real(inventory, RuntimeStore.CANONICAL_V2), backend,
            mapOf(specs.single().name to terminal.fenceId), quadletSource = terminal).kopia
        RecoveryReferenceOperations.bindCaptured(base, pending, snapshot)
        KopiaCaptureOutcome(captureId, expected, true, snapshot)
    }
    /** Authenticated Kopia payload extraction into fresh private scratch only.
     * No target resources, application process, functional readback or original
     * initializer can run through this verification operation.
     */
    fun verifyQuadletKopia(inventory: AcquiredInventory, generation: String, expected: String,
        captureId: String, verificationId: String,
        custody: Path = Path.of("/mnt/media/p0-v3/kopia-custody"), store: GenerationSnapshotStore? = null): GenerationRecoveryCheck = mutating {
        require(captureId.matches(Regex("cap-[a-f0-9]{12}")) &&
            verificationId.matches(Regex("ver-[a-f0-9]{12}")))
        val (source, specs) = load(generation, expected)
        require(source.request.store == RuntimeStore.CANONICAL_V2 && source.ownership != null &&
            specs.single().executionBackend == RuntimeExecutionBackend.QUADLET_V2)
        val snapshot = RecoveryReferenceOperations.receipt(base, generation, expected, captureId)
        val root = base.resolve(generation)
        val terminal = requireNotNull(RuntimeQuadletCapacityTerminal.read(root, source, expected))
        val observed = RuntimeQuadletColdCapture(root, source, expected, runtimeBase).audit(specs.single(), false)
        require(observed.maintenanceId == terminal.fenceId)
        val verifications = root.resolve("kopia-verifications")
        if (!Files.exists(verifications, NOFOLLOW_LINKS)) {
            Files.createDirectory(verifications, PosixFilePermissions.asFileAttribute(privateDir))
            FileChannel.open(root, READ).use { it.force(true) }
        }
        directory(verifications)
        val operation = verifications.resolve(verificationId)
        Files.createDirectory(operation, PosixFilePermissions.asFileAttribute(privateDir))
        FileChannel.open(verifications, READ).use { it.force(true) }
        save(operation.resolve("verify.intent.json"), json.encodeToString(mapOf(
            "generation" to generation, "bundleSha256" to expected, "captureId" to captureId,
            "snapshotId" to snapshot.snapshotId, "snapshotReceiptSha256" to KopiaGenerationStore.receiptHash(snapshot),
            "terminalSha256" to ReleaseLocks.sha256(data(root.resolve("quadlet-capacity.terminal.json"))),
            "workerStore" to RuntimeStore.CANONICAL_V2.name)))
        RecoveryReferenceOperations.protect(base, snapshot, "unknown", verificationId)
        val recovered = operation.resolve("recovered")
        (store ?: KopiaGenerationStore.real(inventory, RuntimeStore.CANONICAL_V2)).restore(
            root.resolve("kopia-store/repository"), custody.resolve("$generation.env"), operation, snapshot, recovered)
        val checked = GenerationRecovery.validateKopia(recovered, snapshot)
        require(checked.bundle == source && checked.manifest.quadletSources.size == 1 &&
            checked.manifest.quadletSources.single().member == specs.single().name &&
            checked.check.generation == generation && checked.check.kopiaSnapshotId == snapshot.snapshotId &&
            !checked.check.runtimeImported && !checked.check.functionalRestoreVerified) {
            "Recovered Quadlet state or original initializer proof differs"
        }
        save(operation.resolve("verify.result.json"), json.encodeToString(checked.check))
        checked.check
    }
    /** Read-only diagnosis of the first failed volume import; NEVER retries an
     * import, metadata modification, unit start or failed generation stage.
     */
    fun auditFailedQuadletImport(target: String, expected: String, volumeId: String): String =
        RecoveryDeadline.within { locked {
            val (bundle, specs) = load(target, expected)
            val spec = specs.single()
            val volume = spec.volumes.single { it.id == volumeId }
            val root = base.resolve(target)
            val result = json.decodeFromString<GenerationOutcome>(data(root.resolve("import.result.json")).decodeToString())
            require(!result.passed && result.bundleSha256 == expected &&
                Files.exists(root.resolve("quadlet-import-$volumeId.intent.json"), NOFOLLOW_LINKS) &&
                !Files.exists(root.resolve("quadlet-import-$volumeId.result.json"), NOFOLLOW_LINKS) &&
                !Files.exists(root.resolve("stage.intent.json"), NOFOLLOW_LINKS))
            val fence = RuntimeMaintenance.read(runtimeBase.resolve(spec.name), bundle.members.single().runtimeFingerprint)
            require(fence?.reason == "restore")
            val importIntent = json.parseToJsonElement(data(root.resolve("import.intent.json")).decodeToString()).jsonObject
            val source = requireNotNull(importIntent["source"]).jsonPrimitive.content
            val verificationId = requireNotNull(importIntent["verificationId"]).jsonPrimitive.content
            val snapshot = requireNotNull(bundle.recoverySourceKopia)
            require(source == snapshot.generation && verificationId.matches(Regex("ver-[a-f0-9]{12}")))
            val sourceMember = load(source, snapshot.bundleSha256).first.members.single().spec.name
            val archive = base.resolve(source).resolve(
                "kopia-verifications/$verificationId/recovered/$sourceMember/volumes/$volumeId.tar")
            val entries = VolumeTar.inspect(archive, volume.userId,
                volume.mappedOwners.map { it.userId to it.groupId }.toSet())
            ColdVolumeMetadata().auditTree(spec, volume, entries)
            "read-only native import metadata preflight passed for ${entries.size} entries; original import remains failed"
        } }
    /** Read-only compiled target, protected source and native artifact admission.
     * This is not an import intent, installation ACK or functional restore.
     */
    fun auditQuadletImport(inventory: AcquiredInventory, source: String, sourceBundle: String,
        captureId: String, verificationId: String, target: String, controllerHash: String): String =
        RecoveryDeadline.within { locked {
            require(id.matches(source) && id.matches(target) && source != target &&
                captureId.matches(Regex("cap-[a-f0-9]{12}")) &&
                verificationId.matches(Regex("ver-[a-f0-9]{12}")) && controllerHash.matches(hash))
            val (original, specs) = load(source, sourceBundle)
            require(original.ownership != null && specs.size == 1 &&
                specs.single().executionBackend == RuntimeExecutionBackend.QUADLET_V2)
            val snapshot = RecoveryReferenceOperations.receipt(base, source, sourceBundle, captureId)
            val sourceRoot = base.resolve(source)
            val terminal = requireNotNull(RuntimeQuadletCapacityTerminal.read(sourceRoot, original, sourceBundle))
            require(RuntimeQuadletColdCapture(sourceRoot, original, sourceBundle, runtimeBase)
                .audit(specs.single(), false).maintenanceId == terminal.fenceId)
            val verified = GenerationRecovery.validateKopia(sourceRoot.resolve(
                "kopia-verifications/$verificationId/recovered"), snapshot)
            require(verified.bundle == original && verified.check == json.decodeFromString<GenerationRecoveryCheck>(
                data(sourceRoot.resolve("kopia-verifications/$verificationId/verify.result.json")).decodeToString()))
            PinnedBackupController.verifyDistribution(Path.of(
                "/mnt/media/p0-v3/runtime-supervision/releases/$controllerHash"), controllerHash, "p0-v3-platform")
            val projected = FoundationRestore.bundle(original, inventory, target,
                KopiaGenerationStore.receiptHash(snapshot), ColdRestoreCohort.FORGEJO_POSTGRES,
                RuntimeStore.CANONICAL_V2, targetControllerSha256 = controllerHash).copy(
                    recoverySourceArchiveSha256 = null, recoverySourceKopia = snapshot)
            require(projected.members.size == 1 && projected.members.single().spec.processes.none { it.oneShot } &&
                !Files.exists(base.resolve(target), NOFOLLOW_LINKS) &&
                !Files.exists(runtimeBase.resolve(projected.members.single().spec.name), NOFOLLOW_LINKS))
            admit(projected)
            RuntimeQuadletPreflight.verify(projected.members.single().spec)
            ReleaseLocks.sha256(json.encodeToString(projected).toByteArray())
        } }
    /** Fresh private Quadlet import from an independently authenticated Kopia
     * scratch extraction. Only resources and volumes are imported: no archived
     * initializer, direct-backend job ledger or application container is run.
     */
    fun importQuadletKopia(inventory: AcquiredInventory, source: String, sourceBundle: String,
        captureId: String, verificationId: String, target: String, controllerHash: String,
        installer: RuntimeQuadletInstaller = RuntimeQuadletInstaller()): GenerationOutcome = mutating {
        require(id.matches(target) && id.matches(source) && target != source &&
            controllerHash.matches(hash) &&
            captureId.matches(Regex("cap-[a-f0-9]{12}")) && verificationId.matches(Regex("ver-[a-f0-9]{12}")))
        val (original, originals) = load(source, sourceBundle)
        require(original.request.store == RuntimeStore.CANONICAL_V2 && original.ownership != null &&
            originals.size == 1 && originals.single().executionBackend == RuntimeExecutionBackend.QUADLET_V2)
        val snapshot = RecoveryReferenceOperations.receipt(base, source, sourceBundle, captureId)
        val sourceRoot = base.resolve(source)
        val terminal = requireNotNull(RuntimeQuadletCapacityTerminal.read(sourceRoot, original, sourceBundle))
        val verification = sourceRoot.resolve("kopia-verifications/$verificationId")
        directory(verification)
        val checked = GenerationRecovery.validateKopia(verification.resolve("recovered"), snapshot)
        require(checked.bundle == original && checked.check == json.decodeFromString<GenerationRecoveryCheck>(
            data(verification.resolve("verify.result.json")).decodeToString()) &&
            checked.manifest.quadletSources.singleOrNull()?.terminalSha256 ==
                ReleaseLocks.sha256(data(sourceRoot.resolve("quadlet-capacity.terminal.json"))) &&
            checked.manifest.quadletSources.single().member == originals.single().name &&
            !checked.check.runtimeImported && !checked.check.functionalRestoreVerified)
        PinnedBackupController.verifyDistribution(Path.of(
            "/mnt/media/p0-v3/runtime-supervision/releases/$controllerHash"), controllerHash, "p0-v3-platform")
        val bundle = FoundationRestore.bundle(original, inventory, target, KopiaGenerationStore.receiptHash(snapshot),
            ColdRestoreCohort.FORGEJO_POSTGRES, RuntimeStore.CANONICAL_V2,
            targetControllerSha256 = controllerHash).copy(
                recoverySourceArchiveSha256 = null, recoverySourceKopia = snapshot)
        require(bundle.members.size == 1 && bundle.members.single().spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2 &&
            bundle.members.single().spec.processes.none { it.oneShot } && bundle.ownership == null)
        admit(bundle, workers = 0)
        val root = base.resolve(target)
        require(!Files.exists(root, NOFOLLOW_LINKS) && !Files.exists(runtimeBase.resolve(bundle.members.single().spec.name), NOFOLLOW_LINKS))
        val bundleBytes = json.encodeToString(bundle).toByteArray()
        val targetHash = ReleaseLocks.sha256(bundleBytes)
        RecoveryReferenceOperations.protect(base, snapshot, "import", target)
        Files.createDirectory(root, PosixFilePermissions.asFileAttribute(privateDir))
        FileChannel.open(base, READ).use { it.force(true) }
        save(root.resolve("bundle.json"), bundleBytes)
        save(root.resolve("import.intent.json"), json.encodeToString(mapOf(
            "action" to "quadlet-cold-import-v1", "source" to source, "sourceBundleSha256" to sourceBundle,
            "targetBundleSha256" to targetHash, "controllerSha256" to controllerHash,
            "captureId" to captureId, "verificationId" to verificationId,
            "snapshotId" to snapshot.snapshotId, "sourceTerminalSha256" to
                ReleaseLocks.sha256(data(sourceRoot.resolve("quadlet-capacity.terminal.json"))))))
        save(root.resolve("recovery.source.json"), json.encodeToString(snapshot))
        save(root.resolve("recovery.check.json"), json.encodeToString(checked.check))
        val pin = bundle.members.single()
        val spec = pin.spec
        try {
            // Preparation owns its namespace gate and member lock itself. It
            // expressly forbids nesting under withOrderedNativeLocks: first
            // prepare sealed recovered inputs, then hold source+target locks
            // throughout all native import and immutable-unit effects.
            RuntimePreparation.prepare(spec, runtimeBase) {
                pin.inputHashes.mapValues { (file, expected) ->
                    val bytes = data(verification.resolve("recovered/${originals.single().name}/inputs/$file"))
                    require(ReleaseLocks.sha256(bytes) == expected) { "Recovered protected input changed" }
                    bytes.decodeToString(throwOnInvalidSequence = true)
                }
            }
            PrivateDeployment.withOrderedNativeLocks(listOf(originals.single().name, spec.name), runtimeBase) {
                require(RuntimeQuadletColdCapture(sourceRoot, original, sourceBundle, runtimeBase)
                    .audit(originals.single(), false).maintenanceId == terminal.fenceId)
                RuntimeQuadletPreflight.verify(spec)
                require(load(target, targetHash).first == bundle)
                installer.install(root, target, targetHash, spec)
                RuntimeQuadletResources(root, runtimeBase).provision(spec, pin.runtimeFingerprint, pin.inputHashes)
                val memberRoot = runtimeBase.resolve(spec.name)
                val fence = RuntimeMaintenance.create(memberRoot, pin.runtimeFingerprint, "restore", null)
                save(root.resolve("quadlet-import-fence.result.json"), json.encodeToString(fence))
                val recovered = verification.resolve("recovered")
                val archives = spec.volumes.associate { volume -> volume.id to
                    recovered.resolve("${originals.single().name}/volumes/${volume.id}.tar") }
                val hashes = spec.volumes.associate { volume ->
                    val name = "${originals.single().name}/volumes/${volume.id}.tar"
                    volume.id to (checked.manifest.volumes.singleOrNull { it.name == name }?.sha256
                        ?: checked.manifest.files.single { it.name == name }.sha256)
                }
                val readback = root.resolve("native-volume-readback")
                Files.createDirectory(readback, PosixFilePermissions.asFileAttribute(privateDir))
                FileChannel.open(root, READ).use { it.force(true) }
                val volumes = RuntimeQuadletColdImport(root).importVolumes(spec, pin.runtimeFingerprint,
                    archives, hashes, readback)
                save(root.resolve("quadlet-import-member.result.json"), json.encodeToString(volumes))
                GenerationOutcome("restore-import", targetHash, true, fences = mapOf(spec.name to fence.id)).also {
                    save(root.resolve("import.result.json"), json.encodeToString(it))
                }
            }
        } catch (failure: Exception) {
            GenerationOutcome("restore-import", targetHash, false, failure.javaClass.name).also {
                save(root.resolve("import.result.json"), json.encodeToString(it))
            }
        }
    }
    private fun captureLocked(generation: String, expected: String, captureId: String, custody: Path,
        kopia: GenerationSnapshotStore, backupRuntime: GenerationBackend? = null,
        backupFences: Map<String, String>? = null,
        quadletSource: QuadletCapacityTerminalObservation? = null): CapturedPayload {
        require(captureId.matches(Regex("cap-[a-f0-9]{12}"))) { "Invalid capture identity" }
        val (bundle, specs) = load(generation, expected)
        val generationRoot = base.resolve(generation)
        require(bundle.request.rssPlan == null) { "Managed RSS capture requires controller payload custody and exclusion" }
        RssQualificationIntents.requireClear(generationRoot)
        completedCaptureSource(bundle, expected, allowRecovered = backupRuntime != null)
        val runtime = backupRuntime ?: backend(bundle)
        val cold = runtime as? ColdGenerationBackend ?: error("Cold capture backend unavailable")
        val observations = specs.map { runtime.audit(it, false) }
        fun matches(fences: Map<String, String>) = fences.keys == specs.map { it.name }.toSet() && observations.all {
            it.maintenanceId != null && it.maintenanceId == fences[it.name]
        }
        val fences = if (backupRuntime == null) isolationOutcomes(generationRoot, expected).firstOrNull { it.passed && matches(it.fences) }?.fences
            ?: error("Capture requires verified generation isolation")
        else requireNotNull(backupFences).also { require(matches(it)) { "Backup fences changed before capture" } }
        val measured = capacity(bundle.request.store)
        RuntimeLockBudget.requireAvailable(measured.availableRuntimeLocks, workers = 3)
        require(measured.availableMemoryMiB >= 1024 + bundle.request.memoryHeadroomMiB) {
            "Insufficient capture headroom; protected data must not be evicted"
        }
        admitRecoveryScratch(bundle.request, measured, 4)
        val payloadBudget = Math.multiplyExact(bundle.request.recoveryStateReservationMiB ?: bundle.request.diskReservationMiB, 1048576L)
        fun ensure(path: Path) {
            require(path.parent.toRealPath() == path.parent &&
                (Files.getAttribute(path.parent, "unix:uid") as Number).toLong() == UnixSystem().uid &&
                Files.getPosixFilePermissions(path.parent).none { it.name in setOf("GROUP_WRITE", "OTHERS_WRITE") }) { "Unsafe capture parent" }
            if (!Files.exists(path, NOFOLLOW_LINKS)) {
                Files.createDirectory(path, PosixFilePermissions.asFileAttribute(privateDir))
                FileChannel.open(path.parent, READ).use { it.force(true) }
            }
            directory(path)
        }
        val captures = generationRoot.resolve("kopia-captures"); ensure(captures); ensure(custody)
        val repository = generationRoot.resolve("kopia-store")
        ensure(repository)
        val root = captures.resolve(captureId)
        Files.createDirectory(root, PosixFilePermissions.asFileAttribute(privateDir))
        FileChannel.open(captures, READ).use { it.force(true) }
        val payloads = linkedMapOf("source/bundle.json" to generationRoot.resolve("bundle.json"))
        specs.forEach { spec ->
            payloads["${spec.name}/spec.json"] = runtimeBase.resolve("${spec.name}.json")
            PrivateDeployment.inputNames(spec).forEach { input -> payloads["${spec.name}/inputs/$input"] = runtimeBase.resolve(spec.name).resolve(input) }
            if (Files.exists(runtimeBase.resolve(spec.name).resolve("runtime.jobs"), NOFOLLOW_LINKS)) {
                require(spec.executionBackend == RuntimeExecutionBackend.DIRECT_PODMAN_V1 && quadletSource == null) {
                    "Quadlet source cannot inherit direct-backend runtime.jobs"
                }
                payloads["${spec.name}/jobs.json"] = runtimeBase.resolve(spec.name).resolve("runtime.jobs")
            }
            spec.volumes.forEach { volume -> payloads["${spec.name}/volumes/${volume.id}.tar"] = root.resolve("${spec.name}-${volume.id}.tar") }
        }
        val quadletEvidence = quadletSource?.let { original ->
            val member = specs.single()
            require(member.executionBackend == RuntimeExecutionBackend.QUADLET_V2 &&
                original.member == member.name && original.bundleSha256 == expected &&
                original.generation == generation &&
                RuntimeQuadletCapacityTerminal.read(generationRoot, bundle, expected) == original)
            val files = original.originalEvidenceSha256.keys.sorted()
            payloads[QuadletColdEvidence.terminal(member.name)] = generationRoot.resolve("quadlet-capacity.terminal.json")
            for (file in files) payloads[QuadletColdEvidence.original(member.name, file)] = generationRoot.resolve(file)
            QuadletColdSourceEvidence(member.name,
                ReleaseLocks.sha256(data(generationRoot.resolve("quadlet-capacity.terminal.json"))), files)
        }
        val volumeExports = payloads.values.filter { it.parent == root }.toList()
        val controllerFiles = RecoveryControllerPayloads.capture(generationRoot, payloads)
        val plannedManaged = if (bundle.request.managedLanes == null) emptySet() else setOf(
            "managed/index.json", "managed/oracle.json", "managed/source-manifest.toml",
            "managed/home/tree.tar", "managed/workspace/tree.tar", "managed/manifests/tree.tar", "managed/transcripts/tree.tar")
        val credentialHead = if (base == BASE && runtimeBase == PrivateDeployment.BASE &&
            bundle.request.store == RuntimeStore.CANONICAL_V2)
            NativeCredentialRevision.expectedCaptureHeadSha256(generationRoot) else null
        val plannedCredentials = if (base == BASE && runtimeBase == PrivateDeployment.BASE &&
            bundle.request.store == RuntimeStore.CANONICAL_V2)
            NativeCredentialRevision.expectedCapturePaths(generationRoot) else emptySet()
        require((credentialHead == null) == plannedCredentials.isEmpty() &&
            plannedCredentials.intersect(payloads.keys + plannedManaged).isEmpty())
        save(root.resolve("capture.intent.json"), json.encodeToString(GenerationCaptureIntent(captureId, generation, expected,
            fences, payloads.keys + plannedManaged + plannedCredentials, credentialHeadSha256 = credentialHead)))
        fun failed(error: Exception): Nothing {
            val interrupted = Thread.interrupted() || error is InterruptedException
            try { save(root.resolve("capture.result.json"),
                json.encodeToString(KopiaCaptureOutcome(captureId, expected, false, failureType = error.javaClass.name))) }
            finally { if (interrupted) Thread.currentThread().interrupt() }
            throw error
        }
        try {
            val frozen = mutableListOf<FrozenRuntimeObservation>()
            fun collect(index: Int): CapturedPayload {
                if (index < specs.size) return cold.withFrozen(specs[index], fences.getValue(specs[index].name)) { observed ->
                    require(observed.name == specs[index].name && observed.fingerprint == bundle.members[index].runtimeFingerprint &&
                        observed.fenceId == fences[observed.name]) { "Foreign frozen observation" }
                    frozen += observed
                    collect(index + 1)
                }
                // Every member lock remains held until all export/encryption/verification work returns.
                completedCaptureSource(bundle, expected, allowRecovered = backupRuntime != null)
                var exported = payloads.values.filterNot { it in volumeExports }.fold(0L) { total, path ->
                    Math.addExact(total, Files.size(path))
                }
                if (base == BASE && runtimeBase == PrivateDeployment.BASE &&
                    bundle.request.store == RuntimeStore.CANONICAL_V2) {
                    require(exported <= payloadBudget)
                    val capturedCredentials = NativeCredentialRevision.captureEffective(generationRoot, root,
                        payloads, Math.subtractExact(payloadBudget, exported), credentialHead)
                    require(capturedCredentials.toSet() == plannedCredentials &&
                        capturedCredentials.size == plannedCredentials.size)
                    exported = payloads.values.filterNot { it in volumeExports }.fold(0L) { total, path ->
                        Math.addExact(total, Files.size(path))
                    }
                }
                for (spec in specs) for (volume in spec.volumes) {
                    require(exported < payloadBudget) { "Capture export budget exceeded" }
                    val target = payloads.getValue("${spec.name}/volumes/${volume.id}.tar")
                    cold.exportVolume(spec, volume, target, Math.subtractExact(payloadBudget, exported))
                    RecoveryCapsule.guard(target, RecoveryCapsule.MAX_TOTAL)
                    exported = Math.addExact(exported, Files.size(target))
                    require(exported <= payloadBudget) { "Capture aggregate budget exceeded" }
                }
                GenerationManagedComponents.capture(generationRoot, root, captureId, payloads,
                    Math.subtractExact(payloadBudget, exported))
                require(payloads.values.fold(0L) { total, path -> Math.addExact(total, Files.size(path)) } <= payloadBudget) {
                    "Capture payload exceeds admitted release reservation"
                }
                val segments = RecoverySegments.prepare(payloads)
                val described = RecoveryCapsule.describe(payloads)
                val manifest = CapsuleManifest(id = captureId, generation = generation, bundleSha256 = expected,
                    members = frozen.toList(), files = described, volumes = segments,
                    controllerFiles = controllerFiles, managedFiles = payloads.keys.filter { it.startsWith("managed/") }.sorted(),
                    quadletSources = listOfNotNull(quadletEvidence),
                    credentialFiles = described.filter { it.name.startsWith("credential-revisions/") })
                GenerationManagedComponents.validateCaptured(bundle, manifest, root)
                val result = CapturedPayload(kopia.snapshot(repository.resolve("repository"), custody.resolve("$generation.env"), root, manifest, payloads))
                load(generation, expected)
                return result
            }
            val verification = collect(0)
            val result = json.encodeToString(KopiaCaptureOutcome(captureId, expected, true, verification.kopia))
            // Remove only this attempt's scratch exports AFTER authenticated verification. Never source data or intents.
            (payloads.values.filter { it.parent == root } + volumeExports).distinct().forEach(Files::delete)
            val credentialScratch = root.resolve("credential-capture")
            if (Files.exists(credentialScratch, NOFOLLOW_LINKS)) Files.walk(credentialScratch).use { entries ->
                entries.sorted(Comparator.reverseOrder()).forEach(Files::delete)
            }
            save(root.resolve("capture.result.json"), result)
            // Caller atomically replaces its pre-repository pending fence with this durable native receipt.
            return verification
        } catch (error: InterruptedException) { failed(error) }
        catch (error: Exception) { failed(error) }
    }
    fun verifyCapture(generation: String, expected: String, captureId: String,
        custody: Path = Path.of("/mnt/media/p0-v3/generation-custody")): CapsuleVerification = locked {
        require(id.matches(generation) && hash.matches(expected) && captureId.matches(Regex("cap-[a-f0-9]{12}"))) { "Invalid capture binding" }
        val root = base.resolve(generation).resolve("captures").resolve(captureId); directory(root)
        val result = json.decodeFromString<GenerationCaptureOutcome>(data(root.resolve("capture.result.json")).decodeToString())
        require(result.passed && result.id == captureId && result.bundleSha256 == expected) { "No completed capture" }
        val verified = RecoveryCapsule.verify(root.resolve("state.cap"), custody.resolve("$captureId.key"), captureId, generation, expected)
        require(verified == result.verification) { "Capture evidence changed" }
        verified
    }
    fun isolate(generation: String, expected: String): GenerationOutcome = mutating { isolateLocked(generation, expected) }
    /** Stops/fences only: no accepted application write or initializer can be retried here. */
    fun reconcileIsolation(generation: String, expected: String, reconciliationId: String, priorIntent: String): GenerationOutcome = mutating {
        isolateLocked(generation, expected, reconciliationId, priorIntent)
    }
}
