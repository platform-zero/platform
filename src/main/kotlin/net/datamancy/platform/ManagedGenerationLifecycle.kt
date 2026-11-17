package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
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

@Serializable internal data class ManagedGenerationStartIntent(val generation: String, val bundleSha256: String,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val importResultSha256: String? = null, val mode: String, val planSha256: String,
    val identityHeadSha256: String, val brokerUnitSha256: String)
@Serializable internal data class ManagedInitialPreparation(val generation: String, val bundleSha256: String,
    val intentSha256: String, val preparations: Map<ManagedLaneKind, ManagedLaneEvidence>)
@Serializable internal data class ManagedGenerationIsolationResult(val generation: String, val bundleSha256: String,
    val operationId: String, val intentSha256: String, val brokerUnitSha256: String,
    val brokerSocketAbsent: Boolean, val lanes: Map<ManagedLaneKind, ManagedLaneEvidence>)
@Serializable internal data class ManagedGenerationResumeResult(val generation: String, val bundleSha256: String,
    val isolatedOperationId: String, val operationId: String, val intentSha256: String,
    val brokerMainPid: Long, val brokerSocketInode: String, val lanes: Map<ManagedLaneKind, ManagedLaneEvidence>,
    val mode: String = "original")
@Serializable internal data class ManagedGenerationStartResult(val intentSha256: String, val generation: String,
    val mode: String, val bundleSha256: String, val identityHeadSha256: String,
    val brokerUnitSha256: String, val brokerMainPid: Long, val brokerSocketInode: String,
    val lanes: Map<ManagedLaneKind, ManagedLaneEvidence>, val promotable: Boolean)

/** Native identity observations must predate START and remain current on every broker request.
 * A revision is append-only; a changed head revokes prior grants immediately. A restored
 * target receives a NEW ledger/issuer revision, never an imported source bearer or reader secret.
 */
@Serializable internal data class ManagedIdentityRevision(val generation: String, val bundleSha256: String,
    val subject: String, val readerSubject: String, val issuer: String, val audience: String,
    val nativeIdentityReceipt: ActivationInput, val previousSha256: String? = null,
    val active: Boolean = true)
internal class NativeManagedIdentityLedger(private val root: Path) : IdentityGenerationLedger {
    private val json = Json { ignoreUnknownKeys = false }
    private val sha = Regex("[a-f0-9]{64}")
    private fun head(generation: String): Pair<ManagedIdentityRevision, String> {
        require(root == GenerationRuntime.BASE.resolve(generation).resolve("managed/identity") &&
            generation.matches(Regex("q-[a-f0-9]{12}")))
        ReleasePrivateFiles.directory(root)
        val pointer = ReleasePrivateFiles.read(root.resolve("head.json"), 4096)
        val name = json.decodeFromString<ManagedIdentityHead>(pointer.decodeToString(throwOnInvalidSequence = true))
        require(sha.matches(name.sha256) && name.generation == generation &&
            name.revision == "${name.sha256}.json")
        val bytes = ReleasePrivateFiles.read(root.resolve("revisions/${name.revision}"), 65536)
        require(ReleaseLocks.sha256(bytes) == name.sha256)
        val record = json.decodeFromString<ManagedIdentityRevision>(bytes.decodeToString(throwOnInvalidSequence = true))
        require(record.generation == generation && record.bundleSha256 ==
            ReleaseLocks.sha256(ReleasePrivateFiles.read(root.parent.parent.resolve("bundle.json"))) &&
            record.issuer == ManagedLaneIdentityAuthority.ISSUER &&
            record.audience == ManagedLaneIdentityAuthority.AUDIENCE &&
            record.subject != record.readerSubject && record.nativeIdentityReceipt.sha256.matches(sha) &&
            (record.previousSha256 == null || record.previousSha256.matches(sha)))
        val native = Path.of(record.nativeIdentityReceipt.path)
        require(native.parent == root.resolve("native") &&
            native.fileName.toString() == "${record.nativeIdentityReceipt.sha256}.json")
        val observationBytes = ReleasePrivateFiles.read(native, 65536)
        require(ReleaseLocks.sha256(observationBytes) == record.nativeIdentityReceipt.sha256)
        val observed = json.decodeFromString<ManagedIdentityNativeObservation>(
            observationBytes.decodeToString(throwOnInvalidSequence = true))
        require(observed.generation == generation && observed.subject == record.subject &&
            observed.readerSubject == record.readerSubject && observed.issuer == record.issuer &&
            observed.audience == record.audience && observed.observedAtEpochSeconds > 0 &&
            listOf(observed.agentTokenSha256, observed.agentIntrospectionSha256, observed.enabledUserSha256,
                observed.readerEnabledSha256).all(sha::matches))
        return record to name.sha256
    }
    override fun revisionHead(generation: String): String {
        val (record, hash) = head(generation)
        confirmed(generation, record, hash)
        return hash
    }
    override fun generationActive(generation: String): Boolean = runCatching {
        val (record, hash) = head(generation)
        confirmed(generation, record, hash)
        record.active
    }.getOrDefault(false)
    private fun confirmed(generation: String, revision: ManagedIdentityRevision, hash: String) {
        val intent = ReleasePrivateFiles.read(root.resolve("provision.intent.json"), 65536)
        val result = json.decodeFromString<ManagedIdentityProvisionResult>(
            ReleasePrivateFiles.read(root.resolve("provision.result.json"), 65536)
                .decodeToString(throwOnInvalidSequence = true))
        require(result.generation == generation && result.bundleSha256 == revision.bundleSha256 &&
            result.revisionSha256 == hash && result.nativeObservationSha256 == revision.nativeIdentityReceipt.sha256 &&
            result.intentSha256 == ReleaseLocks.sha256(intent))
    }
    fun requireBound(plan: ManagedLanePlan, bundleSha256: String): String {
        val (revision, hash) = head(plan.generation)
        confirmed(plan.generation, revision, hash)
        require(revision.active && revision.subject == plan.lanes.first().subject &&
            revision.bundleSha256 == bundleSha256)
        return hash
    }
}
@Serializable internal data class ManagedIdentityHead(val generation: String, val revision: String, val sha256: String)
@Serializable internal data class ManagedIdentityNativeObservation(val generation: String, val subject: String,
    val readerSubject: String, val issuer: String, val audience: String, val agentTokenSha256: String,
    val agentIntrospectionSha256: String, val enabledUserSha256: String,
    val readerEnabledSha256: String, val observedAtEpochSeconds: Long)
@Serializable internal data class ManagedIdentityProvisionResult(val generation: String, val bundleSha256: String,
    val revisionSha256: String, val nativeObservationSha256: String, val intentSha256: String)

/** Host-only minting. The agent confidential secret remains in sealed native custody and
 * MUST NOT be imported into a lane or broker environment; A05's issuer verifies 300s expiry.
 */
internal fun interface NativeManagedAgentTokenIssuer { fun mint(generation: String, subject: String): String }

internal object ManagedIdentityProvision {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    fun initial(bundle: GenerationBundle, root: Path, readerSubject: String,
        issuer: NativeManagedAgentTokenIssuer, transport: IdentityNativeTransport,
        adminBearer: () -> String): ManagedIdentityProvisionResult {
        val plan = requireNotNull(bundle.request.managedLanes)
        plan.validate(bundle.request.id)
        require(root == GenerationRuntime.BASE.resolve(plan.generation).resolve("managed/identity"))
        val generationRoot = root.parent.parent
        val bundleBytes = ReleasePrivateFiles.read(generationRoot.resolve("bundle.json"))
        val bundleSha = ReleaseLocks.sha256(bundleBytes)
        require(json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString(throwOnInvalidSequence = true)) == bundle)
        SiteOwnerships.checkSealed(bundle)
        val subject = plan.lanes.first().subject
        require(readerSubject != subject && (plan.readerSubject == null || plan.readerSubject == readerSubject) &&
            listOf(readerSubject, subject).all {
            runCatching { java.util.UUID.fromString(it).toString() == it }.getOrDefault(false)
        })
        ReleasePrivateFiles.directory(root)
        val revisionRoot = root.resolve("revisions")
        val nativeRoot = root.resolve("native")
        listOf(revisionRoot, nativeRoot).forEach { ReleasePrivateFiles.directory(it) }
        require(!Files.exists(root.resolve("head.json"), NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("provision.intent.json"), NOFOLLOW_LINKS))
        val intent = "$bundleSha|$subject|$readerSubject|${plan.generation}\n".toByteArray()
        ReleasePrivateFiles.save(root.resolve("provision.intent.json"), intent)
        // The token is a real Keycloak confidential grant, <=300 seconds; no token bytes
        // enter the durable ledger, source backup, unit file or restored lane.
        val bearer = issuer.mint(plan.generation, subject)
        require(bearer.length in 24..8192)
        val agent = transport.introspect(bearer)
        val enabled = transport.user(subject, adminBearer())
        val reader = transport.user(readerSubject, adminBearer())
        require(agent["active"]?.toString() == "true" &&
            agent["sub"]?.toString() == "\"$subject\"" &&
            agent["p0v3_generation"]?.toString() == "\"${plan.generation}\"" &&
            enabled["id"]?.toString() == "\"$subject\"" && enabled["enabled"]?.toString() == "true" &&
            reader["id"]?.toString() == "\"$readerSubject\"" && reader["enabled"]?.toString() == "true")
        val observation = ManagedIdentityNativeObservation(plan.generation, subject, readerSubject,
            ManagedLaneIdentityAuthority.ISSUER, ManagedLaneIdentityAuthority.AUDIENCE,
            ReleaseLocks.sha256(bearer.toByteArray()), ReleaseLocks.sha256(json.encodeToString(agent).toByteArray()),
            ReleaseLocks.sha256(json.encodeToString(enabled).toByteArray()),
            ReleaseLocks.sha256(json.encodeToString(reader).toByteArray()), java.time.Instant.now().epochSecond)
        // The native record is created at a unique content-derived address. Only its
        // hashes, NOT a bearer or confidential credential, persist in control state.
        val observationBytes = json.encodeToString(observation).toByteArray()
        val nativeHash = ReleaseLocks.sha256(observationBytes)
        val nativePath = nativeRoot.resolve("$nativeHash.json")
        val revision = ManagedIdentityRevision(plan.generation, bundleSha, subject, readerSubject,
            observation.issuer, observation.audience, ActivationInput(nativePath.toString(), nativeHash))
        val revisionBytes = json.encodeToString(revision).toByteArray()
        val revisionHash = ReleaseLocks.sha256(revisionBytes)
        ReleasePrivateFiles.save(nativePath, observationBytes)
        ReleasePrivateFiles.save(revisionRoot.resolve("$revisionHash.json"), revisionBytes)
        ReleasePrivateFiles.save(root.resolve("head.json"), json.encodeToString(
            ManagedIdentityHead(plan.generation, "$revisionHash.json", revisionHash)).toByteArray())
        // A05 validates actual JWKS RSA signature and LIVE introspection, issuer, audience,
        // original subject and fresh enabled-user readback against the real immutable ledger.
        // A failed check leaves the intent/head without a provision result and cannot START.
        val bootstrap = object : IdentityGenerationLedger {
            override fun revisionHead(generation: String): String {
                require(generation == plan.generation &&
                    ReleaseLocks.sha256(ReleasePrivateFiles.read(revisionRoot.resolve("$revisionHash.json"))) == revisionHash)
                return revisionHash
            }
            override fun generationActive(generation: String): Boolean =
                generation == plan.generation && transport.user(subject, adminBearer())["enabled"]?.toString() == "true"
        }
        val authority = ManagedLaneIdentityAuthority(transport, bootstrap, adminBearer,
            setOf(subject), mapOf("managed-lane-agent" to "AGENT"))
        val now = java.time.Instant.now().epochSecond
        val grant = ManagedLaneGrant(subject, observation.issuer, plan.generation, plan.lanes.first().laneId,
            plan.lanes.first().session, plan.provider, plan.model, now + 120, revisionHash, observation.agentTokenSha256)
        require(authority.authorizeBearer(bearer, grant, now)) { "Native managed agent signature, scope or user readback refused" }
        val result = ManagedIdentityProvisionResult(plan.generation, bundleSha, revisionHash, nativeHash,
            ReleaseLocks.sha256(intent))
        ReleasePrivateFiles.save(root.resolve("provision.result.json"), json.encodeToString(result).toByteArray())
        return result
    }
}

/** Fixed native ordering. Caller holds controller exclusion and ordered generation/member locks.
 * Never retry a partial START: even an absent result after a native command is uncertain.
 * Independent native broker and lane readback is required in addition to durable receipts.
 */
internal object ManagedGenerationLifecycle {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private val systemd = Path.of("/home/gerald/.config/systemd/user")

    /** Initial source uses a separately verified real Worklane manifest and local OCI
     * image, not an invented source tar or a cold projection of future credentials.
     * Caller stages the exact sealed input files before this one-use native PREPARE.
     */
    fun prepareInitial(bundle: GenerationBundle, targetRoot: Path,
        runtimeFactory: (Path, ManagedLanePlan) -> ManagedLaneRuntime = ManagedLaneRuntime::real
    ): ManagedInitialPreparation? {
        val plan = bundle.request.managedLanes ?: return null
        plan.validate(bundle.request.id)
        require(bundle.ownership != null && bundle.ownedUpdate == null && bundle.recoverySourceKopia == null &&
            targetRoot == GenerationRuntime.BASE.resolve(plan.generation) &&
            bundle.request.store == RuntimeStore.CANONICAL_V2 && plan.native.imageArchive != null &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(targetRoot.resolve("bundle.json"))) ==
                ReleaseLocks.sha256(json.encodeToString(bundle).toByteArray()))
        SiteOwnerships.checkSealed(bundle)
        val root = targetRoot.resolve("managed")
        ReleasePrivateFiles.directory(root)
        for (pin in listOf(plan.native.manifest, plan.native.storageConfig,
            requireNotNull(plan.native.broker).configuration)) {
            require(ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(pin.path), 1048576)) == pin.sha256)
        }
        val deadline = RecoveryDeadline.observedUtcDeadline().toEpochMilli()
        require(!Files.exists(targetRoot.resolve("managed-initial.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(targetRoot.resolve("managed-import.intent.json"), NOFOLLOW_LINKS))
        val intent = "${plan.generation}|${ReleaseLocks.sha256(json.encodeToString(bundle).toByteArray())}|" +
            "${ReleaseLocks.sha256(json.encodeToString(plan).toByteArray())}|$deadline\n"
        ReleasePrivateFiles.save(targetRoot.resolve("managed-initial.intent.json"), intent.toByteArray())
        for (name in listOf("control/home", "control/config", "control/data", "control/run", "control/leases",
            "control/podman-graph", "control/podman-run", "worklane", "tuios", "pi",
            "identity", "identity/revisions", "identity/native")) {
            val path = root.resolve(name)
            if (!Files.exists(path, NOFOLLOW_LINKS)) {
                ReleasePrivateFiles.directory(path.parent)
                Files.createDirectory(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
                ReleasePrivateFiles.sync(path.parent)
            }
            ReleasePrivateFiles.directory(path)
        }
        val runtime = runtimeFactory(targetRoot, plan)
        val preparations = plan.lanes.associate { lane ->
            lane.kind to runtime.operate(lane, ManagedLaneOperation.PREPARE, "managed-initial",
                deadlineEpochMillis = deadline)
        }
        require(preparations.keys == ManagedLaneKind.entries.toSet() && preparations.values.all {
            it.generation == plan.generation && it.operation == ManagedLaneOperation.PREPARE && it.isolated
        })
        val result = ManagedInitialPreparation(plan.generation,
            ReleaseLocks.sha256(json.encodeToString(bundle).toByteArray()), ReleaseLocks.sha256(intent.toByteArray()), preparations)
        ReleasePrivateFiles.save(targetRoot.resolve("managed-initial.result.json"), json.encodeToString(result).toByteArray())
        return result
    }

    private fun requireDelivery(plan: ManagedLanePlan, root: Path, operationId: String): ManagedLaneInitialDeliveryReceipt {
        val path = root.resolve("control/run/delivery-$operationId.result.json")
        val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(120)
        while (!Files.exists(path, NOFOLLOW_LINKS)) {
            require(System.nanoTime() < deadline) { "Native Pi bearer not delivered after Worklane START" }
            Thread.sleep(200)
        }
        val receipt = json.decodeFromString<ManagedLaneInitialDeliveryReceipt>(
            ReleasePrivateFiles.read(path, 65536).decodeToString(throwOnInvalidSequence = true))
        val lane = plan.lanes.single { it.kind == ManagedLaneKind.PI }
        require(receipt.generation == plan.generation && receipt.laneId == lane.laneId &&
            receipt.session == lane.session && receipt.operationId == operationId &&
            receipt.tokenHash.matches(Regex("[a-f0-9]{64}")) &&
            receipt.nativeReadbackSha256 == receipt.tokenHash &&
            receipt.expiresAtEpochSeconds - java.time.Instant.now().epochSecond in 1..300) {
            "Native Pi delivery is stale or belongs to another generation/lane"
        }
        val proof = root.resolve("control/data/worklane/v3-pi-process").resolve(
            if (operationId == "managed-start") "${lane.laneId}.credential.json"
            else "${lane.laneId}.$operationId.credential.json")
        val native = Json.parseToJsonElement(ReleasePrivateFiles.read(proof, 65536)
            .decodeToString(throwOnInvalidSequence = true)).jsonObject
        val scope = native.getValue("scope").jsonObject
        require(native["delivered"]?.jsonPrimitive?.content == "true" &&
            native["native_readback_sha256"]?.jsonPrimitive?.content == receipt.tokenHash &&
            scope["lane_id"]?.jsonPrimitive?.content == lane.laneId &&
            scope["session"]?.jsonPrimitive?.content == lane.session &&
            scope["subject"]?.jsonPrimitive?.content == lane.subject &&
            scope["generation"]?.jsonPrimitive?.content == plan.generation &&
            scope["provider"]?.jsonPrimitive?.content == plan.provider &&
            scope["model"]?.jsonPrimitive?.content == plan.model &&
            scope["expires_at"]?.jsonPrimitive?.content == receipt.expiresAtEpochSeconds.toString()) {
            "Worklane native in-lane bearer proof differs from the issuer's selected token"
        }
        return receipt
    }

    /** Source isolation revokes the supervised broker before stopping the fixed lane.
     * Native absence is independently read back; the source-resume actor holds all
     * locks until real original restoration, never a caller boolean or a generic fence.
     */
    fun isolate(bundle: GenerationBundle, generationRoot: Path, operationId: String,
        runtimeFactory: (Path, ManagedLanePlan) -> ManagedLaneRuntime = ManagedLaneRuntime::real
    ): ManagedGenerationIsolationResult? {
        val plan = bundle.request.managedLanes ?: return null
        require(generationRoot == GenerationRuntime.BASE.resolve(plan.generation) &&
            operationId.matches(Regex("[a-z0-9-]{1,64}")) &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(generationRoot.resolve("bundle.json"))) ==
                ReleaseLocks.sha256(json.encodeToString(bundle).toByteArray()))
        val startedBytes = ReleasePrivateFiles.read(generationRoot.resolve("managed-start.result.json"), 1048576)
        val started = json.decodeFromString<ManagedGenerationStartResult>(
            startedBytes.decodeToString(throwOnInvalidSequence = true))
        require(started.generation == plan.generation && started.bundleSha256 ==
            ReleaseLocks.sha256(json.encodeToString(bundle).toByteArray()) &&
            started.lanes.keys == ManagedLaneKind.entries.toSet() &&
            started.lanes.values.all { it.operation == ManagedLaneOperation.START && !it.isolated } &&
            NativeManagedBrokerSupervisor(plan, generationRoot).inspect().active &&
            !runtimeFactory(generationRoot, plan).recorded(
                plan.lanes.single { it.kind == ManagedLaneKind.WORKLANE }, ManagedLaneOperation.START,
                "managed-start").isolated) {
            "Original managed source must be running before a new isolation attempt"
        }
        val record = "${plan.generation}|${started.bundleSha256}|${ReleaseLocks.sha256(startedBytes)}|$operationId\n"
        val intent = generationRoot.resolve("managed-isolate-$operationId.intent.json")
        val resultPath = generationRoot.resolve("managed-isolate-$operationId.result.json")
        require(!Files.exists(intent, NOFOLLOW_LINKS) && !Files.exists(resultPath, NOFOLLOW_LINKS))
        ReleasePrivateFiles.save(intent, record.toByteArray())
        val broker = NativeManagedBrokerSupervisor(plan, generationRoot).isolate(operationId, started.brokerUnitSha256)
        require(!broker.active && broker.mainPid == 0L && broker.socketInode == null)
        val runtime = runtimeFactory(generationRoot, plan)
        val lanes = plan.lanes.associate { lane ->
            lane.kind to runtime.operate(lane, ManagedLaneOperation.ISOLATE, operationId)
        }
        require(lanes.keys == ManagedLaneKind.entries.toSet() && lanes.values.all {
            it.operation == ManagedLaneOperation.ISOLATE && it.operationId == operationId &&
                it.generation == plan.generation && it.isolated
        } && !NativeManagedBrokerSupervisor(plan, generationRoot).inspect().active)
        val outcome = ManagedGenerationIsolationResult(plan.generation, started.bundleSha256,
            operationId, ReleaseLocks.sha256(record.toByteArray()), started.brokerUnitSha256,
            brokerSocketAbsent = true, lanes)
        ReleasePrivateFiles.save(resultPath, json.encodeToString(outcome).toByteArray())
        return outcome
    }

    /** Only a source-resume caller that already proved isolated target/bridge removal may
     * call this under the controller+ordered member locks; use a NEW native operation ID.
     * The broker mints a fresh <=300s native JWT; never reuse the first launch bearer.
     */
    fun resumeOriginal(bundle: GenerationBundle, generationRoot: Path, isolatedOperationId: String,
        operationId: String, runtimeFactory: (Path, ManagedLanePlan) -> ManagedLaneRuntime = ManagedLaneRuntime::real
    ): ManagedGenerationResumeResult? = resume(bundle, generationRoot, isolatedOperationId, operationId,
        ownedCandidate = false, runtimeFactory = runtimeFactory)

    fun resumeOwnedCandidate(bundle: GenerationBundle, generationRoot: Path, isolatedOperationId: String,
        operationId: String, runtimeFactory: (Path, ManagedLanePlan) -> ManagedLaneRuntime = ManagedLaneRuntime::real
    ): ManagedGenerationResumeResult? = resume(bundle, generationRoot, isolatedOperationId, operationId,
        ownedCandidate = true, runtimeFactory = runtimeFactory)

    private fun resume(bundle: GenerationBundle, generationRoot: Path, isolatedOperationId: String,
        operationId: String, ownedCandidate: Boolean,
        runtimeFactory: (Path, ManagedLanePlan) -> ManagedLaneRuntime): ManagedGenerationResumeResult? {
        val plan = bundle.request.managedLanes ?: return null
        require(generationRoot == GenerationRuntime.BASE.resolve(plan.generation) &&
            isolatedOperationId.matches(Regex("[a-z0-9-]{1,64}")) &&
            operationId.matches(Regex("[a-z0-9-]{1,48}")) && bundle.ownership != null &&
            bundle.recoverySourceKopia == null && (bundle.ownedUpdate != null) == ownedCandidate)
        if (ownedCandidate) OwnedReleaseUpdates.validate(bundle)
        SiteOwnerships.checkSealed(bundle)
        val isolated = json.decodeFromString<ManagedGenerationIsolationResult>(
            ReleasePrivateFiles.read(generationRoot.resolve("managed-isolate-$isolatedOperationId.result.json"), 1048576)
                .decodeToString(throwOnInvalidSequence = true))
        val bundleHash = ReleaseLocks.sha256(ReleasePrivateFiles.read(generationRoot.resolve("bundle.json")))
        require(isolated.generation == plan.generation && isolated.bundleSha256 == bundleHash &&
            isolated.operationId == isolatedOperationId && isolated.brokerSocketAbsent &&
            isolated.lanes.keys == ManagedLaneKind.entries.toSet() && isolated.lanes.values.all { it.isolated })
        val identityHead = NativeManagedIdentityLedger(generationRoot.resolve("managed/identity"))
            .requireBound(plan, bundleHash)
        val unit = ManagedLaneBrokerService.unit(plan, generationRoot, UnixSystem().uid.toInt())
        require(unit.sha256 == isolated.brokerUnitSha256 &&
            !NativeManagedBrokerSupervisor(plan, generationRoot).inspect().active)
        val action = "resume-$operationId"
        val claim = "${plan.generation}|$bundleHash|$identityHead|$isolatedOperationId|$operationId\n"
        val intent = generationRoot.resolve("managed-$action.intent.json")
        val resultPath = generationRoot.resolve("managed-$action.result.json")
        require(!Files.exists(intent, NOFOLLOW_LINKS) && !Files.exists(resultPath, NOFOLLOW_LINKS))
        ReleasePrivateFiles.save(intent, claim.toByteArray())
        val broker = NativeManagedBrokerSupervisor(plan, generationRoot).start(action, unit.sha256)
        require(broker.active && broker.mainPid > 1 && broker.socketInode != null)
        val runtime = runtimeFactory(generationRoot, plan)
        val lanes = plan.lanes.associate { lane ->
            val evidence = runtime.operate(lane, ManagedLaneOperation.START, action)
            if (lane.kind == ManagedLaneKind.WORKLANE) requireDelivery(plan, generationRoot.resolve("managed"), action)
            lane.kind to evidence
        }
        require(lanes.keys == ManagedLaneKind.entries.toSet() && lanes.values.all {
            !it.isolated && it.operation == ManagedLaneOperation.START && it.operationId == action
        } && identityHead == NativeManagedIdentityLedger(generationRoot.resolve("managed/identity"))
            .requireBound(plan, bundleHash))
        val result = ManagedGenerationResumeResult(plan.generation, bundleHash, isolatedOperationId,
            operationId, ReleaseLocks.sha256(claim.toByteArray()), broker.mainPid, broker.socketInode.toString(), lanes,
            mode = if (ownedCandidate) "owned-candidate" else "original")
        ReleasePrivateFiles.save(resultPath, json.encodeToString(result).toByteArray())
        return result
    }

    internal fun validateReceipt(intent: ManagedGenerationStartIntent, result: ManagedGenerationStartResult,
        imported: ManagedImportResult?, plan: ManagedLanePlan,
        initial: ManagedInitialPreparation? = null) {
        require(intent.generation == plan.generation && result.generation == plan.generation &&
            intent.bundleSha256 == result.bundleSha256 && intent.mode == result.mode &&
            intent.mode in setOf("owned-private", "recovered-private", "original-private") &&
            ((intent.mode == "original-private" && imported == null && initial != null &&
                initial.generation == plan.generation && initial.bundleSha256 == intent.bundleSha256) ||
                (intent.mode != "original-private" && imported != null && initial == null)) &&
            intent.identityHeadSha256 == result.identityHeadSha256 &&
            intent.brokerUnitSha256 == result.brokerUnitSha256 &&
            result.brokerMainPid > 1 && result.brokerSocketInode.isNotBlank() && !result.promotable &&
            (imported?.preparations ?: initial?.preparations)?.keys == ManagedLaneKind.entries.toSet() &&
            (imported == null || imported.imports.keys == ManagedLaneKind.entries.toSet()) &&
            result.lanes.keys == ManagedLaneKind.entries.toSet() && plan.lanes.all { lane ->
                requireNotNull(imported?.preparations ?: initial?.preparations).getValue(lane.kind)
                    .let { it.isolated && it.operation == ManagedLaneOperation.PREPARE } &&
                (imported == null || imported.imports.getValue(lane.kind).let {
                    it.isolated && it.operation == ManagedLaneOperation.IMPORT }) &&
                result.lanes.getValue(lane.kind).let { evidence -> evidence.operation == ManagedLaneOperation.START &&
                    evidence.operationId == "managed-start" && !evidence.isolated &&
                    evidence.generation == plan.generation && evidence.laneId == lane.laneId }
            }) { "Managed native startup cannot claim import, broker or site authority from a callback" }
    }

    fun start(bundle: GenerationBundle, targetRoot: Path, recovered: Boolean, initial: Boolean = false,
        runtimeFactory: (Path, ManagedLanePlan) -> ManagedLaneRuntime = ManagedLaneRuntime::real,
        brokerFactory: (ManagedLanePlan, Path) -> NativeManagedBrokerSupervisor = { plan, path ->
            NativeManagedBrokerSupervisor(plan, path)
        }
    ): ManagedGenerationStartResult? {
        val plan = bundle.request.managedLanes ?: return null
        plan.validate(bundle.request.id)
        require(targetRoot == GenerationRuntime.BASE.resolve(plan.generation) &&
            bundle.request.store == RuntimeStore.CANONICAL_V2 &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(targetRoot.resolve("bundle.json"))) ==
                ReleaseLocks.sha256(json.encodeToString(bundle).toByteArray()))
        SiteOwnerships.checkSealed(bundle)
        require(!initial || !recovered && bundle.ownedUpdate == null && bundle.recoverySourceKopia == null &&
            bundle.ownership != null)
        require((bundle.recoverySourceKopia != null && bundle.ownedUpdate == null && bundle.ownership == null) == recovered) {
            "Recovered managed generation cannot inherit site ownership"
        }
        if (!recovered && !initial) require(bundle.ownedUpdate != null && bundle.recoverySourceKopia == null)
        val initialReceipt = if (initial) json.decodeFromString<ManagedInitialPreparation>(
            ReleasePrivateFiles.read(targetRoot.resolve("managed-initial.result.json"), 1048576)
                .decodeToString(throwOnInvalidSequence = true)) else null
        val importBytes = if (initial) null else ReleasePrivateFiles.read(targetRoot.resolve("managed-import.result.json"), 1048576)
        val import = importBytes?.let { json.decodeFromString<ManagedImportResult>(
            it.decodeToString(throwOnInvalidSequence = true)) }
        if (initial) require(initialReceipt?.generation == plan.generation &&
            initialReceipt.bundleSha256 == ReleaseLocks.sha256(json.encodeToString(bundle).toByteArray()) &&
            initialReceipt.intentSha256 == ReleaseLocks.sha256(
                ReleasePrivateFiles.read(targetRoot.resolve("managed-initial.intent.json"), 65536)) &&
            initialReceipt.preparations.keys == ManagedLaneKind.entries.toSet() &&
            initialReceipt.preparations.values.all { it.operation == ManagedLaneOperation.PREPARE && it.isolated })
        else {
            val importIntentBytes = ReleasePrivateFiles.read(targetRoot.resolve("managed-import.intent.json"), 1048576)
            val imported = json.decodeFromString<ManagedImportIntent>(importIntentBytes.decodeToString(throwOnInvalidSequence = true))
            val receipt = requireNotNull(import)
            require(receipt.intentSha256 == ReleaseLocks.sha256(importIntentBytes) &&
                imported.targetGeneration == plan.generation && imported.sourceGeneration != plan.generation &&
                imported.targetBundleSha256 == ReleaseLocks.sha256(json.encodeToString(bundle).toByteArray()) &&
                imported.targetPlanSha256 == ReleaseLocks.sha256(json.encodeToString(plan).toByteArray()) &&
                receipt.imports.values.all { it.operationId == imported.captureId } &&
                receipt.preparations.values.all { it.operationId == imported.captureId } &&
                receipt.imports.keys == ManagedLaneKind.entries.toSet() &&
                receipt.preparations.keys == ManagedLaneKind.entries.toSet() &&
                receipt.imports.values.all { it.isolated && it.operation == ManagedLaneOperation.IMPORT } &&
                receipt.preparations.values.all { it.isolated && it.operation == ManagedLaneOperation.PREPARE })
        }
        val root = targetRoot.resolve("managed")
        val identityHead = NativeManagedIdentityLedger(root.resolve("identity"))
            .requireBound(plan, ReleaseLocks.sha256(json.encodeToString(bundle).toByteArray()))
        if (plan.native.brokerHost?.graphOwnedLatePublicTrust==true) {
            // This must occur after the graph's original Caddy/Keycloak StartUnits
            // and current SNI/PKIX readback, never in the pre-start request.
            val expected=ReleaseLocks.sha256(json.encodeToString(bundle).toByteArray())
            if (Files.exists(targetRoot.resolve("managed/control/issuer-hosts.result.json"),NOFOLLOW_LINKS))
                ManagedGraphIssuerHosts.verify(bundle,targetRoot,expected)
            else ManagedGraphIssuerHosts.adopt(bundle,targetRoot,expected)
        }
        val unit = ManagedLaneBrokerService.unit(plan, targetRoot, UnixSystem().uid.toInt())
        val intent = ManagedGenerationStartIntent(plan.generation,
            ReleaseLocks.sha256(json.encodeToString(bundle).toByteArray()), importBytes?.let(ReleaseLocks::sha256),
            if (recovered) "recovered-private" else if (initial) "original-private" else "owned-private", ReleaseLocks.sha256(json.encodeToString(plan).toByteArray()),
            identityHead, unit.sha256)
        val intentPath = targetRoot.resolve("managed-start.intent.json")
        require(!Files.exists(intentPath, NOFOLLOW_LINKS) &&
            !Files.exists(targetRoot.resolve("managed-start.result.json"), NOFOLLOW_LINKS))
        val intentBytes = json.encodeToString(intent).toByteArray()
        ReleasePrivateFiles.save(intentPath, intentBytes)
        // The user's systemd directory must be private and owned. Never overwrite an existing
        // unit (including a symlink): a failed publication leaves this START permanently fenced.
        ReleasePrivateFiles.directory(systemd)
        ReleasePrivateFiles.save(systemd.resolve(unit.name), unit.text.toByteArray())
        val broker = brokerFactory(plan, targetRoot).start("managed-start", unit.sha256)
        require(broker.active && broker.unitSha256 == unit.sha256 && broker.mainPid > 1 && broker.socketInode != null)
        val runtime = runtimeFactory(targetRoot, plan)
        val lanes = plan.lanes.associate { lane ->
            val prior = requireNotNull(import?.preparations ?: initialReceipt?.preparations).getValue(lane.kind)
            require(prior.generation == plan.generation && prior.laneId == lane.laneId)
            val evidence = runtime.operate(lane, ManagedLaneOperation.START, "managed-start")
            if (lane.kind == ManagedLaneKind.WORKLANE) requireDelivery(plan, root, "managed-start")
            lane.kind to evidence
        }
        require(lanes.keys == ManagedLaneKind.entries.toSet() && lanes.values.all {
            it.generation == plan.generation && it.operation == ManagedLaneOperation.START && !it.isolated
        } && identityHead == NativeManagedIdentityLedger(root.resolve("identity")).requireBound(plan, intent.bundleSha256))
        // Each result can be independently reopened by the generation startup caller.
        val result = ManagedGenerationStartResult(ReleaseLocks.sha256(intentBytes), plan.generation,
            intent.mode, intent.bundleSha256, identityHead, unit.sha256, broker.mainPid,
            broker.socketInode.toString(), lanes, promotable = false)
        validateReceipt(intent, result, import, plan, initialReceipt)
        ReleasePrivateFiles.save(targetRoot.resolve("managed-start.result.json"), json.encodeToString(result).toByteArray())
        return result
    }
}
