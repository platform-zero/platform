package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable internal data class ReleaseGeneration(val id: String, val bundleSha256: String) {
    fun validate() { require(id.matches(Regex("q-[a-f0-9]{12}")) && bundleSha256.matches(Regex("[a-f0-9]{64}"))) }
}
@Serializable internal data class ReleaseIngress(val site: CaddySiteBinding, val root: String,
    val upstreams: List<CaddyUpstream>, val acceptanceToken: ActivationInput,
    val expectedConfigurationSha256: String, val expectedSlotSha256: String?,
    val cutover: String, val activation: String, val restriction: String, val rollback: String,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val runtime: ReleaseCaddyEndpoint? = null)
@Serializable internal data class ReleasePublication(val root: String, val bindingSha256: String)
@Serializable internal data class ReleaseEffectIntent(val schemaVersion: Int = 1, val transactionId: String,
    val requestSha256: String, val effect: String)
@Serializable internal data class ReleaseEffectOutcome(val intentSha256: String, val passed: Boolean,
    val result: String? = null, val failureType: String? = null)

/** Generation actions must verify their postconditions before returning. Restoration never promotes a
 * target and resume must verify target isolation first. This boundary permits runtime registry locking
 * without holding the release-journal file lock across native processes. */
internal interface ReleaseGenerationControl {
    fun preflight()
    fun stage()
    fun readiness()
    fun freeze()
    fun verifyQuiesced()
    fun capture(): String
    fun restoreTest(snapshot: String)
    fun migrate()
    fun resumeRestrictedCandidate()
    fun isolateCandidate()
    fun restorePrevious(snapshot: String)
    fun verifyPrevious()
    fun qualificationSnapshot(): String
    /** After actual first-install COMMITTED, preserve selected second snapshot before typed claim closure. */
    fun retireInstalledAfterCommittedSite(): Unit = error("First-install reference retirement needs native completion and active-site evidence")
    fun retireOwnedAfterCommittedSite(): Unit = error("Owned retirement requires protected selected candidate and old source hold")
    fun retireOwnedAfterRollback(): Unit = error("Owned rollback retirement requires typed isolation and source resume")
    /** Must observe the actual imported/migrated native target, never guess a future bundle. */
    fun bindStagedDeployment(snapshotId: String): ReleaseStagedGeneration =
        error("Owned update control must supply a native staged deployment binding")
}
internal interface ReleasePublicationControl {
    fun pause()
    fun release()
    /** Only after durable original source-resume and candidate isolation proof, never on callback return. */
    fun completeOwnedRollback(): Unit = error("Owned update publication recovery requires native completion proof")
    fun commitOwnedRetirement(): Unit = error("Permanent old-site retirement requires global committed site proof")
}

/** Durable effect intents are independent of transaction phase records. A successful old result is
 * never permission to execute again; partial freeze/capture/cutover/outbound operations retain their
 * identities. Production uses the actual TransactionalCaddy CAS actuator, not a shell or boolean gate. */
internal class GenerationReleaseEffects(private val root: Path, private val transactionId: String,
    private val requestSha256: String, private val originalDeployment: ReleaseDeploymentBinding?,
    private val ingress: ReleaseIngress, private val generation: ReleaseGenerationControl,
    private val publication: ReleasePublicationControl, private val caddy: TransactionalCaddy,
    private val update: ReleaseUpdatePreparation? = null) : ReleaseEffects, ReleaseQualificationSnapshotEffects, ReleaseUpdateEffects {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private var cutover: CaddyChangeResult? = null
    private var publicChange: CaddyChangeResult? = null
    private var restricted = false
    private var stagedDeployment: ReleaseDeploymentBinding? = null
    private fun deployment(): ReleaseDeploymentBinding = originalDeployment ?: stagedDeployment ?:
        requireNotNull(TransactionJournal.verify(root.resolve("transaction.jsonl")).last().deployment) {
            "Owned target deployment has not been natively observed"
        }
    private fun <T> effect(name: String, encode: (T) -> String = { "verified" }, action: () -> T): T {
        require(name.matches(Regex("[a-z][a-z0-9-]{0,63}")))
        // Clear cancellation only while retaining local evidence: an interrupt flag closes NIO
        // channels. Never clear it and then accidentally proceed with the external effect.
        var interrupted = Thread.interrupted()
        try {
            ReleasePrivateFiles.directory(root)
            val intent = json.encodeToString(ReleaseEffectIntent(transactionId = transactionId, requestSha256 = requestSha256, effect = name)).toByteArray()
            val intentPath = root.resolve("$name.intent.json")
            require(!Files.exists(intentPath, NOFOLLOW_LINKS)) { "Existing effect intent: observation-only reconciliation required, never replay" }
            ReleasePrivateFiles.save(intentPath, intent)
            try {
                if (interrupted || Thread.currentThread().isInterrupted) throw InterruptedException("Interrupted before $name")
                val result = action()
                if (Thread.currentThread().isInterrupted) throw InterruptedException("Interrupted after $name; effect requires reconciliation")
                ReleasePrivateFiles.save(root.resolve("$name.result.json"), json.encodeToString(
                    ReleaseEffectOutcome(ReleaseLocks.sha256(intent), true, encode(result))).toByteArray())
                return result
            } catch (error: Exception) {
                interrupted = Thread.interrupted() || error is InterruptedException || interrupted
                try {
                    if (!Files.exists(root.resolve("$name.result.json"), NOFOLLOW_LINKS))
                        ReleasePrivateFiles.save(root.resolve("$name.result.json"), json.encodeToString(
                            ReleaseEffectOutcome(ReleaseLocks.sha256(intent), false, failureType = error.javaClass.name)).toByteArray())
                } catch (recording: Exception) { error.addSuppressed(recording) }
                throw error
            }
        } catch (error: Exception) {
            interrupted = Thread.interrupted() || error is InterruptedException || interrupted
            if (interrupted && error !is InterruptedException)
                throw InterruptedException("Interrupted release effect; retain original intent").also { it.initCause(error) }
            throw error
        } finally { if (interrupted) Thread.currentThread().interrupt() }
    }
    private fun token(): String = ReleasePrivateFiles.read(Path.of(ingress.acceptanceToken.path)).also {
        require(ReleaseLocks.sha256(it) == ingress.acceptanceToken.sha256)
    }.decodeToString().trim().also { require(it.matches(Regex("[a-f0-9]{64}"))) }
    override fun preflight() {
        require((update == null) == (originalDeployment != null)) { "Install/update deployment binding changed" }
        originalDeployment?.validate()
        update?.let { require(it.intent.source.id != it.intent.targetGeneration) }
        require(requestSha256.matches(Regex("[a-f0-9]{64}")) && transactionId.matches(Regex("[a-z][a-z0-9-]{0,63}")))
        require(listOf(ingress.cutover, ingress.activation, ingress.restriction, ingress.rollback).let {
            it.distinct().size == 4 && it.all { id -> id.matches(Regex("r-[a-f0-9]{12}")) }
        })
        originalDeployment?.let { initial -> require(TransactionalCaddy.digest(caddy.revision(ingress.cutover, initial.generationId, ingress.upstreams, token())) ==
            initial.restrictedConfigurationSha256) { "Prepared deployment does not bind this restricted route" } }
        require(caddy.observeConfigurationSha256() == ingress.expectedConfigurationSha256 &&
            caddy.observeSlotSha256() == ingress.expectedSlotSha256) { "Ingress changed before release admission" }
        generation.preflight()
    }
    override fun stageImmutableCandidate() = effect("stage") { generation.stage() }
    override fun checkPrivateReadinessAndIntegrations() = effect("readiness") { generation.readiness() }
    override fun freezeNonTestWrites() = effect("freeze") { generation.freeze() }
    override fun pauseOutbound() {
        // Failures may call pause after an earlier successful pause. The control is stop-only and
        // idempotent, but each distinct request gets its own retained intent, never an outbound retry.
        effect(if (Files.exists(root.resolve("pause.intent.json"))) "pause-after-failure" else "pause") { publication.pause() }
    }
    override fun quiesceQueues() = effect("quiesce") { generation.verifyQuiesced() }
    override fun snapshotCoordinated(): String = effect("capture", { it }) { generation.capture() }
    override fun verifySnapshotAndIsolatedFunctionalRestore(snapshotId: String) = effect("restore-test") { generation.restoreTest(snapshotId) }
    override fun migrateStaged() = effect("migrate") { generation.migrate() }
    override fun bindStagedDeployment(snapshotId: String): ReleaseDeploymentBinding = effect("bind-staged", { json.encodeToString(it) }) {
        val prepared = requireNotNull(update) { "Install deployment is already bound" }
        val native = generation.bindStagedDeployment(snapshotId).also { it.validate() }
        require(native.generationId == prepared.intent.targetGeneration &&
            native.sitePolicySha256 == prepared.intent.sitePolicySha256) {
            "Native staged target/site differs from immutable update intent"
        }
        val restricted = TransactionalCaddy.digest(caddy.revision(ingress.cutover, native.generationId, ingress.upstreams, token()))
        ReleaseDeploymentBinding(native.generationId, native.bundleSha256, native.sitePolicySha256, restricted).also {
            it.validate(); stagedDeployment = it
        }
    }
    override fun restrictPublicWritesToAcceptance() {
        if (publicChange == null && !Files.exists(root.resolve("open-writes.intent.json"))) {
            effect("restrict") { generation.resumeRestrictedCandidate() }
            restricted = true
        } else {
            // Never overwrite an uncertain public change. Caddy's pending guard forces observation.
            effect("restrict-after-activation") {
                val expected = requireNotNull(publicChange) { "Unknown activation cutover; reconcile Caddy before restricting" }
                caddy.replace(ingress.restriction, expected.observedConfigurationSha256, expected.observedSlotSha256,
                    deployment().generationId, ingress.upstreams, token())
            }
        }
    }
    override fun loadAllApprovedHostsOnce() = effect("cutover") {
        require(restricted)
        cutover = caddy.replace(ingress.cutover, ingress.expectedConfigurationSha256, ingress.expectedSlotSha256,
            deployment().generationId, ingress.upstreams, token())
        require(cutover!!.status == "applied" && cutover!!.observedSlotSha256 == deployment().restrictedConfigurationSha256)
    }
    override fun openPublicWrites() = effect("open-writes") {
        require(caddy.observeRestrictedSlotSha256(deployment().generationId, ingress.upstreams) == deployment().restrictedConfigurationSha256)
        publicChange = caddy.replace(ingress.activation, caddy.observeConfigurationSha256(), deployment().restrictedConfigurationSha256,
            deployment().generationId, ingress.upstreams, null)
        require(publicChange!!.status == "applied")
    }
    override fun releaseOutbound() = effect("outbound") { publication.release() }
    override fun verifyQualificationSnapshot(): String = effect("qualification-snapshot", { it }) { generation.qualificationSnapshot() }
    override fun reloadPreviousCaddyConfig() = effect("rollback-ingress") {
        val result = cutover ?: run {
            val path = Path.of(ingress.root).resolve("${ingress.cutover}.intent.json")
            val bytes = ReleasePrivateFiles.read(path)
            val hash = ReleaseLocks.sha256(bytes)
            val resultPath = path.resolveSibling("${ingress.cutover}.result.json")
            if (Files.exists(resultPath, NOFOLLOW_LINKS)) {
                // A separately dispatched rollback has no in-memory cutover result. Completed
                // operations have no pending claim and must not be sent to pending reconciliation.
                json.decodeFromString<CaddyChangeResult>(ReleasePrivateFiles.read(resultPath).decodeToString()).also {
                    require(it.operation == ingress.cutover && it.intentSha256 == hash) { "Foreign retained cutover result" }
                }
            } else caddy.reconcile(ingress.cutover, hash)
        }
        require(result.status in setOf("applied", "not-applied"))
        if (result.status == "applied") caddy.revert(ingress.rollback, ingress.cutover, result.intentSha256,
            caddy.observeConfigurationSha256())
    }
    override fun isolateCandidate() = effect("isolate") { generation.isolateCandidate() }
    override fun restoreOldSnapshot(snapshotId: String) = effect("restore-previous") { generation.restorePrevious(snapshotId) }
    override fun verifyOldStack() = effect("verify-previous") {
        generation.verifyPrevious()
        publication.completeOwnedRollback()
        generation.retireOwnedAfterRollback()
    }
    override fun retireInstalledAfterCommittedSite() = effect("retire-install-site") {
        require(update == null && TransactionJournal.verify(root.resolve("transaction.jsonl")).last().phase == Phase.COMMITTED)
        generation.retireInstalledAfterCommittedSite()
    }
    override fun retirePreviousAfterCommittedSite() = effect("retire-owned-source") {
        require(update != null && TransactionJournal.verify(root.resolve("transaction.jsonl")).last().phase == Phase.COMMITTED)
        publication.commitOwnedRetirement()
        generation.retireOwnedAfterCommittedSite()
    }
}
