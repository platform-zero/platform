package net.datamancy.platform

import java.nio.file.Path

/** Release actuator boundary. GenerationReleaseEffects supplies durable typed production composition. */
interface ReleaseEffects {
    fun preflight()
    fun stageImmutableCandidate()
    fun checkPrivateReadinessAndIntegrations()
    fun freezeNonTestWrites()
    fun pauseOutbound()
    fun quiesceQueues()
    fun snapshotCoordinated(): String
    fun verifySnapshotAndIsolatedFunctionalRestore(snapshotId: String)
    fun migrateStaged()
    fun restrictPublicWritesToAcceptance()
    /** Single Caddy API load; failure must retain the previous config. */
    fun loadAllApprovedHostsOnce()
    fun openPublicWrites()
    fun releaseOutbound()
    fun reloadPreviousCaddyConfig()
    fun isolateCandidate()
    fun restoreOldSnapshot(snapshotId: String)
    fun verifyOldStack()
}

/** Evaluates executed evidence; AI self-qualification is not independent acceptance. */
interface ReleaseQualification {
    fun verifyStagedJourneys()
    fun verifyRealDomainJourneys()
}

/** Compatibility only for earlier callers; the active contract no longer claims independent review. */
@Deprecated("Use ReleaseQualification; automated self-qualification is not independent review")
interface IndependentReleaseReview : ReleaseQualification

/** Restricted preparation and separately authorized activation. Every uncertain effect remains non-replayable. */
class ReleaseTransaction(private val journal: Path, private val effects: ReleaseEffects,
                         private val qualification: ReleaseQualification) {
    /** Stage and check a restricted candidate only. This method never opens public writes/outbound. */
    fun execute(transactionId: String, lockDigest: String, lastGood: String?, deployment: ReleaseDeploymentBinding? = null,
                update: ReleaseUpdateBinding? = null): JournalRecord {
        // Never infer safe resume after a crash. Existing journal requires explicit investigation.
        require(!java.nio.file.Files.exists(journal)) { "Transaction journal exists: reconcile the recorded attempt before starting a fresh transaction" }
        deployment?.validate(); update?.validate()
        require(update == null || deployment == null && lastGood == update.sourceGeneration && effects is ReleaseUpdateEffects) {
            "Owned update requires an immutable source intent and late-binding actuator"
        }
        effects.preflight()
        TransactionJournal.append(journal, transactionId, lockDigest, Phase.PREPARED, lastGood, null, deployment, update)
        var snapshot: String? = null
        var snapshotVerified = false
        var candidateLoaded = false
        var writesFrozen = false
        try {
            if (lastGood != null) {
                writesFrozen = true // A failed freeze request may already have changed write admission.
                effects.freezeNonTestWrites()
                effects.pauseOutbound()
                effects.quiesceQueues()
                TransactionJournal.appendExisting(journal, Phase.FROZEN, null)
                val created = effects.snapshotCoordinated()
                require(created.matches(Regex("[a-z][a-z0-9-]{0,63}"))) { "Invalid snapshot identity" }
                snapshot = created
                effects.verifySnapshotAndIsolatedFunctionalRestore(snapshot)
                snapshotVerified = true
                TransactionJournal.appendExisting(journal, Phase.SNAPSHOT_VERIFIED, snapshot)
            } else {
                // A clean install starts with no public/outbound jobs at all.
                effects.pauseOutbound()
            }
            effects.stageImmutableCandidate()
            if (lastGood != null) effects.migrateStaged()
            effects.checkPrivateReadinessAndIntegrations()
            qualification.verifyStagedJourneys()
            if (lastGood == null) {
                // A new stack is still mutable: initialization, acceptance and queued jobs may
                // have written data. No snapshot is consistent merely because public routes are closed.
                writesFrozen = true // Freeze may partially apply even when its acknowledgement fails.
                effects.freezeNonTestWrites()
                effects.quiesceQueues()
                TransactionJournal.appendExisting(journal, Phase.FROZEN, null)
                val created = effects.snapshotCoordinated()
                require(created.matches(Regex("[a-z][a-z0-9-]{0,63}"))) { "Invalid snapshot identity" }
                snapshot = created
                effects.verifySnapshotAndIsolatedFunctionalRestore(snapshot)
                snapshotVerified = true
                TransactionJournal.appendExisting(journal, Phase.SNAPSHOT_VERIFIED, snapshot)
            }
            val stagedDeployment = if (update == null) null else (effects as ReleaseUpdateEffects).bindStagedDeployment(requireNotNull(snapshot))
            TransactionJournal.appendExisting(journal, Phase.STAGED, snapshot, deployment = stagedDeployment)
            effects.restrictPublicWritesToAcceptance()
            // Record the restricted gate before attempting any public cutover.
            TransactionJournal.appendExisting(journal, Phase.CUTOVER_RESTRICTED, snapshot)
            effects.loadAllApprovedHostsOnce()
            candidateLoaded = true
            qualification.verifyRealDomainJourneys()
            val qualificationSnapshot = (effects as? ReleaseQualificationSnapshotEffects)?.verifyQualificationSnapshot()
            require(update == null || qualificationSnapshot != null) { "Owned update requires candidate functional restore after real-domain execution" }
            return TransactionJournal.appendExisting(journal, Phase.ACCEPTED, snapshot, qualificationSnapshotId = qualificationSnapshot)
        } catch (failure: Exception) {
            var interrupted = Thread.interrupted() || failure is InterruptedException
            try {
                // A lost Caddy acknowledgement requires the backend's compare/observe reconciliation,
                // not an unconditional replacement of unrelated configuration.
                val reachedCutover = runCatching { TransactionJournal.verify(journal).last().phase in
                    setOf(Phase.CUTOVER_RESTRICTED, Phase.ACCEPTED) }.getOrDefault(true)
                var recovered = true
                fun attempt(block: () -> Unit) = try { block() } catch (recoveryFailure: Exception) {
                    if (recoveryFailure is InterruptedException) interrupted = true
                    failure.addSuppressed(recoveryFailure)
                    recovered = false
                }
                if (reachedCutover || candidateLoaded) attempt { effects.reloadPreviousCaddyConfig() }
                var isolated = false
                attempt { effects.isolateCandidate(); isolated = true }
                if (lastGood != null && writesFrozen) {
                    // A failed stop/timeout is NOT proof of target isolation. Never restore/resume
                    // source state while a competing candidate may still write to its providers.
                    if (snapshot != null && snapshotVerified && isolated && recovered) {
                        var restored = false
                        attempt { effects.restoreOldSnapshot(snapshot); restored = true }
                        if (restored) attempt { effects.verifyOldStack() }
                    } else recovered = false // Never overwrite unverified state or race an unknown writer.
                }
                // Never silently reopen writes or outbound jobs on a failed transaction.
                attempt { TransactionJournal.appendExisting(journal, Phase.RECOVERY_REQUIRED, snapshot) }
                throw IllegalStateException(
                    if (recovered) "Release failed; candidate isolated; diagnose, correct and qualify a fresh attempt before resuming writes/outbound"
                    else "Release failed; possible external effects or recovery incomplete; reconcile authoritative state before any retry", failure)
            } finally { if (interrupted) Thread.currentThread().interrupt() }
        }
    }

    /** Explicit activation after whole-trial qualification. A crash after the claim is never auto-replayed. */
    fun activate(transactionId: String, lockDigest: String, expectedHead: String,
                 authorization: ReleaseActivationAuthorization): JournalRecord {
        val accepted = TransactionJournal.verify(journal).last()
        require(accepted.phase == Phase.ACCEPTED && accepted.hash == expectedHead &&
            accepted.transactionId == transactionId && accepted.lockDigest == lockDigest) { "Exact accepted transaction head required" }
        val deployment = requireNotNull(accepted.deployment) { "Legacy unbound transactions cannot authorize activation" }
        deployment.validate()
        val binding = ReleaseActivationBinding(transactionId, lockDigest, accepted.hash, deployment)
        val permit = try { authorization.verify(binding) } catch (interrupted: InterruptedException) {
            Thread.currentThread().interrupt()
            throw interrupted
        }
        require(permit.matches(Regex("[a-f0-9]{64}"))) { "Verified activation permit digest required" }
        val claimed = TransactionJournal.appendExisting(journal, Phase.ACTIVATION_STARTED, accepted.snapshotId, expectedHead, permit)
        try {
            authorization.consume(binding, permit, claimed.hash)
            if (Thread.currentThread().isInterrupted) throw InterruptedException("Activation interrupted before public writes")
            effects.openPublicWrites()
            if (Thread.currentThread().isInterrupted) throw InterruptedException("Activation interrupted before outbound release")
            effects.releaseOutbound() // Last external effect; cannot be recalled.
            return TransactionJournal.appendExisting(journal, Phase.COMMITTED, accepted.snapshotId, claimed.hash)
        } catch (failure: Exception) {
            var interrupted = Thread.interrupted() || failure is InterruptedException
            fun attempt(action: () -> Unit) {
                try { action() } catch (error: Exception) {
                    if (error is InterruptedException) interrupted = true
                    failure.addSuppressed(error)
                }
            }
            try {
                // A failed acknowledgement may hide an escaped write: never restore stale state here.
                var restricted = false
                attempt { effects.restrictPublicWritesToAcceptance(); restricted = true }
                attempt { effects.pauseOutbound() }
                // Unknown Caddy acknowledgement cannot be overwritten. Stop/fence the backing
                // candidate instead of leaving a potentially open route to a running writer.
                if (!restricted) attempt { effects.isolateCandidate() }
                attempt { TransactionJournal.appendExisting(journal, Phase.RECOVERY_REQUIRED, accepted.snapshotId, claimed.hash) }
                throw IllegalStateException("Activation failed or uncertain; reconcile authoritative state before any retry", failure)
            } finally { if (interrupted) Thread.currentThread().interrupt() }
        }
    }
}
