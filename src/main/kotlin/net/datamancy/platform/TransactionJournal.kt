package net.datamancy.platform

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** No actuator is attached: a journal record is not evidence that a deployment step happened. */
@Serializable enum class Phase { PREPARED, FROZEN, SNAPSHOT_VERIFIED, STAGED, CUTOVER_RESTRICTED, ACCEPTED, ACTIVATION_STARTED, COMMITTED, RECOVERY_REQUIRED }
@Serializable data class JournalRecord(val transactionId: String, val lockDigest: String, val phase: Phase,
    val lastGood: String?, val snapshotId: String?, val prevHash: String, val hash: String,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val deployment: ReleaseDeploymentBinding? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val activationPermitSha256: String? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val update: ReleaseUpdateBinding? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val qualificationSnapshotId: String? = null)

/** Append-only, newline-delimited hash chain; partial or altered tails require operator recovery. */
object TransactionJournal {
    private val json = Json { ignoreUnknownKeys = false }
    private val slug = Regex("[a-z][a-z0-9-]{0,63}")
    private val hex = Regex("[a-f0-9]{64}")
    private val privateMode = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
    private val first = "0".repeat(64)
    private val next = mapOf(
        Phase.PREPARED to setOf(Phase.FROZEN, Phase.RECOVERY_REQUIRED),
        Phase.FROZEN to setOf(Phase.SNAPSHOT_VERIFIED, Phase.RECOVERY_REQUIRED),
        Phase.SNAPSHOT_VERIFIED to setOf(Phase.STAGED, Phase.RECOVERY_REQUIRED),
        Phase.STAGED to setOf(Phase.CUTOVER_RESTRICTED, Phase.RECOVERY_REQUIRED),
        Phase.CUTOVER_RESTRICTED to setOf(Phase.ACCEPTED, Phase.RECOVERY_REQUIRED),
        // Direct historical ACCEPTED -> COMMITTED remains readable only for old unbound records.
        Phase.ACCEPTED to setOf(Phase.ACTIVATION_STARTED, Phase.COMMITTED, Phase.RECOVERY_REQUIRED),
        Phase.ACTIVATION_STARTED to setOf(Phase.COMMITTED, Phase.RECOVERY_REQUIRED),
        Phase.COMMITTED to emptySet(), Phase.RECOVERY_REQUIRED to emptySet()
    )
    private fun payload(r: JournalRecord) = json.encodeToString(r.copy(hash = ""))
    private fun hash(r: JournalRecord) = ReleaseLocks.sha256(payload(r).toByteArray(Charsets.UTF_8))

    fun verify(path: Path): List<JournalRecord> {
        require(Files.isRegularFile(path, NOFOLLOW_LINKS) && Files.size(path) in 1..1048576) { "Missing or oversized journal" }
        val mode = Files.getPosixFilePermissions(path, NOFOLLOW_LINKS)
        require(PosixFilePermission.OWNER_READ in mode && mode.none { it.name.startsWith("GROUP_") || it.name.startsWith("OTHERS_") }) {
            "Journal must be private"
        }
        val bytes = Files.readAllBytes(path)
        return parse(bytes)
    }
    private fun parse(bytes: ByteArray): List<JournalRecord> {
        require(bytes.isNotEmpty() && bytes.last() == '\n'.code.toByte()) { "Incomplete journal tail; recovery required" }
        val lines = bytes.toString(Charsets.UTF_8).dropLast(1).split('\n')
        require(lines.size <= 1024) { "Journal too long" }
        var prior: JournalRecord? = null
        return lines.map { line ->
            val r = json.decodeFromString<JournalRecord>(line)
            require(slug.matches(r.transactionId) && hex.matches(r.lockDigest) &&
                (r.lastGood == null || slug.matches(r.lastGood)) &&
                (r.snapshotId == null || slug.matches(r.snapshotId)) &&
                r.prevHash == (prior?.hash ?: first) && r.hash == hash(r) &&
                (prior == null && r.phase == Phase.PREPARED || prior != null &&
                    r.transactionId == prior!!.transactionId && r.lockDigest == prior!!.lockDigest &&
                    r.lastGood == prior!!.lastGood && r.phase in next.getValue(prior!!.phase))) {
                "Invalid journal sequence or hash; recovery required"
            }
            if (r.phase in setOf(Phase.SNAPSHOT_VERIFIED, Phase.STAGED, Phase.CUTOVER_RESTRICTED, Phase.ACCEPTED, Phase.COMMITTED) &&
                prior?.phase == Phase.FROZEN) require(r.snapshotId != null) { "Verified snapshot missing" }
            if (prior?.snapshotId != null) require(r.snapshotId == prior!!.snapshotId) { "Snapshot changed mid-transaction" }
            r.deployment?.validate()
            if (r.qualificationSnapshotId != null) {
                require(r.qualificationSnapshotId.matches(Regex("cap-[a-f0-9]{12}"))) { "Invalid qualification snapshot identity" }
                if (prior?.qualificationSnapshotId == null) require(r.phase == Phase.ACCEPTED && prior?.phase == Phase.CUTOVER_RESTRICTED) {
                    "Qualification snapshot binds only after real-domain execution and verified functional restore"
                } else require(r.qualificationSnapshotId == prior!!.qualificationSnapshotId) { "Qualification snapshot changed" }
            } else require(prior?.qualificationSnapshotId == null) { "Qualification snapshot removed" }
            r.update?.validate()
            if (r.update != null && r.phase in setOf(Phase.ACCEPTED, Phase.ACTIVATION_STARTED, Phase.COMMITTED))
                require(r.qualificationSnapshotId != null) { "Updated candidate requires its own qualified snapshot, not the old source rollback snapshot" }
            if (prior == null && r.update != null) require(r.deployment == null && r.lastGood == r.update.sourceGeneration) {
                "Update must prepare its exact source without inventing a candidate bundle"
            }
            if (prior != null) {
                require(r.update == prior!!.update) { "Update authority changed mid-transaction" }
                val newlyBound = prior!!.deployment == null && r.deployment != null
                if (newlyBound) {
                    val update = requireNotNull(r.update) { "Legacy unbound records cannot acquire promotion authority" }
                    require(prior!!.phase == Phase.SNAPSHOT_VERIFIED && r.phase == Phase.STAGED && r.snapshotId != null &&
                        r.deployment!!.generationId == update.targetGeneration && r.deployment.sitePolicySha256 == update.sitePolicySha256) {
                        "Update deployment may bind once, after verified snapshot and before cutover"
                    }
                } else require(r.deployment == prior!!.deployment) { "Activation deployment changed mid-transaction" }
            }
            if (r.update != null && r.phase in setOf(Phase.STAGED, Phase.CUTOVER_RESTRICTED, Phase.ACCEPTED,
                    Phase.ACTIVATION_STARTED, Phase.COMMITTED)) require(r.deployment != null) { "Update candidate not sealed" }
            if (r.activationPermitSha256 != null) require(hex.matches(r.activationPermitSha256)) { "Invalid activation permit digest" }
            if (prior?.activationPermitSha256 != null) require(r.activationPermitSha256 == prior!!.activationPermitSha256) { "Activation permit changed" }
            if (r.phase == Phase.ACTIVATION_STARTED) require(r.deployment != null && r.activationPermitSha256 != null) { "Bound single-use activation required" }
            else if (prior?.activationPermitSha256 == null) require(r.activationPermitSha256 == null) { "Unexpected activation authority" }
            if (r.phase == Phase.COMMITTED && r.deployment != null) require(prior?.phase == Phase.ACTIVATION_STARTED) { "Activation cannot bypass permit consumption" }
            prior = r
            r
        }
    }

    /** Only under an independently reviewed, dedicated private parent. Not used by release CLI until actuator exists. */
    fun append(path: Path, transactionId: String, lockDigest: String, phase: Phase, lastGood: String?, snapshotId: String?,
               deployment: ReleaseDeploymentBinding? = null, update: ReleaseUpdateBinding? = null): JournalRecord {
        deployment?.validate(); update?.validate()
        require(update == null || deployment == null && lastGood == update.sourceGeneration) { "Update source must bind before candidate creation" }
        require(slug.matches(transactionId) && hex.matches(lockDigest) &&
            (lastGood == null || slug.matches(lastGood)) && (snapshotId == null || slug.matches(snapshotId))) { "Invalid journal identity" }
        require(phase == Phase.PREPARED) { "First journal entry must prepare" }
        require(Files.isDirectory(path.parent, NOFOLLOW_LINKS) &&
            Files.getPosixFilePermissions(path.parent, NOFOLLOW_LINKS).none {
                it.name.startsWith("GROUP_") || it.name.startsWith("OTHERS_")
            }) { "Dedicated private journal parent required" }
        // File lock serializes competing writers; validation happens under that lock, not before it.
        FileChannel.open(path, setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
            PosixFilePermissions.asFileAttribute(privateMode)).use { channel ->
            // Only initial creation is allowed here. Subsequent transitions require appendExisting.
            Files.setPosixFilePermissions(path, privateMode)
            val r = JournalRecord(transactionId, lockDigest, phase, lastGood, snapshotId, first, "", deployment, update = update)
            val stamped = r.copy(hash = hash(r))
            val buffer = ByteBuffer.wrap((json.encodeToString(stamped) + "\n").toByteArray())
            while (buffer.hasRemaining()) channel.write(buffer)
            channel.force(true)
            FileChannel.open(path.parent, StandardOpenOption.READ).use { it.force(true) }
            return stamped
        }
    }
    fun appendExisting(path: Path, phase: Phase, snapshotId: String?, expectedHead: String? = null,
                       activationPermitSha256: String? = null, deployment: ReleaseDeploymentBinding? = null,
                       qualificationSnapshotId: String? = null): JournalRecord {
        require(expectedHead == null || hex.matches(expectedHead)) { "Invalid expected transaction head" }
        require(Files.isRegularFile(path, NOFOLLOW_LINKS)) { "Missing journal" }
        FileChannel.open(path, StandardOpenOption.READ, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS).use { channel ->
            channel.lock().use {
                val records = verify(path)
                val last = records.last()
                require(expectedHead == null || expectedHead == last.hash) { "Stale transaction head; reconcile instead of replaying" }
                val r = last.copy(phase = phase, snapshotId = snapshotId, prevHash = last.hash, hash = "",
                    activationPermitSha256 = activationPermitSha256 ?: last.activationPermitSha256,
                    deployment = deployment ?: last.deployment,
                    qualificationSnapshotId = qualificationSnapshotId ?: last.qualificationSnapshotId)
                val stamped = r.copy(hash = hash(r))
                // Validate the proposed record against the exact bytes before writing.
                val line = (json.encodeToString(stamped) + "\n").toByteArray()
                parse(Files.readAllBytes(path) + line)
                require(Files.size(path) + line.size <= 1048576) { "Journal full" }
                channel.position(channel.size())
                val buffer = ByteBuffer.wrap(line)
                while (buffer.hasRemaining()) channel.write(buffer)
                channel.force(true)
                return stamped
            }
        }
    }
}
