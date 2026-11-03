package net.datamancy.platform

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.util.UUID
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable data class PendingRssPost(val draft: DraftPost, val createdAtMillis: Long,
    val attemptedAtMillis: Long? = null)
@Serializable data class RssReconciledDelivery(val feedId: String, val itemId: String, val idempotencyKey: String,
    val account: String, val remoteStatusId: String, val observedAtMillis: Long, val responseSha256: String)
@Serializable data class RssStoreDocument(val schemaVersion: Int = 1, val publisher: PublisherState = PublisherState(),
    val pending: List<PendingRssPost> = emptyList(), val checksum: String = "",
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val reconciled: List<RssReconciledDelivery> = emptyList())

/** Durable v3-private RSS checkpoint/outbox. An ambiguous send is never automatically replayed. */
class RssStateStore(private val root: Path) {
    private val json = Json { ignoreUnknownKeys = false }
    private val state = root.resolve("rss-state.json")
    private val lockFile = root.resolve("rss-state.lock")
    private val previous = root.resolve("rss-state.previous")
    private val ownerOnly = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)

    private fun guardRoot() {
        require(Files.isDirectory(root, NOFOLLOW_LINKS) && root.isAbsolute && root == root.normalize() &&
            root.toRealPath() == root &&
            (Files.getAttribute(root, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == com.sun.security.auth.module.UnixSystem().uid &&
            Files.getPosixFilePermissions(root, NOFOLLOW_LINKS).let { permissions ->
                PosixFilePermission.OWNER_READ in permissions && PosixFilePermission.OWNER_WRITE in permissions &&
                    PosixFilePermission.OWNER_EXECUTE in permissions && permissions.none {
                        it.name.startsWith("GROUP_") || it.name.startsWith("OTHERS_")
                    }
            }) { "Dedicated private RSS directory required" }
        Files.list(root).use { entries ->
            require(entries.allMatch { it.fileName.toString() in setOf(
                "rss-state.json", "rss-state.lock", "rss-state.previous") }) {
                "Unexpected RSS directory entry; recovery required"
            }
        }
    }
    private fun guardFile(path: Path) {
        require(Files.isRegularFile(path, NOFOLLOW_LINKS) && Files.size(path) in 1..1048576 &&
            (Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == com.sun.security.auth.module.UnixSystem().uid &&
            (Files.getAttribute(path, "unix:nlink", NOFOLLOW_LINKS) as Number).toLong() == 1L &&
            Files.getPosixFilePermissions(path, NOFOLLOW_LINKS).let { mode ->
                PosixFilePermission.OWNER_READ in mode && mode.none { it.name.startsWith("GROUP_") || it.name.startsWith("OTHERS_") }
            }) { "Missing or unprotected RSS state" }
    }
    private fun encoded(doc: RssStoreDocument): ByteArray {
        val payload = json.encodeToString(doc.copy(checksum = ""))
        val text = json.encodeToString(doc.copy(checksum = ReleaseLocks.sha256(payload.toByteArray(Charsets.UTF_8))))
        val result = text.toByteArray(Charsets.UTF_8)
        require(result.size <= 1048576) { "RSS state exceeds bounded capacity" }
        return result
    }
    private fun load(): RssStoreDocument {
        guardFile(state)
        val doc = json.decodeFromString<RssStoreDocument>(Files.readString(state))
        require(doc.schemaVersion == 1 && doc.publisher.schemaVersion == 1 && doc.pending.size <= 256 &&
            doc.publisher.checkpoints.map { it.feedId }.distinct().size == doc.publisher.checkpoints.size &&
            doc.pending.map { it.draft.feedId to it.draft.itemId }.distinct().size == doc.pending.size &&
            doc.reconciled.size <= 256 && doc.reconciled.map { it.account to it.remoteStatusId }.distinct().size == doc.reconciled.size &&
            doc.checksum.matches(Regex("[a-f0-9]{64}")) && encoded(doc).contentEquals(Files.readAllBytes(state))) {
            "RSS state corrupt or ambiguous; recovery required"
        }
        return doc
    }
    private fun fsyncDirectory() = FileChannel.open(root, StandardOpenOption.READ).use { it.force(true) }
    private fun newFile(path: Path, bytes: ByteArray) {
        FileChannel.open(path, setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
            PosixFilePermissions.asFileAttribute(ownerOnly)).use { channel ->
            val buffer = ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) channel.write(buffer)
            channel.force(true)
        }
    }
    /** Only for a genuinely fresh, empty v3-owned state directory. Never reinitialize on reinstall. */
    fun initializeFresh() {
        guardRoot()
        require(!Files.exists(state, NOFOLLOW_LINKS) && !Files.exists(lockFile, NOFOLLOW_LINKS) &&
            !Files.exists(previous, NOFOLLOW_LINKS)) { "Existing RSS state or incomplete initialization; never reset" }
        newFile(lockFile, "rss-state-lock-v1\n".toByteArray())
        newFile(state, encoded(RssStoreDocument()))
        fsyncDirectory()
    }
    fun read(): RssStoreDocument {
        guardRoot()
        guardFile(lockFile)
        return load()
    }
    private fun <T> transaction(block: (RssStoreDocument) -> Pair<RssStoreDocument, T>): T {
        guardRoot()
        guardFile(lockFile)
        FileChannel.open(lockFile, StandardOpenOption.READ, StandardOpenOption.WRITE, NOFOLLOW_LINKS).use { channel ->
            channel.lock().use {
                val before = load()
                val (after, result) = block(before)
                if (after != before) {
                    val bytes = encoded(after)
                    val previousBytes = Files.readAllBytes(state)
                    atomicWrite(previous, previousBytes)
                    atomicWrite(state, bytes)
                }
                return result
            }
        }
    }
    private fun atomicWrite(destination: Path, bytes: ByteArray) {
        require(!Files.isSymbolicLink(destination)) { "Linked RSS state target" }
        val temp = root.resolve(".rss-${UUID.randomUUID()}.tmp")
        try {
            newFile(temp, bytes)
            Files.move(temp, destination, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            fsyncDirectory()
        } finally { Files.deleteIfExists(temp) }
    }

    /** Persist the first-poll baseline and drafts BEFORE any transport may act on them. */
    fun checkpoint(feed: ReviewedFeed, items: List<FeedItem>, gate: PollGate, nowMillis: Long): List<PendingRssPost> {
        require(feed in RssPacks.load()) { "Unpinned feed" }
        return checkpointWithReview(feed, items, gate, nowMillis, RssPacks.reviewedForPublication())
    }
    internal fun checkpointWithReview(feed: ReviewedFeed, items: List<FeedItem>, gate: PollGate,
                                      nowMillis: Long, reviewed: Boolean): List<PendingRssPost> {
        require(nowMillis >= 0)
        return transaction { current ->
            // Staging/reinstall must not silently acknowledge an outbox item, especially an uncertain send.
            // An attempted send freezes this feed's checkpoint in every mode until explicit reconciliation.
            val held = current.pending.filter { it.draft.feedId == feed.feed.id }
            if (held.any { it.attemptedAtMillis != null } || gate == PollGate.STAGING && held.isNotEmpty())
                return@transaction current to emptyList()
            val result = RssPublisher.pollWithReview(current.publisher, feed, items, gate, reviewed)
            if (gate == PollGate.RESTORING) return@transaction current to emptyList()
            val queued = current.pending.toMutableList()
            if (gate == PollGate.ACTIVE && reviewed) result.drafts.forEach { draft ->
                if (queued.none { it.draft.feedId == draft.feedId && it.draft.itemId == draft.itemId }) {
                    queued += PendingRssPost(draft, nowMillis)
                }
            }
            require(queued.size <= 256) { "RSS outbox full; explicit reconciliation required" }
            val uncertain = queued.any { it.draft.feedId == feed.feed.id && it.attemptedAtMillis != null }
            val eligible = if (gate == PollGate.ACTIVE && reviewed && !uncertain) queued.filter {
                it.attemptedAtMillis == null && it.draft.feedId == feed.feed.id && nowMillis >= it.createdAtMillis &&
                    nowMillis - it.createdAtMillis < 3_600_000
            } else emptyList()
            current.copy(publisher = result.state, pending = queued) to eligible
        }
    }
    /** Fsync a single-send claim BEFORE HTTP. Crash/timeout after this requires reconciliation, not a blind retry. */
    fun claim(post: PendingRssPost, nowMillis: Long): Boolean {
        require(nowMillis >= 0)
        return transaction { current ->
            val match = current.pending.singleOrNull { it == post && it.attemptedAtMillis == null }
            if (match == null || nowMillis < match.createdAtMillis || nowMillis - match.createdAtMillis >= 3_600_000 ||
                current.pending.any { it.draft.feedId == post.draft.feedId && it.attemptedAtMillis != null })
                return@transaction current to false
            current.copy(pending = current.pending.map {
                if (it == match) it.copy(attemptedAtMillis = nowMillis) else it
            }) to true
        }
    }

    /** Read-only remote resolution under the state lock. Absence is NOT permission to resend an uncertain post. */
    internal fun reconcileConfirmed(expectedChecksum: String, feedId: String, itemId: String,
        observe: (PendingRssPost) -> RssReconciledDelivery?): RssReconciledDelivery? = transaction { current ->
        require(expectedChecksum.matches(Regex("[a-f0-9]{64}")) && current.checksum == expectedChecksum) { "RSS state changed before reconciliation" }
        val pending = current.pending.single { it.draft.feedId == feedId && it.draft.itemId == itemId }
        require(pending.attemptedAtMillis != null) { "Only an attempted uncertain send can be reconciled" }
        require(current.reconciled.size < 256) { "Reconciliation evidence bound reached; retain history" }
        val proof = observe(pending) ?: return@transaction current to null
        require(proof.feedId == feedId && proof.itemId == itemId && proof.idempotencyKey == pending.draft.idempotencyKey &&
            proof.account == pending.draft.account && proof.remoteStatusId.matches(Regex("[0-9]{1,32}")) &&
            proof.responseSha256.matches(Regex("[a-f0-9]{64}")) && proof.observedAtMillis >= pending.attemptedAtMillis &&
            current.reconciled.none { it.account == proof.account && it.remoteStatusId == proof.remoteStatusId }) { "Foreign or reused RSS delivery proof" }
        val next = RssPublisher.acknowledge(PollResult(current.publisher, listOf(pending.draft)), setOf(itemId))
        current.copy(publisher = next, pending = current.pending - pending, reconciled = current.reconciled + proof) to proof
    }

    /** Confirm only a matching remote status after the server reports success. Unknown sends use reconcileConfirmed. */
    fun confirm(feedId: String, itemId: String, idempotencyKey: String, remoteStatusId: String) {
        require(remoteStatusId.matches(Regex("[0-9]{1,32}"))) { "Missing remote status confirmation" }
        transaction { current ->
            val pending = current.pending.singleOrNull {
                it.draft.feedId == feedId && it.draft.itemId == itemId && it.draft.idempotencyKey == idempotencyKey
            } ?: throw IllegalArgumentException("Unrecognized pending post")
            require(pending.attemptedAtMillis != null) { "Unclaimed RSS post cannot be confirmed" }
            val next = RssPublisher.acknowledge(PollResult(current.publisher, listOf(pending.draft)), setOf(itemId))
            current.copy(publisher = next, pending = current.pending - pending) to Unit
        }
    }
}
