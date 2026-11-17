package net.datamancy.platform

import java.net.URI
import com.sun.security.auth.module.UnixSystem
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

@Serializable internal data class RssPackFixture(val schemaVersion: Int = 1, val pack: String,
    val items: Map<String, List<FeedItem>>)
@Serializable internal data class RssPackFeedObservation(val feed: FeedDefinition, val items: List<FeedItem>, val previews: List<DraftPost>)
@Serializable internal data class RssPackObservation(val schemaVersion: Int = 1, val pack: String,
    val fixtureSha256: String, val checkpointSha256: String, val feeds: List<RssPackFeedObservation>, val pending: Int)

/** Native read-only pack qualification, using separate original fixtures, never the installed publication state.
 * Preview uses the actual attributed draft engine but has no sender, token or publication effect attached.
 */
internal class RssPackObserver(private val fetch: (ReviewedFeed) -> List<FeedItem>) {
    fun observe(pack: String, stateRoot: Path, fixturePath: Path, restoring: Boolean): RssPackObservation {
        val feeds = RssPacks.load().filter { it.pack == pack }
        require(feeds.isNotEmpty()) { "Unknown pinned RSS pack" }
        val store = RssStateStore(stateRoot)
        val before = store.read()
        val fixture: RssPackFixture
        val bytes: ByteArray
        if (restoring) {
            bytes = ReleasePrivateFiles.read(fixturePath, 1048576)
            fixture = Json.decodeFromString<RssPackFixture>(bytes.decodeToString())
        } else {
            require(before.publisher.checkpoints.isEmpty() && before.pending.isEmpty() && before.reconciled.isEmpty()) {
                "Native first-poll observation requires fresh dedicated fixture state; never reset installed state"
            }
            // Fetch the entire pack before writing anything. An unresolved publisher cannot advance its checkpoint.
            fixture = RssPackFixture(pack = pack, items = feeds.associate { it.feed.id to fetch(it) })
            require(fixture.items.values.all { it.isNotEmpty() }) { "Empty feed cannot prove native attribution" }
            bytes = Json.encodeToString(fixture).toByteArray()
            require(bytes.size <= 1048576) { "Original RSS fixture exceeds authenticated recovery payload bound" }
            ReleasePrivateFiles.save(fixturePath, bytes) // Preserve original native items for restore; never refetch then relabel.
            feeds.forEach { feed -> store.checkpoint(feed, fixture.items.getValue(feed.feed.id), PollGate.STAGING, 0) }
        }
        require(fixture.schemaVersion == 1 && fixture.pack == pack && fixture.items.keys == feeds.map { it.feed.id }.toSet())
        val after = store.read()
        require(after.pending.isEmpty() && after.reconciled.isEmpty() &&
            after.publisher.checkpoints.associate { it.feedId to it.seen } == fixture.items.mapValues { it.value.map { item -> item.id }.toSet() }) {
            "First-poll checkpoint differs from original feed fixture"
        }
        if (restoring) require(before == after) { "Restore observation changed original checkpoint" }
        val observations = feeds.map { feed ->
            val items = fixture.items.getValue(feed.feed.id)
            require(items.isNotEmpty())
            val preview = RssPublisher.pollWithReview(PublisherState(checkpoints = listOf(FeedCheckpoint(feed.feed.id, emptySet()))),
                feed, items, PollGate.ACTIVE, true).drafts
            RssPackFeedObservation(feed.feed, items, preview)
        }
        return RssPackObservation(pack = pack, fixtureSha256 = ReleaseLocks.sha256(bytes),
            checkpointSha256 = ReleaseLocks.sha256(ReleasePrivateFiles.read(stateRoot.resolve("rss-state.json"))),
            feeds = observations, pending = after.pending.size)
    }
}

@Serializable internal data class RssSyntheticObservation(val schemaVersion: Int = 1, val pack: String,
    val feedId: String, val account: String, val firstCheckpointSha256: String,
    val finalCheckpointSha256: String, val firstPollPosts: Int, val attemptedPosts: Int,
    val replayPosts: Int, val reconciledStatusId: String, val restoredFetches: Int = 0)

/** Local protocol exerciser: synthetic accounts, 47 synthetic feed responses, one POST whose
 * acknowledgement is lost, one read-only remote reconciliation. No real token, hostname or
 * reviewed-feed endpoint can be sent here. Runs only in a dedicated qualification directory. */
internal object RssSyntheticQualification {
    private val json = Json { ignoreUnknownKeys = false }
    fun observe(pack: String, root: Path, restoring: Boolean): RssSyntheticObservation {
        require(pack in RssPacks.load().map { it.pack }.toSet())
        ReleasePrivateFiles.directory(root)
        val stateRoot = root.resolve("synthetic-state")
        val observation = root.resolve("synthetic-observation.json")
        if (restoring) {
            require(Files.exists(stateRoot, NOFOLLOW_LINKS))
            val bytes = ReleasePrivateFiles.read(observation)
            val original = json.decodeFromString<RssSyntheticObservation>(bytes.decodeToString(throwOnInvalidSequence = true))
            val state = RssStateStore(stateRoot).read()
            val selected = RssPacks.load().first { it.pack == pack }
            require(original.schemaVersion == 1 && original.pack == pack &&
                original.feedId == selected.feed.id && original.account == selected.feed.account &&
                state.publisher.checkpoints.size == RssPacks.load().size &&
                state.reconciled.singleOrNull()?.let { it.feedId == original.feedId && it.account == original.account &&
                    it.itemId == "synthetic-new" && it.idempotencyKey ==
                    ReleaseLocks.sha256("${original.account}\u0000synthetic-new".toByteArray()) } == true &&
                original.firstPollPosts == 0 &&
                original.attemptedPosts == 1 && original.replayPosts == 0 && original.reconciledStatusId == "777" &&
                state.pending.isEmpty() && state.reconciled.singleOrNull()?.remoteStatusId == "777" &&
                state.publisher.checkpoints.any { it.feedId == original.feedId && "synthetic-new" in it.seen } &&
                ReleaseLocks.sha256(ReleasePrivateFiles.read(stateRoot.resolve("rss-state.json"))) == original.finalCheckpointSha256) {
                "Recovered original synthetic POST/lost-ack/reconciliation oracle differs"
            }
            return original
        }
        require(!Files.exists(stateRoot, NOFOLLOW_LINKS) && !Files.exists(observation, NOFOLLOW_LINKS)) {
            "Synthetic RSS oracle can be produced once, never reset"
        }
        Files.createDirectory(stateRoot, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.sync(root)
        val state = RssStateStore(stateRoot).also { it.initializeFresh() }
        val feeds = RssPacks.load()
        require(feeds.size == 47 && feeds.map { it.feed.account }.toSet().size == 47) {
            "Synthetic journey requires all 47 unchanged pinned identities"
        }
        val selected = feeds.first { it.pack == pack }
        val baseline = FeedItem("synthetic-baseline", "Original synthetic baseline", "https://fixture.invalid/original")
        val fresh = FeedItem("synthetic-new", "New synthetic item", "https://fixture.invalid/new")
        var newItem = false
        var posts = 0
        var stored: DraftPost? = null
        val http = RssHttp { method, uri, headers, body ->
            require(uri.host == "synthetic.invalid" && uri.scheme == "https" &&
                headers["Authorization"] == "Bearer synthetic-qualified-bearer-123456")
            when {
                method == "GET" && uri.path == "/api/v1/accounts/verify_credentials" ->
                    RssHttpReply(200, """{"id":"17","acct":"${selected.feed.account}","bot":true}""".toByteArray())
                method == "POST" && uri.path == "/api/v1/statuses" -> {
                    val draft = requireNotNull(stored)
                    require(headers["Idempotency-Key"] == draft.idempotencyKey &&
                        body.contains("visibility=public") && body.contains("status="))
                    posts++
                    throw IllegalStateException("synthetic lost acknowledgement after remote POST")
                }
                method == "GET" && uri.path == "/api/v1/statuses/777" && posts == 1 ->
                    RssHttpReply(200, """{"id":"777","account":{"id":"17"},"visibility":"public","created_at":"1970-01-01T00:16:40Z"}""".toByteArray())
                method == "GET" && uri.path == "/api/v1/statuses/777/source" && posts == 1 ->
                    RssHttpReply(200, buildJsonObject { put("id", "777"); put("text", requireNotNull(stored).text)
                        put("spoiler_text", "") }.toString().toByteArray())
                else -> error("Synthetic RSS endpoint not allowed")
            }
        }
        val sender = MastodonRssSender(URI("https://synthetic.invalid"),
            { account -> require(account == selected.feed.account); "synthetic-qualified-bearer-123456" }, http)
        val worker = RssWorker(state, { feed ->
            listOf(baseline) + if (newItem && feed == selected) listOf(fresh) else emptyList()
        }, { draft -> stored = draft; sender.sendReviewed(draft) }, { 1_000_000L })
        val first = worker.pollReviewed(PollGate.STAGING, true)
        require(first.feeds == feeds.size && first.confirmed == 0 && posts == 0 && first.failedFeeds.isEmpty())
        val firstHash = ReleaseLocks.sha256(ReleasePrivateFiles.read(stateRoot.resolve("rss-state.json")))
        newItem = true
        try { worker.pollReviewed(PollGate.ACTIVE, true) } catch (error: IllegalStateException) {
            require(error.message == "synthetic lost acknowledgement after remote POST")
        }
        require(posts == 1 && state.read().pending.singleOrNull()?.attemptedAtMillis == 1_000_000L)
        // Claimed attempt blocks a second POST even after an apparent restart.
        worker.pollReviewed(PollGate.ACTIVE, true)
        require(posts == 1 && state.read().pending.size == 1)
        val pending = state.read().pending.single()
        val proof = sender.reconcile(state, state.read().checksum, pending.draft.feedId,
            pending.draft.itemId, "777", 1_000_000L, PollGate.ACTIVE)
        require(proof?.remoteStatusId == "777" && posts == 1 && state.read().pending.isEmpty())
        require(state.read().publisher.checkpoints.single { it.feedId == selected.feed.id }.seen.contains("synthetic-new"))
        val beforeRestore = ReleasePrivateFiles.read(stateRoot.resolve("rss-state.json"))
        require(RssWorker(state, { error("Restore must not fetch") }, { error("Restore must not POST") })
            .poll(PollGate.RESTORING).feeds == 0 &&
            ReleasePrivateFiles.read(stateRoot.resolve("rss-state.json")).contentEquals(beforeRestore))
        val result = RssSyntheticObservation(pack = pack, feedId = selected.feed.id, account = selected.feed.account,
            firstCheckpointSha256 = firstHash, finalCheckpointSha256 = ReleaseLocks.sha256(beforeRestore),
            firstPollPosts = 0, attemptedPosts = posts, replayPosts = 0, reconciledStatusId = "777")
        ReleasePrivateFiles.save(observation, Json.encodeToString(result).toByteArray())
        return result
    }
}

/** Feed-only loopback HTTPS + actual SINGLE canonical Mastodon product; the synthetic
 * rssq_<hex> bot and credentials are disjoint from all forty-seven real RSS principals. */
@Serializable internal data class RssNativeFixtureBinding(val schemaVersion: Int = 1, val generation: String,
    val bundleSha256: String, val pack: String, val origin: String, val baselineUrl: String,
    val newItemUrl: String, val tokenFile: String, val caFile: String, val caSha256: String,
    val syntheticAccount: String, val mastodonOrigin: String, val mastodonCaFile: String,
    val mastodonCaSha256: String, val controllerSha256: String, val userId: Int,
    val intervalSeconds: Int = 900, val mastodonScopedAddress: String? = null,
    val mastodonLeafSha256: String? = null)
@Serializable internal data class RssNativeFixtureRemoteEvidence(val schemaVersion: Int = 1,
    val accountId: String, val baselineStatuses: Int, val observedStatuses: Int,
    val statusId: String, val receiptSha256: String)
@Serializable internal data class RssNativeFixtureState(val schemaVersion: Int = 1,
    val generation: String, val pack: String, val feedId: String, val account: String,
    val accountId: String, val baselineStatuses: Int, val baselineItemId: String,
    val baselineFeedSha256: String)
@Serializable internal data class RssNativeFixtureAttempt(val schemaVersion: Int = 1,
    val itemId: String, val idempotencyKey: String, val text: String, val attemptedAtMillis: Long)
@Serializable internal data class RssNativeFixtureAccepted(val schemaVersion: Int = 1,
    val statusId: String, val accountId: String, val itemId: String, val responseSha256: String)
@Serializable internal data class RssNativeFixtureResult(val schemaVersion: Int = 1, val generation: String,
    val pack: String, val feedId: String, val account: String, val phase: String,
    val stateSha256: String, val remoteStatusId: String? = null, val responseSha256: String? = null)

internal object RssNativeFixtureTimer {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private val mode = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
    private fun identity(root: Path, binding: RssNativeFixtureBinding,
        originalIngress: Boolean = true): ReviewedFeed {
        require(root.isAbsolute && root.normalize() == root && root.parent.fileName.toString() == "rss-qualification" &&
            root.parent.parent.fileName.toString() == binding.generation &&
            binding.generation.matches(Regex("q-[a-f0-9]{12}")) &&
            binding.bundleSha256.matches(Regex("[a-f0-9]{64}")) &&
            binding.controllerSha256.matches(Regex("[a-f0-9]{64}")) && binding.userId.toLong() == UnixSystem().uid &&
            binding.intervalSeconds in 300..86400 && binding.caSha256.matches(Regex("[a-f0-9]{64}")) &&
            binding.mastodonCaSha256.matches(Regex("[a-f0-9]{64}")) &&
            binding.syntheticAccount.matches(Regex("rssq_[a-f0-9]{12}")) &&
            binding.syntheticAccount !in RssPacks.load().map { it.feed.account }.toSet())
        val origin = URI(binding.origin)
        require(origin.scheme == "https" && origin.host == "127.0.0.1" && origin.port in 49152..65535 &&
            origin.path in setOf("", "/") && origin.userInfo == null)
        for (value in listOf(binding.baselineUrl, binding.newItemUrl)) {
            val feed = URI(value)
            require(feed.scheme == "https" && feed.host == origin.host && feed.port == origin.port &&
                feed.path in setOf("/feed/baseline", "/feed/new") && feed.userInfo == null &&
                feed.rawQuery == null && feed.rawFragment == null)
        }
        require(URI(binding.baselineUrl).path == "/feed/baseline" &&
            URI(binding.newItemUrl).path == "/feed/new" &&
            Path.of(binding.tokenFile) == root.parent.parent.resolve("rss/qualification-custody/${root.fileName}/bot.token") &&
            Path.of(binding.caFile) == root.resolve("fixture-ca.pem") &&
            binding.mastodonOrigin == "https://social.datamancy.net" &&
            Path.of(binding.mastodonCaFile) == root.resolve("mastodon-ca.pem")) {
            "Actual canonical bot credential and feed trust must be separately scoped to this original fixture"
        }
        val generationRoot = root.parent.parent
        val bundleBytes=ReleasePrivateFiles.read(generationRoot.resolve("bundle.json"))
        require(ReleaseLocks.sha256(bundleBytes) == binding.bundleSha256) {
            "Fixture generation bundle changed"
        }
        val bundle=json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString(throwOnInvalidSequence=true))
        require(bundle.request.id==binding.generation &&
            bundle.members.single().spec.fragmentBinding?.recipe==CanonicalSharedYamlGraph.RECIPE &&
            bundle.members.single().spec.fragmentBinding?.controllerSha256==binding.controllerSha256 &&
            binding.mastodonLeafSha256?.matches(Regex("[a-f0-9]{64}"))==true &&
            binding.mastodonScopedAddress?.let { address ->
                val octets=address.split('.').map { it.toIntOrNull() }
                octets.size==4 && octets.all { it != null && it in 0..255 } &&
                    java.net.InetAddress.getByAddress(octets.map { requireNotNull(it).toByte() }.toByteArray())
                        .let { it.hostAddress==address && it.isSiteLocalAddress }
            } == true)
        if (originalIngress) {
            val issuer=CanonicalCaddyServedLeafReadback(generationRoot,bundle,binding.bundleSha256,
                PackagedGraphFragment.pendingV3R9().first)
            val receipt=issuer.verify("social.datamancy.net")
            val served=json.decodeFromString<CaddyServedLeafReadback>(ReleasePrivateFiles.read(Path.of(receipt.path),8192)
                .decodeToString(throwOnInvalidSequence=true))
            require(served.servedLeafDerSha256==binding.mastodonLeafSha256 &&
                served.caSha256==binding.mastodonCaSha256 &&
                issuer.verifiedPrivateEndpoint("social.datamancy.net")==
                    "https://${binding.mastodonScopedAddress}:443") {
                "Synthetic Mastodon endpoint must be the current native private Caddy CID/SNI/leaf"
            }
        }
        return RssPacks.load().first { it.pack == binding.pack }
    }
    private fun timerRoot(fixture: Path) = fixture.parent.parent.resolve("rss/fixture-timers/${fixture.fileName}")
    private fun binding(fixture: Path, digest: String): RssNativeFixtureBinding {
        val timer = timerRoot(fixture)
        val bytes = ReleasePrivateFiles.read(timer.resolve("binding.json"))
        require(digest.matches(Regex("[a-f0-9]{64}")) && ReleaseLocks.sha256(bytes) == digest &&
            ReleasePrivateFiles.read(timer.resolve("enrolled")).decodeToString() == digest) {
            "Missing or changed native fixture timer enrollment"
        }
        val result = json.decodeFromString<RssNativeFixtureBinding>(bytes.decodeToString(throwOnInvalidSequence = true))
        identity(fixture, result)
        PinnedBackupController.verify(result.controllerSha256)
        return result
    }
    private fun syntheticIdentity(http: RssHttp, binding: RssNativeFixtureBinding,
        tokenPath: Path): Pair<String, Int> {
        val token = MastodonRssSender.privateToken(tokenPath)
        val reply = http.request("GET", URI(binding.mastodonOrigin).resolve("/api/v1/accounts/verify_credentials"),
            mapOf("Authorization" to "Bearer $token", "Accept" to "application/json"), "")
        require(reply.status == 200) { "Actual synthetic Mastodon bot identity is not available" }
        val account = Json.parseToJsonElement(reply.body.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val id = account.getValue("id").jsonPrimitive.content
        val statusCount = account.getValue("statuses_count").jsonPrimitive.content.toInt()
        require(id.matches(Regex("[0-9]{1,32}")) && statusCount in 0..100000000 &&
            account.getValue("acct").jsonPrimitive.content == binding.syntheticAccount &&
            account.getValue("bot").jsonPrimitive.content == "true" &&
            account.getValue("followers_count").jsonPrimitive.content == "0" &&
            account.getValue("following_count").jsonPrimitive.content == "0") {
            "Foreign, followed or non-bot synthetic account cannot receive qualified RSS posts"
        }
        return id to statusCount
    }
    fun enroll(fixture: Path, input: Path): String {
        ReleasePrivateFiles.directory(fixture)
        val bytes = ReleasePrivateFiles.read(input, 1048576)
        val original = json.decodeFromString<RssNativeFixtureBinding>(bytes.decodeToString(throwOnInvalidSequence = true))
        val selected = identity(fixture, original)
        PinnedBackupController.verify(original.controllerSha256)
        require(selected.feed.account.isNotBlank() && !Files.exists(fixture.resolve("native-fixture-state.json"), NOFOLLOW_LINKS))
        // Source bot is an ACTUAL canonical Mastodon account, never the feed fixture server.
        val http = PinnedRssMastodonHttp(URI(original.mastodonOrigin), Path.of(original.mastodonCaFile),
            original.mastodonCaSha256, original.mastodonScopedAddress, original.mastodonLeafSha256)
        syntheticIdentity(http, original, Path.of(original.tokenFile))
        val root = timerRoot(fixture)
        if (!Files.exists(root.parent, NOFOLLOW_LINKS)) Files.createDirectory(root.parent, mode)
        ReleasePrivateFiles.directory(root.parent)
        Files.createDirectory(root, mode); ReleasePrivateFiles.sync(root.parent)
        val bound = json.encodeToString(original).toByteArray()
        val digest = ReleaseLocks.sha256(bound)
        ReleasePrivateFiles.save(root.resolve("binding.json"), bound)
        ReleasePrivateFiles.save(root.resolve("enrolled"), digest.toByteArray())
        return digest
    }
    fun units(fixture: Path, digest: String): Map<String, String> {
        val bound = binding(fixture, digest)
        val name = "p0v3-rss-fixture-${bound.generation}-${fixture.fileName}"
        val binary = "/mnt/media/p0-v3/runtime-supervision/releases/${bound.controllerSha256}/bin/p0-v3-platform"
        val invocation = System.getenv("P0V3_CASE_INVOCATION_ID")
        val claim = System.getenv("P0V3_RSS_QUALIFICATION_SHA256")
        val phaseClaim = System.getenv("P0V3_RSS_PHASE_CLAIM_SHA256")
        require((invocation == null) == (claim == null) && (claim == null) == (phaseClaim == null) &&
            (invocation == null || invocation.matches(Regex("case-[a-f0-9-]{36}")) &&
                claim!!.matches(Regex("[a-f0-9]{64}")) && phaseClaim!!.matches(Regex("[a-f0-9]{64}")))) {
            "Foreign native fixture timer qualification claim"
        }
        val qualificationEnvironment = if (invocation == null) "" else
            "Environment=P0V3_CASE_INVOCATION_ID=$invocation\nEnvironment=P0V3_RSS_QUALIFICATION_SHA256=$claim\nEnvironment=P0V3_RSS_PHASE_CLAIM_SHA256=$phaseClaim\n"
        return linkedMapOf("$name.service" to """
            [Unit]
            Description=Scoped native RSS fixture timer ${bound.generation}
            [Service]
            Type=oneshot
            User=${bound.userId}
            UMask=0077
            ExecStart=$binary rss fixture-tick $fixture $digest
            TimeoutStartSec=180
            Restart=no
        """.trimIndent().replace("ExecStart=$binary", qualificationEnvironment + "ExecStart=$binary") + "\n", "$name.timer" to """
            [Unit]
            Description=Scoped native RSS fixture timer ${bound.generation}
            [Timer]
            OnUnitInactiveSec=${bound.intervalSeconds}s
            Unit=$name.service
            [Install]
            WantedBy=timers.target
        """.trimIndent() + "\n")
    }
    private fun hash(path: Path) = ReleaseLocks.sha256(ReleasePrivateFiles.read(path))
    private fun fetched(uri: URI, http: RssHttp): List<FeedItem> {
        val response = http.request("GET", uri, mapOf("Accept" to "application/rss+xml"), "")
        require(response.status == 200 && response.body.size in 1..2097152) { "Native fixture feed failed" }
        return RssXml.parse(response.body, uri).also { require(it.size in 1..200) }
    }
    fun tick(fixture: Path, digest: String): RssNativeFixtureResult = ReleasePrivateFiles.locked(timerRoot(fixture)) {
        val bound = binding(fixture, digest)
        val feed = identity(fixture, bound)
        val baseline = fixture.resolve("native-fixture-state.json")
        val pending = fixture.resolve("native-pending.json")
        val acceptedPath = fixture.resolve("native-accepted.json")
        val receipt = fixture.resolve("native-receipt.json")
        if (Files.exists(receipt, NOFOLLOW_LINKS)) {
            require(Files.exists(pending, NOFOLLOW_LINKS) && Files.exists(acceptedPath, NOFOLLOW_LINKS) &&
                Files.exists(fixture.resolve("native-remote-evidence.json"), NOFOLLOW_LINKS)) {
                "Incomplete original canonical bot reconciliation; no replay"
            }
            return@locked RssNativeFixtureResult(generation = bound.generation, pack = bound.pack,
                feedId = feed.feed.id, account = bound.syntheticAccount, phase = "COMPLETED_NO_REPLAY",
                stateSha256 = hash(pending))
        }
        if (Files.exists(pending, NOFOLLOW_LINKS)) {
            // Uncertain send remains blocked EVEN if the network failed before yielding 201.
            val original = json.decodeFromString<RssNativeFixtureAttempt>(ReleasePrivateFiles.read(pending)
                .decodeToString(throwOnInvalidSequence = true))
            require(original.schemaVersion == 1 && original.itemId == "synthetic-new")
            return@locked RssNativeFixtureResult(generation = bound.generation, pack = bound.pack,
                feedId = feed.feed.id, account = bound.syntheticAccount, phase = "HELD_NO_REPLAY",
                stateSha256 = hash(pending))
        }
        val http = PinnedRssFixtureHttp(URI(bound.origin), Path.of(bound.caFile), bound.caSha256)
        val mastodon = PinnedRssMastodonHttp(URI(bound.mastodonOrigin), Path.of(bound.mastodonCaFile),
            bound.mastodonCaSha256, bound.mastodonScopedAddress, bound.mastodonLeafSha256)
        if (!Files.exists(baseline, NOFOLLOW_LINKS)) {
            val items = fetched(URI(bound.baselineUrl), http)
            require(items.size == 1 && items.single().id == "synthetic-baseline" &&
                !Files.exists(acceptedPath, NOFOLLOW_LINKS)) { "First real HTTPS feed poll must be silent" }
            val (accountId, statusCount) = syntheticIdentity(mastodon, bound, Path.of(bound.tokenFile))
            val state = RssNativeFixtureState(generation = bound.generation, pack = bound.pack,
                feedId = feed.feed.id, account = bound.syntheticAccount, accountId = accountId,
                baselineStatuses = statusCount, baselineItemId = items.single().id,
                baselineFeedSha256 = ReleaseLocks.sha256(items.single().toString().toByteArray()))
            ReleasePrivateFiles.save(baseline, json.encodeToString(state).toByteArray())
            return@locked RssNativeFixtureResult(generation = bound.generation, pack = bound.pack,
                feedId = feed.feed.id, account = bound.syntheticAccount, phase = "FIRST_POLL_SILENT",
                stateSha256 = hash(baseline))
        }
        val state = json.decodeFromString<RssNativeFixtureState>(ReleasePrivateFiles.read(baseline)
            .decodeToString(throwOnInvalidSequence = true))
        require(state.schemaVersion == 1 && state.generation == bound.generation && state.pack == bound.pack &&
            state.feedId == feed.feed.id && state.account == bound.syntheticAccount &&
            state.baselineItemId == "synthetic-baseline" && state.baselineFeedSha256.matches(Regex("[a-f0-9]{64}")) &&
            !Files.exists(acceptedPath, NOFOLLOW_LINKS)) { "Original silent baseline changed" }
        require(syntheticIdentity(mastodon, bound, Path.of(bound.tokenFile)) ==
            (state.accountId to state.baselineStatuses)) {
            "Synthetic bot gained an unrelated status before its one qualified POST"
        }
        val items = fetched(URI(bound.newItemUrl), http)
        require(items.size == 2 && items.map { it.id }.toSet() == setOf("synthetic-baseline", "synthetic-new") &&
            ReleaseLocks.sha256(items.single { it.id == "synthetic-baseline" }.toString().toByteArray()) ==
                state.baselineFeedSha256) { "Native feed changed old source item or added a second new item" }
        val item = items.single { it.id == "synthetic-new" }
        val text = "${item.title.trim()} — ${feed.feed.source.trim()}\n${item.link}"
        require(text.codePointCount(0, text.length) in 1..500 && '@' !in text &&
            item.link == "https://fixture.invalid/new") { "Synthetic direct status must have no mentions or recipients" }
        val attempt = RssNativeFixtureAttempt(itemId = item.id,
            idempotencyKey = ReleaseLocks.sha256("${bound.syntheticAccount}\u0000${item.id}".toByteArray()),
            text = text, attemptedAtMillis = System.currentTimeMillis())
        ReleasePrivateFiles.save(pending, json.encodeToString(attempt).toByteArray()) // Fsync BEFORE real HTTP POST.
        val token = MastodonRssSender.privateToken(Path.of(bound.tokenFile))
        val body = buildJsonObject { put("status", text); put("visibility", "direct") }.toString()
        val response = mastodon.request("POST", URI(bound.mastodonOrigin).resolve("/api/v1/statuses"),
            mapOf("Authorization" to "Bearer $token", "Accept" to "application/json",
                "Content-Type" to "application/json", "Idempotency-Key" to attempt.idempotencyKey), body)
        require(response.status == 201) { "Actual canonical Mastodon POST is uncertain; retained intent forbids retry" }
        val posted = Json.parseToJsonElement(response.body.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val statusId = posted.getValue("id").jsonPrimitive.content
        require(statusId.matches(Regex("[0-9]{1,32}")) &&
            posted.getValue("account").jsonObject.getValue("id").jsonPrimitive.content == state.accountId &&
            posted.getValue("visibility").jsonPrimitive.content == "direct") { "Actual 201 belongs to wrong account or visibility" }
        val accepted = RssNativeFixtureAccepted(statusId = statusId, accountId = state.accountId,
            itemId = attempt.itemId, responseSha256 = ReleaseLocks.sha256(response.body))
        ReleasePrivateFiles.save(acceptedPath, json.encodeToString(accepted).toByteArray())
        try { throw RssNativeLostAcknowledgement() } catch (_: RssNativeLostAcknowledgement) {
            require(Files.exists(pending, NOFOLLOW_LINKS) && Files.exists(acceptedPath, NOFOLLOW_LINKS))
            return@locked RssNativeFixtureResult(generation = bound.generation, pack = bound.pack,
                feedId = feed.feed.id, account = bound.syntheticAccount, phase = "REAL_POST_ACK_LOST",
                stateSha256 = hash(pending), remoteStatusId = statusId, responseSha256 = hash(acceptedPath))
        }
    }
    private class RssNativeLostAcknowledgement : IllegalStateException("Canonical Mastodon accepted one direct status; client acknowledgement intentionally lost")
    private fun remoteProof(binding: RssNativeFixtureBinding, state: RssNativeFixtureState,
        attempt: RssNativeFixtureAttempt, accepted: RssNativeFixtureAccepted, tokenPath: Path,
        restoredHttp: RssHttp? = null): Pair<Int, String> {
        val http = restoredHttp ?: PinnedRssMastodonHttp(URI(binding.mastodonOrigin), Path.of(binding.mastodonCaFile),
            binding.mastodonCaSha256,binding.mastodonScopedAddress,binding.mastodonLeafSha256)
        val (accountId, statusCount) = syntheticIdentity(http, binding, tokenPath)
        require(accountId == state.accountId && statusCount == state.baselineStatuses + 1 &&
            accepted.accountId == accountId && accepted.itemId == attempt.itemId &&
            attempt.itemId == "synthetic-new" && attempt.text.isNotBlank() &&
            attempt.idempotencyKey == ReleaseLocks.sha256("${binding.syntheticAccount}\u0000${attempt.itemId}".toByteArray()) &&
            accepted.statusId.matches(Regex("[0-9]{1,32}"))) { "Canonical original synthetic account/status count changed; never resend" }
        val token = MastodonRssSender.privateToken(tokenPath)
        val headers = mapOf("Authorization" to "Bearer $token", "Accept" to "application/json")
        val status = http.request("GET", URI(binding.mastodonOrigin).resolve("/api/v1/statuses/${accepted.statusId}"),
            headers, "")
        require(status.status == 200) { "Original canonical Mastodon status ID not readable" }
        val observed = Json.parseToJsonElement(status.body.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val created = java.time.Instant.parse(observed.getValue("created_at").jsonPrimitive.content).toEpochMilli()
        require(observed.getValue("id").jsonPrimitive.content == accepted.statusId &&
            observed.getValue("account").jsonObject.getValue("id").jsonPrimitive.content == state.accountId &&
            observed.getValue("visibility").jsonPrimitive.content == "direct" &&
            observed["reblog"] in listOf(null, kotlinx.serialization.json.JsonNull) &&
            observed["in_reply_to_id"] in listOf(null, kotlinx.serialization.json.JsonNull) &&
            observed["mentions"]?.jsonArray?.isEmpty() != false &&
            created in maxOf(0, attempt.attemptedAtMillis - 120000)..attempt.attemptedAtMillis + 120000) {
            "Foreign or public/recipient-bearing synthetic status cannot reconcile"
        }
        val source = http.request("GET", URI(binding.mastodonOrigin).resolve(
            "/api/v1/statuses/${accepted.statusId}/source"), headers, "")
        require(source.status == 200)
        val author = Json.parseToJsonElement(source.body.decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(author.getValue("id").jsonPrimitive.content == accepted.statusId &&
            author.getValue("text").jsonPrimitive.content == attempt.text &&
            author.getValue("spoiler_text").jsonPrimitive.content.isEmpty()) {
            "Actual author-owned source differs from original pending direct draft"
        }
        val stable = "${accepted.statusId}\u0000${state.accountId}\u0000${created}\u0000${attempt.text}\u0000direct"
        return statusCount to ReleaseLocks.sha256(stable.toByteArray())
    }
    fun reconcile(fixture: Path, digest: String): RssNativeFixtureResult = ReleasePrivateFiles.locked(timerRoot(fixture)) {
        val bound = binding(fixture, digest)
        val feed = identity(fixture, bound)
        val state = json.decodeFromString<RssNativeFixtureState>(ReleasePrivateFiles.read(
            fixture.resolve("native-fixture-state.json")).decodeToString(throwOnInvalidSequence = true))
        val attempt = json.decodeFromString<RssNativeFixtureAttempt>(ReleasePrivateFiles.read(
            fixture.resolve("native-pending.json")).decodeToString(throwOnInvalidSequence = true))
        val accepted = json.decodeFromString<RssNativeFixtureAccepted>(ReleasePrivateFiles.read(
            fixture.resolve("native-accepted.json")).decodeToString(throwOnInvalidSequence = true))
        require(state.generation == bound.generation && state.pack == bound.pack && state.feedId == feed.feed.id &&
            state.account == bound.syntheticAccount && !Files.exists(fixture.resolve("native-receipt.json"), NOFOLLOW_LINKS)) {
            "Reconciliation must bind a single unreplayed actual canonical status"
        }
        val (_, statusSourceSha) = remoteProof(bound, state, attempt, accepted, Path.of(bound.tokenFile))
        val result = RssNativeFixtureResult(generation = bound.generation, pack = bound.pack,
            feedId = feed.feed.id, account = bound.syntheticAccount, phase = "REMOTE_RECONCILED",
            stateSha256 = hash(fixture.resolve("native-pending.json")), remoteStatusId = accepted.statusId,
            responseSha256 = statusSourceSha)
        ReleasePrivateFiles.save(fixture.resolve("native-receipt.json"), json.encodeToString(result).toByteArray())
        result
    }
    fun evidence(fixture: Path, digest: String): RssNativeFixtureRemoteEvidence = ReleasePrivateFiles.locked(timerRoot(fixture)) {
        val bound = binding(fixture, digest)
        val receipt = ReleasePrivateFiles.read(fixture.resolve("native-receipt.json"))
        val completed = json.decodeFromString<RssNativeFixtureResult>(receipt.decodeToString(throwOnInvalidSequence = true))
        require(completed.phase == "REMOTE_RECONCILED" && completed.account == bound.syntheticAccount)
        val state = json.decodeFromString<RssNativeFixtureState>(ReleasePrivateFiles.read(
            fixture.resolve("native-fixture-state.json")).decodeToString(throwOnInvalidSequence = true))
        val attempt = json.decodeFromString<RssNativeFixtureAttempt>(ReleasePrivateFiles.read(
            fixture.resolve("native-pending.json")).decodeToString(throwOnInvalidSequence = true))
        val accepted = json.decodeFromString<RssNativeFixtureAccepted>(ReleasePrivateFiles.read(
            fixture.resolve("native-accepted.json")).decodeToString(throwOnInvalidSequence = true))
        val (count, remoteSha) = remoteProof(bound, state, attempt, accepted, Path.of(bound.tokenFile))
        require(completed.responseSha256 == remoteSha && completed.remoteStatusId == accepted.statusId)
        val result = RssNativeFixtureRemoteEvidence(accountId = state.accountId,
            baselineStatuses = state.baselineStatuses, observedStatuses = count,
            statusId = accepted.statusId, receiptSha256 = ReleaseLocks.sha256(receipt))
        require(result.observedStatuses == result.baselineStatuses + 1 &&
            result.statusId == completed.remoteStatusId) { "Actual canonical account did not gain exactly one direct status" }
        ReleasePrivateFiles.save(fixture.resolve("native-remote-evidence.json"), json.encodeToString(result).toByteArray())
        result
    }
    fun restored(fixture: Path, original: RssNativeFixtureResult, bridgeFile: Path,
        bridgeSha256: String): RssNativeFixtureResult {
        ReleasePrivateFiles.directory(fixture)
        val generation = fixture.parent.parent
        val bridgeBytes = ReleasePrivateFiles.read(bridgeFile, 1048576)
        require(ReleaseLocks.sha256(bridgeBytes) == bridgeSha256)
        val bridge = json.decodeFromString<RestoredBridgeIntent>(bridgeBytes.decodeToString(throwOnInvalidSequence = true)).binding
        require(original.phase == "REMOTE_RECONCILED" && !Files.exists(timerRoot(fixture), NOFOLLOW_LINKS) &&
            bridge.sourceGeneration == original.generation && bridge.targetGeneration == generation.fileName.toString() &&
            bridge.sourceGeneration != bridge.targetGeneration &&
            "social.datamancy.net" in bridge.originalHosts &&
            "rss-mastodon" in bridge.nativeClientCapabilities && bridge.clientAddress.isNotBlank() &&
            bridge.clientNetwork.isNotBlank()) { "Target lacks the audited original-host native RSS bridge"
        }
        val captured = json.decodeFromString<RssNativeFixtureBinding>(ReleasePrivateFiles.read(
            fixture.resolve("native-fixture-binding.json")).decodeToString(throwOnInvalidSequence = true))
        val token = generation.resolve("rss/qualification-custody/${fixture.fileName}/bot.token")
        val bound = captured.copy(generation = generation.fileName.toString(),
            bundleSha256 = hash(generation.resolve("bundle.json")), tokenFile = token.toString(),
            caFile = fixture.resolve("fixture-ca.pem").toString(),
            mastodonCaFile = fixture.resolve("mastodon-ca.pem").toString())
        // Cold RESTORE authenticates the captured original binding and uses the
        // distinct target-native original-host bridge; the source Caddy is STOPPED.
        identity(fixture, bound, originalIngress=false)
        require(captured.generation == original.generation && original.account == captured.syntheticAccount &&
            captured.bundleSha256.matches(Regex("[a-f0-9]{64}"))) {
            "Captured original RSS fixture identity differs from the restored canonical bot"
        }
        val bytes = ReleasePrivateFiles.read(fixture.resolve("native-receipt.json"))
        val receipt = json.decodeFromString<RssNativeFixtureResult>(bytes.decodeToString(throwOnInvalidSequence = true))
        val remote = json.decodeFromString<RssNativeFixtureRemoteEvidence>(ReleasePrivateFiles.read(
            fixture.resolve("native-remote-evidence.json")).decodeToString(throwOnInvalidSequence = true))
        val state = json.decodeFromString<RssNativeFixtureState>(ReleasePrivateFiles.read(
            fixture.resolve("native-fixture-state.json")).decodeToString(throwOnInvalidSequence = true))
        val attempt = json.decodeFromString<RssNativeFixtureAttempt>(ReleasePrivateFiles.read(
            fixture.resolve("native-pending.json")).decodeToString(throwOnInvalidSequence = true))
        val accepted = json.decodeFromString<RssNativeFixtureAccepted>(ReleasePrivateFiles.read(
            fixture.resolve("native-accepted.json")).decodeToString(throwOnInvalidSequence = true))
        require(receipt == original && remote.schemaVersion == 1 &&
            remote.accountId == state.accountId && remote.baselineStatuses == state.baselineStatuses &&
            remote.observedStatuses == remote.baselineStatuses + 1 && remote.statusId == receipt.remoteStatusId &&
            remote.receiptSha256 == ReleaseLocks.sha256(bytes) &&
            receipt.stateSha256 == hash(fixture.resolve("native-pending.json")) &&
            attempt.itemId == accepted.itemId && state.accountId == accepted.accountId) {
            "Original fsynced synthetic claim, 201 status or remote receipt changed during cold import"
        }
        val native = RssRestoredMastodonHttp(generation, bridgeFile, bridgeSha256,
            Path.of(bound.mastodonCaFile), bound.mastodonCaSha256, token, bound.syntheticAccount)
        val (count, originalSourceSha) = remoteProof(bound, state, attempt, accepted, token, native)
        require(count == remote.observedStatuses && originalSourceSha == receipt.responseSha256) {
            "Native restored canonical status/author source differs from the original oracle"
        }
        return receipt
    }
}
