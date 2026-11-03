package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import kotlin.test.*

class RssScheduleTest {
    private val hex = "a".repeat(64)
    private fun directory(parent: Path? = null, name: String = "rss-schedule-unit"): Path = if (parent == null)
        Files.createTempDirectory(name, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        else Files.createDirectory(parent.resolve(name), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
    private fun save(path: Path, value: String) = ReleasePrivateFiles.save(path, value.toByteArray())
    private fun fixture(block: (Path, RssScheduleBinding) -> Unit) {
        val root = directory()
        try {
            val state = directory(root, "state"); RssStateStore(state).initializeFresh()
            val tokens = directory(root, "tokens")
            RssPacks.load().forEach { save(tokens.resolve("${it.feed.account}.token"), "synthetic-unit-token-not-a-secret") }
            block(root, RssScheduleBinding(deployment = ReleaseDeploymentBinding("q-123456789abc", hex, hex, hex),
                transactionJournal = root.resolve("journal").toString(), stateDirectory = state.toString(),
                tokenDirectory = tokens.toString(), mastodonOrigin = "https://social.datamancy.net", controllerSha256 = hex,
                artifactClosure = ActivationInput(root.resolve("closure").toString(), hex), userId = UnixSystem().uid.toInt()))
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `enrollment never resets state and disabled suspended ticks perform no HTTP`() = fixture { parent, binding ->
        val state = RssStateStore(Path.of(binding.stateDirectory)); val before = state.read()
        var checks = 0
        val schedule = RssSchedule({ _, committed -> checks++; assertFalse(committed) }, {},
            RssHttp { _, _, _, _ -> error("disabled worker cannot use HTTP") })
        val root = parent.resolve("schedule"); val hash = schedule.enroll(root, binding)
        assertEquals(before, state.read()); assertNull(schedule.tick(root, hash)); assertEquals(0, checks)
        assertEquals(17, schedule.quiesce(root, hash, "cap-unit") {
            assertFailsWith<java.nio.channels.OverlappingFileLockException> { schedule.tick(root, hash) }
            17
        })
        assertEquals(before, state.read())
        assertFails { schedule.enroll(root, binding) }; assertEquals(before, state.read())
        val units = schedule.units(root, hash)
        assertEquals(2, units.size)
        assertTrue(units.values.any { "rss schedule-tick $root $hash" in it && "User=${binding.userId}" in it })
        assertTrue(units.values.any { "OnUnitInactiveSec=900s" in it })
        schedule.release(root, hash); assertEquals(1, checks)
        // Current manifest still prevents publication even if a synthetic unit authority allows it.
        assertFails { schedule.tick(root, hash) }
        schedule.pause(root, hash); schedule.pause(root, hash)
        assertNull(schedule.tick(root, hash)); assertFails { schedule.release(root, hash) }
        assertEquals(before, state.read())
        assertFails { schedule.units(root, "b".repeat(64)) }
    }
    @Test fun `maintenance interruption survives lock release and blocks publication activation and new IDs`() = fixture { parent, binding ->
        var authorities = 0
        val schedule = RssSchedule({ _, _ -> authorities++ }, {}, RssHttp { _, _, _, _ -> error("no network") })
        val root = parent.resolve("schedule"); val hash = schedule.enroll(root, binding)
        schedule.release(root, hash)
        try {
            assertFailsWith<InterruptedException> { schedule.quiesce(root, hash, "cap-interrupted") {
                throw InterruptedException("unit controller interruption")
            } }
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
        val priorChecks = authorities
        assertFails { schedule.tick(root, hash) }
        assertFails { schedule.release(root, hash) }
        assertFails { schedule.quiesce(root, hash, "cap-new-id") { error("must not execute") } }
        assertFails { schedule.quiesce(root, hash, "cap-interrupted") { error("must not replay") } }
        assertEquals(priorChecks, authorities)
        assertTrue(Files.exists(root.resolve("maintenance-cap-interrupted.intent")))
        assertFalse(Files.exists(root.resolve("maintenance-cap-interrupted.complete")))
        schedule.pause(root, hash)
        assertNull(schedule.tick(root, hash)) // Permanent retirement stays safe, never clears the hold.
        assertTrue(Files.exists(root.resolve("maintenance-cap-interrupted.intent")))
    }
    @Test fun `successful maintenance checks live source before completion and cannot replay`() = fixture { parent, binding ->
        var live = true; var observed = 0
        val schedule = RssSchedule({ _, committed -> if (committed) { observed++; require(live) } }, {},
            RssHttp { _, _, _, _ -> error("no network") })
        val root = parent.resolve("schedule"); val hash = schedule.enroll(root, binding)
        schedule.release(root, hash)
        assertEquals(42, schedule.quiesce(root, hash, "cap-first") { 42 })
        assertEquals(1, observed)
        assertFails { schedule.quiesce(root, hash, "cap-first") { error("no replay") } }
        assertTrue(Files.readAllBytes(root.resolve("maintenance-cap-first.intent"))
            .contentEquals(Files.readAllBytes(root.resolve("maintenance-cap-first.complete"))))
        live = false
        assertFails { schedule.quiesce(root, hash, "cap-second") { Unit } }
        assertFalse(Files.exists(root.resolve("maintenance-cap-second.complete")))
        live = true
        assertFails { schedule.tick(root, hash) } // A later healthy observation does not erase uncertainty.
    }
    @Test fun `maintenance records reject foreign orphan linked and malformed state`() {
        for (mode in listOf("foreign", "orphan", "link", "unknown", "changed-binding", "changed-enabled", "retired")) fixture { parent, binding ->
            val schedule = RssSchedule({ _, _ -> }, {}, RssHttp { _, _, _, _ -> error("no network") })
            val root = parent.resolve("schedule"); val hash = schedule.enroll(root, binding)
            if (mode in setOf("changed-binding", "changed-enabled", "retired")) {
                if (mode == "retired") schedule.release(root, hash)
                assertFails { schedule.quiesce(root, hash, "cap-change") {
                    when (mode) {
                        "changed-binding" -> Files.writeString(root.resolve("binding.json"), "{}")
                        "changed-enabled" -> save(root.resolve("enabled"), hash)
                        else -> save(root.resolve("suspended"), hash)
                    }
                } }
                assertFalse(Files.exists(root.resolve("maintenance-cap-change.complete")))
            } else {
                schedule.quiesce(root, hash, "cap-good") { Unit }
                when (mode) {
                    "foreign" -> Files.writeString(root.resolve("maintenance-cap-good.complete"), "foreign")
                    "orphan" -> Files.delete(root.resolve("maintenance-cap-good.intent"))
                    "link" -> {
                        Files.delete(root.resolve("maintenance-cap-good.complete"))
                        Files.createSymbolicLink(root.resolve("maintenance-cap-good.complete"), root.resolve("maintenance-cap-good.intent"))
                    }
                    else -> save(root.resolve("maintenance-unrecognized"), "not a recognized record")
                }
                assertFails { schedule.release(root, hash) }
                assertFails { schedule.quiesce(root, hash, "cap-new") { error("must not execute") } }
            }
        }
        fixture { parent, binding ->
            val schedule = RssSchedule({ _, _ -> }, {}, RssHttp { _, _, _, _ -> error("no network") })
            val root = parent.resolve("schedule"); val hash = schedule.enroll(root, binding)
            assertFails { schedule.quiesce(root, hash, "../foreign") { error("no effect") } }
        }
    }

    @Test fun `installed tick preserves first poll silence deduplication failed Washington Post and uncertainty`() = fixture { parent, binding ->
        val feed = RssPacks.load().first()
        val washington = RssPacks.load().single { it.feed.id == "washpost-politics" }
        var article = "old"; var posts = 0; var failSend = false
        var committed = true; var authorityCalls = 0
        val http = RssHttp { method, uri, _, _ ->
            when {
                method == "POST" -> {
                    posts++; if (failSend) throw IllegalStateException("synthetic lost acknowledgement")
                    RssHttpReply(201, """{"id":"${100 + posts}","account":{"id":"17"}}""".toByteArray())
                }
                uri.path == "/api/v1/accounts/verify_credentials" -> RssHttpReply(200,
                    """{"id":"17","acct":"${feed.feed.account}","bot":true}""".toByteArray())
                uri.path == "/api/v1/statuses/777" -> RssHttpReply(200,
                    """{"id":"777","account":{"id":"17"},"visibility":"public","created_at":"1970-01-01T00:00:01Z"}""".toByteArray())
                uri.path == "/api/v1/statuses/777/source" -> RssHttpReply(200, buildJsonObject {
                    put("id", "777"); put("text", "Synthetic — ${feed.feed.source.trim()}\nhttps://example.org/uncertain"); put("spoiler_text", "")
                }.toString().toByteArray())
                uri == URI(washington.feed.url) -> throw IllegalStateException("synthetic unresolved feed")
                else -> RssHttpReply(200, (if (uri == URI(feed.feed.url))
                    "<rss><channel><item><guid>$article</guid><title>Synthetic</title><link>https://example.org/$article</link></item></channel></rss>"
                    else "<rss><channel/></rss>").toByteArray())
            }
        }
        val schedule = RssSchedule({ _, requireCommitted -> authorityCalls++; require(!requireCommitted || committed) }, {}, http, { 1000 }, { true })
        val root = parent.resolve("schedule"); val hash = schedule.enroll(root, binding); schedule.release(root, hash)
        assertEquals(0, assertNotNull(schedule.tick(root, hash)).confirmed); assertEquals(0, posts)
        article = "later"
        val result = assertNotNull(schedule.tick(root, hash))
        assertEquals(1, result.confirmed); assertEquals(listOf(washington.feed.id), result.failedFeeds)
        assertEquals(0, assertNotNull(schedule.tick(root, hash)).confirmed); assertEquals(1, posts)
        article = "uncertain"; failSend = true
        assertFails { schedule.tick(root, hash) }; assertEquals(2, posts)
        val store = RssStateStore(Path.of(binding.stateDirectory)); val before = store.read()
        assertNotNull(before.pending.single().attemptedAtMillis)
        assertFalse(before.publisher.checkpoints.any { it.feedId == washington.feed.id })
        schedule.tick(root, hash); assertEquals(2, posts); assertEquals(before, store.read())
        assertNotNull(schedule.reconcile(root, hash, before.checksum, feed.feed.id, article, "777"))
        val reconciled = store.read(); assertTrue(reconciled.pending.isEmpty()); assertEquals(2, posts)
        assertTrue(article in reconciled.publisher.checkpoints.single { it.feedId == feed.feed.id }.seen)
        committed = false
        assertFails { schedule.tick(root, hash) }; assertEquals(reconciled, store.read())
        assertTrue(authorityCalls > 47)
        schedule.pause(root, hash)
        assertFails { schedule.reconcile(root, hash, reconciled.checksum, feed.feed.id, article, "123") }
    }
    @Test fun `registered command namespace enrolls renders and suspends without ambient publication`() = fixture { parent, binding ->
        val schedule = RssSchedule({ _, _ -> error("not activated") }, {}, RssHttp { _, _, _, _ -> error("no HTTP") })
        val output = mutableListOf<String>()
        fun command(vararg args: String) = RssScheduleCommands.run(arrayOf(*args), output::add, { schedule })
        val root = parent.resolve("schedule")
        val input = parent.resolve("binding-input.json"); save(input, Json.encodeToString(binding))
        assertFalse(command("other", "command")); assertFalse(command("rss"))
        assertTrue(command("rss", "schedule-enroll", root.toString(), input.toString()))
        val hash = output.last()
        assertTrue(command("rss", "schedule-units", root.toString(), hash))
        assertTrue(output.last().contains("OnUnitInactiveSec"))
        assertTrue(command("rss", "schedule-tick", root.toString(), hash)); assertEquals("disabled", output.last())
        assertTrue(command("rss", "schedule-pause", root.toString(), hash)); assertEquals("suspended", output.last())
        assertFails { command("rss", "schedule-pause") }
        assertFails { command("rss", "reconcile", root.toString(), hash, hex, "feed", "item", "123") }
    }

    @Test fun `invalid descriptors unsafe markers and changed enrollment fail closed`() = fixture { parent, binding ->
        for (bad in listOf(binding.copy(intervalSeconds = 1), binding.copy(userId = 0),
            binding.copy(stateDirectory = "/tmp/../state"), binding.copy(mastodonOrigin = "https://user@social.datamancy.net"),
            binding.copy(controllerSha256 = "bad"), binding.copy(tokenDirectory = binding.stateDirectory))) {
            assertFails { RssSchedule.validate(bad) }
        }
        val schedule = RssSchedule({ _, _ -> error("authority denied") }, {}, RssHttp { _, _, _, _ -> error("no HTTP") })
        val root = parent.resolve("schedule"); val hash = schedule.enroll(root, binding)
        assertFails { schedule.release(root, hash) }; assertFalse(Files.exists(root.resolve("enabled")))
        save(root.resolve("suspended"), "foreign")
        assertFails { schedule.tick(root, hash) }; assertFails { schedule.pause(root, hash) }
        Files.writeString(root.resolve("binding.json"), "{}")
        assertFails { schedule.units(root, hash) }
    }
    @Test fun `consumed activation must match exact journal candidate controller and live origin`() = fixture { root, initial ->
        val consumptionRoot = directory(root, "consumptions")
        val closure = ActivationArtifactClosure(controllers = mapOf("platform" to hex, "acceptance" to hex),
            images = mapOf("unit" to ActivationImagePin("example.org/unit@sha256:$hex", hex)), assets = emptyMap())
        val closureBytes = Json.encodeToString(closure).toByteArray()
        ReleasePrivateFiles.save(Path.of(initial.artifactClosure.path), closureBytes)
        val binding = initial.copy(artifactClosure = initial.artifactClosure.copy(sha256 = ReleaseLocks.sha256(closureBytes)))
        val journal = Path.of(binding.transactionJournal)
        TransactionJournal.append(journal, "unit-rss", hex, Phase.PREPARED, null, null, binding.deployment)
        for (phase in listOf(Phase.FROZEN, Phase.SNAPSHOT_VERIFIED, Phase.STAGED, Phase.CUTOVER_RESTRICTED, Phase.ACCEPTED))
            TransactionJournal.appendExisting(journal, phase, if (phase == Phase.FROZEN) null else "cap-123456789abc")
        val accepted = TransactionJournal.verify(journal).last()
        val candidate = buildJsonObject {
            put("implementationSha256", hex); put("artifactsSha256", binding.artifactClosure.sha256)
            put("configurationSha256", hex); put("acceptanceSha256", hex); put("sitePolicySha256", hex)
        }
        val permit = buildJsonObject {
            put("schemaVersion", 1); put("qualificationHead", hex); put("candidate", candidate)
            put("binding", buildJsonObject {
                put("transactionId", accepted.transactionId); put("lockDigest", hex); put("acceptedJournalHead", accepted.hash)
                put("deployment", Json.encodeToJsonElement(binding.deployment))
            })
        }
        val permitHash = ReleaseLocks.sha256(permit.toString().toByteArray())
        val claim = TransactionJournal.appendExisting(journal, Phase.ACTIVATION_STARTED, accepted.snapshotId, accepted.hash, permitHash)
        val claimText = Files.readString(journal)
        val consumption = buildJsonObject {
            put("schemaVersion", 1); put("generation", binding.deployment.generationId); put("permitSha256", permitHash)
            put("activationJournalHead", claim.hash); put("qualificationHead", hex)
            put("claimJournalSha256", ReleaseLocks.sha256(claimText.toByteArray()))
        }
        save(consumptionRoot.resolve("${binding.deployment.generationId}.consumed.json"), buildJsonObject {
            put("permit", permit); put("consumption", consumption); put("claimJournal", claimText)
        }.toString())
        var live = true; var observed = 0
        val authority = RssActivationAuthority(consumptionRoot) { deployment, actualCandidate, images ->
            observed++; require(live); assertEquals(binding.deployment, deployment); assertEquals(candidate, actualCandidate)
            assertEquals(setOf("example.org/unit@sha256:$hex" to hex), images)
            listOf(CaddyUpstream("social.datamancy.net", "unit:3000"))
        }
        authority.verify(binding, false); assertEquals(1, observed)
        assertFails { authority.verify(binding, true) }
        TransactionJournal.appendExisting(journal, Phase.COMMITTED, accepted.snapshotId, claim.hash)
        authority.verify(binding, true)
        assertFails { authority.verify(binding, false) }
        assertFails { authority.verify(binding.copy(mastodonOrigin = "https://other.datamancy.net"), true) }
        live = false; assertFails { authority.verify(binding, true) }; live = true
        Files.writeString(Path.of(binding.artifactClosure.path), "{}")
        assertFails { authority.verify(binding, true) }
    }
}
