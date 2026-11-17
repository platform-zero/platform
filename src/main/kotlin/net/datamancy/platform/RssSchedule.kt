package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.net.URI
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** A release-owned authority, never inferred from PollGate or the presence of bot credentials. */
internal fun interface RssPublicationAuthority { fun verify() }

@Serializable internal data class RssScheduleBinding(val schemaVersion: Int = 1,
    val deployment: ReleaseDeploymentBinding, val transactionJournal: String, val stateDirectory: String,
    val tokenDirectory: String, val mastodonOrigin: String, val controllerSha256: String,
    val artifactClosure: ActivationInput, val userId: Int, val intervalSeconds: Int = 900)

/** Installed worker control. The outbox remains in its original state directory across enrollments/restores.
 * All effects share a lock with pause: once pause returns, this schedule cannot send again.
 */
internal class RssSchedule(private val authority: (RssScheduleBinding, Boolean) -> Unit,
    private val controller: (String) -> Unit, private val http: RssHttp,
    private val clock: () -> Long = System::currentTimeMillis,
    private val reviewed: () -> Boolean = RssPacks::reviewedForPublication,
    private val enrollment: RssEnrollmentAuthority? = null,
    private val operationScope: GenerationRssOperations? = null) {
    companion object {
        private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
        private val hex = Regex("[a-f0-9]{64}")
        private val safePath = Regex("/[A-Za-z0-9_./-]+")
        private val heldSchedule = ThreadLocal.withInitial { mutableSetOf<Path>() }
        internal fun holdsSchedule(root: Path): Boolean = root in heldSchedule.get()
        fun real(generationBase: Path = GenerationRuntime.BASE) =
            RssSchedule(RssActivationAuthority()::verify, PinnedBackupController::verify, JdkRssHttp(),
                enrollment = GenerationRssEnrollmentAuthority(generationBase),
                operationScope = GenerationRssOperations(generationBase))
        fun decode(bytes: ByteArray): RssScheduleBinding = json.decodeFromString(bytes.decodeToString(throwOnInvalidSequence = true))
        fun validate(binding: RssScheduleBinding) {
            binding.deployment.validate()
            require(binding.schemaVersion == 1 && hex.matches(binding.controllerSha256) &&
                hex.matches(binding.artifactClosure.sha256) && binding.userId in 1..65534 && binding.intervalSeconds in 300..86400)
            listOf(binding.transactionJournal, binding.stateDirectory, binding.tokenDirectory, binding.artifactClosure.path).forEach {
                val path = Path.of(it)
                require(safePath.matches(it) && path.isAbsolute && path.normalize() == path) { "Canonical private RSS path required" }
            }
            require(binding.stateDirectory != binding.tokenDirectory)
            val uri = URI(binding.mastodonOrigin)
            require(uri.scheme == "https" && uri.host != null && uri.userInfo == null && uri.port == -1 &&
                uri.path in setOf("", "/") && uri.rawQuery == null && uri.rawFragment == null) { "Exact HTTPS publication origin required" }
        }
    }
    fun enroll(root: Path, binding: RssScheduleBinding): String =
        operationScope?.withExclusion { enrollUnscoped(root, binding) } ?: enrollUnscoped(root, binding)
    private fun enrollUnscoped(root: Path, binding: RssScheduleBinding): String {
        validate(binding); require(binding.userId.toLong() == UnixSystem().uid)
        ReleasePrivateFiles.directory(root.parent)
        require(safePath.matches(root.toString()) && root.isAbsolute && root.normalize() == root)
        controller(binding.controllerSha256)
        enrollment?.preflight(root, binding)
        // Enrollment is intentionally permitted before activation but cannot initialize or rewrite checkpoints.
        RssStateStore(Path.of(binding.stateDirectory)).read()
        ReleasePrivateFiles.directory(Path.of(binding.tokenDirectory))
        Files.createDirectory(root, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.sync(root.parent)
        return ReleasePrivateFiles.locked(root) {
            val bytes = json.encodeToString(binding).toByteArray()
            val hash = ReleaseLocks.sha256(bytes)
            enrollment?.claim(root, binding, hash)
            ReleasePrivateFiles.save(root.resolve("binding.json"), bytes)
            ReleasePrivateFiles.save(root.resolve("enrolled"), hash.toByteArray())
            enrollment?.complete(root, binding, hash)
            hash
        }
    }
    private fun binding(root: Path, expected: String): RssScheduleBinding {
        require(hex.matches(expected) && safePath.matches(root.toString()))
        ReleasePrivateFiles.directory(root)
        val bytes = ReleasePrivateFiles.read(root.resolve("binding.json"))
        require(ReleaseLocks.sha256(bytes) == expected && ReleasePrivateFiles.read(root.resolve("enrolled")).decodeToString() == expected) {
            "Changed or incomplete RSS enrollment"
        }
        return decode(bytes).also {
            validate(it); require(it.userId.toLong() == UnixSystem().uid)
            enrollment?.verify(root, it, expected)
        }
    }
    private fun marker(root: Path, name: String, expected: String): Boolean {
        val path = root.resolve(name)
        if (!Files.exists(path, NOFOLLOW_LINKS)) return false
        require(ReleasePrivateFiles.read(path).decodeToString() == expected) { "Foreign RSS schedule marker" }
        return true
    }
    private fun mark(root: Path, name: String, expected: String) {
        if (!marker(root, name, expected)) ReleasePrivateFiles.save(root.resolve(name), expected.toByteArray())
    }
    private fun <T> locked(root: Path, expected: String, action: (RssScheduleBinding) -> T): T = try {
        val body = { ReleasePrivateFiles.locked(root) {
            require(heldSchedule.get().add(root)) { "Nested RSS scheduler lock forbidden" }
            try {
                val binding = binding(root, expected)
                RssQualificationIntents.requireClear(Path.of(binding.stateDirectory).parent.parent.parent)
                controller(binding.controllerSha256); action(binding)
            } finally { heldSchedule.get().remove(root) }
        } }
        operationScope?.withExclusion(body) ?: body()
    } catch (interrupted: InterruptedException) {
        Thread.currentThread().interrupt(); throw interrupted
    }
    /** Controller-only operation: the body must throw unless its durable operation results and source
     * resume/isolation checks succeeded. Hold this across the WHOLE operation, not just capture.
     * Returning normally is not publication authority: previously enabled schedules additionally
     * revalidate the live committed generation before completion. No callback/finally clears failure.
     * Incomplete claims survive process death and block ticks even after the OS lock is released.
     */
    fun <T> quiesce(root: Path, expected: String, operationId: String, operation: () -> T): T {
        require(enrollment == null) { "Release-bound RSS maintenance requires typed durable completion proof" }
        return quiesceInternal(root, expected, operationId, null, operation)
    }
    fun <T> quiesceProven(root: Path, expected: String, operationId: String,
        proof: RssDurableOperationProof, operation: () -> T): T =
        quiesceInternal(root, expected, operationId, proof, operation)
    private fun <T> quiesceInternal(root: Path, expected: String, operationId: String,
        proof: RssDurableOperationProof?, operation: () -> T): T = locked(root, expected) { binding ->
        if (enrollment != null) (proof as? RssKopiaOperationProof)?.bind(binding, operationId, false)
            ?: error("Release-bound RSS backup requires exact native durable proof")
        proof?.verifyBefore()
        val wasEnabled = marker(root, "enabled", expected)
        RssMaintenance.claim(root, expected, operationId)
        val result = operation()
        proof?.verifyAfter()
        require(this.binding(root, expected) == binding && marker(root, "enabled", expected) == wasEnabled) {
            "RSS enrollment or enabled state changed during maintenance"
        }
        if (wasEnabled) {
            require(!marker(root, "suspended", expected)) { "Retired schedule cannot resume from maintenance" }
            authority(binding, true)
        }
        RssMaintenance.complete(root, expected, operationId)
        result
    }
    /** A held restore spans multiple controller entrypoints. Its durable intent blocks every tick
     * between calls; finishing it requires the SAME claim plus native isolation/resume proof.
     * There is no operation retry or recovery shortcut for an uncertain claim. */
    fun beginHeld(root: Path, expected: String, operationId: String,
        proof: RssDurableOperationProof): RssHeldOperation = locked(root, expected) { binding ->
        if (enrollment != null) when (proof) {
            is RssKopiaOperationProof -> proof.bind(binding, operationId, true)
            is RssOwnedUpdateOperationProof -> proof.bind(binding, operationId, true)
            else -> error("Release-bound RSS hold requires exact native restore or update proof")
        }
        proof.verifyBefore()
        RssMaintenance.claim(root, expected, operationId)
        RssHeldOperation(root.toString(), expected, operationId, RssMaintenance.pending(root, expected, operationId),
            binding.deployment.generationId, binding.deployment.bundleSha256)
    }
    fun completeHeld(claim: RssHeldOperation, proof: RssDurableOperationProof) = locked(Path.of(claim.root), claim.bindingSha256) { binding ->
        require(binding.deployment.generationId == claim.generation &&
            binding.deployment.bundleSha256 == claim.bundleSha256 &&
            RssMaintenance.pending(Path.of(claim.root), claim.bindingSha256, claim.operationId) == claim.intentSha256) {
            "Held RSS operation no longer matches its exact source"
        }
        if (enrollment != null) when (proof) {
            is RssKopiaOperationProof -> proof.bind(binding, claim.operationId, true)
            is RssOwnedUpdateOperationProof -> proof.bind(binding, claim.operationId, true)
            is RssEarlyUpdateRollbackProof -> proof.bind(binding, claim.operationId, true)
            else -> error("Release-bound RSS completion requires exact native restore, update, or no-target rollback proof")
        }
        proof.verifyAfter() // MUST read durable results, target isolation and source resume before completion.
        require(!marker(Path.of(claim.root), "suspended", claim.bindingSha256)) { "Retired source cannot reopen" }
        if (marker(Path.of(claim.root), "enabled", claim.bindingSha256)) authority(binding, true)
        RssMaintenance.complete(Path.of(claim.root), claim.bindingSha256, claim.operationId)
    }
    fun requireWritable(root: Path, expected: String) = locked(root, expected) {
        RssMaintenance.requireClear(root, expected)
        require(!marker(root, "suspended", expected)) { "Retired RSS generation cannot be a writer" }
    }
    fun pause(root: Path, expected: String) = locked(root, expected) { binding ->
        if (enrollment != null) {
            // This is ONLY a stop-only candidate safety fence after activation started or
            // RECOVERY_REQUIRED. A PREPARED update source has no candidate deployment in its
            // journal and must use reversible beginHeld, never permanent preacceptance pause.
            RssMaintenance.requireClear(root, expected)
            val records = TransactionJournal.verify(Path.of(binding.transactionJournal))
            val last = records.last()
            require(last.phase in setOf(Phase.ACTIVATION_STARTED, Phase.RECOVERY_REQUIRED) &&
                last.deployment == binding.deployment && last.transactionId == records.first().transactionId &&
                (last.update == null || last.update.sourceGeneration != binding.deployment.generationId &&
                    last.update.targetGeneration == binding.deployment.generationId)) {
                "Only exact native activation candidate may be stopped after public/outbound uncertainty"
            }
        }
        mark(root, "suspended", expected)
    }
    /** A02 calls this ONLY after COMMITTED site CAS and candidate native adoption. No source
     * resume is claimed on success: retired original stays inert, whereas rollback completes
     * the same held claim only after actual target isolation and original source restart. */
    fun commitRetirement(root: Path, expected: String, operationId: String,
        proof: RssOwnedUpdateOperationProof) = locked(root, expected) { binding ->
        require(enrollment != null)
        proof.bind(binding, operationId, true)
        RssMaintenance.pending(root, expected, operationId)
        proof.verifyCommittedRetirement()
        mark(root, "suspended", expected)
        RssMaintenance.complete(root, expected, operationId)
    }
    fun release(root: Path, expected: String) = locked(root, expected) { binding ->
        RssMaintenance.requireClear(root, expected)
        require(!marker(root, "suspended", expected)) { "Suspended RSS schedule cannot reopen; fresh qualified release required" }
        authority(binding, false) // ACTIVATION_STARTED plus durable consumption; not yet permission for ticks.
        mark(root, "enabled", expected)
    }
    private fun active(root: Path, expected: String, binding: RssScheduleBinding) {
        RssMaintenance.requireClear(root, expected)
        require(!marker(root, "suspended", expected) && marker(root, "enabled", expected)) { "RSS schedule is not enabled" }
        authority(binding, true) // COMMITTED selection OR signed still-current original ordinal-zero head.
    }
    fun tick(root: Path, expected: String): RssPollSummary? = locked(root, expected) { binding ->
        if (marker(root, "suspended", expected)) return@locked null
        RssMaintenance.requireClear(root, expected)
        if (!marker(root, "enabled", expected)) return@locked null
        val permit = RssPublicationAuthority { active(root, expected, binding) }
        permit.verify()
        require(reviewed()) { "RSS publication review pending" }
        val sender = sender(binding)
        val worker = RssWorker(RssStateStore(Path.of(binding.stateDirectory)), RssFetcher(http)::fetch,
            { draft -> sender.sendReviewed(draft, permit::verify) }, clock)
        // No catch-up loop: one current fetch per feed. Outbox claims survive every failure/restart.
        worker.pollReviewed(PollGate.ACTIVE, true, permit::verify)
    }
    fun reconcile(root: Path, expected: String, checksum: String, feedId: String, itemId: String,
        statusId: String): RssReconciledDelivery? = locked(root, expected) { binding ->
        active(root, expected, binding)
        // Read-only reconciliation does not require fresh editorial approval, but does require live release ownership.
        sender(binding).reconcile(RssStateStore(Path.of(binding.stateDirectory)), checksum, feedId, itemId,
            statusId, clock(), PollGate.ACTIVE)
    }
    private fun sender(binding: RssScheduleBinding) = MastodonRssSender(URI(binding.mastodonOrigin), { account ->
        MastodonRssSender.privateToken(Path.of(binding.tokenDirectory).resolve("$account.token"))
    }, http)
    fun units(root: Path, expected: String): Map<String, String> {
        val binding = binding(root, expected)
        controller(binding.controllerSha256)
        val name = "p0v3-rss-${binding.deployment.generationId}"
        val executable = "/mnt/media/p0-v3/runtime-supervision/releases/${binding.controllerSha256}/bin/p0-v3-platform"
        return linkedMapOf("$name.service" to """
            [Unit]
            Description=Release-bound RSS polling ${binding.deployment.generationId}
            After=network-online.target
            Wants=network-online.target
            [Service]
            Type=oneshot
            User=${binding.userId}
            UMask=0077
            ExecStart=$executable rss schedule-tick $root $expected
            Environment=JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
            Environment="JAVA_OPTS=-Xms32m -Xmx256m"
            TimeoutStartSec=3600
            KillMode=control-group
            # Live generation observation uses the existing scoped rootful runtime controller.
            # Do not enable NoNewPrivileges/readonly runtime locks: that would break its sudo admission.
            Restart=no
            StandardOutput=journal
            StandardError=journal
            [Install]
            WantedBy=multi-user.target
        """.trimIndent() + "\n", "$name.timer" to """
            [Unit]
            Description=Release-bound RSS polling timer ${binding.deployment.generationId}
            [Timer]
            OnActiveSec=${binding.intervalSeconds}s
            OnUnitActiveSec=${binding.intervalSeconds}s
            AccuracySec=30s
            RandomizedDelaySec=30s
            Unit=$name.service
            [Install]
            WantedBy=timers.target
        """.trimIndent() + "\n")
    }
}

/** Validates retained committed consumption OR the distinct externally signed original-site
 * ordinal-zero head. Neither path mints authority or consumes a caller-supplied permit. */
/** Independent committed-site check; kept separate from consumption/journal verification.
 * Production always reopens the sealed bundle and the global current-site registry. */
private fun requireRssCurrentSite(binding: RssScheduleBinding, journalPath: Path) {
    val root = GenerationRuntime.BASE.resolve(binding.deployment.generationId)
    val bundleBytes = ReleasePrivateFiles.read(root.resolve("bundle.json"), 4194304)
    require(ReleaseLocks.sha256(bundleBytes) == binding.deployment.bundleSha256)
    val bundle = Json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString(throwOnInvalidSequence = true))
    SiteOwnerships.checkSealed(bundle)
    val owned = requireNotNull(bundle.ownership)
    ActiveSiteRegistry.requireActive(binding.deployment, journalPath,
        owned.contract.site, owned.approvedHosts)
}

internal class RssActivationAuthority(
    private val consumptionRoot: Path = Path.of("/mnt/media/p0-v3/release-activation-consumptions"),
    private val requireCurrentSite: (RssScheduleBinding, Path) -> Unit = ::requireRssCurrentSite,
    private val observe: (ReleaseDeploymentBinding, JsonObject, Set<Pair<String, String>>) -> List<CaddyUpstream> =
        { deployment, candidate, images -> GenerationRuntime.real().checkActivationSource(deployment, candidate, images) }) {
    /** Independently signed, STILL-CURRENT original site at ordinal zero. This does not
     * invent a transaction, consume a permit, enable a timer or approve a candidate. Only
     * the already enrolled/enabled RSS source tick may call verify(committed=true). */
    private fun originalBootstrap(binding: RssScheduleBinding, journalPath: Path): Boolean {
        val root = GenerationRuntime.BASE.resolve(binding.deployment.generationId)
        val bundleBytes = ReleasePrivateFiles.read(root.resolve("bundle.json"), 4194304)
        require(ReleaseLocks.sha256(bundleBytes) == binding.deployment.bundleSha256)
        val bundle = Json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString(throwOnInvalidSequence = true))
        SiteOwnerships.checkSealed(bundle)
        if (bundle.ownedUpdate != null) return false // Owned candidate MUST prove rev1+ COMMITTED selection.
        val owned = requireNotNull(bundle.ownership)
        val plan = requireNotNull(bundle.request.rssPlan)
        require(bundle.request.id == binding.deployment.generationId &&
            bundle.request.store == RuntimeStore.CANONICAL_V2 && bundle.ownedUpdate == null &&
            bundle.recoverySourceKopia == null && bundle.recoverySourceArchiveSha256 == null &&
            bundle.request.recoveredRssPlan == null &&
            plan.controllerSha256 == binding.controllerSha256 &&
            plan.artifactClosure == binding.artifactClosure &&
            plan.mastodonOrigin == binding.mastodonOrigin &&
            plan.intervalSeconds == binding.intervalSeconds &&
            URI(plan.mastodonOrigin).host in owned.approvedHosts &&
            owned.contract.routes.any { it.host == URI(plan.mastodonOrigin).host && it.product == "mastodon" } &&
            binding.stateDirectory == root.resolve("rss/state").toString() &&
            binding.tokenDirectory == root.resolve("rss/tokens").toString() &&
            journalPath.fileName.toString() == "transaction.jsonl" &&
            journalPath.parent.parent == ActiveSiteRegistry.BASE.parent) {
            "Only a sealed, original, owned and exactly enrolled Mastodon RSS source may use bootstrap"
        }
        val site = ActiveSiteRegistry.BASE.resolve(ReleaseLocks.sha256(owned.contract.site.toByteArray()))
        val headPath = site.resolve("head.json")
        if (!Files.exists(headPath, NOFOLLOW_LINKS)) return false
        val head = Json.decodeFromString<ActiveSiteHead>(ReleasePrivateFiles.read(headPath).decodeToString())
        if (head.ordinal != 0) return false // rev1+ MUST prove COMMITTED/consumed active-site selection.
        val closureBytes = ReleasePrivateFiles.read(Path.of(binding.artifactClosure.path), 4194304)
        require(ReleaseLocks.sha256(closureBytes) == binding.artifactClosure.sha256)
        val closure = Json.decodeFromString<ActivationArtifactClosure>(closureBytes.decodeToString(throwOnInvalidSequence = true))
        require(closure.schemaVersion == 1 && closure.controllers.keys == setOf("platform", "acceptance") &&
            closure.controllers.getValue("platform") == binding.controllerSha256 &&
            closure.controllers.values.all { it.matches(Regex("[a-f0-9]{64}")) } &&
            closure.images.size in 1..256 && closure.images.values.all { it.imageId.matches(Regex("[a-f0-9]{64}")) &&
                it.reference.matches(Regex("[a-z0-9][a-z0-9./_:-]*@sha256:[a-f0-9]{64}")) }) {
            "Original RSS artifact closure differs from externally signed controller/images"
        }
        val source = ReleaseGeneration(binding.deployment.generationId, binding.deployment.bundleSha256)
        val consumed = consumptionRoot.resolve("${binding.deployment.generationId}.consumed.json")
        val bootstrap = ActiveSiteRegistry.real(journalPath, owned.contract.site, owned.approvedHosts,
            source, consumed).requireOriginalBootstrap(source, binding.deployment.sitePolicySha256, owned.approvedHosts)
        require(bootstrap.source == source && bootstrap.siteId == owned.contract.site &&
            bootstrap.hosts == owned.approvedHosts.sorted() &&
            bootstrap.sitePolicySha256 == binding.deployment.sitePolicySha256) {
            "Original signed site authority differs from the exact RSS source"
        }
        // The external signed anchor records a historical inspection. Publication must
        // ALSO see the originally pinned daemon cohort actually running NOW.
        val current = GenerationRuntime.real().inspect(source.id, source.bundleSha256)
        require(current.id == source.id && current.bundleSha256 == source.bundleSha256 &&
            current.members.size == bundle.members.size && current.members.zip(bundle.members).all { (audit, pin) ->
                audit.name == pin.member.name && audit.fingerprint == pin.runtimeFingerprint &&
                audit.existingResources > 0 && audit.maintenanceId == null &&
                pin.spec.processes.all { process -> audit.statuses.singleOrNull { it.id == process.id }?.let { status ->
                    if (process.oneShot) status.state in setOf("completed", "exited") && status.exitCode == 0
                    else status.state == "running"
                } == true }
            }) { "Original RSS daemon cohort is no longer running or has been fenced" }
        require(ReleasePrivateFiles.read(root.resolve("bundle.json"), 4194304).contentEquals(bundleBytes) &&
            ReleasePrivateFiles.read(Path.of(binding.artifactClosure.path), 4194304).contentEquals(closureBytes) &&
            Json.decodeFromString<ActiveSiteHead>(ReleasePrivateFiles.read(headPath).decodeToString()) == head) {
            "Original source, controller closure or signed global site head changed during authorization"
        }
        return true
    }
    fun verify(binding: RssScheduleBinding, committed: Boolean) {
        RssSchedule.validate(binding)
        val journalPath = Path.of(binding.transactionJournal)
        // A retained consumption (including an invalid/partial one) selects the release
        // path. Never fall back to ordinal-zero bootstrap to bypass a failed release claim.
        val consumptionPath = consumptionRoot.resolve("${binding.deployment.generationId}.consumed.json")
        if (committed && !Files.exists(consumptionPath, NOFOLLOW_LINKS) && originalBootstrap(binding, journalPath)) return
        val journalBytes = ReleasePrivateFiles.read(journalPath, 1048576)
        val records = TransactionJournal.verify(journalPath)
        val last = records.last()
        require(last.deployment == binding.deployment && last.phase == (if (committed) Phase.COMMITTED else Phase.ACTIVATION_STARTED)) {
            "RSS requires exact release activation phase"
        }
        val claim = records.single { it.phase == Phase.ACTIVATION_STARTED }
        val accepted = records.single { it.phase == Phase.ACCEPTED }
        val retained = Json.parseToJsonElement(ReleasePrivateFiles.read(
            consumptionRoot.resolve("${binding.deployment.generationId}.consumed.json")).decodeToString()).jsonObject
        val permit = retained.getValue("permit").jsonObject
        val consumption = retained.getValue("consumption").jsonObject
        val claimedBytes = retained.getValue("claimJournal").jsonPrimitive.content.toByteArray()
        require(journalBytes.take(claimedBytes.size).toByteArray().contentEquals(claimedBytes) &&
            claimedBytes.size == journalBytes.indexOfNthNewline(records.indexOf(claim) + 1) &&
            ReleaseLocks.sha256(permit.toString().toByteArray()) == claim.activationPermitSha256) { "RSS consumption claim differs from activation" }
        require(consumption == buildJsonObject {
            put("schemaVersion", 1); put("generation", binding.deployment.generationId)
            put("permitSha256", claim.activationPermitSha256); put("activationJournalHead", claim.hash)
            put("qualificationHead", permit.getValue("qualificationHead")); put("claimJournalSha256", ReleaseLocks.sha256(claimedBytes))
        }) { "RSS activation consumption changed" }
        require(permit.getValue("schemaVersion") == JsonPrimitive(1) && permit.getValue("binding") == buildJsonObject {
            put("transactionId", last.transactionId); put("lockDigest", last.lockDigest); put("acceptedJournalHead", accepted.hash)
            put("deployment", Json.encodeToJsonElement(binding.deployment))
        }) { "RSS permit belongs to a different release" }
        val candidate = permit.getValue("candidate").jsonObject
        val bytes = ReleasePrivateFiles.read(Path.of(binding.artifactClosure.path))
        require(ReleaseLocks.sha256(bytes) == binding.artifactClosure.sha256 &&
            candidate.getValue("artifactsSha256").jsonPrimitive.content == binding.artifactClosure.sha256 &&
            candidate.getValue("sitePolicySha256").jsonPrimitive.content == binding.deployment.sitePolicySha256)
        val closure = Json.decodeFromString<ActivationArtifactClosure>(bytes.decodeToString())
        require(closure.schemaVersion == 1 && closure.controllers.keys == setOf("platform", "acceptance") &&
            closure.controllers.getValue("platform") == binding.controllerSha256 &&
            closure.controllers.values.all { it.matches(Regex("[a-f0-9]{64}")) } &&
            closure.images.size in 1..256 && closure.images.values.all {
                it.imageId.matches(Regex("[a-f0-9]{64}")) &&
                    it.reference.matches(Regex("[a-z0-9][a-z0-9./_:-]*@sha256:[a-f0-9]{64}"))
            }) { "RSS artifact closure differs from activated controller/images" }
        val upstreams = observe(binding.deployment, candidate, closure.images.values.map { it.reference to it.imageId }.toSet())
        require(upstreams.any { it.host == URI(binding.mastodonOrigin).host }) { "RSS origin is not an exact activated site" }
        if (committed) requireCurrentSite(binding, journalPath)
        require(ReleasePrivateFiles.read(journalPath, 1048576).contentEquals(journalBytes)) { "Release changed during RSS authorization" }
    }
    private fun ByteArray.indexOfNthNewline(count: Int): Int {
        var seen = 0
        for (i in indices) if (this[i] == '\n'.code.toByte() && ++seen == count) return i + 1
        error("Incomplete activation claim")
    }
}

/** Main delegates only this namespace; all errors are sanitized by the caller. */
internal object RssScheduleCommands {
    fun run(args: Array<String>, out: (String) -> Unit,
        schedule: () -> RssSchedule = { RssSchedule.real() },
        // Production fetch is admitted only inside the exact phase/case/fixture scope.
        // RESTORE replays the original fixture bytes without invoking this fetcher.
        packObserver: () -> RssPackObserver = { RssPackObserver(RssQualificationPackSource::fetch) },
        operationScope: GenerationRssOperations? = GenerationRssOperations()): Boolean {
        if (args.size < 2 || args[0] != "rss" || args[1] !in setOf("schedule-enroll", "schedule-units", "schedule-tick", "schedule-pause", "reconcile", "pack-observe", "qualification-phase-begin", "qualification-phase-complete", "qualification-begin", "qualification-complete", "fixture-enroll", "fixture-units", "fixture-tick", "fixture-reconcile", "fixture-evidence", "fixture-readback", "fixture-serve", "restored-account", "account-list")) return false
        if (args[1].startsWith("qualification-")) {
            require(args.size == when (args[1]) {
                "qualification-phase-begin" -> 4
                "qualification-phase-complete" -> 6
                "qualification-begin" -> 5
                else -> 7
            })
            val generation = Path.of(args[2])
            val record = Path.of(args[3])
            val scope = requireNotNull(operationScope) { "RSS qualification requires controller exclusion" }
            out(scope.withExclusion {
                require(generation.parent == GenerationRuntime.BASE &&
                    generation.fileName.toString().matches(Regex("q-[a-f0-9]{12}"))) {
                    "Original RSS generation required for qualification claim"
                }
                when (args[1]) {
                    "qualification-phase-begin" -> {
                        scope.requireWritableGeneration(generation)
                        Json.encodeToString(RssQualificationIntents.beginPhase(generation, record))
                    }
                    "qualification-phase-complete" -> {
                        scope.requireWritableGeneration(generation, phaseClaimSha256 = args[4])
                        Json.encodeToString(RssQualificationIntents.completePhase(generation, record, args[4], args[5]))
                    }
                    "qualification-begin" -> {
                        scope.requireWritableGeneration(generation, phaseClaimSha256 = args[4])
                        Json.encodeToString(RssQualificationIntents.begin(generation, record, args[4]))
                    }
                    else -> {
                        val caseIntent = Json.parseToJsonElement(ReleasePrivateFiles.read(record.resolve("intent.json"),
                            1048576).decodeToString(throwOnInvalidSequence = true)).jsonObject
                        scope.requireWritableGeneration(generation, requireNotNull(caseIntent["invocationId"]).jsonPrimitive.content,
                            args[4], args[6])
                        Json.encodeToString(RssQualificationIntents.complete(generation, record, args[4], args[5], args[6]))
                    }
                }
            })
            return true
        }
        if (args[1] == "account-list") {
            require(args.size == 2)
            val accounts = RssPacks.load().map { it.feed.account }.sorted()
            require(accounts.size == 47 && accounts.toSet().size == 47)
            out(Json.encodeToString(accounts))
            return true
        }
        if (args[1] == "restored-account") {
            require(args.size == 9)
            val generation = GenerationRuntime.BASE.resolve(args[2])
            val scope = requireNotNull(operationScope)
            out(scope.withExclusion {
                scope.requireWritableGeneration(generation, System.getenv("P0V3_CASE_INVOCATION_ID"),
                    System.getenv("P0V3_RSS_QUALIFICATION_SHA256"), System.getenv("P0V3_RSS_PHASE_CLAIM_SHA256"))
                val tokenFile = Path.of(args[7]); val account = args[8]
                require(account.matches(Regex("rss_[a-z0-9_]+")) &&
                    tokenFile == generation.resolve("rss/tokens/$account.token")) {
                    "Original real47 RSS token must be exact generation/subject custody"
                }
                val http = RssRestoredMastodonHttp(generation, Path.of(args[3]), args[4],
                    Path.of(args[5]), args[6], tokenFile, account)
                val bearer = MastodonRssSender.privateToken(tokenFile)
                val reply = http.request("GET", URI("https://social.datamancy.net/api/v1/accounts/verify_credentials"),
                    mapOf("Authorization" to "Bearer $bearer", "Accept" to "application/json"), "")
                require(reply.status == 200 && reply.body.size in 1..1048576) { "Original RSS account readback denied" }
                val identity = Json.parseToJsonElement(reply.body.decodeToString(throwOnInvalidSequence = true)).jsonObject
                require(identity.getValue("acct").jsonPrimitive.content == account &&
                    identity.getValue("bot").jsonPrimitive.boolean &&
                    identity.getValue("id").jsonPrimitive.content.matches(Regex("[0-9]{1,32}")) &&
                    identity.getValue("statuses_count").jsonPrimitive.int >= 0) {
                    "Original recovered real47 account/principal mismatched"
                }
                buildJsonObject {
                    put("acct", account); put("bot", true)
                    put("id", identity.getValue("id").jsonPrimitive.content)
                    put("statuses_count", identity.getValue("statuses_count").jsonPrimitive.int)
                }.toString()
            })
            return true
        }
        if (args[1] == "fixture-serve") {
            require(args.size == 3)
            RssNativeFixtureServer.serve(Path.of(args[2])) // Exact local-only TLS fixture, operator starts separately.
        }
        if (args[1].startsWith("fixture-")) {
            val command = args[1]
            require(args.size == if (command == "fixture-readback") 5 else 4)
            val fixture = Path.of(args[2])
            val result = {
                if (operationScope != null) {
                    require(fixture.parent.fileName.toString() == "rss-qualification")
                    operationScope.requireWritableGeneration(fixture.parent.parent,
                        System.getenv("P0V3_CASE_INVOCATION_ID"), System.getenv("P0V3_RSS_QUALIFICATION_SHA256"),
                        System.getenv("P0V3_RSS_PHASE_CLAIM_SHA256"))
                    RssQualificationIntents.requireFixtureBinding(fixture.parent.parent,
                        requireNotNull(System.getenv("P0V3_CASE_INVOCATION_ID")), fixture.fileName.toString(),
                        command != "fixture-readback")
                }
                when (command) {
                    "fixture-enroll" -> RssNativeFixtureTimer.enroll(fixture, Path.of(args[3]))
                    "fixture-units" -> Json.encodeToString(RssNativeFixtureTimer.units(fixture, args[3]))
                    "fixture-tick" -> Json.encodeToString(RssNativeFixtureTimer.tick(fixture, args[3]))
                    "fixture-reconcile" -> Json.encodeToString(RssNativeFixtureTimer.reconcile(fixture, args[3]))
                    "fixture-evidence" -> Json.encodeToString(RssNativeFixtureTimer.evidence(fixture, args[3]))
                    else -> {
                        val bridgeBytes = ReleasePrivateFiles.read(Path.of(args[3]), 1048576)
                        require(args[4].matches(Regex("[a-f0-9]{64}")) &&
                            ReleaseLocks.sha256(bridgeBytes) == args[4]) { "Changed restricted original-host bridge binding" }
                        Json.decodeFromString<RestoredBridgeIntent>(bridgeBytes.decodeToString(throwOnInvalidSequence = true))
                        val receipt = Json.decodeFromString<RssNativeFixtureResult>(ReleasePrivateFiles.read(
                            fixture.resolve("native-receipt.json")).decodeToString(throwOnInvalidSequence = true))
                        Json.encodeToString(RssNativeFixtureTimer.restored(fixture, receipt, Path.of(args[3]), args[4]))
                    }
                }
            }
            out(operationScope?.withExclusion(result) ?: result())
            return true
        }
        if (args[1] == "pack-observe") {
            require(args.size == 6 && args[2] in setOf("install", "restore"))
            val observer = packObserver()
            val stateRoot = Path.of(args[4])
            val fixture = Path.of(args[5])
            val observe = {
                if (operationScope != null) {
                    require(stateRoot.parent == fixture.parent && stateRoot.fileName.toString() == "state" &&
                        fixture.parent.parent.fileName.toString() == "rss-qualification") {
                        "RSS qualification state must be in the generation-owned fixture"
                    }
                    operationScope.requireWritableGeneration(fixture.parent.parent.parent,
                        System.getenv("P0V3_CASE_INVOCATION_ID"), System.getenv("P0V3_RSS_QUALIFICATION_SHA256"),
                        System.getenv("P0V3_RSS_PHASE_CLAIM_SHA256"))
                }
                if (operationScope != null) RssQualificationIntents.requireFixtureBinding(
                    fixture.parent.parent.parent, requireNotNull(System.getenv("P0V3_CASE_INVOCATION_ID")),
                    fixture.parent.fileName.toString(), args[2] == "install")
                if (args[2] == "install" && !Files.exists(stateRoot, NOFOLLOW_LINKS)) {
                    // Only this fresh case-owned fixture may initialize; NEVER the recovered original.
                    require(operationScope == null || System.getenv("P0V3_CASE_INVOCATION_ID") != null)
                    Files.createDirectory(stateRoot,
                        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
                    ReleasePrivateFiles.sync(stateRoot.parent)
                    RssStateStore(stateRoot).initializeFresh()
                }
                if (operationScope == null) observer.observe(args[3], stateRoot, fixture, args[2] == "restore")
                else RssQualificationPackSource.withCase(stateRoot, fixture, args[3]) {
                    observer.observe(args[3], stateRoot, fixture, args[2] == "restore")
                }
            }
            out(Json { encodeDefaults = true }.encodeToString(operationScope?.withExclusion(observe) ?: observe()))
            return true
        }
        val scheduler = schedule()
        require(args.size == if (args[1] == "reconcile") 8 else 4) { "Invalid RSS schedule arguments" }
        val root = Path.of(args[2])
        when (args[1]) {
            "schedule-enroll" -> out(scheduler.enroll(root, RssSchedule.decode(ReleasePrivateFiles.read(Path.of(args[3])))))
            "schedule-units" -> out(Json.encodeToString(scheduler.units(root, args[3])))
            "schedule-pause" -> { scheduler.pause(root, args[3]); out("suspended") }
            "schedule-tick" -> {
                val result = scheduler.tick(root, args[3])
                out(if (result == null) "disabled" else "feeds=${result.feeds} observed=${result.observed} confirmed=${result.confirmed} failed=${result.failedFeeds.joinToString(",")}")
                require(result == null || result.failedFeeds.isEmpty()) { "Partial RSS poll; failed checkpoints unchanged" }
            }
            "reconcile" -> out(scheduler.reconcile(root, args[3], args[4], args[5], args[6], args[7])?.let { Json.encodeToString(it) } ?: "unresolved")
        }
        return true
    }
}
