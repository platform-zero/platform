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
    private val enrollment: RssEnrollmentAuthority? = null) {
    companion object {
        private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
        private val hex = Regex("[a-f0-9]{64}")
        private val safePath = Regex("/[A-Za-z0-9_./-]+")
        fun real() = RssSchedule(RssActivationAuthority()::verify, PinnedBackupController::verify, JdkRssHttp(),
            enrollment = GenerationRssEnrollmentAuthority())
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
    fun enroll(root: Path, binding: RssScheduleBinding): String {
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
        ReleasePrivateFiles.locked(root) {
            val binding = binding(root, expected); controller(binding.controllerSha256); action(binding)
        }
    } catch (interrupted: InterruptedException) {
        Thread.currentThread().interrupt(); throw interrupted
    }
    /** Controller-only operation: the body must throw unless its durable operation results and source
     * resume/isolation checks succeeded. Hold this across the WHOLE operation, not just capture.
     * Returning normally is not publication authority: previously enabled schedules additionally
     * revalidate the live committed generation before completion. No callback/finally clears failure.
     * Incomplete claims survive process death and block ticks even after the OS lock is released.
     */
    fun <T> quiesce(root: Path, expected: String, operationId: String, operation: () -> T): T = locked(root, expected) { binding ->
        val wasEnabled = marker(root, "enabled", expected)
        RssMaintenance.claim(root, expected, operationId)
        val result = operation()
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
    fun pause(root: Path, expected: String) = locked(root, expected) { mark(root, "suspended", expected) }
    fun release(root: Path, expected: String) = locked(root, expected) { binding ->
        RssMaintenance.requireClear(root, expected)
        require(!marker(root, "suspended", expected)) { "Suspended RSS schedule cannot reopen; fresh qualified release required" }
        authority(binding, false) // ACTIVATION_STARTED plus durable consumption; not yet permission for ticks.
        mark(root, "enabled", expected)
    }
    private fun active(root: Path, expected: String, binding: RssScheduleBinding) {
        RssMaintenance.requireClear(root, expected)
        require(!marker(root, "suspended", expected) && marker(root, "enabled", expected)) { "RSS schedule is not enabled" }
        authority(binding, true) // COMMITTED, original live generation, exact consumed permit.
    }
    fun tick(root: Path, expected: String): RssPollSummary? = locked(root, expected) { binding ->
        if (marker(root, "suspended", expected) || !marker(root, "enabled", expected)) return@locked null
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
            OnBootSec=5min
            OnUnitInactiveSec=${binding.intervalSeconds}s
            AccuracySec=30s
            RandomizedDelaySec=30s
            Unit=$name.service
            [Install]
            WantedBy=timers.target
        """.trimIndent() + "\n")
    }
}

/** Validates retained consumption, not a second consumption or a reusable caller-supplied permit. */
internal class RssActivationAuthority(
    private val consumptionRoot: Path = Path.of("/mnt/media/p0-v3/release-activation-consumptions"),
    private val observe: (ReleaseDeploymentBinding, JsonObject, Set<Pair<String, String>>) -> List<CaddyUpstream> =
        { deployment, candidate, images -> GenerationRuntime.real().checkActivationSource(deployment, candidate, images) }) {
    fun verify(binding: RssScheduleBinding, committed: Boolean) {
        RssSchedule.validate(binding)
        val journalPath = Path.of(binding.transactionJournal)
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
        packObserver: () -> RssPackObserver = { RssPackObserver(RssFetcher(JdkRssHttp())::fetch) }): Boolean {
        if (args.size < 2 || args[0] != "rss" || args[1] !in setOf("schedule-enroll", "schedule-units", "schedule-tick", "schedule-pause", "reconcile", "pack-observe")) return false
        if (args[1] == "pack-observe") {
            require(args.size == 6 && args[2] in setOf("install", "restore"))
            val observer = packObserver()
            out(Json { encodeDefaults = true }.encodeToString(observer.observe(args[3], Path.of(args[4]), Path.of(args[5]), args[2] == "restore")))
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
