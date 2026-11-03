package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions
import java.time.Instant
import java.time.ZoneOffset
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable internal data class BackupScheduleBinding(val schemaVersion: Int = 1, val generation: String,
    val bundleSha256: String, val inventorySha256: String, val controllerSha256: String, val userId: Int, val enrolledAt: String)
@Serializable internal data class BackupScheduleEnrollment(val bindingSha256: String, val binding: BackupScheduleBinding)
@Serializable internal data class BackupScheduleSlot(val bindingSha256: String, val day: String, val capture: String)
@Serializable internal data class BackupScheduleResult(val slot: BackupScheduleSlot, val backup: GenerationBackupOutcome? = null,
    val failureType: String? = null)
@Serializable internal data class BackupScheduleTick(val status: String, val slot: BackupScheduleSlot? = null)

/** Daily canonical-generation controller job. No direct live-volume snapshots, pruning or whole-release claim. */
internal class GenerationBackupSchedule(private val base: Path, private val now: () -> Instant,
    private val checkSource: (AcquiredInventory, String, String) -> Unit,
    private val backup: (AcquiredInventory, String, String, String) -> GenerationBackupOutcome,
    private val checkController: (BackupScheduleBinding) -> Unit) {
    companion object {
        private val json = Json { encodeDefaults = true }
        private val privateDir = PosixFilePermissions.fromString("rwx------")
        private val privateFile = PosixFilePermissions.fromString("rw-------")
        fun real(): GenerationBackupSchedule {
            val runtime = GenerationRuntime.real()
            return GenerationBackupSchedule(GenerationRuntime.BASE, Instant::now, runtime::checkBackupSource,
                { inventory, generation, bundle, capture -> runtime.backupKopia(inventory, generation, bundle, capture) },
                { PinnedBackupController.verify(it.controllerSha256) })
        }
        fun validate(binding: BackupScheduleBinding) {
            RuntimeBackupAccess(binding.generation, "cap-000000000000", binding.bundleSha256).validate()
            require(binding.schemaVersion == 1 && binding.inventorySha256.matches(Regex("[a-f0-9]{64}")) &&
                binding.controllerSha256.matches(Regex("[a-f0-9]{64}")) && binding.userId in 1..65534 &&
                Instant.parse(binding.enrolledAt).toString() == binding.enrolledAt) { "Invalid daily backup binding" }
        }
        fun day(at: Instant): String {
            val utc = at.atZone(ZoneOffset.UTC)
            return (if (utc.hour < 3) utc.minusDays(1) else utc).toLocalDate().toString()
        }
        fun slot(bindingHash: String, day: String) = BackupScheduleSlot(bindingHash, day,
            "cap-" + ReleaseLocks.sha256("daily-backup-v1\n$bindingHash\n$day".toByteArray()).take(12))
    }
    private fun dir(path: Path) {
        require(path.isAbsolute && path.normalize() == path && path.toRealPath() == path && Files.isDirectory(path, NOFOLLOW_LINKS) &&
            Files.getPosixFilePermissions(path) == privateDir && (Files.getAttribute(path, "unix:uid") as Number).toLong() == UnixSystem().uid) {
            "Owned private schedule directory required"
        }
    }
    private fun root(generation: String): Path {
        require(generation.matches(Regex("q-[a-f0-9]{12}")))
        dir(base); dir(base.resolve(generation))
        return base.resolve(generation).resolve("backup-schedule")
    }
    private fun read(path: Path) = GenerationRuntime.privateInput(path)
    private fun save(path: Path, text: String) {
        val bytes = text.toByteArray(); require(bytes.size in 1..1048576)
        FileChannel.open(path, setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS), PosixFilePermissions.asFileAttribute(privateFile)).use {
            val buffer = ByteBuffer.wrap(bytes); while (buffer.hasRemaining()) it.write(buffer); it.force(true)
        }
        FileChannel.open(path.parent, READ).use { it.force(true) }
    }
    fun enroll(inventory: ByteArray, generation: String, bundle: String, controller: String, userId: Int): BackupScheduleEnrollment {
        require(inventory.size in 1..1048576 && userId.toLong() == UnixSystem().uid)
        val binding = BackupScheduleBinding(generation = generation, bundleSha256 = bundle, inventorySha256 = ReleaseLocks.sha256(inventory),
            controllerSha256 = controller, userId = userId, enrolledAt = now().toString())
        validate(binding)
        val acquired = json.decodeFromString<AcquiredInventory>(inventory.decodeToString(throwOnInvalidSequence = true))
        checkSource(acquired, generation, bundle) // No scheduling files or credentials before source eligibility.
        val root = root(generation)
        Files.createDirectory(root, PosixFilePermissions.asFileAttribute(privateDir))
        FileChannel.open(root.parent, READ).use { it.force(true) }
        val bytes = json.encodeToString(binding)
        save(root.resolve("binding.json"), bytes)
        // Partial enrollment is retained; never regenerate it or silently replace inventory/controller pins.
        save(root.resolve("inventory.json"), inventory.decodeToString(throwOnInvalidSequence = true))
        save(root.resolve("enrolled.json"), ReleaseLocks.sha256(bytes.toByteArray()))
        return BackupScheduleEnrollment(ReleaseLocks.sha256(bytes.toByteArray()), binding)
    }
    private fun binding(root: Path, expected: String): BackupScheduleBinding {
        require(expected.matches(Regex("[a-f0-9]{64}"))); dir(root)
        val bytes = read(root.resolve("binding.json"))
        require(ReleaseLocks.sha256(bytes) == expected && read(root.resolve("enrolled.json")).decodeToString() == expected) { "Schedule enrollment binding changed or incomplete" }
        return json.decodeFromString<BackupScheduleBinding>(bytes.decodeToString()).also {
            validate(it); require(it.generation == root.parent.fileName.toString() && it.userId.toLong() == UnixSystem().uid)
        }
    }
    private fun <T> locked(generation: String, expected: String, action: (Path, BackupScheduleBinding) -> T): T {
        val root = root(generation); val binding = binding(root, expected)
        val lock = root.resolve("schedule.lock")
        FileChannel.open(lock, setOf(CREATE, READ, WRITE, NOFOLLOW_LINKS), PosixFilePermissions.asFileAttribute(privateFile)).use { channel ->
            require(lock.toRealPath() == lock && Files.isRegularFile(lock, NOFOLLOW_LINKS) && Files.getPosixFilePermissions(lock) == privateFile &&
                (Files.getAttribute(lock, "unix:uid") as Number).toLong() == UnixSystem().uid &&
                (Files.getAttribute(lock, "unix:nlink") as Number).toInt() == 1) { "Unsafe schedule lock" }
            channel.lock().use { return action(root, binding) }
        }
    }
    private fun alert(root: Path, expected: String) {
        val path = root.resolve("failure.alert")
        if (Files.exists(path, NOFOLLOW_LINKS)) require(read(path).decodeToString() == expected) { "Foreign schedule alert" }
        else save(path, expected)
    }
    fun signalFailure(generation: String, expected: String) = locked(generation, expected) { root, binding ->
        checkController(binding); alert(root, expected)
    }
    fun suspend(generation: String, expected: String) = locked(generation, expected) { root, binding ->
        checkController(binding)
        val marker = root.resolve("suspended")
        if (Files.exists(marker, NOFOLLOW_LINKS)) require(read(marker).decodeToString() == expected) else save(marker, expected)
    }
    fun units(generation: String, expected: String): Map<String, String> {
        val binding = binding(root(generation), expected)
        return BackupScheduleUnits.render(binding, expected)
    }
    fun tick(generation: String, expected: String): BackupScheduleTick = locked(generation, expected) { root, binding ->
        checkController(binding)
        if (Files.exists(root.resolve("suspended"), NOFOLLOW_LINKS)) {
            require(read(root.resolve("suspended")).decodeToString() == expected)
            return@locked BackupScheduleTick("suspended")
        }
        require(!Files.exists(root.resolve("failure.alert"), NOFOLLOW_LINKS)) { "Schedule failure retained; automatic retry forbidden" }
        val inventory = read(root.resolve("inventory.json"))
        require(ReleaseLocks.sha256(inventory) == binding.inventorySha256) { "Scheduled inventory changed" }
        val acquired = json.decodeFromString<AcquiredInventory>(inventory.decodeToString())
        val current = now(); require(current >= Instant.parse(binding.enrolledAt)) { "Schedule clock moved before enrollment" }
        val latest = day(current)
        val attempts = root.resolve("slots")
        if (!Files.exists(attempts, NOFOLLOW_LINKS)) {
            Files.createDirectory(attempts, PosixFilePermissions.asFileAttribute(privateDir))
            FileChannel.open(root, READ).use { it.force(true) }
        }
        dir(attempts)
        val prior = Files.list(attempts).use { it.limit(129).toList() }
        require(prior.size <= 128) { "Schedule history bound reached; no evidence deletion" }
        var completed = false
        for (path in prior) {
            dir(path)
            val date = java.time.LocalDate.parse(path.fileName.toString()).toString()
            require(date == path.fileName.toString() && date <= latest && date >= day(Instant.parse(binding.enrolledAt))) { "Invalid slot or clock rollback" }
            val intent = json.decodeFromString<BackupScheduleSlot>(read(path.resolve("intent.json")).decodeToString())
            require(intent == slot(expected, date)) { "Foreign scheduled operation identity" }
            try {
                val result = json.decodeFromString<BackupScheduleResult>(read(path.resolve("result.json")).decodeToString())
                require(result.slot == intent && result.failureType == null)
                validateBackup(binding, intent, requireNotNull(result.backup))
            } catch (e: InterruptedException) { throw e }
            catch (e: Exception) { alert(root, expected); throw IllegalStateException("Unknown or failed scheduled backup; never resubmit", e) }
            if (date == latest) completed = true
        }
        if (completed) return@locked BackupScheduleTick("already-completed", slot(expected, latest))
        require(prior.size < 128) { "Schedule history bound reached; no evidence deletion" }
        val slot = slot(expected, latest) // At most ONE latest due slot; missed slots are never replayed in a burst.
        val attempt = attempts.resolve(latest)
        Files.createDirectory(attempt, PosixFilePermissions.asFileAttribute(privateDir))
        FileChannel.open(attempts, READ).use { it.force(true) }
        save(attempt.resolve("intent.json"), json.encodeToString(slot))
        try {
            val result = backup(acquired, generation, binding.bundleSha256, slot.capture)
            validateBackup(binding, slot, result)
            save(attempt.resolve("result.json"), json.encodeToString(BackupScheduleResult(slot, result)))
            BackupScheduleTick("completed", slot)
        } catch (e: InterruptedException) {
            Thread.interrupted()
            try { recordFailure(root, attempt, expected, slot, e) } finally { Thread.currentThread().interrupt() }
            throw e
        } catch (e: Exception) {
            recordFailure(root, attempt, expected, slot, e)
            throw e
        }
    }
    private fun recordFailure(root: Path, attempt: Path, expected: String, slot: BackupScheduleSlot, error: Exception) {
        // Always attempt the independent local alert, even if outcome persistence fails. Never overwrite uncertain records.
        try {
            if (!Files.exists(attempt.resolve("result.json"), NOFOLLOW_LINKS))
                save(attempt.resolve("result.json"), json.encodeToString(BackupScheduleResult(slot, failureType = error.javaClass.name)))
        } finally { alert(root, expected) }
    }
    private fun validateBackup(binding: BackupScheduleBinding, slot: BackupScheduleSlot, result: GenerationBackupOutcome) {
        require(result.access == RuntimeBackupAccess(binding.generation, slot.capture, binding.bundleSha256) && result.passed &&
            result.sourceResumed && result.failureType == null) { "Scheduled backup did not safely complete" }
        val snapshot = requireNotNull(result.snapshot); KopiaGenerationStore.validate(snapshot)
        require(snapshot.id == slot.capture && snapshot.generation == binding.generation && snapshot.bundleSha256 == binding.bundleSha256)
    }
}

internal object BackupScheduleUnits {
    fun render(binding: BackupScheduleBinding, expected: String): Map<String, String> {
        GenerationBackupSchedule.validate(binding); require(expected.matches(Regex("[a-f0-9]{64}")))
        val name = "p0v3-backup-${binding.generation}"
        val cli = "/mnt/media/p0-v3/runtime-supervision/releases/${binding.controllerSha256}/bin/p0-v3-platform"
        fun service(operation: String, failure: Boolean) = """
            # Managed by p0v3-canonical-backup-v1; no public activation or image updates.
            [Unit]
            Description=Canonical daily backup ${binding.generation}
            RequiresMountsFor=/mnt/media/p0-v3 /run/p0-v3-release-runtime
            After=apparmor.service
            ${if (failure) "OnFailure=$name-alert.service" else ""}
            [Service]
            Type=oneshot
            User=${binding.userId}
            UMask=0077
            Environment=JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
            Environment="JAVA_OPTS=-Xms32m -Xmx512m"
            ExecStart=$cli release $operation ${binding.generation} $expected
            TimeoutStartSec=28800
            TimeoutStopSec=30
            KillMode=process
            Restart=no
            StandardOutput=journal
            StandardError=journal
        """.trimIndent() + "\n"
        return linkedMapOf("$name.service" to service("backup-schedule-tick", true),
            "$name-alert.service" to service("backup-schedule-alert", false), "$name.timer" to """
            # Managed by p0v3-canonical-backup-v1; latest-slot bounded catch-up.
            [Unit]
            Description=Canonical daily backup timer ${binding.generation}
            [Timer]
            OnCalendar=*-*-* 03:00:00 UTC
            OnActiveSec=5s
            AccuracySec=1s
            Persistent=true
            Unit=$name.service
            [Install]
            WantedBy=timers.target
        """.trimIndent() + "\n")
    }
}
