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
@Serializable internal data class BackupScheduleMissingResultReadback(val schemaVersion: Int = 1,
    val bindingSha256: String, val slot: BackupScheduleSlot, val originalIntentSha256: String,
    val nativeOutcomeSha256: String, val workerQuiescence: ActivationInput,
    val referenceWriterExclusion: ActivationInput, val originalAcknowledged: Boolean = false,
    val disposition: String = "native-complete-original-schedule-result-absent")
@Serializable internal data class BackupScheduleTerminalReadback(val schemaVersion: Int = 1,
    val bindingSha256: String, val slot: BackupScheduleSlot, val originalFailureSha256: String,
    val nativeOutcomeSha256: String, val originalAcknowledged: Boolean = false,
    val disposition: String = "native-source-resumed-original-schedule-failed")

/** Daily canonical-generation controller job. No direct live-volume snapshots, pruning or whole-release claim. */
internal class GenerationBackupSchedule(private val base: Path, private val now: () -> Instant,
    private val checkSource: (AcquiredInventory, String, String) -> Unit,
    private val backup: (AcquiredInventory, String, String, String) -> GenerationBackupOutcome,
    private val checkController: (BackupScheduleBinding) -> Unit,
    private val missingResultQuiescence: (BackupScheduleBinding, BackupScheduleSlot) -> ActivationInput = { _, _ ->
        error("Original schedule worker quiescence has no core owner proof") },
    private val referenceWriterExclusion: (BackupScheduleBinding, BackupScheduleSlot, GenerationBackupOutcome) -> ActivationInput = { _, _, _ ->
        error("Source reference writer exclusion has no core owner proof") }) {
    companion object {
        private val json = Json { encodeDefaults = true }
        private val privateDir = PosixFilePermissions.fromString("rwx------")
        private val privateFile = PosixFilePermissions.fromString("rw-------")
        fun real(
            missingResultQuiescence: (BackupScheduleBinding, BackupScheduleSlot) -> ActivationInput = { _, _ ->
                error("Original schedule worker quiescence has no core owner proof") },
            referenceWriterExclusion: (BackupScheduleBinding, BackupScheduleSlot, GenerationBackupOutcome) -> ActivationInput = { _, _, _ ->
                error("Source reference writer exclusion has no core owner proof") }): GenerationBackupSchedule {
            val runtime = GenerationRuntime.real()
            return GenerationBackupSchedule(GenerationRuntime.BASE, Instant::now, runtime::checkBackupSource,
                { inventory, generation, bundle, capture -> runtime.backupKopia(inventory, generation, bundle, capture) },
                { PinnedBackupController.verify(it.controllerSha256) },
                missingResultQuiescence, referenceWriterExclusion)
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
    /** A lost scheduled callback ACK remains a failure. Only the *same* completed native
     * capture and independently retained source-resume/reference proof may dispose the
     * daily schedule fence for future days. Never resubmit its deterministic capture ID.
     */
    fun reconcileNativeCompletion(generation: String, expected: String, date: String): BackupScheduleTerminalReadback =
        locked(generation, expected) { root, binding ->
            checkController(binding)
            require(java.time.LocalDate.parse(date).toString() == date && date >= day(Instant.parse(binding.enrolledAt)))
            require(read(root.resolve("failure.alert")).decodeToString() == expected)
            val slot = slot(expected, date)
            val location = root.resolve("slots/$date")
            dir(location)
            require(json.decodeFromString<BackupScheduleSlot>(read(location.resolve("intent.json")).decodeToString()) == slot)
            val original = read(location.resolve("result.json"))
            val failed = json.decodeFromString<BackupScheduleResult>(original.decodeToString())
            require(failed.slot == slot && failed.failureType != null && failed.backup == null) {
                "Only a retained original failed schedule result admits independent disposition"
            }
            val inventory = read(root.resolve("inventory.json"))
            require(ReleaseLocks.sha256(inventory) == binding.inventorySha256)
            checkSource(json.decodeFromString(inventory.decodeToString()), generation, binding.bundleSha256)
            val source = base.resolve(generation)
            val nativeBytes = ReleasePrivateFiles.read(source.resolve("backups/${slot.capture}/result.json"))
            val native = json.decodeFromString<GenerationBackupOutcome>(nativeBytes.decodeToString())
            validateBackup(binding, slot, native)
            RecoveryReferenceOperations.authority(base, generation, binding.bundleSha256).requireTerminalDaily(native)
            val result = BackupScheduleTerminalReadback(bindingSha256 = expected, slot = slot,
                originalFailureSha256 = ReleaseLocks.sha256(original), nativeOutcomeSha256 = ReleaseLocks.sha256(nativeBytes))
            save(location.resolve("terminal-readback.json"), json.encodeToString(result))
            result
        }

    /** Distinct original-result-ABSENT disposition. The two injected owner proofs MUST be
     * typed current observations, not files this schedule can issue or derive from its own alert. */
    fun reconcileMissingResult(generation: String, expected: String, date: String): BackupScheduleMissingResultReadback =
        locked(generation, expected) { root, binding ->
            checkController(binding)
            require(java.time.LocalDate.parse(date).toString() == date && date >= day(Instant.parse(binding.enrolledAt)))
            require(read(root.resolve("failure.alert")).decodeToString() == expected)
            val slot = slot(expected, date)
            val location = root.resolve("slots/$date"); dir(location)
            val original = read(location.resolve("intent.json"))
            require(json.decodeFromString<BackupScheduleSlot>(original.decodeToString()) == slot &&
                !Files.exists(location.resolve("result.json"), NOFOLLOW_LINKS) &&
                !Files.exists(location.resolve("terminal-readback.json"), NOFOLLOW_LINKS))
            val inventory = read(root.resolve("inventory.json"))
            require(ReleaseLocks.sha256(inventory) == binding.inventorySha256)
            checkSource(json.decodeFromString(inventory.decodeToString()), generation, binding.bundleSha256)
            val nativeBytes = ReleasePrivateFiles.read(base.resolve(generation).resolve("backups/${slot.capture}/result.json"))
            val native = json.decodeFromString<GenerationBackupOutcome>(nativeBytes.decodeToString())
            validateBackup(binding, slot, native)
            RecoveryReferenceOperations.authority(base, generation, binding.bundleSha256).requireTerminalDaily(native)
            val worker = missingResultQuiescence(binding, slot)
            val writer = referenceWriterExclusion(binding, slot, native)
            requirePinnedOwnerProof(worker, binding, slot, "worker-quiescence")
            requirePinnedOwnerProof(writer, binding, slot, "reference-writer-exclusion")
            require(worker.path != writer.path && worker.sha256 != writer.sha256)
            val readback = BackupScheduleMissingResultReadback(bindingSha256 = expected, slot = slot,
                originalIntentSha256 = ReleaseLocks.sha256(original), nativeOutcomeSha256 = ReleaseLocks.sha256(nativeBytes),
                workerQuiescence = worker, referenceWriterExclusion = writer)
            save(location.resolve("missing-result-terminal.json"), json.encodeToString(readback))
            readback
        }

    private fun requirePinnedOwnerProof(proof: ActivationInput, binding: BackupScheduleBinding,
        slot: BackupScheduleSlot, label: String) {
        val path = Path.of(proof.path)
        require(proof.sha256.matches(Regex("[a-f0-9]{64}")) && path.isAbsolute &&
            path.normalize() == path && path.startsWith(base.resolve(binding.generation).resolve("backup-schedule/owner-proofs")) &&
            path.fileName.toString() == "${slot.day}-$label.json" &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(path, 1048576)) == proof.sha256) {
            "Missing-result core owner $label changed or absent"
        }
    }
    private fun missingTerminal(root: Path, binding: BackupScheduleBinding, slot: BackupScheduleSlot) {
        val location = root.resolve("slots/${slot.day}")
        require(!Files.exists(location.resolve("result.json"), NOFOLLOW_LINKS)) {
            "Original schedule result arrived after absent-result terminal; stop for core review"
        }
        val intent = read(location.resolve("intent.json"))
        val disposition = json.decodeFromString<BackupScheduleMissingResultReadback>(
            read(location.resolve("missing-result-terminal.json")).decodeToString())
        require(disposition.schemaVersion == 1 && disposition.bindingSha256 == slot.bindingSha256 &&
            disposition.slot == slot && !disposition.originalAcknowledged &&
            disposition.disposition == "native-complete-original-schedule-result-absent" &&
            disposition.originalIntentSha256 == ReleaseLocks.sha256(intent))
        val nativeBytes = ReleasePrivateFiles.read(base.resolve(binding.generation)
            .resolve("backups/${slot.capture}/result.json"))
        require(disposition.nativeOutcomeSha256 == ReleaseLocks.sha256(nativeBytes))
        val native = json.decodeFromString<GenerationBackupOutcome>(nativeBytes.decodeToString())
        validateBackup(binding, slot, native)
        RecoveryReferenceOperations.authority(base, binding.generation, binding.bundleSha256).requireTerminalDaily(native)
        val worker = missingResultQuiescence(binding, slot)
        val writer = referenceWriterExclusion(binding, slot, native)
        requirePinnedOwnerProof(worker, binding, slot, "worker-quiescence")
        requirePinnedOwnerProof(writer, binding, slot, "reference-writer-exclusion")
        require(disposition.workerQuiescence == worker && disposition.referenceWriterExclusion == writer)
    }

    private fun terminal(root: Path, binding: BackupScheduleBinding, slot: BackupScheduleSlot,
        original: ByteArray, outcome: BackupScheduleResult) {
        require(outcome.slot == slot && outcome.failureType != null && outcome.backup == null)
        val disposition = json.decodeFromString<BackupScheduleTerminalReadback>(read(
            root.resolve("slots/${slot.day}/terminal-readback.json")).decodeToString())
        require(disposition.schemaVersion == 1 && !disposition.originalAcknowledged &&
            disposition.bindingSha256 == slot.bindingSha256 && disposition.slot == slot &&
            disposition.originalFailureSha256 == ReleaseLocks.sha256(original) &&
            disposition.disposition == "native-source-resumed-original-schedule-failed")
        val nativeBytes = ReleasePrivateFiles.read(base.resolve(binding.generation)
            .resolve("backups/${slot.capture}/result.json"))
        require(disposition.nativeOutcomeSha256 == ReleaseLocks.sha256(nativeBytes))
        val native = json.decodeFromString<GenerationBackupOutcome>(nativeBytes.decodeToString())
        validateBackup(binding, slot, native)
        RecoveryReferenceOperations.authority(base, binding.generation, binding.bundleSha256).requireTerminalDaily(native)
    }

    fun tick(generation: String, expected: String): BackupScheduleTick = locked(generation, expected) { root, binding ->
        checkController(binding)
        if (Files.exists(root.resolve("suspended"), NOFOLLOW_LINKS)) {
            require(read(root.resolve("suspended")).decodeToString() == expected)
            return@locked BackupScheduleTick("suspended")
        }
        val alert = Files.exists(root.resolve("failure.alert"), NOFOLLOW_LINKS)
        if (alert) require(read(root.resolve("failure.alert")).decodeToString() == expected) {
            "Unknown schedule failure alert"
        }
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
        val history = ScheduleHistory.inspect(root, expected, "daily")
        require(history.lastDay == null || latest >= history.lastDay) { "Archived daily clock rollback" }
        val prior = mutableListOf<Path>()
        Files.list(attempts).use { paths -> paths.forEach { path ->
            val day = path.fileName.toString()
            require(day.matches(Regex("[0-9]{4}-[0-9]{2}-[0-9]{2}")) && java.time.LocalDate.parse(day).toString() == day)
            if (day in history.archivedDays) {
                dir(path) // Original evidence remains present at its original path.
            } else {
                require(history.lastDay == null || day > history.lastDay) { "Unindexed old schedule slot" }
                require(prior.size < ScheduleHistory.PAGE_SIZE) { "Unresolved active history bound reached" }
                prior.add(path)
            }
        } }
        var completed = false
        for (path in prior.sorted()) {
            dir(path)
            val date = java.time.LocalDate.parse(path.fileName.toString()).toString()
            require(date == path.fileName.toString() && date <= latest && date >= day(Instant.parse(binding.enrolledAt))) { "Invalid slot or clock rollback" }
            val intent = json.decodeFromString<BackupScheduleSlot>(read(path.resolve("intent.json")).decodeToString())
            require(intent == slot(expected, date)) { "Foreign scheduled operation identity" }
            try {
                if (Files.exists(path.resolve("missing-result-terminal.json"), NOFOLLOW_LINKS))
                    missingTerminal(root, binding, intent)
                else {
                    val original = read(path.resolve("result.json"))
                    val result = json.decodeFromString<BackupScheduleResult>(original.decodeToString())
                    require(result.slot == intent)
                    if (result.failureType == null) validateBackup(binding, intent, requireNotNull(result.backup))
                    else terminal(root, binding, intent, original, result)
                }
            } catch (e: InterruptedException) { throw e }
            catch (e: Exception) { alert(root, expected); throw IllegalStateException("Unknown or failed scheduled backup; never resubmit", e) }
            if (date == latest) completed = true
        }
        if (alert) {
            val disposed = (prior.map { it.fileName.toString() } + history.archivedDays).filter { date ->
                Files.exists(attempts.resolve(date).resolve("terminal-readback.json"), NOFOLLOW_LINKS) ||
                    Files.exists(attempts.resolve(date).resolve("missing-result-terminal.json"), NOFOLLOW_LINKS)
            }
            require(disposed.size == 1) { "Schedule failure has no unique independent native readback" }
            val date = disposed.single()
            val slot = slot(expected, date)
            if (Files.exists(attempts.resolve(date).resolve("missing-result-terminal.json"), NOFOLLOW_LINKS))
                missingTerminal(root, binding, slot)
            else {
                val original = read(attempts.resolve(date).resolve("result.json"))
                terminal(root, binding, slot, original,
                    json.decodeFromString<BackupScheduleResult>(original.decodeToString()))
            }
        }
        if (completed || history.lastDay == latest)
            return@locked BackupScheduleTick(if (Files.exists(attempts.resolve(latest)
                .resolve("missing-result-terminal.json"), NOFOLLOW_LINKS)) "native-terminal-original-result-absent"
                else "already-completed", slot(expected, latest))
        if (prior.size == ScheduleHistory.PAGE_SIZE) {
            if (Files.exists(base.resolve("$generation/bundle.json"), NOFOLLOW_LINKS)) {
                val references = RecoveryReferenceOperations.authority(base, generation, binding.bundleSha256)
                prior.forEach { path ->
                    if (Files.exists(path.resolve("missing-result-terminal.json"), NOFOLLOW_LINKS)) {
                        val original = slot(expected, path.fileName.toString())
                        missingTerminal(root, binding, original)
                    } else {
                        val record = json.decodeFromString<BackupScheduleResult>(read(path.resolve("result.json")).decodeToString())
                        references.requireTerminalDaily(requireNotNull(record.backup))
                    }
                }
            }
            ScheduleHistory.checkpoint(root, expected, "daily", prior.map { it.fileName.toString() }.sorted())
        }
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
        // Production callback success is not an independent completion proof. The runtime
        // must have durably recorded the identical source resume result before this slot may
        // be considered terminal or included in an immutable history checkpoint.
        val source = base.resolve(binding.generation)
        if (Files.exists(source.resolve("bundle.json"), NOFOLLOW_LINKS)) {
            val native = json.decodeFromString<GenerationBackupOutcome>(ReleasePrivateFiles.read(
                source.resolve("backups/${slot.capture}/result.json")).decodeToString())
            require(native == result) { "Scheduled result differs from durable native source-resume outcome" }
        }
    }
}

@Serializable internal data class ScheduleHistoryEntry(val day: String, val resultSha256: String,
    val evidenceFile: String = "result.json")
@Serializable internal data class ScheduleHistorySegment(val schemaVersion: Int = 1, val kind: String,
    val bindingSha256: String, val previousSha256: String, val entries: List<ScheduleHistoryEntry>)

/** Immutable checkpoints, not removal of old slot files. Segment marker is the cursor; a
 * partial intent/segment/marker is unknown and blocks ALL further tick effects. Every read
 * authenticates the chain and each original result at its original evidence path.
 */
internal object ScheduleHistory {
    private val json = Json { encodeDefaults = true }
    private val hash = Regex("[a-f0-9]{64}")
    const val PAGE_SIZE = 128
    private const val MAX_SEGMENTS = 4096
    data class Cursor(val lastDay: String?, val head: String, val segments: Int, val archivedDays: Set<String>)
    fun inspect(root: Path, binding: String, kind: String): Cursor {
        require(binding.matches(hash) && kind in setOf("daily", "weekly"))
        val history = root.resolve("history")
        if (!Files.exists(history, NOFOLLOW_LINKS)) return Cursor(null, binding, 0, emptySet())
        ReleasePrivateFiles.directory(history)
        val files = Files.list(history).use { it.limit(MAX_SEGMENTS * 3L + 1).toList() }
        require(files.size <= MAX_SEGMENTS * 3 && files.size % 3 == 0) { "Partial schedule checkpoint retained" }
        var previous = binding; var last: String? = null
        val archived = mutableSetOf<String>()
        for (index in 1..(files.size / 3)) {
            val stem = "segment-%08d".format(index)
            val intent = ReleasePrivateFiles.read(history.resolve("$stem.intent.json"))
            val segmentBytes = ReleasePrivateFiles.read(history.resolve("$stem.json"))
            val complete = ReleasePrivateFiles.read(history.resolve("$stem.complete.json")).decodeToString()
            val segment = json.decodeFromString<ScheduleHistorySegment>(segmentBytes.decodeToString())
            val digest = ReleaseLocks.sha256(segmentBytes)
            require(segment.schemaVersion == 1 && segment.kind == kind && segment.bindingSha256 == binding &&
                segment.previousSha256 == previous && complete == digest &&
                intent.decodeToString() == "$kind\n$binding\n$previous\n" &&
                segment.entries.size == PAGE_SIZE && segment.entries.map { it.day }.distinct().size == PAGE_SIZE) {
                "Schedule checkpoint chain differs from its original completed slots"
            }
            for (entry in segment.entries) {
                require(entry.day.matches(Regex("[0-9]{4}-[0-9]{2}-[0-9]{2}")) &&
                    java.time.LocalDate.parse(entry.day).toString() == entry.day &&
                    (last == null || entry.day > last) && entry.resultSha256.matches(hash))
                require(entry.evidenceFile in setOf("result.json", "missing-result-terminal.json"))
                val location = root.resolve("slots/${entry.day}")
                if (entry.evidenceFile == "missing-result-terminal.json")
                    require(!Files.exists(location.resolve("result.json"), NOFOLLOW_LINKS)) {
                        "Original schedule ACK appeared after absent-result disposition"
                    }
                val original = ReleasePrivateFiles.read(location.resolve(entry.evidenceFile))
                require(ReleaseLocks.sha256(original) == entry.resultSha256) { "Archived slot terminal evidence changed" }
                require(archived.add(entry.day))
                last = entry.day
            }
            previous = digest
        }
        require(files.all { path ->
            val name = path.fileName.toString()
            name.matches(Regex("segment-[0-9]{8}(\\.intent|\\.complete)?\\.json")) &&
                name.substring(8, 16).toInt() in 1..(files.size / 3)
        }) { "Foreign schedule archive entry" }
        return Cursor(last, previous, files.size / 3, archived)
    }
    fun checkpoint(root: Path, binding: String, kind: String, completed: List<String>): Cursor {
        require(completed.size == PAGE_SIZE && completed == completed.sorted() && completed.distinct().size == PAGE_SIZE)
        val prior = inspect(root, binding, kind)
        require(prior.segments < MAX_SEGMENTS && completed.all { prior.lastDay == null || it > prior.lastDay })
        val history = root.resolve("history")
        if (!Files.exists(history, NOFOLLOW_LINKS)) {
            Files.createDirectory(history, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(root)
        }
        val stem = "segment-%08d".format(prior.segments + 1)
        val entries = completed.map { day ->
            val location = root.resolve("slots/$day")
            val evidence = if (Files.exists(location.resolve("missing-result-terminal.json"), NOFOLLOW_LINKS)) {
                require(!Files.exists(location.resolve("result.json"), NOFOLLOW_LINKS))
                "missing-result-terminal.json"
            } else "result.json"
            ScheduleHistoryEntry(day, ReleaseLocks.sha256(ReleasePrivateFiles.read(location.resolve(evidence))), evidence)
        }
        ReleasePrivateFiles.save(history.resolve("$stem.intent.json"), "$kind\n$binding\n${prior.head}\n".toByteArray())
        val bytes = json.encodeToString(ScheduleHistorySegment(kind = kind, bindingSha256 = binding,
            previousSha256 = prior.head, entries = entries)).toByteArray()
        ReleasePrivateFiles.save(history.resolve("$stem.json"), bytes)
        ReleasePrivateFiles.save(history.resolve("$stem.complete.json"), ReleaseLocks.sha256(bytes).toByteArray())
        return inspect(root, binding, kind)
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
