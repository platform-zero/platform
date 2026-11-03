package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.time.DayOfWeek
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.time.temporal.TemporalAdjusters
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable internal data class WeeklyRestoreBinding(val source: BackupScheduleBinding, val evaluatorSha256: String,
    val requiredAssertions: Set<String>)
@Serializable internal data class WeeklyRestoreSlot(val bindingSha256: String, val sunday: String, val operation: String, val target: String)
@Serializable internal data class WeeklyFunctionalResult(val operation: String, val target: String, val targetBundleSha256: String,
    val snapshotId: String, val assertions: Set<String>, val passed: Boolean)
@Serializable internal data class WeeklyRestoreResult(val operation: String, val target: String, val targetBundleSha256: String,
    val snapshot: KopiaSnapshotReceipt, val functional: WeeklyFunctionalResult, val requiredAssertions: Set<String>,
    val targetIsolation: GenerationOutcome, val sourceResumed: Boolean)
@Serializable internal data class WeeklyRestoreTick(val status: String, val slot: WeeklyRestoreSlot? = null,
    val result: WeeklyRestoreResult? = null)

internal interface WeeklyRestoreBackend {
    fun holdSource(): GenerationHeldCapture
    fun restore(snapshot: KopiaSnapshotReceipt): GenerationOutcome
    fun startTarget(imported: GenerationOutcome)
    fun verify(snapshot: KopiaSnapshotReceipt, imported: GenerationOutcome, deadline: Instant): WeeklyFunctionalResult
    fun isolateTarget(imported: GenerationOutcome): GenerationOutcome
    fun verifyTargetIsolation(isolation: GenerationOutcome)
    fun resumeSource(fences: Map<String, String>)
}

/** Single-use weekly restore ledger. Failure, timeout, interruption and unknown results NEVER resume
 * the source or authorize another target. Isolation is observed before any source fence release.
 * Functional evidence comes from a separately pinned evaluator, not from container health checks.
 */
internal class WeeklyRestoreSchedule(private val base: Path, private val now: () -> Instant,
    private val controller: (WeeklyRestoreBinding) -> Unit,
    private val checkSource: (AcquiredInventory, String, String) -> Unit,
    private val backend: (WeeklyRestoreBinding, WeeklyRestoreSlot, AcquiredInventory, Path) -> WeeklyRestoreBackend,
    private val references: (String) -> RecoveryReferences,
    private val retention: (AcquiredInventory, String, String, String) -> KopiaRetentionResult,
    private val monotonicNanos: () -> Long = System::nanoTime) {
    companion object {
        private val json = Json { encodeDefaults = true }
        private val hash = Regex("[a-f0-9]{64}")
        const val BUDGET_SECONDS = 8 * 60 * 60L
        fun sunday(at: Instant): String {
            val utc = at.atZone(ZoneOffset.UTC)
            var due = utc.with(TemporalAdjusters.previousOrSame(DayOfWeek.SUNDAY)).withHour(4).withMinute(0).withSecond(0).withNano(0)
            if (due.toInstant() > at) due = due.minusWeeks(1)
            return due.toLocalDate().toString()
        }
        fun slot(binding: String, sunday: String): WeeklyRestoreSlot {
            require(binding.matches(hash) && java.time.LocalDate.parse(sunday).dayOfWeek == DayOfWeek.SUNDAY)
            val id = ReleaseLocks.sha256("weekly-restore-v1\n$binding\n$sunday".toByteArray()).take(12)
            return WeeklyRestoreSlot(binding, sunday, "cap-$id", "q-$id")
        }
        fun validate(binding: WeeklyRestoreBinding) {
            GenerationBackupSchedule.validate(binding.source)
            require(binding.evaluatorSha256.matches(hash) && binding.requiredAssertions.isNotEmpty() && binding.requiredAssertions.size <= 256 &&
                binding.requiredAssertions.all { it.matches(Regex("[a-z0-9][a-z0-9_.:-]{0,127}")) })
        }
        fun validateResult(result: WeeklyRestoreResult) {
            KopiaGenerationStore.validate(result.snapshot)
            RuntimeBackupAccess(result.snapshot.generation, result.operation, result.snapshot.bundleSha256).validate()
            require(result.target.matches(Regex("q-[a-f0-9]{12}")) && result.target != result.snapshot.generation && result.targetBundleSha256.matches(hash))
            require(result.requiredAssertions.isNotEmpty() && result.functional == WeeklyFunctionalResult(result.operation, result.target,
                result.targetBundleSha256, result.snapshot.snapshotId, result.requiredAssertions, true)) { "Incomplete or foreign functional restore evaluation" }
            require(result.sourceResumed && result.targetIsolation.passed && result.targetIsolation.failureType == null &&
                result.targetIsolation.action == "isolate" && result.targetIsolation.bundleSha256 == result.targetBundleSha256 &&
                result.targetIsolation.fences.isNotEmpty() && result.targetIsolation.fences.keys.all { it.startsWith(result.target + "-") } &&
                result.targetIsolation.fences.values.all { it.matches(Regex("[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}")) }) {
                "Source resume requires verified target isolation"
            }
        }
        fun real(): WeeklyRestoreSchedule {
            val runtime = GenerationRuntime.real()
            return WeeklyRestoreSchedule(GenerationRuntime.BASE, Instant::now, { binding ->
                PinnedBackupController.verify(binding.source.controllerSha256)
            }, runtime::checkBackupSource, { binding, slot, inventory, attempt ->
                NativeWeeklyRestoreBackend(GenerationRuntime.BASE, binding, slot, inventory, attempt, runtime)
            }, { generation -> RecoveryReferences(GenerationRuntime.BASE.resolve("$generation/recovery-references")) }, runtime::retainKopia)
        }
    }
    private fun root(generation: String): Path {
        require(generation.matches(Regex("q-[a-f0-9]{12}")))
        ReleasePrivateFiles.directory(base); ReleasePrivateFiles.directory(base.resolve(generation))
        return base.resolve("$generation/weekly-restore")
    }
    private fun mkdir(path: Path) {
        Files.createDirectory(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.sync(path.parent)
    }
    private inline fun <reified T> read(path: Path): T = json.decodeFromString(ReleasePrivateFiles.read(path).decodeToString())
    private inline fun <reified T> save(path: Path, value: T) = ReleasePrivateFiles.save(path, json.encodeToString(value).toByteArray())
    fun enroll(inventory: ByteArray, binding: WeeklyRestoreBinding, functionalPlan: ByteArray): String {
        validate(binding)
        require(ReleaseLocks.sha256(functionalPlan) == binding.evaluatorSha256)
        WeeklyFunctionalVerifier.validate(json.decodeFromString(functionalPlan.decodeToString()), binding.requiredAssertions)
        require(binding.source.userId.toLong() == UnixSystem().uid && binding.source.inventorySha256 == ReleaseLocks.sha256(inventory) &&
            Duration.between(Instant.parse(binding.source.enrolledAt), now()).seconds in 0..60) { "Enrollment must bind current time, owner and inventory" }
        controller(binding)
        checkSource(json.decodeFromString(inventory.decodeToString()), binding.source.generation, binding.source.bundleSha256)
        val root = root(binding.source.generation); mkdir(root)
        save(root.resolve("binding.json"), binding)
        ReleasePrivateFiles.save(root.resolve("inventory.json"), inventory)
        ReleasePrivateFiles.save(root.resolve("functional-plan.json"), functionalPlan)
        val expected = ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("binding.json")))
        ReleasePrivateFiles.save(root.resolve("enrolled"), expected.toByteArray())
        return expected
    }
    private fun binding(root: Path, expected: String): WeeklyRestoreBinding {
        require(expected.matches(hash))
        val bytes = ReleasePrivateFiles.read(root.resolve("binding.json"))
        require(ReleaseLocks.sha256(bytes) == expected && ReleasePrivateFiles.read(root.resolve("enrolled")).decodeToString() == expected)
        return json.decodeFromString<WeeklyRestoreBinding>(bytes.decodeToString()).also {
            validate(it); require(it.source.generation == root.parent.fileName.toString() && it.source.userId.toLong() == UnixSystem().uid)
        }
    }
    private fun alert(root: Path, expected: String) {
        val path = root.resolve("failure.alert")
        if (Files.exists(path, NOFOLLOW_LINKS)) require(ReleasePrivateFiles.read(path).decodeToString() == expected)
        else ReleasePrivateFiles.save(path, expected.toByteArray())
    }
    fun signalFailure(generation: String, expected: String) = ReleasePrivateFiles.locked(root(generation)) {
        val root = root(generation); controller(binding(root, expected)); alert(root, expected)
    }
    fun suspend(generation: String, expected: String) = ReleasePrivateFiles.locked(root(generation)) {
        val root = root(generation); controller(binding(root, expected))
        val path = root.resolve("suspended")
        if (Files.exists(path, NOFOLLOW_LINKS)) require(ReleasePrivateFiles.read(path).decodeToString() == expected)
        else ReleasePrivateFiles.save(path, expected.toByteArray())
    }
    fun units(generation: String, expected: String): Map<String, String> = WeeklyRestoreUnits.render(binding(root(generation), expected), expected)
    fun tick(generation: String, expected: String): WeeklyRestoreTick = ReleasePrivateFiles.locked(root(generation)) {
        val root = root(generation); val binding = binding(root, expected); controller(binding)
        if (Files.exists(root.resolve("suspended"), NOFOLLOW_LINKS)) {
            require(ReleasePrivateFiles.read(root.resolve("suspended")).decodeToString() == expected)
            return@locked WeeklyRestoreTick("suspended")
        }
        require(!Files.exists(root.resolve("failure.alert"), NOFOLLOW_LINKS)) { "Weekly failure retained; no retry" }
        val current = now(); require(current >= Instant.parse(binding.source.enrolledAt))
        val due = sunday(current)
        val attempts = root.resolve("slots")
        if (!Files.exists(attempts, NOFOLLOW_LINKS)) mkdir(attempts)
        ReleasePrivateFiles.directory(attempts)
        val prior = Files.list(attempts).use { it.limit(129).toList() }; require(prior.size <= 128)
        var completed: WeeklyRestoreResult? = null
        for (attempt in prior) {
            ReleasePrivateFiles.directory(attempt)
            val date = attempt.fileName.toString()
            require(date <= due && date >= sunday(Instant.parse(binding.source.enrolledAt))) { "Clock rollback or foreign weekly slot" }
            val intent = read<WeeklyRestoreSlot>(attempt.resolve("intent.json")); require(intent == slot(expected, date))
            try {
                val result = read<WeeklyRestoreResult>(attempt.resolve("result.json")); validateResult(result)
                require(result.operation == intent.operation && result.target == intent.target && result.snapshot.generation == generation &&
                    result.snapshot.bundleSha256 == binding.source.bundleSha256 && result.requiredAssertions == binding.requiredAssertions)
                if (date == due) completed = result
            } catch (e: Exception) { alert(root, expected); throw IllegalStateException("Unknown weekly outcome; never retry or resume", e) }
        }
        if (completed != null) return@locked WeeklyRestoreTick("already-completed", slot(expected, due), completed)
        require(prior.size < 128)
        val inventory = ReleasePrivateFiles.read(root.resolve("inventory.json"))
        require(ReleaseLocks.sha256(inventory) == binding.source.inventorySha256)
        val slot = slot(expected, due); require(slot.target != generation)
        val attempt = attempts.resolve(due); mkdir(attempt); save(attempt.resolve("intent.json"), slot)
        val deadline = current.plusSeconds(BUDGET_SECONDS)
        val started = monotonicNanos()
        var lastObserved = current
        fun budget() {
            check(!Thread.currentThread().isInterrupted) { "Weekly worker interrupted" }
            val observed = now(); val elapsed = monotonicNanos() - started
            check(observed >= lastObserved && observed < deadline && elapsed in 0 until BUDGET_SECONDS * 1_000_000_000L) {
                "Weekly budget exhausted or clock rolled back; source stays fenced"
            }
            lastObserved = observed
        }
        fun <T> effect(name: String, action: () -> T): T {
            budget(); save(attempt.resolve("$name.intent.json"), slot)
            return action().also { budget(); save(attempt.resolve("$name.complete.json"), slot) }
        }
        try {
            val native = backend(binding, slot, json.decodeFromString(inventory.decodeToString()), attempt)
            val held = effect("hold-source", native::holdSource).also { it.validate() }
            val snapshot = held.snapshot; KopiaGenerationStore.validate(snapshot)
            require(held.access == RuntimeBackupAccess(generation, slot.operation, binding.source.bundleSha256) &&
                snapshot.generation == generation && snapshot.bundleSha256 == binding.source.bundleSha256 && snapshot.id == slot.operation)
            val refs = references(generation); refs.register(snapshot); refs.protect("weekly", slot.operation, setOf(snapshot.snapshotId))
            save(attempt.resolve("snapshot.json"), snapshot)
            val fences = held.fences; save(attempt.resolve("source-fences.json"), fences)
            val imported = effect("restore") { native.restore(snapshot) }
            require(imported.passed && imported.action == "restore-import" && imported.failureType == null)
            save(attempt.resolve("import.json"), imported)
            effect("start-target") { native.startTarget(imported) }
            val functional = effect("functional") { native.verify(snapshot, imported, deadline) }
            require(functional == WeeklyFunctionalResult(slot.operation, slot.target, imported.bundleSha256, snapshot.snapshotId, binding.requiredAssertions, true))
            save(attempt.resolve("functional.json"), functional)
            val isolation = effect("isolate-target") { native.isolateTarget(imported) }
            require(isolation.passed && isolation.action == "isolate" && isolation.bundleSha256 == imported.bundleSha256 && isolation.failureType == null)
            effect("verify-isolation") { native.verifyTargetIsolation(isolation) }
            save(attempt.resolve("isolation.json"), isolation)
            effect("resume-source") { native.resumeSource(fences) }
            val result = WeeklyRestoreResult(slot.operation, slot.target, imported.bundleSha256, snapshot, functional, binding.requiredAssertions, isolation, true)
            validateResult(result)
            refs.verified(result)
            if (refs.retentionReady()) {
                val retained = effect("retention") { retention(json.decodeFromString(inventory.decodeToString()), generation,
                    binding.source.bundleSha256, "r-" + slot.operation.removePrefix("cap-")) }
                save(attempt.resolve("retention.json"), retained)
            }
            save(attempt.resolve("result.json"), result)
            WeeklyRestoreTick("completed", slot, result)
        } catch (e: Exception) {
            val interrupted = Thread.interrupted() || e is InterruptedException
            try { try { save(attempt.resolve("failure.json"), mapOf("type" to e.javaClass.name)) } finally { alert(root, expected) } }
            finally { if (interrupted) Thread.currentThread().interrupt() }
            throw e
        }
    }
}

internal object WeeklyRestoreUnits {
    fun render(binding: WeeklyRestoreBinding, expected: String): Map<String, String> {
        WeeklyRestoreSchedule.validate(binding); require(expected.matches(Regex("[a-f0-9]{64}")))
        val source = binding.source; val name = "p0v3-weekly-restore-${source.generation}"
        val cli = "/mnt/media/p0-v3/runtime-supervision/releases/${source.controllerSha256}/bin/p0-v3-platform"
        fun service(operation: String, failure: Boolean) = """
            # Managed by p0v3-weekly-restore-v1; no promotion authority.
            [Unit]
            Description=Weekly functional restore ${source.generation}
            RequiresMountsFor=/mnt/media/p0-v3 /run/p0-v3-release-runtime
            After=apparmor.service
            ${if (failure) "OnFailure=$name-alert.service" else ""}
            [Service]
            Type=oneshot
            User=${source.userId}
            UMask=0077
            Environment=JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
            Environment="JAVA_OPTS=-Xms32m -Xmx512m"
            ExecStart=$cli release $operation ${source.generation} $expected
            TimeoutStartSec=28800
            TimeoutStopSec=30
            KillMode=process
            Restart=no
            StandardOutput=journal
            StandardError=journal
        """.trimIndent() + "\n"
        return linkedMapOf("$name.service" to service("weekly-restore-tick", true), "$name-alert.service" to service("weekly-restore-alert", false),
            "$name.timer" to """
                # Managed by p0v3-weekly-restore-v1; only latest missed Sunday is eligible.
                [Unit]
                Description=Weekly functional restore timer ${source.generation}
                [Timer]
                OnCalendar=Sun *-*-* 04:00:00 UTC
                OnActiveSec=5s
                Persistent=true
                AccuracySec=1s
                Unit=$name.service
                [Install]
                WantedBy=timers.target
            """.trimIndent() + "\n")
    }
}

/** Real runtime adapter. Restored inputs never inherit scheduler or public activation authority. */
internal class NativeWeeklyRestoreBackend(private val base: Path, private val binding: WeeklyRestoreBinding,
    private val slot: WeeklyRestoreSlot, private val inventory: AcquiredInventory, private val attempt: Path,
    private val runtime: GenerationRuntime) : WeeklyRestoreBackend {
    private val json = Json { encodeDefaults = true }
    private fun bundle(generation: String, expected: String): GenerationBundle {
        val bytes = GenerationRuntime.privateInput(base.resolve("$generation/bundle.json"))
        require(ReleaseLocks.sha256(bytes) == expected)
        return json.decodeFromString<GenerationBundle>(bytes.decodeToString()).also { require(it.request.id == generation) }
    }
    private val source = bundle(binding.source.generation, binding.source.bundleSha256)
    private var held: GenerationHeldCapture? = null
    private var targetBundle: String? = null
    private fun members(bundle: GenerationBundle) = GenerationRuntime.validateScope(bundle.request).map { member -> bundle.members.single { it.member == member }.spec }
    private fun functionalPlan(): WeeklyFunctionalPlan {
        val bytes = ReleasePrivateFiles.read(attempt.parent.parent.resolve("functional-plan.json"))
        require(ReleaseLocks.sha256(bytes) == binding.evaluatorSha256)
        val plan = json.decodeFromString<WeeklyFunctionalPlan>(bytes.decodeToString())
        WeeklyFunctionalVerifier.validate(plan, binding.requiredAssertions)
        require(WeeklyFunctionalVerifier.candidateHash(plan) == (source.request.releaseCandidateSha256 ?: source.request.candidateSha256))
        fun capabilities(value: GenerationBundle, depth: Int): Set<String> {
            require(depth <= 8) { "Recovery lineage bound exceeded" }
            value.ownership?.let { return it.assembly.members.flatMap { member -> member.primaryCapabilities }.toSet() }
            val original = requireNotNull(value.recoverySourceKopia) { "Owned functional coverage closure required" }
            return capabilities(bundle(original.generation, original.bundleSha256), depth + 1)
        }
        val required = capabilities(source, 0) - "backup-restore"
        require(required.isNotEmpty() && plan.cases.map { it.serviceId }.toSet().containsAll(required)) { "Functional plan omits source capabilities" }
        return plan
    }
    override fun holdSource(): GenerationHeldCapture {
        WeeklyFunctionalVerifier.validateInstalled(functionalPlan()) // Fail missing/tampered probes before source maintenance.
        return runtime.holdKopiaForRestore(inventory, binding.source.generation,
            binding.source.bundleSha256, slot.operation).also { held = it }
    }
    override fun restore(snapshot: KopiaSnapshotReceipt) = runtime.restoreKopiaWholeRelease(inventory, snapshot.generation, snapshot.bundleSha256,
        snapshot.id, slot.target, targetStore = source.request.store).also { targetBundle = it.bundleSha256 }
    override fun startTarget(imported: GenerationOutcome) {
        require(imported == json.decodeFromString<GenerationOutcome>(ReleasePrivateFiles.read(
            base.resolve("${slot.target}/stage.result.json")).decodeToString()))
        check(runtime.startRestored(inventory, slot.target, imported.bundleSha256).passed) { "Weekly restore startup failed" }
    }
    override fun verify(snapshot: KopiaSnapshotReceipt, imported: GenerationOutcome, deadline: Instant): WeeklyFunctionalResult {
        return WeeklyFunctionalVerifier.real().verify(functionalPlan(),
            WeeklyFunctionalRequest(slot.operation, snapshot, slot.target, imported.bundleSha256, binding.requiredAssertions), attempt, deadline)
    }
    override fun isolateTarget(imported: GenerationOutcome) = runtime.isolate(slot.target, imported.bundleSha256)
    override fun verifyTargetIsolation(isolation: GenerationOutcome) {
        val target = bundle(slot.target, isolation.bundleSha256)
        require(isolation.fences.keys == target.members.map { it.spec.name }.toSet())
        val native = PrivateDeployment.real(target.members.associate { it.member.name to it.runtimeFingerprint })
        for (spec in members(target)) {
            require(native.maintenanceStatus(spec)?.id == isolation.fences.getValue(spec.name))
            require(native.status(spec).none { it.state in setOf("running", "paused", "restarting", "created") }) { "Target isolation not observed" }
        }
    }
    override fun resumeSource(fences: Map<String, String>) {
        val hold = requireNotNull(held); require(fences == hold.fences)
        val result = runtime.resumeHeldSourceAfterIsolation(inventory, binding.source.generation, binding.source.bundleSha256,
            slot.operation, hold.sha256, slot.target, requireNotNull(targetBundle))
        require(result.passed && result.sourceResumed && result.snapshot == hold.snapshot && result.failureType == null)
    }
}

@Serializable internal data class WeeklyFunctionalRequest(val operation: String, val snapshot: KopiaSnapshotReceipt,
    val target: String, val targetBundleSha256: String, val requiredAssertions: Set<String>)
