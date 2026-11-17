package net.datamancy.platform

import kotlinx.serialization.Serializable

@Serializable internal data class GenerationResources(val memoryMiB: Long, val diskMiB: Long, val objectLocks: Long) {
    init { require(memoryMiB >= 0 && diskMiB >= 0 && objectLocks >= 0) { "Negative resource reservation" } }
    operator fun plus(other: GenerationResources) = GenerationResources(Math.addExact(memoryMiB, other.memoryMiB),
        Math.addExact(diskMiB, other.diskMiB), Math.addExact(objectLocks, other.objectLocks))
}
@Serializable internal data class GenerationCapacityPlan(val steady: GenerationResources, val install: GenerationResources,
    val stopped: GenerationResources, val startup: List<GenerationStartupStep>,
    /** Diagnostic only. A cgroup ceiling is never silently treated as actual resident work. */
    val steadyHardCeilingsMiB: Long = steady.memoryMiB,
    /** Initial first-start admission uses a live next-stage bound instead of pretending
     * the whole candidate has already consumed its prospective steady working budget. */
    val incrementalFirstStart: Boolean = false)
/** An explicit, sealed per-process *working* envelope, not a change to OCI
 * MemoryMax. A caller cannot omit an expensive process, one-shot or idle agent.
 * Initial values may be conservatively derived from pinned selected heap/worker
 * settings, OLD topology, host baseline and an explicit next-stage allowance;
 * fresh-r9 RSS cannot exist before first startup and is not a prerequisite.
 * Native stepwise headroom is checked before/after each original start, and
 * observations refine subsequent admission without retroactively rewriting it.
 */
@Serializable internal data class GenerationWorkingBudget(val evidence: ActivationInput,
    val workingMiB: Map<String, Long>, val scope: String = "r9-full-private-working-envelope")
@Serializable internal data class GenerationStartupStep(val process: String, val oneShot: Boolean, val memoryMiB: Long)
@Serializable internal enum class GenerationPhase { INSTALL, STEADY, BACKUP, RESTORE_IMPORT, RESTORE_VERIFY, UPDATE }
@Serializable internal enum class SourceCapacityMode { RUNNING, ISOLATED }
@Serializable internal data class GenerationPhaseReservation(val phase: GenerationPhase, val resources: GenerationResources,
    val sourceMode: SourceCapacityMode, val memoryHeadroomMiB: Long, val diskHeadroomMiB: Long)

/** Pure resource arithmetic, not permission to stop/resume a source. Callers must verify isolation under
 * their operation lease before choosing ISOLATED. Stopped objects and volumes still consume capacity.
 * The startup trace matches serial member staging and PrivateDeployment's serial topological apply.
 * Limits are never reduced to measured RSS. Existing legacy bundle reservations remain unchanged.
 */
internal object GenerationCapacityPlanner {
    fun plan(specs: List<PrivateDeploymentSpec>, diskReservationMiB: Long,
        budget: GenerationWorkingBudget? = null): GenerationCapacityPlan {
        require(specs.isNotEmpty() && specs.map { it.name }.distinct().size == specs.size) { "Distinct generation members required" }
        val ordered = specs.map { it to PrivateDeployment.validate(it) }
        val minimumDisk = specs.sumOf { it.volumes.size.toLong() * 1024 }
        require(diskReservationMiB >= maxOf(1024, minimumDisk)) { "Disk reservation below state minimum" }
        val selected = ordered.flatMap { (spec, processes) -> processes.map { "${spec.name}/${it.id}" to it } }
        val selectedBootstrapNotebooks = specs.filter { spec ->
            val generation=spec.name.take(14)
            NotebookSelectedGraph.selected(GenerationRuntime.BASE.resolve(generation),spec)
        }.flatMap { spec -> listOf("alice","bob").map { "${spec.name}/$it" } }.toSet()
        budget?.let { bound ->
            require(bound.scope in setOf("r9-full-private-working-envelope",
                    "r9-full-private-incremental-first-start", "r10-full-private-incremental-first-start") &&
                bound.evidence.sha256.matches(Regex("[a-f0-9]{64}")) &&
                bound.workingMiB.keys == selected.map { it.first }.toSet() &&
                bound.workingMiB.size == selected.size && selected.all { (id,process) ->
                    bound.workingMiB.getValue(id) in 64L..process.memoryMiB.toLong() &&
                        // This is the assembled full-graph member, NOT a fictitious
                        // `-jupyterhub` member. Both containers run together during
                        // original stage; keep their hard ceilings reserved until
                        // stage retirement and active-episode accounting have an
                        // admitted, independently evidenced working envelope.
                        (id !in selectedBootstrapNotebooks ||
                            bound.workingMiB.getValue(id) == process.memoryMiB.toLong())
                }) { "Incomplete or unbounded whole-generation working budget" }
        }
        var resident = 0L
        val startup = selected.map { (id, process) ->
            val peak = Math.addExact(resident, budget?.workingMiB?.getValue(id) ?: process.memoryMiB.toLong())
            if (!process.oneShot) resident = peak
            GenerationStartupStep(id, process.oneShot, peak)
        }
        val locks = specs.sumOf { it.processes.size.toLong() + it.volumes.size }
        val stopped = GenerationResources(0, diskReservationMiB, locks)
        val incremental = budget?.scope in setOf("r9-full-private-incremental-first-start",
            "r10-full-private-incremental-first-start")
        // Before original startup the selected *prospective* per-daemon working
        // model is NOT already resident. One serialized process can consume its
        // unchanged cgroup ceiling, plus 512 MiB for owner/conmon startup work.
        // Native owner stage rechecks the real host before EACH original intent and
        // after readiness. This does not assert any prior fresh-generation RSS.
        val initialStep = selected.maxOf { Math.addExact(it.second.memoryMiB.toLong(), 512L) }
        return GenerationCapacityPlan(stopped.copy(memoryMiB = resident),
            stopped.copy(memoryMiB = if (incremental) initialStep else startup.maxOf { it.memoryMiB }),
            stopped, startup, selected.filterNot { it.second.oneShot }.sumOf { it.second.memoryMiB.toLong() },
            incrementalFirstStart = incremental)
    }

    /** Work includes pinned helper/client limits AND their additional disk footprint. Snapshot/import
     * callers must supply bounded archive/scratch reservations; a zero scratch estimate is refused.
     * Retained allocations are separate so neither a stopped source nor other generations disappear.
     */
    fun phase(target: GenerationCapacityPlan, phase: GenerationPhase, source: GenerationCapacityPlan? = null,
        sourceMode: SourceCapacityMode = SourceCapacityMode.RUNNING,
        work: GenerationResources = GenerationResources(0, 0, 0),
        retained: GenerationResources = GenerationResources(0, 0, 0),
        memoryHeadroomMiB: Long = 16384, diskHeadroomMiB: Long = 10240): GenerationPhaseReservation {
        require(memoryHeadroomMiB in 16384..1048576 && diskHeadroomMiB in 10240..10485760) { "Unsafe capacity headroom" }
        require(!target.incrementalFirstStart || phase == GenerationPhase.INSTALL) {
            "Provisional first-start budget cannot stand in for captured steady, backup or RESTORE demand"
        }
        require(source != null || sourceMode == SourceCapacityMode.RUNNING) { "Source mode without a source" }
        require(phase != GenerationPhase.UPDATE || source != null) { "Update requires the retained source reservation" }
        if (phase in setOf(GenerationPhase.BACKUP, GenerationPhase.RESTORE_IMPORT)) {
            require(work.memoryMiB >= 1024 && work.diskMiB > 0 && work.objectLocks >= 1) { "Explicit Kopia worker and scratch reservation required" }
        }
        val targetResources = when (phase) {
            GenerationPhase.INSTALL, GenerationPhase.UPDATE -> target.install
            GenerationPhase.STEADY, GenerationPhase.RESTORE_VERIFY -> target.steady
            GenerationPhase.BACKUP, GenerationPhase.RESTORE_IMPORT -> target.stopped
        }
        val sourceResources = source?.let { if (sourceMode == SourceCapacityMode.RUNNING) it.steady else it.stopped }
            ?: GenerationResources(0, 0, 0)
        return GenerationPhaseReservation(phase, targetResources + sourceResources + work + retained,
            sourceMode, memoryHeadroomMiB, diskHeadroomMiB)
    }

    fun admit(reservation: GenerationPhaseReservation, availableMemoryMiB: Long, usableDiskMiB: Long, availableLocks: Long) {
        require(availableMemoryMiB >= 0 && usableDiskMiB >= 0 && availableLocks >= 0) { "Unknown available capacity" }
        val required = reservation.resources
        require(availableMemoryMiB >= Math.addExact(required.memoryMiB, reservation.memoryHeadroomMiB) &&
            usableDiskMiB >= Math.addExact(required.diskMiB, reservation.diskHeadroomMiB)) {
            "Insufficient phase capacity; no workload eviction or implicit maintenance fallback"
        }
        val locks = Math.addExact(required.objectLocks, RuntimeLockBudget.TRANSIENT_HEADROOM)
        if (availableLocks < locks) throw InsufficientRuntimeLocks(availableLocks, locks)
    }
}
