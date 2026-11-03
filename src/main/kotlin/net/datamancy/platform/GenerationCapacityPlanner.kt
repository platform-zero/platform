package net.datamancy.platform

import kotlinx.serialization.Serializable

@Serializable internal data class GenerationResources(val memoryMiB: Long, val diskMiB: Long, val objectLocks: Long) {
    init { require(memoryMiB >= 0 && diskMiB >= 0 && objectLocks >= 0) { "Negative resource reservation" } }
    operator fun plus(other: GenerationResources) = GenerationResources(Math.addExact(memoryMiB, other.memoryMiB),
        Math.addExact(diskMiB, other.diskMiB), Math.addExact(objectLocks, other.objectLocks))
}
@Serializable internal data class GenerationCapacityPlan(val steady: GenerationResources, val install: GenerationResources,
    val stopped: GenerationResources, val startup: List<GenerationStartupStep>)
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
    fun plan(specs: List<PrivateDeploymentSpec>, diskReservationMiB: Long): GenerationCapacityPlan {
        require(specs.isNotEmpty() && specs.map { it.name }.distinct().size == specs.size) { "Distinct generation members required" }
        val ordered = specs.map { it to PrivateDeployment.validate(it) }
        val minimumDisk = specs.sumOf { it.volumes.size.toLong() * 1024 }
        require(diskReservationMiB >= maxOf(1024, minimumDisk)) { "Disk reservation below state minimum" }
        var resident = 0L
        val startup = ordered.flatMap { (spec, processes) -> processes.map { process ->
            val peak = Math.addExact(resident, process.memoryMiB.toLong())
            if (!process.oneShot) resident = peak
            GenerationStartupStep("${spec.name}/${process.id}", process.oneShot, peak)
        } }
        val locks = specs.sumOf { it.processes.size.toLong() + it.volumes.size }
        val stopped = GenerationResources(0, diskReservationMiB, locks)
        return GenerationCapacityPlan(stopped.copy(memoryMiB = resident),
            stopped.copy(memoryMiB = startup.maxOf { it.memoryMiB }), stopped, startup)
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
