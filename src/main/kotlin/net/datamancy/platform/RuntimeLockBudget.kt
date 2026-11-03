package net.datamancy.platform

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

internal class InsufficientRuntimeLocks(val available: Long, val required: Long) : IllegalArgumentException(
    "Insufficient dedicated runtime object locks; preserve retained resources and do not renumber shared locks")

/** Podman containers, pods and volumes consume persistent engine locks even while stopped.
 * No renumbering, pruning, configuration mutation or default-store fallback is authorized here.
 */
internal object RuntimeLockBudget {
    const val TRANSIENT_HEADROOM = 4L
    const val ISOLATED_OBJECT_LIMIT = 4096L
    fun available(commands: RuntimeCommands, runtimeStore: RuntimeStore = RuntimeStore.LEGACY): Long {
        val result = commands.run(listOf("info", "--format", "json"))
        require(result.exitCode == 0) { "Runtime lock capacity observation failed" }
        val info = Json.parseToJsonElement(result.output).jsonObject
        val store = info.getValue("store").jsonObject
        require(store.getValue("graphRoot").jsonPrimitive.content == runtimeStore.graph &&
            store.getValue("runRoot").jsonPrimitive.content == runtimeStore.run) { "Dedicated store lock observation required" }
        val locks = info.getValue("host").jsonObject["freeLocks"]?.jsonPrimitive
        if (runtimeStore == RuntimeStore.CANONICAL_V2) {
            require(locks == null || locks == JsonNull) { "Isolated file-lock backend required" }
            // File locks have no semaphore ceiling; impose a bounded project policy rather than treating null as infinity.
            val used = listOf(listOf("ps", "-aq", "--no-trunc"), listOf("pod", "ps", "-q", "--no-trunc"),
                listOf("volume", "ls", "-q")).sumOf { args ->
                val count = commands.run(args)
                require(count.exitCode == 0 && count.output.length <= 1048576) { "Runtime object census failed" }
                val ids = count.output.lineSequence().filter { it.isNotBlank() }.toList()
                require(ids.size <= ISOLATED_OBJECT_LIMIT && ids.distinct().size == ids.size &&
                    ids.all { it.matches(Regex("[a-zA-Z0-9][a-zA-Z0-9_.-]{0,255}")) }) { "Invalid runtime object census" }
                ids.size.toLong()
            }
            return (ISOLATED_OBJECT_LIMIT - used).coerceAtLeast(0)
        }
        require(locks != null && !locks.isString) { "Numeric runtime lock capacity required" }
        return locks.long.also {
            require(it in 0..Int.MAX_VALUE.toLong()) { "Unknown runtime lock capacity" }
        }
    }
    fun requireAvailable(available: Long, specs: List<PrivateDeploymentSpec> = emptyList(), workers: Int = 0) {
        require(workers in 0..3)
        val needed = specs.sumOf { it.processes.size.toLong() + it.volumes.size } + workers + TRANSIENT_HEADROOM
        if (available < needed) throw InsufficientRuntimeLocks(available, needed)
    }
}
