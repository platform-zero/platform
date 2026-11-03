package net.datamancy.platform

import kotlinx.serialization.Serializable

/** Offline dependency ordering only. Not a Podman/systemd or migration plan. */
@Serializable data class ReleasePlan(val lockDigest: String, val processOrder: List<String>,
    val outwardHosts: List<String>, val stateOwners: List<String>, val executable: Boolean = false)

object ReleasePlanning {
    fun offline(lock: ReleaseLock, digest: String): ReleasePlan {
        require(digest.matches(Regex("[a-f0-9]{64}"))) { "Invalid digest" }
        val byId = lock.products.flatMap { it.processes }.associateBy { it.id }
        val visited = mutableSetOf<String>()
        val visiting = mutableSetOf<String>()
        val ordered = mutableListOf<String>()
        fun visit(id: String) {
            if (id in visited) return
            require(visiting.add(id)) { "Dependency cycle" }
            byId.getValue(id).dependencies.sorted().forEach(::visit)
            visiting.remove(id)
            visited.add(id)
            ordered += id
        }
        byId.keys.sorted().forEach(::visit)
        return ReleasePlan(digest, ordered, lock.products.flatMap { it.routes }.map { it.host }.sorted(),
            lock.products.flatMap { it.state }.map { it.owner }.distinct().sorted())
    }
}
