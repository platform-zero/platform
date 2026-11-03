package net.datamancy.platform

/** Renders ONLY an offline Caddyfile; no DNS change, certificate request, API load, or public listener. */
enum class AcmeEnvironment(val directory: String) {
    STAGING("https://acme-staging-v02.api.letsencrypt.org/directory"),
    PRODUCTION("https://acme-v02.api.letsencrypt.org/directory")
}

object CaddyConfig {
    fun offline(lock: ReleaseLock, approvedHosts: Set<String>, environment: AcmeEnvironment): String {
        ReleaseLocks.check(lock, approvedHosts)
        val caddy = lock.products.single { it.id == "caddy" }
        require(caddy.processes.any { it.id == "caddy" && it.role == ProcessRole.DAEMON &&
            it.networks.containsAll(listOf(NetworkRole.APP, NetworkRole.INGRESS)) &&
            it.stateIds.any { stateId -> caddy.state.any { it.id == stateId && it.containerPath == "/data" } } }) {
            "Caddy needs an app/ingress process and a durable /data state set for ACME"
        }
        val routes = lock.products.flatMap { it.routes }
        require(routes.all { AcmePreflight.hostPattern.matches(it.host) }) { "Exact approved datamancy.net subdomains only; no apex or wildcard" }
        require(routes.isNotEmpty() && routes.none { it.processId == "caddy" } && routes.all { route ->
            lock.products.flatMap { it.processes }.single { it.id == route.processId }.networks.contains(NetworkRole.APP)
        }) { "Caddy cannot proxy to itself or an unreachable private backend" }
        return buildString {
            append("{\n")
            append("    storage file_system /data/caddy\n")
            append("    cert_issuer acme {\n")
            append("        dir ${environment.directory}\n")
            append("        disable_tlsalpn_challenge\n")
            append("    }\n")
            append("}\n\n")
            routes.sortedBy { it.host }.forEach { route ->
                append("${route.host} {\n")
                append("    reverse_proxy p0v3-${route.processId}:${route.port}\n")
                append("}\n\n")
            }
        }
    }
}
