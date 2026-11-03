package net.datamancy.platform

/** Exact, reviewed cold-start projections. Caller must verify compiled recipe equality and import first. */
internal object BusinessApplicationRecovery {
    private val initializers = mapOf(
        "erpnext" to setOf("mariadb-init", "site-config-init", "site-init", "installer-retire"),
        "firefly" to setOf("postgres-init", "firefly-db-init", "firefly-files-init", "firefly-migrate"),
        "bookstack" to setOf("mariadb-init", "bookstack-files-init", "bookstack-migrate"),
        "sogo" to setOf("database-init", "accounts-init"),
        "mail" to setOf("mail-init"),
        "sogo-mail" to setOf("database-init", "accounts-init", "mail-init"),
        "node-metrics" to setOf("metrics-init"),
        "qbittorrent" to setOf("config-init"),
        "searxng" to setOf("corpus-init"),
        "opensearch" to setOf("search-config-init", "search-security-init")
    )
    val recipes: Set<String> get() = initializers.keys.toSet()

    fun coldRestoreSpec(recipe: String, compiled: PrivateDeploymentSpec): PrivateDeploymentSpec {
        val retired = requireNotNull(initializers[recipe]) { "Unsupported business/mail cold-start projection" }
        PrivateDeployment.validate(compiled)
        require(compiled.processes.filter { it.oneShot }.map { it.id }.toSet() == retired) {
            "Compiled recipe initializer set changed; review recovery before accepting it"
        }
        val byId = compiled.processes.associateBy { it.id }
        // Preserve provider readiness through retired one-shots, without executing a replacement
        // restore job or accidentally letting the application race its restored SQL daemon.
        fun liveDependencies(id: String): List<String> = if (id !in retired) listOf(id)
            else byId.getValue(id).dependencies.flatMap(::liveDependencies)
        val processes = compiled.processes.filterNot { it.oneShot }.map { p ->
            val base = p.copy(dependencies = p.dependencies.flatMap(::liveDependencies).distinct())
            when {
                p.id == "mariadb" && recipe in setOf("erpnext", "bookstack") -> base.copy(environmentFile = null,
                    readiness = listOf("/bin/sh", "-ec", "mariadb-admin --no-defaults --socket=/tmp/mysql.sock ping >/dev/null 2>&1"))
                p.id == "postgres" && recipe == "firefly" -> base.copy(environmentFile = null)
                else -> base
            }
        }
        return compiled.copy(processes = processes, databaseAccess = compiled.databaseAccess.filterNot { it.consumer in retired })
            .also { restored ->
                PrivateDeployment.validate(restored)
                require(PrivateDeployment.inputNames(restored).none { it in setOf("bootstrap.env", "installer.env", "database-init.env", "mail-bootstrap.env", "admin.env") }) {
                    "Bootstrap-only credential leaked into restored business/mail daemon"
                }
            }
    }
}
