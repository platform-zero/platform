package net.datamancy.platform

import java.nio.file.Path

/** Private Planka with its own database/role, durable one-time migrations, and local upload storage. */
internal object PlankaRuntime {
    const val FIXTURE_TERMS = "# Private automated test instance\n\nSynthetic test accounts and fixture data only. No public service or human end-user agreement is offered here. This notice does not replace upstream software licenses.\n"
    fun spec(inventory: AcquiredInventory, name: String = "planka"): PrivateDeploymentSpec {
        val foundation = FoundationRuntime.spec(inventory, name)
        val pg = foundation.processes.single { it.id == "postgres" }
        val image = inventory.images.single { it.product == "planka" }
        require(image.os == "linux" && image.architecture == "amd64")
        val app = RuntimeProcess("planka", image.pinnedImage, image.imageId, 1000, entrypoint = "/usr/local/bin/node",
            environmentFile = "planka.env", volumes = listOf(RuntimeMount("uploads", "/app/data")),
            files = listOf(RuntimeFile("fixture-terms.md", "/app/terms/custom/en-US.md")),
            tmpfs = listOf("/tmp", "/app/.tmp"), memoryMiB = 1024, apparmorProfile = "p0v3-private-v1",
            readinessHttpPort = 1337)
        return PrivateDeploymentSpec(name = name, volumes = listOf(RuntimeVolume("postgres", 999), RuntimeVolume("uploads", 1000)),
            processes = foundation.processes.filter { it.id in setOf("postgres-init", "postgres") } + listOf(
                RuntimeProcess("planka-db-init", pg.image, pg.imageId, 999, dependencies = listOf("postgres"),
                    entrypoint = "/bin/sh", environmentFile = "database-init.env", oneShot = true, apparmorProfile = "p0v3-private-v1",
                    command = listOf("-ec", """
                        export PGPASSWORD="${'$'}POSTGRES_PASSWORD"
                        psql -X -h postgres -U postgres -v ON_ERROR_STOP=1 <<SQL
                        CREATE ROLE planka LOGIN PASSWORD '${'$'}PLANKA_PASSWORD';
                        CREATE DATABASE planka OWNER planka;
                        SQL
                    """.trimIndent())),
                app.copy(id = "planka-init", dependencies = listOf("planka-db-init"), command = listOf("db/init.js"),
                    oneShot = true, readinessHttpPort = null),
                app.copy(dependencies = listOf("planka-init"), command = listOf("app.js", "--prod"))
            )).also { PrivateDeployment.validate(it) }
    }
    /** Cold restoration never runs database creation, Knex migrations or administrator seeding. */
    fun coldRestoreSpec(compiled: PrivateDeploymentSpec): PrivateDeploymentSpec {
        PrivateDeployment.validate(compiled)
        val initializers = setOf("postgres-init", "planka-db-init", "planka-init")
        require(compiled.processes.filter { it.oneShot }.map { it.id }.toSet() == initializers &&
            compiled.processes.map { it.id }.toSet() == initializers + setOf("postgres", "planka")) {
            "Exact standalone Planka recipe required; canonical provider restoration has its own projection"
        }
        val application = compiled.processes.single { it.id == "planka" }
        require(application.entrypoint == "/usr/local/bin/node" && application.command == listOf("app.js", "--prod") &&
            application.environmentFile == "planka.env") { "Application entrypoint may not bootstrap or migrate on restore" }
        return compiled.copy(processes = compiled.processes.filterNot { it.oneShot }.map {
            // The application still depends on the provider even though the init chain is retired.
            // DEFAULT_ADMIN_* in historical planka.env are inactive under app.js --prod; only
            // db/init.js runs seeding, and that process is absent from the restored definition.
            it.copy(dependencies = if (it.id == "planka") listOf("postgres") else it.dependencies.filterNot(initializers::contains))
        }, databaseAccess = compiled.databaseAccess.filterNot { it.consumer in initializers || it.provider in initializers })
            .also { PrivateDeployment.validate(it) }
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "planka", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) {
            val postgres = RuntimePreparation.password()
            val database = RuntimePreparation.password()
            mapOf("fixture-terms.md" to FIXTURE_TERMS, "postgres.env" to "POSTGRES_PASSWORD=$postgres\n",
                "database-init.env" to "POSTGRES_PASSWORD=$postgres\nPLANKA_PASSWORD=$database\n",
                "planka.env" to "NODE_ENV=production\nLOG_FILE=/tmp/planka.log\nBASE_URL=http://planka:1337\nDATABASE_URL=postgresql://planka:$database@postgres:5432/planka\nSECRET_KEY=${RuntimePreparation.password()}\nDEFAULT_ADMIN_EMAIL=bootstrap@localhost.invalid\nDEFAULT_ADMIN_USERNAME=p0v3_bootstrap\nDEFAULT_ADMIN_NAME=Private bootstrap\nDEFAULT_ADMIN_PASSWORD=${RuntimePreparation.password()}\nOUTGOING_PROXY=http://127.0.0.1:9\n")
        }
}
