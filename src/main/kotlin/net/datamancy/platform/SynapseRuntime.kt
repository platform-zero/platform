package net.datamancy.platform

import java.nio.file.Path

/** Private local Matrix homeserver. Federation, public signup, previews and telemetry are disabled. */
internal object SynapseRuntime {
    fun spec(inventory: AcquiredInventory, name: String = "synapse"): PrivateDeploymentSpec {
        val foundation = FoundationRuntime.spec(inventory, name)
        val pg = foundation.processes.single { it.id == "postgres" }
        val image = inventory.images.single { it.product == "synapse" }
        require(image.os == "linux" && image.architecture == "amd64")
        return PrivateDeploymentSpec(name = name,
            volumes = listOf(RuntimeVolume("postgres", 999), RuntimeVolume("synapse", 991)),
            processes = foundation.processes.filter { it.id in setOf("postgres-init", "postgres") } + listOf(
                RuntimeProcess("synapse-db-init", pg.image, pg.imageId, 999, dependencies = listOf("postgres"),
                    entrypoint = "/bin/sh", environmentFile = "database-init.env", oneShot = true,
                    apparmorProfile = "p0v3-private-v1", command = listOf("-ec", """
                        export PGPASSWORD="${'$'}POSTGRES_PASSWORD"
                        psql -X -h postgres -U postgres -v ON_ERROR_STOP=1 <<SQL
                        CREATE ROLE synapse LOGIN PASSWORD '${'$'}SYNAPSE_PASSWORD';
                        CREATE DATABASE synapse OWNER synapse ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C' TEMPLATE template0;
                        SQL
                    """.trimIndent())),
                RuntimeProcess("signing-key-init", image.pinnedImage, image.imageId, 991, oneShot = true,
                    entrypoint = "/usr/local/bin/python", volumes = listOf(RuntimeMount("synapse", "/data")),
                    apparmorProfile = "p0v3-private-v1", command = listOf("-c", """
                        import os
                        from signedjson.key import generate_signing_key, write_signing_keys
                        os.umask(0o077)
                        with open('/data/homeserver.signing.key', 'x') as output:
                            write_signing_keys(output, [generate_signing_key('p0v3')])
                    """.trimIndent())),
                RuntimeProcess("synapse", image.pinnedImage, image.imageId, 991,
                    dependencies = listOf("synapse-db-init", "signing-key-init"), entrypoint = "/usr/local/bin/python",
                    command = listOf("-m", "synapse.app.homeserver", "--config-path", "/run/secrets/homeserver.yaml"),
                    files = listOf(RuntimeFile("homeserver.yaml", "/run/secrets/homeserver.yaml"), RuntimeFile("logging.yaml", "/run/secrets/logging.yaml")),
                    environmentFile = "synapse.env", volumes = listOf(RuntimeMount("synapse", "/data")),
                    memoryMiB = 1024, apparmorProfile = "p0v3-private-v1", readinessHttpPort = 8008, readinessHttpPath = "/health")
            )).also { PrivateDeployment.validate(it) }
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "synapse", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }

    /** Cold-import projection; caller verifies exact compiled image/config equality before calling. */
    fun coldRestoreSpec(compiled: PrivateDeploymentSpec): PrivateDeploymentSpec {
        val retired = setOf("postgres-init", "synapse-db-init", "signing-key-init")
        require(compiled.processes.filter { it.oneShot }.map { it.id }.toSet() == retired)
        require(compiled.processes.map { it.id }.toSet() == retired + setOf("postgres", "synapse"))
        require(compiled.processes.single { it.id == "synapse" }.command ==
            listOf("-m", "synapse.app.homeserver", "--config-path", "/run/secrets/homeserver.yaml"))
        return compiled.copy(processes = compiled.processes.filterNot { it.oneShot }.map {
            it.copy(dependencies = it.dependencies.filterNot(retired::contains))
        }, databaseAccess = compiled.databaseAccess.filterNot { it.consumer in retired })
            .also { PrivateDeployment.validate(it) }
    }

    fun inputs(publicBaseUrl: String = "http://synapse:8008/"): Map<String, String> {
            require(publicBaseUrl in setOf("http://synapse:8008/", "https://element:8443/"))
            val pg = RuntimePreparation.password()
            val db = RuntimePreparation.password()
            val registration = RuntimePreparation.password()
            return mapOf(
                "postgres.env" to "POSTGRES_PASSWORD=$pg\n",
                "database-init.env" to "POSTGRES_PASSWORD=$pg\nSYNAPSE_PASSWORD=$db\n",
                "synapse.env" to "P0V3_REGISTRATION_SECRET=$registration\nP0V3_FIXTURE_PASSWORD=${RuntimePreparation.password()}\n",
                "logging.yaml" to "version: 1\nhandlers:\n  console:\n    class: logging.StreamHandler\n    stream: ext://sys.stdout\nroot:\n  level: WARNING\n  handlers: [console]\ndisable_existing_loggers: false\n",
                "homeserver.yaml" to """
                    server_name: matrix.private.invalid
                    public_baseurl: $publicBaseUrl
                    pid_file: /tmp/synapse.pid
                    listeners:
                      - port: 8008
                        tls: false
                        type: http
                        bind_addresses: ['0.0.0.0']
                        x_forwarded: false
                        resources:
                          - names: [client]
                            compress: false
                    database:
                      name: psycopg2
                      args:
                        user: synapse
                        password: '$db'
                        database: synapse
                        host: postgres
                        port: 5432
                        cp_min: 2
                        cp_max: 5
                    media_store_path: /data/media
                    signing_key_path: /data/homeserver.signing.key
                    log_config: /run/secrets/logging.yaml
                    report_stats: false
                    enable_registration: false
                    allow_guest_access: false
                    registration_shared_secret: '$registration'
                    macaroon_secret_key: '${RuntimePreparation.password()}'
                    form_secret: '${RuntimePreparation.password()}'
                    trusted_key_servers: []
                    suppress_key_server_warning: true
                    federation_domain_whitelist: []
                    allow_public_rooms_without_auth: false
                    allow_public_rooms_over_federation: false
                    url_preview_enabled: false
                    max_upload_size: 10M
                """.trimIndent() + "\n")
        }
}
