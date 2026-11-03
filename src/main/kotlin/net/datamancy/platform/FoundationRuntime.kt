package net.datamancy.platform

import java.nio.file.Path

/** Engineering-owned, persistent private foundation. No operator-authored lock or public activation needed. */
internal object FoundationRuntime {
    fun spec(inventory: AcquiredInventory, name: String = "foundation"): PrivateDeploymentSpec {
        require(inventory.schemaVersion == 1)
        fun image(id: String) = inventory.images.single { it.product == id }.also {
            require(it.architecture == "amd64" && it.os == "linux" && it.pinnedImage.endsWith("@${it.selectedManifestDigest}"))
        }
        val pg = image("postgres"); val valkey = image("valkey"); val ntfy = image("ntfy")
        val database = RuntimeMount("postgres", "/var/lib/postgresql/data")
        return PrivateDeploymentSpec(name = name, volumes = listOf(
            RuntimeVolume("postgres", 999), RuntimeVolume("valkey", 999), RuntimeVolume("ntfy", 65532)), processes = listOf(
            RuntimeProcess("postgres-init", pg.pinnedImage, pg.imageId, 999, entrypoint = "/bin/sh",
                command = listOf("-ec", """
                    umask 077
                    printf '%s' "${'$'}POSTGRES_PASSWORD" > /tmp/pw
                    /usr/lib/postgresql/17/bin/initdb -D /var/lib/postgresql/data --username=postgres --pwfile=/tmp/pw --auth-host=scram-sha-256 --auth-local=trust
                    printf 'host all all 0.0.0.0/0 scram-sha-256\n' >> /var/lib/postgresql/data/pg_hba.conf
                """.trimIndent()), environmentFile = "postgres.env", volumes = listOf(database), oneShot = true),
            RuntimeProcess("postgres", pg.pinnedImage, pg.imageId, 999, dependencies = listOf("postgres-init"),
                entrypoint = "/usr/lib/postgresql/17/bin/postgres", command = listOf("-D", "/var/lib/postgresql/data", "-c", "listen_addresses=*"),
                volumes = listOf(database), tmpfs = listOf("/tmp", "/var/run/postgresql"),
                readiness = listOf("pg_isready", "-U", "postgres", "-d", "postgres")),
            RuntimeProcess("valkey", valkey.pinnedImage, valkey.imageId, 999, entrypoint = "/usr/local/bin/valkey-server",
                command = listOf("/etc/valkey/valkey.conf"), volumes = listOf(RuntimeMount("valkey", "/data")),
                files = listOf(RuntimeFile("valkey.conf", "/etc/valkey/valkey.conf")),
                readiness = listOf("/bin/sh", "-ec", "export REDISCLI_AUTH=\"${'$'}(sed -n 's/^requirepass //p' /etc/valkey/valkey.conf)\"; test \"${'$'}(valkey-cli ping)\" = PONG")),
            RuntimeProcess("ntfy", ntfy.pinnedImage, ntfy.imageId, 65532,
                command = listOf("serve", "--listen-http=:8080", "--base-url=http://ntfy:8080", "--cache-file=/var/cache/ntfy/cache.db",
                    "--attachment-cache-dir=/var/cache/ntfy/attachments"),
                volumes = listOf(RuntimeMount("ntfy", "/var/cache/ntfy")),
                readiness = listOf("/bin/sh", "-ec", "wget -q -O - http://127.0.0.1:8080/v1/health | grep -q '\"healthy\":true'"))
        )).let { spec -> spec.copy(processes = spec.processes.map { it.copy(apparmorProfile = "p0v3-private-v1") }) }
            .also { PrivateDeployment.validate(it) }
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "foundation", store: RuntimeStore = RuntimeStore.LEGACY): Path {
        return RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) {
            mapOf("postgres.env" to "POSTGRES_PASSWORD=${RuntimePreparation.password()}\n",
                "valkey.conf" to "bind 0.0.0.0\nprotected-mode yes\nport 6379\ndir /data\nappendonly yes\nappendfsync everysec\nrequirepass ${RuntimePreparation.password()}\n")
        }
    }
}
