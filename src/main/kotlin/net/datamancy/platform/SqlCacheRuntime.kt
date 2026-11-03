package net.datamancy.platform

import java.nio.file.Path

/** MariaDB's initialization is a journalled one-shot, never an entrypoint that silently retries a partial database. */
internal object SqlCacheRuntime {
    fun spec(inventory: AcquiredInventory, name: String = "sql-cache"): PrivateDeploymentSpec {
        val maria = inventory.images.single { it.product == "mariadb" }
        val cache = inventory.images.single { it.product == "memcached" }
        require(listOf(maria, cache).all { it.os == "linux" && it.architecture == "amd64" })
        val database = RuntimeProcess("mariadb", maria.pinnedImage, maria.imageId, 999,
            environmentFile = "mariadb.env", volumes = listOf(RuntimeMount("mariadb", "/var/lib/mysql")),
            memoryMiB = 1024, apparmorProfile = "p0v3-private-v1")
        return PrivateDeploymentSpec(name = name, volumes = listOf(RuntimeVolume("mariadb", 999)), processes = listOf(
            database.copy(id = "mariadb-init", entrypoint = "/bin/sh", oneShot = true, command = listOf("-ec", """
                mariadb-install-db --no-defaults --datadir=/var/lib/mysql --auth-root-authentication-method=normal --skip-test-db
                mariadbd --no-defaults --datadir=/var/lib/mysql --bootstrap --skip-networking <<SQL
                DELETE FROM mysql.global_priv WHERE User = '' OR (User = 'root' AND Host <> 'localhost');
                FLUSH PRIVILEGES;
                ALTER USER 'root'@'localhost' IDENTIFIED BY '${'$'}MARIADB_ROOT_PASSWORD';
                SQL
            """.trimIndent())),
            database.copy(dependencies = listOf("mariadb-init"), entrypoint = "/usr/sbin/mariadbd", command = listOf(
                "--no-defaults", "--datadir=/var/lib/mysql", "--socket=/tmp/mysql.sock", "--pid-file=/tmp/mysql.pid",
                "--bind-address=0.0.0.0", "--skip-name-resolve", "--max-connections=64", "--innodb-buffer-pool-size=128M"),
                readiness = listOf("/bin/sh", "-ec", "MYSQL_PWD=\"${'$'}MARIADB_ROOT_PASSWORD\" mariadb --socket=/tmp/mysql.sock -u root -Nse 'SELECT 1' | grep -qx 1")),
            RuntimeProcess("memcached", cache.pinnedImage, cache.imageId, 11211, entrypoint = "/usr/local/bin/memcached",
                command = listOf("-m", "64", "-U", "0", "-l", "0.0.0.0"), memoryMiB = 128, apparmorProfile = "p0v3-private-v1",
                readiness = listOf("/bin/sh", "-ec", "printf 'version\\r\\nquit\\r\\n' | nc -w 2 127.0.0.1 11211 | grep -q '^VERSION '"))
        )).also { PrivateDeployment.validate(it) }
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "sql-cache", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) {
            mapOf("mariadb.env" to "MARIADB_ROOT_PASSWORD=${RuntimePreparation.password()}\n")
        }
}
