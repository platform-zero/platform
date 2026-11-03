package net.datamancy.platform

import java.nio.file.Path
import java.util.Base64

/** Private BookStack with an isolated MariaDB and native initial-admin replacement before web startup. */
internal object BookStackRuntime {
    fun spec(inventory: AcquiredInventory, name: String = "bookstack"): PrivateDeploymentSpec {
        val sql = SqlCacheRuntime.spec(inventory, name)
        val image = inventory.images.single { it.product == "bookstack" }
        require(image.os == "linux" && image.architecture == "amd64")
        val database = sql.processes.filter { it.id != "memcached" }.map { p ->
            if (p.id != "mariadb-init") p else p.copy(environmentFile = "database-init.env", command = p.command.map {
                it.replace("ALTER USER", """
                    CREATE DATABASE bookstack CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
                    CREATE USER 'bookstack'@'%' IDENTIFIED BY '${'$'}BOOKSTACK_DB_PASSWORD';
                    GRANT ALL PRIVILEGES ON bookstack.* TO 'bookstack'@'%';
                    ALTER USER
                """.trimIndent())
            })
        }
        val app = RuntimeProcess("php", image.pinnedImage, image.imageId, 911, environmentFile = "bookstack.env",
            apparmorProfile = "p0v3-private-v1", memoryMiB = 1024,
            volumes = listOf(RuntimeMount("config", "/config"), RuntimeMount("storage", "/app/www/storage"),
                RuntimeMount("cache", "/app/www/bootstrap/cache"), RuntimeMount("uploads", "/config/www/uploads")))
        return PrivateDeploymentSpec(name = name,
            volumes = sql.volumes + listOf("config", "storage", "cache", "uploads").map { RuntimeVolume(it, 911) },
            processes = database + listOf(
                app.copy(id = "bookstack-files-init", oneShot = true, entrypoint = "/bin/sh",
                    volumes = listOf(RuntimeMount("config", "/config"), RuntimeMount("storage", "/seed/storage"),
                        RuntimeMount("cache", "/seed/cache"), RuntimeMount("uploads", "/seed/uploads")),
                    command = listOf("-ec", """
                        cp -R /app/www/storage/. /seed/storage/
                        cp -R /app/www/bootstrap/cache/. /seed/cache/
                        mkdir -p /config/backups /config/log/bookstack /config/www/files /config/www/images /config/www/uploads
                        for folder in cache/data purifier sessions views; do mkdir -p /config/www/framework/${'$'}folder; done
                    """.trimIndent())),
                app.copy(id = "bookstack-migrate", oneShot = true, dependencies = listOf("mariadb", "bookstack-files-init"),
                    entrypoint = "/bin/sh", environmentFile = "admin.env",
                    files = listOf(RuntimeFile("admin.php", "/run/secrets/admin.php")),
                    command = listOf("-ec", "cd /app/www; php artisan migrate --force --no-interaction; php /run/secrets/admin.php; php artisan config:cache --no-interaction")),
                app.copy(dependencies = listOf("bookstack-migrate"), entrypoint = "/usr/sbin/php-fpm85",
                    command = listOf("--nodaemonize", "--fpm-config", "/run/secrets/fpm.conf"),
                    files = listOf(RuntimeFile("fpm.conf", "/run/secrets/fpm.conf"), RuntimeFile("health.php", "/run/secrets/health.php")),
                    readiness = listOf("/usr/bin/php", "-r", "${'$'}s=fsockopen('127.0.0.1',9000,${'$'}e,${'$'}m,3); if(!${'$'}s)exit(1); fclose(${'$'}s);")),
                RuntimeProcess("bookstack", image.pinnedImage, image.imageId, 911, dependencies = listOf("php"),
                    entrypoint = "/usr/sbin/nginx", command = listOf("-e", "/tmp/nginx-error.log", "-c", "/run/secrets/nginx.conf", "-g", "daemon off;"),
                    files = listOf(RuntimeFile("nginx.conf", "/run/secrets/nginx.conf")),
                    volumes = listOf(RuntimeMount("uploads", "/config/www/uploads")),
                    apparmorProfile = "p0v3-private-v1", memoryMiB = 256, readinessHttpPort = 8080, readinessHttpPath = "/login")
            )).also { PrivateDeployment.validate(it) }
    }

    fun inputs(): Map<String, String> {
        val root = RuntimePreparation.password()
        val database = RuntimePreparation.password()
        val key = Base64.getEncoder().encodeToString(java.util.HexFormat.of().parseHex(RuntimePreparation.password()))
        val env = "APP_ENV=production\nAPP_DEBUG=false\nAPP_KEY=base64:$key\nAPP_URL=http://bookstack:8080\nDB_HOST=mariadb\nDB_PORT=3306\nDB_DATABASE=bookstack\nDB_USERNAME=bookstack\nDB_PASSWORD=$database\nMAIL_DRIVER=array\nSTORAGE_TYPE=local_secure_restricted\nLOG_CHANNEL=stderr\nAUTH_METHOD=standard\nSESSION_SECURE_COOKIE=false\nAPP_TIMEZONE=UTC\n"
        val web = FireflyRuntime.inputs()
        return mapOf("mariadb.env" to "MARIADB_ROOT_PASSWORD=$root\n",
            "database-init.env" to "MARIADB_ROOT_PASSWORD=$root\nBOOKSTACK_DB_PASSWORD=$database\n",
            "bookstack.env" to env, "admin.env" to env + "P0V3_FIXTURE_PASSWORD=${RuntimePreparation.password()}\n",
            "fpm.conf" to web.getValue("fpm.conf"), "health.php" to web.getValue("health.php"),
            "nginx.conf" to web.getValue("nginx.conf").replace("/var/www/html/public", "/app/www/public").replace("server_name firefly", "server_name bookstack"),
            "admin.php" to """
                <?php
                require '/app/www/vendor/autoload.php';
                ${'$'}app = require '/app/www/bootstrap/app.php';
                ${'$'}app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
                ${'$'}code = Illuminate\Support\Facades\Artisan::call('bookstack:create-admin', [
                    '--initial' => true, '--email' => 'fixture@localhost.invalid', '--name' => 'Private fixture',
                    '--password' => getenv('P0V3_FIXTURE_PASSWORD'), '--no-interaction' => true
                ]);
                if (${'$'}code !== 0 || BookStack\Users\Models\User::where('email', 'admin@admin.com')->exists()) exit(1);
            """.trimIndent() + "\n")
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "bookstack", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base, ::inputs)
}
