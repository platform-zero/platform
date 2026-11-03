package net.datamancy.platform

import java.nio.file.Path
import java.util.Base64

/** Private Firefly III with PostgreSQL and separate non-root PHP/nginx, not a production SSO integration. */
internal object FireflyRuntime {
    fun spec(inventory: AcquiredInventory, name: String = "firefly"): PrivateDeploymentSpec {
        val foundation = FoundationRuntime.spec(inventory, name)
        val pg = foundation.processes.single { it.id == "postgres" }
        val image = inventory.images.single { it.product == "firefly-iii" }
        require(image.os == "linux" && image.architecture == "amd64")
        val app = RuntimeProcess("php", image.pinnedImage, image.imageId, 33, environmentFile = "firefly.env",
            volumes = listOf(RuntimeMount("storage", "/var/www/html/storage"), RuntimeMount("cache", "/var/www/html/bootstrap/cache")),
            apparmorProfile = "p0v3-private-v1", memoryMiB = 1024)
        return PrivateDeploymentSpec(name = name, volumes = listOf(RuntimeVolume("postgres", 999), RuntimeVolume("storage", 33), RuntimeVolume("cache", 33)),
            processes = foundation.processes.filter { it.id in setOf("postgres-init", "postgres") } + listOf(
                RuntimeProcess("firefly-db-init", pg.image, pg.imageId, 999, dependencies = listOf("postgres"),
                    entrypoint = "/bin/sh", environmentFile = "database-init.env", oneShot = true, apparmorProfile = "p0v3-private-v1",
                    command = listOf("-ec", """
                        export PGPASSWORD="${'$'}POSTGRES_PASSWORD"
                        psql -X -h postgres -U postgres -v ON_ERROR_STOP=1 <<SQL
                        CREATE ROLE firefly LOGIN PASSWORD '${'$'}FIREFLY_PASSWORD';
                        CREATE DATABASE firefly OWNER firefly;
                        SQL
                    """.trimIndent())),
                app.copy(id = "firefly-files-init", oneShot = true, entrypoint = "/bin/sh",
                    volumes = listOf(RuntimeMount("storage", "/seed/storage"), RuntimeMount("cache", "/seed/cache")),
                    command = listOf("-ec", "cp -R /var/www/html/storage/. /seed/storage/; cp -R /var/www/html/bootstrap/cache/. /seed/cache/")),
                app.copy(id = "firefly-migrate", dependencies = listOf("firefly-db-init", "firefly-files-init"), oneShot = true,
                    entrypoint = "/bin/sh", command = listOf("-ec", """
                        php artisan migrate --seed --force --no-interaction
                        php artisan firefly-iii:upgrade-database --no-interaction
                        php artisan firefly-iii:laravel-passport-keys --no-interaction
                        test -s storage/oauth-private.key; test -s storage/oauth-public.key
                        chmod 600 storage/oauth-private.key storage/oauth-public.key
                        php artisan config:cache --no-interaction
                    """.trimIndent())),
                app.copy(dependencies = listOf("firefly-migrate"), entrypoint = "/usr/local/sbin/php-fpm",
                    command = listOf("--nodaemonize", "--fpm-config", "/run/secrets/fpm.conf"),
                    files = listOf(RuntimeFile("fpm.conf", "/run/secrets/fpm.conf"), RuntimeFile("health.php", "/run/secrets/health.php")),
                    readiness = listOf("/usr/local/bin/php", "-r", "${'$'}s=fsockopen('127.0.0.1',9000,${'$'}e,${'$'}m,3); if(!${'$'}s)exit(1); fclose(${ '$'}s);")),
                RuntimeProcess("firefly", image.pinnedImage, image.imageId, 33, dependencies = listOf("php"),
                    entrypoint = "/usr/sbin/nginx", command = listOf("-e", "/tmp/nginx-error.log", "-c", "/run/secrets/nginx.conf", "-g", "daemon off;"),
                    files = listOf(RuntimeFile("nginx.conf", "/run/secrets/nginx.conf")),
                    apparmorProfile = "p0v3-private-v1", memoryMiB = 256, readinessHttpPort = 8080, readinessHttpPath = "/healthz")
            )).also { PrivateDeployment.validate(it) }
    }
    fun inputs(password: () -> String = RuntimePreparation::password): Map<String, String> {
        val postgres = password()
        val database = password()
        val key = Base64.getEncoder().encodeToString(java.util.HexFormat.of().parseHex(password()))
        return mapOf("postgres.env" to "POSTGRES_PASSWORD=$postgres\n",
            "database-init.env" to "POSTGRES_PASSWORD=$postgres\nFIREFLY_PASSWORD=$database\n",
            "firefly.env" to "APP_ENV=production\nAPP_DEBUG=false\nAPP_KEY=base64:$key\nAPP_URL=http://firefly:8080\nSITE_OWNER=fixture@localhost.invalid\nDB_CONNECTION=pgsql\nDB_HOST=postgres\nDB_PORT=5432\nDB_DATABASE=firefly\nDB_USERNAME=firefly\nDB_PASSWORD=$database\nPGSQL_SSL_MODE=disable\nCACHE_STORE=file\nSESSION_DRIVER=file\nCOOKIE_SECURE=false\nCOOKIE_SAMESITE=lax\nAUTHENTICATION_GUARD=web\nMAIL_MAILER=array\nLOG_CHANNEL=stderr\nAPP_LOG_LEVEL=warning\nTZ=UTC\nDEFAULT_LANGUAGE=en_US\nDEFAULT_LOCALE=en_US\nFIREFLY_III_PATH=/var/www/html\nP0V3_FIXTURE_PASSWORD=${password()}\n",
            "health.php" to "<?php http_response_code(200); echo 'ready';\n",
            "fpm.conf" to """
                [global]
                pid = /tmp/php-fpm.pid
                error_log = /proc/self/fd/2
                daemonize = no
                [www]
                listen = 0.0.0.0:9000
                pm = ondemand
                pm.max_children = 5
                pm.process_idle_timeout = 10s
                clear_env = no
                catch_workers_output = yes
                php_admin_flag[log_errors] = on
                php_admin_value[error_log] = /proc/self/fd/2
            """.trimIndent() + "\n",
            "nginx.conf" to """
                worker_processes 1;
                pid /tmp/nginx.pid;
                error_log /tmp/nginx-error.log warn;
                events { worker_connections 512; }
                http {
                    include /etc/nginx/mime.types;
                    access_log off;
                    client_body_temp_path /tmp/client_body;
                    proxy_temp_path /tmp/proxy;
                    fastcgi_temp_path /tmp/fastcgi;
                    uwsgi_temp_path /tmp/uwsgi;
                    scgi_temp_path /tmp/scgi;
                    server {
                        listen 8080;
                        server_name firefly;
                        root /var/www/html/public;
                        index index.php;
                        client_max_body_size 10m;
                        location = /healthz {
                            include /etc/nginx/fastcgi_params;
                            fastcgi_param SCRIPT_FILENAME /run/secrets/health.php;
                            fastcgi_param HTTP_PROXY "";
                            fastcgi_pass php:9000;
                        }
                        location / { try_files ${'$'}uri ${'$'}uri/ /index.php?${'$'}query_string; }
                        location = /index.php {
                            include /etc/nginx/fastcgi_params;
                            fastcgi_param SCRIPT_FILENAME /var/www/html/public/index.php;
                            fastcgi_param HTTP_AUTHORIZATION ${'$'}http_authorization;
                            fastcgi_param HTTP_PROXY "";
                            fastcgi_pass php:9000;
                        }
                        location ~ \.php${'$'} { return 404; }
                        location ~ /\. { deny all; }
                    }
                }
            """.trimIndent() + "\n")
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "firefly", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }
}
