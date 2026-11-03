package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.json.*

/** Private ERPNext with native journalled site installation, isolated queues and no configured mail transport. */
internal object ErpNextRuntime {
    const val SITE = "erp.private.invalid"
    fun spec(inventory: AcquiredInventory, name: String = "erpnext"): PrivateDeploymentSpec {
        fun image(id: String) = inventory.images.single { it.product == id }.also { require(it.os == "linux" && it.architecture == "amd64") }
        val app = image("erpnext"); val maria = image("mariadb"); val redis = image("valkey")
        val database = RuntimeProcess("mariadb", maria.pinnedImage, maria.imageId, 999,
            environmentFile = "mariadb.env", volumes = listOf(RuntimeMount("mariadb", "/var/lib/mysql")),
            memoryMiB = 1024, apparmorProfile = "p0v3-private-v1")
        fun queue(id: String) = RuntimeProcess(id, redis.pinnedImage, redis.imageId, 999,
            entrypoint = "/usr/local/bin/valkey-server", command = listOf("/run/secrets/$id.conf"),
            volumes = listOf(RuntimeMount(id, "/data")), files = listOf(RuntimeFile("$id.conf", "/run/secrets/$id.conf")),
            apparmorProfile = "p0v3-private-v1", readiness = listOf("/bin/sh", "-ec",
                "export REDISCLI_AUTH=\"${'$'}(sed -n 's/^requirepass //p' /run/secrets/$id.conf)\"; test \"${'$'}(valkey-cli ping)\" = PONG"))
        val mounts = listOf(RuntimeMount("sites", "/home/frappe/frappe-bench/sites"), RuntimeMount("logs", "/home/frappe/frappe-bench/logs"), RuntimeMount("config", "/home/frappe/frappe-bench/config"))
        val base = RuntimeProcess("backend", app.pinnedImage, app.imageId, 1000, dependencies = listOf("installer-retire"),
            entrypoint = "/bin/sh", environmentFile = "erp.env", volumes = mounts, apparmorProfile = "p0v3-private-v1", memoryMiB = 1024)
        return PrivateDeploymentSpec(name = name, volumes = listOf(RuntimeVolume("mariadb", 999), RuntimeVolume("cache", 999),
            RuntimeVolume("queue", 999), RuntimeVolume("sites", 1000), RuntimeVolume("logs", 1000), RuntimeVolume("config", 1000)), processes = listOf(
            database.copy(id = "mariadb-init", entrypoint = "/bin/sh", oneShot = true, command = listOf("-ec", """
                mariadb-install-db --no-defaults --datadir=/var/lib/mysql --auth-root-authentication-method=normal --skip-test-db
                mariadbd --no-defaults --datadir=/var/lib/mysql --bootstrap --skip-networking <<SQL
                DELETE FROM mysql.global_priv WHERE User = '' OR (User = 'root' AND Host <> 'localhost');
                FLUSH PRIVILEGES;
                ALTER USER 'root'@'localhost' IDENTIFIED BY '${'$'}MARIADB_ROOT_PASSWORD';
                CREATE USER 'frappe_installer'@'%' IDENTIFIED BY '${'$'}INSTALLER_PASSWORD';
                GRANT ALL PRIVILEGES ON *.* TO 'frappe_installer'@'%' WITH GRANT OPTION;
                SQL
            """.trimIndent())),
            database.copy(dependencies = listOf("mariadb-init"), entrypoint = "/usr/sbin/mariadbd", command = listOf(
                "--no-defaults", "--datadir=/var/lib/mysql", "--socket=/tmp/mysql.sock", "--pid-file=/tmp/mysql.pid", "--bind-address=0.0.0.0",
                "--skip-name-resolve", "--max-connections=96", "--innodb-buffer-pool-size=256M", "--character-set-server=utf8mb4", "--collation-server=utf8mb4_unicode_ci"),
                readiness = listOf("/bin/sh", "-ec", "MYSQL_PWD=\"${'$'}MARIADB_ROOT_PASSWORD\" mariadb --socket=/tmp/mysql.sock -u root -Nse 'SELECT 1' | grep -qx 1")),
            queue("cache"), queue("queue"),
            base.copy(id = "site-config-init", dependencies = listOf("mariadb", "cache", "queue"), oneShot = true,
                environmentFile = null, entrypoint = "/home/frappe/frappe-bench/env/bin/python", command = listOf("/run/secrets/site-config.py"),
                volumes = listOf(RuntimeMount("sites", "/site-state")),
                files = listOf("site-config.py", "common-site.json").map { RuntimeFile(it, "/run/secrets/$it") }),
            base.copy(id = "site-init", dependencies = listOf("site-config-init"), oneShot = true, memoryMiB = 2048,
                environmentFile = "bootstrap.env", entrypoint = "/home/frappe/frappe-bench/env/bin/python", command = listOf("/run/secrets/site-init.py"),
                files = listOf(RuntimeFile("site-init.py", "/run/secrets/site-init.py"))),
            database.copy(id = "installer-retire", dependencies = listOf("site-init"), oneShot = true, entrypoint = "/bin/sh", volumes = emptyList(), environmentFile = "installer.env",
                command = listOf("-ec", "MYSQL_PWD=\"${'$'}INSTALLER_PASSWORD\" mariadb -h mariadb -u frappe_installer -e \"DROP USER 'frappe_installer'@'%';\"")),
            base.copy(command = listOf("-ec", "exec /home/frappe/frappe-bench/env/bin/gunicorn --chdir=/home/frappe/frappe-bench/sites --bind=0.0.0.0:8000 --threads=2 --workers=2 --worker-class=gthread --worker-tmp-dir=/tmp --timeout=120 --preload frappe.app:application"),
                readiness = listOf("/home/frappe/frappe-bench/env/bin/python", "-c", "import urllib.request,json; r=urllib.request.Request('http://127.0.0.1:8000/api/method/ping',headers={'X-Frappe-Site-Name':'$SITE'}); assert json.load(urllib.request.urlopen(r,timeout=5))['message']=='pong'")),
            base.copy(id = "websocket", entrypoint = "/home/frappe/frappe-bench/env/bin/python",
                files = listOf(RuntimeFile("process-init.py", "/run/secrets/process-init.py")),
                command = listOf("/run/secrets/process-init.py", "node", "/home/frappe/frappe-bench/apps/frappe/socketio.js"),
                readiness = listOf("/home/frappe/frappe-bench/env/bin/python", "-c", "import urllib.request; r=urllib.request.urlopen('http://127.0.0.1:9000/socket.io/?EIO=4&transport=polling',timeout=5); assert r.status==200")),
            base.copy(id = "worker", entrypoint = "/home/frappe/frappe-bench/env/bin/python",
                files = listOf(RuntimeFile("process-init.py", "/run/secrets/process-init.py")),
                command = listOf("/run/secrets/process-init.py", "bench", "worker", "--queue", "short,default,long"), readiness = listOf("/bin/sh", "-ec", "kill -0 1")),
            base.copy(id = "scheduler", entrypoint = "/home/frappe/frappe-bench/env/bin/python",
                files = listOf(RuntimeFile("process-init.py", "/run/secrets/process-init.py")),
                command = listOf("/run/secrets/process-init.py", "bench", "schedule"), readiness = listOf("/bin/sh", "-ec", "kill -0 1")),
            base.copy(id = "erp", dependencies = listOf("backend", "websocket", "worker", "scheduler"), entrypoint = "/usr/sbin/nginx",
                command = listOf("-c", "/run/secrets/nginx.conf", "-g", "daemon off;"),
                files = listOf("nginx.conf", "ca.pem", "web.pem", "web-key.pem").map { RuntimeFile(it, "/run/secrets/$it") },
                readinessHttpPort = 8080, readinessHttpPath = "/healthz")
        )).also { PrivateDeployment.validate(it) }
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "erpnext", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }
    fun inputs(pki: () -> Map<String, String> = { PrivateWebPki.generate("erp") }): Map<String, String> {
        val installer = RuntimePreparation.password(); val cache = RuntimePreparation.password(); val queue = RuntimePreparation.password()
        fun redis(password: String, persistent: Boolean) = "bind 0.0.0.0\nprotected-mode yes\nport 6379\ndir /data\nrequirepass $password\nsave \"\"\nappendonly ${if (persistent) "yes" else "no"}\nappendfsync everysec\n"
        val common = buildJsonObject {
            put("db_host", "mariadb"); put("db_port", 3306); put("redis_cache", "redis://:$cache@cache:6379")
            put("redis_queue", "redis://:$queue@queue:6379"); put("redis_socketio", "redis://:$queue@queue:6379")
            put("socketio_port", 9000); put("webserver_host", "backend"); put("webserver_port", 8000); put("default_site", SITE); put("serve_default_site", true)
            put("host_name", "https://erp:8443"); put("disable_telemetry", 1); put("developer_mode", 0)
            put("server_script_enabled", false); put("pause_scheduler", 1)
        }
        return pki() + mapOf("process-init.py" to ErpNextRuntime::class.java.getResource("/runtime/process-init.py")!!.readText(),
            "mariadb.env" to "MARIADB_ROOT_PASSWORD=${RuntimePreparation.password()}\nINSTALLER_PASSWORD=$installer\n",
            "installer.env" to "INSTALLER_PASSWORD=$installer\n",
            "bootstrap.env" to "INSTALLER_PASSWORD=$installer\nADMIN_PASSWORD=${RuntimePreparation.password()}\nSITE_DB_PASSWORD=${RuntimePreparation.password()}\nPYTHONDONTWRITEBYTECODE=1\n",
            "erp.env" to "PYTHONDONTWRITEBYTECODE=1\nHOME=/home/frappe\n",
            "cache.conf" to redis(cache, false), "queue.conf" to redis(queue, true), "common-site.json" to "$common\n",
            "site-config.py" to """
                import os, json
                from pathlib import Path
                if not __debug__:
                    raise SystemExit('Optimized Python refused')
                os.umask(0o077)
                sites = Path('/site-state')
                if list(sites.iterdir()):
                    raise SystemExit('Existing or interrupted site retained')
                (sites / 'apps.txt').write_text('frappe\nerpnext\n')
                (sites / 'common_site_config.json').write_text(Path('/run/secrets/common-site.json').read_text())
                (sites / 'assets').symlink_to('/home/frappe/frappe-bench/assets', target_is_directory=True)
            """.trimIndent() + "\n", "site-init.py" to """
                import os
                from pathlib import Path
                if not __debug__:
                    raise SystemExit('Optimized Python refused')
                os.umask(0o077)
                sites = Path('/home/frappe/frappe-bench/sites')
                if (sites / '$SITE').exists() or not (sites / 'common_site_config.json').is_file():
                    raise SystemExit('Existing or interrupted site retained')
                os.chdir(sites)
                from frappe.commands.site import new_site
                new_site.callback(site='$SITE', db_root_username='frappe_installer', db_root_password=os.environ['INSTALLER_PASSWORD'],
                    admin_password=os.environ['ADMIN_PASSWORD'], db_name='p0_erp', db_password=os.environ['SITE_DB_PASSWORD'],
                    db_type='mariadb', db_host='mariadb', db_port=3306, mariadb_user_host_login_scope='%',
                    install_app=('erpnext',), set_default=True, force=False)
                import frappe
                frappe.destroy()
            """.trimIndent() + "\n", "nginx.conf" to """
                worker_processes 1;
                pid /tmp/nginx.pid;
                error_log /tmp/nginx-error.log warn;
                events { worker_connections 512; }
                http {
                    include /etc/nginx/mime.types;
                    access_log off;
                    client_body_temp_path /tmp/body;
                    proxy_temp_path /tmp/proxy;
                    fastcgi_temp_path /tmp/fastcgi;
                    uwsgi_temp_path /tmp/uwsgi;
                    scgi_temp_path /tmp/scgi;
                    map ${'$'}http_upgrade ${'$'}connection_upgrade { default upgrade; '' close; }
                    map ${'$'}http_origin ${'$'}erp_origin { default ${'$'}http_origin; '' https://erp:8443; }
                    server { listen 8080; location = /healthz { return 200 'ready'; } location / { return 404; } }
                    server {
                        listen 8443 ssl;
                        server_name erp;
                        ssl_certificate /run/secrets/web.pem;
                        ssl_certificate_key /run/secrets/web-key.pem;
                        ssl_protocols TLSv1.2 TLSv1.3;
                        client_max_body_size 10m;
                        location /assets/ { alias /home/frappe/frappe-bench/assets/; }
                        location /files/ { alias /home/frappe/frappe-bench/sites/$SITE/public/files/; }
                        location /socket.io/ {
                            proxy_pass http://websocket:9000;
                            proxy_http_version 1.1;
                            proxy_set_header Upgrade ${'$'}http_upgrade;
                            proxy_set_header Connection ${'$'}connection_upgrade;
                            proxy_set_header Origin ${'$'}erp_origin;
                            proxy_set_header Host ${'$'}http_host;
                            proxy_set_header X-Frappe-Site-Name $SITE;
                        }
                        location / {
                            proxy_pass http://backend:8000;
                            proxy_set_header Host ${'$'}http_host;
                            proxy_set_header X-Forwarded-Proto https;
                            proxy_set_header X-Frappe-Site-Name $SITE;
                        }
                    }
                }
            """.trimIndent() + "\n")
    }
}
