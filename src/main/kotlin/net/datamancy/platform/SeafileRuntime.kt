package net.datamancy.platform

import java.nio.file.Path

/** Native CE filesystem storage and isolated synthetic identities; no host files or office/mail integration. */
internal object SeafileRuntime {
    const val ROOT = "/opt/seafile/seafile-server-13.0.28"
    fun spec(inventory: AcquiredInventory, name: String = "seafile"): PrivateDeploymentSpec {
        fun image(id: String) = inventory.images.single { it.product == id }.also { require(it.os == "linux" && it.architecture == "amd64") }
        val app = image("seafile"); val maria = image("mariadb"); val redis = image("valkey")
        val db = RuntimeProcess("mariadb", maria.pinnedImage, maria.imageId, 999, environmentFile = "mariadb.env",
            volumes = listOf(RuntimeMount("mariadb", "/var/lib/mysql")), memoryMiB = 1024, apparmorProfile = "p0v3-private-v1")
        val base = RuntimeProcess("server", app.pinnedImage, app.imageId, 1000, environmentFile = "app.env",
            volumes = listOf(RuntimeMount("state", "/state"), RuntimeMount("rpc", "/rpc")), memoryMiB = 1024, apparmorProfile = "p0v3-private-v1")
        return PrivateDeploymentSpec(name = name, volumes = listOf(RuntimeVolume("mariadb", 999), RuntimeVolume("cache", 999), RuntimeVolume("state", 1000), RuntimeVolume("rpc", 1000)), processes = listOf(
            db.copy(id = "mariadb-init", oneShot = true, entrypoint = "/bin/sh", command = listOf("-ec", """
                mariadb-install-db --no-defaults --datadir=/var/lib/mysql --auth-root-authentication-method=normal --skip-test-db
                mariadbd --no-defaults --datadir=/var/lib/mysql --bootstrap --skip-networking <<SQL
                DELETE FROM mysql.global_priv WHERE User = '' OR (User = 'root' AND Host <> 'localhost');
                FLUSH PRIVILEGES;
                ALTER USER 'root'@'localhost' IDENTIFIED BY '${'$'}MARIADB_ROOT_PASSWORD';
                CREATE DATABASE ccnet_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
                CREATE DATABASE seafile_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
                CREATE DATABASE seahub_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
                CREATE USER 'seafile'@'%' IDENTIFIED BY '${'$'}APP_PASSWORD';
                GRANT ALL PRIVILEGES ON ccnet_db.* TO 'seafile'@'%';
                GRANT ALL PRIVILEGES ON seafile_db.* TO 'seafile'@'%';
                GRANT ALL PRIVILEGES ON seahub_db.* TO 'seafile'@'%';
                SQL
            """.trimIndent())),
            db.copy(dependencies = listOf("mariadb-init"), entrypoint = "/usr/sbin/mariadbd", command = listOf("--no-defaults", "--datadir=/var/lib/mysql", "--socket=/tmp/mysql.sock", "--pid-file=/tmp/mysql.pid", "--bind-address=0.0.0.0", "--skip-name-resolve", "--max-connections=96", "--innodb-buffer-pool-size=256M", "--character-set-server=utf8mb4", "--collation-server=utf8mb4_unicode_ci"),
                readiness = listOf("/bin/sh", "-ec", "MYSQL_PWD=\"${'$'}MARIADB_ROOT_PASSWORD\" mariadb --socket=/tmp/mysql.sock -u root -Nse 'SELECT 1' | grep -qx 1")),
            RuntimeProcess("cache", redis.pinnedImage, redis.imageId, 999, entrypoint = "/usr/local/bin/valkey-server", command = listOf("/run/secrets/cache.conf"),
                volumes = listOf(RuntimeMount("cache", "/data")), files = listOf(RuntimeFile("cache.conf", "/run/secrets/cache.conf")), apparmorProfile = "p0v3-private-v1",
                readiness = listOf("/bin/sh", "-ec", "export REDISCLI_AUTH=\"${'$'}(sed -n 's/^requirepass //p' /run/secrets/cache.conf)\"; test \"${'$'}(valkey-cli ping)\" = PONG")),
            base.copy(id = "schema-init", dependencies = listOf("mariadb", "cache"), oneShot = true, entrypoint = "/usr/bin/python3", command = listOf("/run/secrets/schema.py"),
                files = listOf("schema.py", "seahub-settings.py", "seafile.conf").map { RuntimeFile(it, "/run/secrets/$it") }),
            base.copy(dependencies = listOf("schema-init"), entrypoint = "/usr/bin/python3",
                files = listOf(RuntimeFile("process-init.py", "/run/secrets/process-init.py")),
                command = listOf("/run/secrets/process-init.py", "$ROOT/seafile/bin/seaf-server", "-c", "/state/ccnet", "-F", "/state/conf", "-d", "/state/seafile-data", "-l", "/state/logs/seafile.log", "-P", "/tmp/seafile.pid", "-p", "/rpc", "-f"),
                readiness = listOf("/usr/bin/python3", "-c", "from seaserv import ccnet_api; ccnet_api.get_emailusers('DB',0,1)")),
            base.copy(id = "users-init", dependencies = listOf("server"), oneShot = true, entrypoint = "/usr/bin/python3", command = listOf("/run/secrets/users.py"),
                files = listOf("users.py", "users.json").map { RuntimeFile(it, "/run/secrets/$it") }),
            base.copy(id = "backend", dependencies = listOf("users-init"), entrypoint = "/usr/bin/python3", command = listOf("/run/secrets/seafile-web.py"),
                files = listOf(RuntimeFile("seafile-web.py", "/run/secrets/seafile-web.py")),
                readiness = listOf("/usr/bin/python3", "-c", "import urllib.request; r=urllib.request.urlopen('http://127.0.0.1:8000/api2/ping/',timeout=5); raise SystemExit(0 if r.status==200 else 1)")),
            base.copy(id = "files", dependencies = listOf("backend"), environmentFile = null, volumes = emptyList(), entrypoint = "/usr/sbin/nginx", command = listOf("-c", "/run/secrets/nginx.conf", "-g", "daemon off;"),
                files = listOf("nginx.conf", "ca.pem", "web.pem", "web-key.pem").map { RuntimeFile(it, "/run/secrets/$it") }, readinessHttpPort = 8080, readinessHttpPath = "/healthz")
        )).also { PrivateDeployment.validate(it) }
    }
    /** Provider-less recipe: compiler must attach the scoped mariadb/cache endpoints before sealing. */
    fun applicationSpec(inventory: AcquiredInventory, name: String = "seafile"): PrivateDeploymentSpec {
        val source = spec(inventory, name)
        val providers = setOf("mariadb-init", "mariadb", "cache")
        return source.copy(volumes = source.volumes.filterNot { it.id in setOf("mariadb", "cache") },
            processes = source.processes.filterNot { it.id in providers }.map { p ->
                p.copy(dependencies = p.dependencies.filterNot { it in providers })
            }).also { PrivateDeployment.validate(it) }
    }

    /** The provider provisions seafile's three databases and isolated cache credential, never a root login. */
    fun applicationInputs(databasePassword: String, cachePassword: String,
        pki: () -> Map<String, String> = { PrivateWebPki.generate("files") }): Map<String, String> {
        require(listOf(databasePassword, cachePassword).all { it.matches(Regex("[a-f0-9]{64}")) } && databasePassword != cachePassword)
        val files = inputs(pki).toMutableMap()
        files.remove("mariadb.env"); files.remove("cache.conf")
        files["app.env"] = files.getValue("app.env").lineSequence().filter { it.isNotEmpty() }.joinToString("\n", postfix = "\n") {
            when {
                it.startsWith("SEAFILE_MYSQL_DB_PASSWORD=") -> "SEAFILE_MYSQL_DB_PASSWORD=$databasePassword"
                it.startsWith("REDIS_PASSWORD=") -> "REDIS_PASSWORD=$cachePassword"
                else -> it
            }
        }
        return files
    }

    /** Pure projection after D03 verifies exact compiled recipe and cold-imported volumes. */
    fun coldRestoreSpec(compiled: PrivateDeploymentSpec): PrivateDeploymentSpec {
        val initializers = compiled.processes.filter { it.oneShot }.map { it.id }.toSet()
        require(initializers == setOf("schema-init", "users-init", "mariadb-init") ||
            initializers == setOf("schema-init", "users-init")) { "Unsupported Seafile initializer cohort" }
        require(compiled.processes.filterNot { it.oneShot }.map { it.id }.toSet() ==
            (if ("mariadb-init" in initializers) setOf("mariadb", "cache", "server", "backend", "files") else setOf("server", "backend", "files")))
        val byId = compiled.processes.associateBy { it.id }
        fun dependencies(id: String): List<String> = if (id in initializers)
            byId.getValue(id).dependencies.flatMap(::dependencies) else listOf(id)
        val guard = "test -d /state/seafile-data; test ! -L /state/seafile-data; test -s /state/conf/seahub_settings.py; test ! -L /state/conf/seahub_settings.py; "
        return compiled.copy(processes = compiled.processes.filterNot { it.oneShot }.map { process ->
            val p = process.copy(dependencies = process.dependencies.flatMap(::dependencies).distinct())
            when (p.id) {
                "mariadb" -> p.copy(environmentFile = null, readiness = listOf("/bin/sh", "-ec", "test -S /tmp/mysql.sock"))
                "server" -> {
                    require(p.entrypoint == "/usr/bin/python3" && p.command.first() == "/run/secrets/process-init.py")
                    p.copy(entrypoint = "/bin/sh", command = listOf("-ec", guard + "exec /usr/bin/python3 \"${'$'}@\"", "restored-seafile") + p.command)
                }
                else -> p
            }
        }, databaseAccess = compiled.databaseAccess.filterNot { it.consumer in initializers }).also { PrivateDeployment.validate(it) }
    }

    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "seafile", store: RuntimeStore = RuntimeStore.LEGACY): Path = RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }
    fun inputs(pki: () -> Map<String, String> = { PrivateWebPki.generate("files") }): Map<String, String> {
        val db = RuntimePreparation.password(); val cache = RuntimePreparation.password()
        val users = kotlinx.serialization.json.buildJsonObject { for (role in listOf("owner", "reader", "outsider")) put(role, kotlinx.serialization.json.JsonPrimitive(RuntimePreparation.password())) }
        return pki() + mapOf(
            "mariadb.env" to "MARIADB_ROOT_PASSWORD=${RuntimePreparation.password()}\nAPP_PASSWORD=$db\n",
            "cache.conf" to "bind 0.0.0.0\nprotected-mode yes\nport 6379\ndir /data\nrequirepass $cache\nsave \"\"\nappendonly no\n",
            "app.env" to """
                PYTHONDONTWRITEBYTECODE=1
                HOME=/tmp
                PYTHON=/usr/bin/python3
                PYTHONPATH=$ROOT/seafile/lib/python3/site-packages:$ROOT/seafile/lib64/python3/site-packages:$ROOT/seahub:$ROOT/seahub/thirdpart:/state/conf
                LD_LIBRARY_PATH=$ROOT/seafile/lib:$ROOT/seafile/lib64
                MARIADB_PLUGIN_DIR=$ROOT/seafile/lib/plugin
                CCNET_CONF_DIR=/state/ccnet
                SEAFILE_CENTRAL_CONF_DIR=/state/conf
                SEAFILE_DATA_DIR=/state/seafile-data
                SEAFILE_RPC_PIPE_PATH=/rpc
                SEAHUB_DIR=$ROOT/seahub
                SEAHUB_LOG_DIR=/state/logs
                DJANGO_SETTINGS_MODULE=seahub.settings
                SEAFILE_MYSQL_DB_HOST=mariadb
                SEAFILE_MYSQL_DB_PORT=3306
                SEAFILE_MYSQL_DB_USER=seafile
                SEAFILE_MYSQL_DB_PASSWORD=$db
                SEAFILE_MYSQL_DB_CCNET_DB_NAME=ccnet_db
                SEAFILE_MYSQL_DB_SEAFILE_DB_NAME=seafile_db
                SEAFILE_MYSQL_DB_SEAHUB_DB_NAME=seahub_db
                SEAFILE_SERVER_HOSTNAME=files:8443
                SEAFILE_SERVER_PROTOCOL=https
                JWT_PRIVATE_KEY=${RuntimePreparation.password()}
                CACHE_PROVIDER=redis
                REDIS_HOST=cache
                REDIS_PORT=6379
                REDIS_PASSWORD=$cache
                ENABLE_GO_FILESERVER=true
                ENABLE_SEADOC=false
                ENABLE_SEAFDAV=false
                ENABLE_SEAFILE_AI=false
            """.trimIndent() + "\n",
            "seafile.conf" to "[fileserver]\nhost=0.0.0.0\nport=8082\nuse_go_fileserver=true\nmax_upload_size=10\n",
            "users.json" to "$users\n",
            "users.py" to """
                if not __debug__: raise SystemExit('Optimized Python refused')
                import json
                from seaserv import ccnet_api
                users=json.load(open('/run/secrets/users.json'))
                for role,password in users.items():
                    email=role+'@localhost.invalid'
                    if ccnet_api.get_emailuser(email) is not None: raise SystemExit('Existing user retained; refusing replay')
                    if ccnet_api.add_emailuser(email,password,1 if role=='owner' else 0,1) != 0: raise SystemExit('Native user creation failed')
            """.trimIndent() + "\n",
            "schema.py" to """
                if not __debug__: raise SystemExit('Optimized Python refused')
                import os,shutil,pymysql
                from pathlib import Path
                os.umask(0o077)
                state=Path('/state')
                if list(state.iterdir()): raise SystemExit('Existing or interrupted state retained')
                for name in ('conf','ccnet','logs','seafile-data','seahub-data'): (state/name).mkdir()
                for source,dest in (('seafile.conf','seafile.conf'),('seahub-settings.py','seahub_settings.py')): shutil.copyfile('/run/secrets/'+source,state/'conf'/dest)
                (state/'conf'/'seafdav.conf').write_text('[WEBDAV]\nenabled=false\n')
                # Same shipped schemas and statement splitting as the pinned native installer;
                # avoid its import-time attempt to create /opt/seafile/conf on the immutable root.
                schemas={'ccnet_db':'sql/mysql/ccnet.sql','seafile_db':'sql/mysql/seafile.sql','seahub_db':'seahub/sql/mysql.sql'}
                connections={name:pymysql.connect(host='mariadb',port=3306,user='seafile',password=os.environ['SEAFILE_MYSQL_DB_PASSWORD'],database=name) for name in schemas}
                for conn in connections.values():
                    with conn.cursor() as cursor:
                        cursor.execute('SHOW TABLES')
                        if cursor.fetchall(): raise SystemExit('Existing database retained; refusing schema replay')
                for name,path in schemas.items():
                    conn=connections[name]
                    with conn.cursor() as cursor:
                        for statement in Path('$ROOT',path).read_text().split(';'):
                            if statement.strip(): cursor.execute(statement.strip())
                    conn.commit();conn.close()
                os.sync()
            """.trimIndent() + "\n",
            "seahub-settings.py" to """
                import os
                SECRET_KEY='${RuntimePreparation.password()}'
                DATABASES={'default':{'ENGINE':'django.db.backends.mysql','NAME':'seahub_db','USER':'seafile','PASSWORD':os.environ['SEAFILE_MYSQL_DB_PASSWORD'],'HOST':'mariadb','PORT':'3306','OPTIONS':{'charset':'utf8mb4'}}}
                ALLOWED_HOSTS=['files','backend','127.0.0.1']
                CSRF_TRUSTED_ORIGINS=['https://files:8443']
                SECURE_PROXY_SSL_HEADER=('HTTP_X_FORWARDED_PROTO','https')
                SESSION_COOKIE_SECURE=True
                CSRF_COOKIE_SECURE=True
                ENABLE_SIGNUP=False
                ENABLE_SETTINGS_VIA_WEB=False
                EMAIL_BACKEND='django.core.mail.backends.dummy.EmailBackend'
                SEND_EMAIL_ON_ADDING_SYSTEM_MEMBER=False
                SEND_EMAIL_ON_RESETTING_USER_PASSWD=False
                AVATAR_FILE_STORAGE='seahub.base.database_storage.DatabaseStorage'
                ENABLE_SEADOC=False
                ENABLE_ONLYOFFICE=False
                TIME_ZONE='UTC'
            """.trimIndent() + "\n",
            "process-init.py" to SeafileRuntime::class.java.getResource("/runtime/process-init.py")!!.readText(),
            "seafile-web.py" to SeafileRuntime::class.java.getResource("/runtime/seafile-web.py")!!.readText(),
            "nginx.conf" to """
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
                    server { listen 8080; location = /healthz { return 200 'ready'; } location / { return 404; } }
                    server {
                        listen 8443 ssl;
                        server_name files;
                        ssl_certificate /run/secrets/web.pem;
                        ssl_certificate_key /run/secrets/web-key.pem;
                        ssl_protocols TLSv1.2 TLSv1.3;
                        client_max_body_size 10m;
                        location /media/ { alias $ROOT/seahub/media/; }
                        location /seafhttp/ {
                            proxy_pass http://backend:8082/;
                            proxy_set_header Host ${'$'}http_host;
                            proxy_set_header X-Forwarded-Proto https;
                        }
                        location / {
                            proxy_pass http://backend:8000;
                            proxy_set_header Host ${'$'}http_host;
                            proxy_set_header X-Forwarded-Proto https;
                        }
                    }
                }
            """.trimIndent() + "\n"
        )
    }
}
