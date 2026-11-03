package net.datamancy.platform

import java.nio.file.Path

/** Private CE 10 memory-first editor plus native Seafile storage. No active-session durability claim. */
internal object OfficeRuntime {
    const val IMAGE = "localhost/p0v3-onlyoffice@sha256:48011079cf6ea448bf71cd88cd8f6e750750638163a3fa0f9ef541e625ede0cf"
    const val IMAGE_ID = "f6e0ea5288868f314c57a0dd67af7a2d32955ed67876e889df36858be359acf8"
    const val ROOT = "/var/www/onlyoffice/documentserver"
    fun spec(inventory: AcquiredInventory, name: String = "files-office"): PrivateDeploymentSpec {
        val source = SeafileRuntime.spec(inventory, name)
        val office = RuntimeProcess("docservice", IMAGE, IMAGE_ID, 1000, entrypoint = "/bin/sh", environmentFile = "office.env", memoryMiB = 2048,
            volumes = listOf(RuntimeMount("office", "/state")), apparmorProfile = "p0v3-private-v1",
            files = listOf(RuntimeFile("office.json", "/run/office/local.json"), RuntimeFile("office-log.json", "/run/office/log.json"), RuntimeFile("ca.pem", "/run/secrets/ca.pem"), RuntimeFile("process-init.py", "/run/secrets/process-init.py")))
        val processes = source.processes.map { p -> if (p.id == "backend") p.copy(files = p.files + listOf(RuntimeFile("office-callback-guard.py", "/run/secrets/office_callback_guard.py"), RuntimeFile("office-ca-bundle.pem", "/run/secrets/office-ca-bundle.pem"))) else p } + listOf(
            office.copy(id = "office-state-init", oneShot = true, command = listOf("-ec", "test -z \"${'$'}(ls -A /state)\"; umask 077; mkdir -p /state/cache/files /state/logs; sync")),
            office.copy(dependencies = listOf("office-state-init"), command = listOf("-ec", "cd $ROOT/server/DocService; exec /usr/bin/python3 /run/secrets/process-init.py $ROOT/server/DocService/docservice"), readinessHttpPort = 8000, readinessHttpPath = "/healthcheck"),
            office.copy(id = "office", dependencies = listOf("docservice"), environmentFile = null, entrypoint = "/usr/sbin/nginx", command = listOf("-c", "/run/secrets/office-nginx.conf", "-g", "daemon off;"),
                files = listOf("office-nginx.conf", "office-ca.pem", "office-web.pem", "office-web-key.pem").map { RuntimeFile(it, "/run/secrets/$it") }, readinessHttpPort = 8080, readinessHttpPath = "/healthcheck")
        )
        return source.copy(volumes = source.volumes + RuntimeVolume("office", 1000), processes = processes).also { PrivateDeployment.validate(it) }
    }
    /** Office plus native Seafile, with SQL/cache supplied exactly once by the canonical compiler. */
    fun applicationSpec(inventory: AcquiredInventory, name: String = "files-office"): PrivateDeploymentSpec {
        val source = spec(inventory, name)
        val providers = setOf("mariadb-init", "mariadb", "cache")
        return source.copy(volumes = source.volumes.filterNot { it.id in setOf("mariadb", "cache") },
            processes = source.processes.filterNot { it.id in providers }.map { p ->
                p.copy(dependencies = p.dependencies.filterNot { it in providers })
            }).also { PrivateDeployment.validate(it) }
    }

    fun applicationInputs(databasePassword: String, cachePassword: String,
        pki: (String) -> Map<String, String> = { PrivateWebPki.generate(it) }): Map<String, String> {
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

    /** Retire only known bootstrap jobs; preserve callback uncertainty and saved document/cache state. */
    fun coldRestoreSpec(compiled: PrivateDeploymentSpec): PrivateDeploymentSpec {
        val officeIds = setOf("office-state-init", "docservice", "office")
        require(compiled.processes.filter { it.id in officeIds }.map { it.id }.toSet() == officeIds)
        require(compiled.processes.single { it.id == "office-state-init" }.oneShot)
        val storage = SeafileRuntime.coldRestoreSpec(compiled.copy(
            processes = compiled.processes.filterNot { it.id in officeIds },
            volumes = compiled.volumes.filterNot { it.id == "office" }))
        val editor = compiled.processes.filter { it.id in setOf("docservice", "office") }.map { p ->
            require(!p.oneShot)
            if (p.id == "docservice") {
                require(p.entrypoint == "/bin/sh" && p.command.size == 2 && p.command.first() == "-ec")
                p.copy(dependencies = p.dependencies.filterNot { it == "office-state-init" },
                    command = listOf("-ec", "test -d /state/cache/files; test ! -L /state/cache/files; " + p.command[1]))
            } else p
        }
        return compiled.copy(processes = storage.processes + editor,
            databaseAccess = storage.databaseAccess).also { PrivateDeployment.validate(it) }
    }

    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "files-office", store: RuntimeStore = RuntimeStore.LEGACY): Path = RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }
    fun inputs(pki: (String) -> Map<String, String> = { PrivateWebPki.generate(it) }): Map<String, String> {
        val files = SeafileRuntime.inputs { pki("files") }.toMutableMap()
        val tls = pki("office"); tls.forEach { (key, value) -> files["office-$key"] = value }
        files["office-ca-bundle.pem"] = files.getValue("ca.pem") + tls.getValue("ca.pem")
        val jwt = RuntimePreparation.password(); val storage = RuntimePreparation.password(); val session = RuntimePreparation.password()
        files["app.env"] = files.getValue("app.env").replace("/state/conf\n", "/state/conf:/run/secrets\n") + "REQUESTS_CA_BUNDLE=/run/secrets/office-ca-bundle.pem\n"
        files["seahub-settings.py"] = files.getValue("seahub-settings.py").replace("ENABLE_ONLYOFFICE=False", "ENABLE_ONLYOFFICE=True") + """
            ONLYOFFICE_APIJS_URL='https://office:8443/web-apps/apps/api/documents/api.js'
            ONLYOFFICE_JWT_SECRET='$jwt'
            ONLYOFFICE_FORCE_SAVE=True
            VERIFY_ONLYOFFICE_CERTIFICATE=True
            from seahub.settings import MIDDLEWARE as DEFAULT_MIDDLEWARE, LOGGING as DEFAULT_LOGGING
            import copy
            MIDDLEWARE=['office_callback_guard.OfficeCallbackGuard']+list(DEFAULT_MIDDLEWARE)
            LOGGING=copy.deepcopy(DEFAULT_LOGGING)
            LOGGING['handlers']['office_null']={'class':'logging.NullHandler'}
            LOGGING['loggers']['onlyoffice']={'handlers':['office_null'],'propagate':False,'level':'CRITICAL'}
        """.trimIndent() + "\n"
        files["schema.py"] = files.getValue("schema.py") + """
            import sqlite3
            ledger=sqlite3.connect(state/'office-callbacks.sqlite3')
            ledger.execute('PRAGMA synchronous=FULL')
            ledger.execute("CREATE TABLE callbacks(key TEXT PRIMARY KEY, expires INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('pending','done')))")
            ledger.commit();ledger.close()
            os.chmod(state/'office-callbacks.sqlite3',0o600)
            os.sync()
        """.trimIndent() + "\n"
        files["office-callback-guard.py"] = resource("office-callback-guard.py")
        files["office.env"] = "NODE_ENV=production-linux\nNODE_CONFIG_DIR=/etc/onlyoffice/documentserver:/run/office\nNODE_DISABLE_COLORS=1\nNODE_EXTRA_CA_CERTS=/run/secrets/ca.pem\nHOME=/tmp\nPKG_NATIVE_CACHE_PATH=/tmp/pkg\nLD_LIBRARY_PATH=$ROOT/server/FileConverter/bin\nPYTHONDONTWRITEBYTECODE=1\n"
        files["office-log.json"] = """{"appenders":{"console":{"type":"console"}},"categories":{"default":{"appenders":["console"],"level":"WARN"}}} """
        files["office.json"] = """
            {"aiSettings":{"enable":false,"allowBrowserProxy":false},"statsd":{"useMetrics":false},
             "log":{"filePath":"/run/office/log.json"},"runtimeConfig":{"filePath":"/state/runtime.json"},
             "storage":{"fs":{"folderPath":"/state/cache/files","secretString":"$storage"}},
             "openpgpjs":{"encrypt":{"passwords":["$session"]},"decrypt":{"passwords":["$session"]}},"aesEncrypt":{"secret":"$session"},
             "services":{"CoAuthoring":{
               "server":{"host":"0.0.0.0","port":8000,"workerpercpu":0.01,"docbuilderEnable":false,"healthcheckfilepath":"$ROOT/server/DocService/public/healthcheck.docx"},
               "requestDefaults":{"rejectUnauthorized":true},
               "request-filtering-agent":{"allowPrivateIPAddress":true,"allowMetaIPAddress":false},
               "ipfilter":{"useforrequest":false,"rules":[{"address":"files","allowed":true},{"address":"office","allowed":true},{"address":"*","allowed":false}]},
               "secret":{"browser":{"string":"$jwt"},"inbox":{"string":"$jwt"},"outbox":{"string":"$jwt"},"session":{"string":"$session"}},
               "token":{"enable":{"browser":true,"request":{"inbox":true,"outbox":true}},"outbox":{"inBody":false,"expires":"5m"}},
               "callbackBackoffOptions":{"retries":0}}},
             "FileConverter":{"converter":{"maxprocesscount":0.01,"maxDownloadBytes":10485760,"downloadAttemptMaxCount":1}}}
        """.trimIndent() + "\n"
        files["office-nginx.conf"] = """
            worker_processes 1;
            pid /tmp/office-nginx.pid;
            error_log /tmp/office-nginx-error.log warn;
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
              upstream docservice { server docservice:8000; }
              server { listen 8080; location = /healthcheck { proxy_pass http://docservice/healthcheck; } location / { return 404; } }
              server {
                listen 8443 ssl;
                server_name office;
                ssl_certificate /run/secrets/office-web.pem;
                ssl_certificate_key /run/secrets/office-web-key.pem;
                ssl_protocols TLSv1.2 TLSv1.3;
                client_max_body_size 10m;
                proxy_http_version 1.1;
                proxy_set_header Host ${'$'}http_host;
                proxy_set_header X-Forwarded-Host ${'$'}http_host;
                proxy_set_header X-Forwarded-Proto https;
                proxy_set_header Upgrade ${'$'}http_upgrade;
                proxy_set_header Connection ${'$'}connection_upgrade;
                proxy_read_timeout 600s;
                location ~ ^/(?:[0-9]+\.[0-9]+\.[0-9]+[.-][\w]+/)?(?:internal|info|ai-proxy)(?:/|${'$'}) { return 403; }
                location ~ ^/(?:[0-9]+\.[0-9]+\.[0-9]+[.-][\w]+/)?(web-apps|sdkjs|sdkjs-plugins|fonts|dictionaries)(/.*)${'$'} { alias $ROOT/${'$'}1${'$'}2; }
                location ~ ^(/cache/files.*)(/.*) {
                  alias /state${'$'}1;
                  secure_link ${'$'}arg_md5,${'$'}arg_expires;
                  secure_link_md5 "${'$'}secure_link_expires${'$'}{uri}$storage";
                  if (${'$'}secure_link = "") { return 403; }
                  if (${'$'}secure_link = "0") { return 410; }
                }
                location ~ ^/[0-9]+\.[0-9]+\.[0-9]+[.-][\w]+/(?<unversioned>.*)${'$'} { proxy_pass http://docservice/${'$'}unversioned${'$'}is_args${'$'}args; }
                location / { proxy_pass http://docservice; }
              }
            }
        """.trimIndent() + "\n"
        return files
    }
    private fun resource(name: String) = OfficeRuntime::class.java.getResource("/runtime/$name")!!.readText()
}
