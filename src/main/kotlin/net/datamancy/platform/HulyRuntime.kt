package net.datamancy.platform

import java.nio.file.Path
import java.security.SecureRandom
import java.util.HexFormat
import kotlinx.serialization.json.*

/** Exact private v0.7.426 cohort. Native Kafka remains unauthenticated inside this dedicated internal network. */
internal object HulyRuntime {
    const val SEARCH_BASE = "docker.io/library/elasticsearch@sha256:55a0901f558968fb615d25032fdbeb9c6dd112d8ead05b830b1da4326e2f482b"
    const val SEARCH_IMAGE = "localhost/p0v3-huly-elasticsearch@sha256:b07456315f9a55e5940a4da24e5d5a0ab6293f8c8cf0f6ae2c826f0b739ae133"
    const val SEARCH_ID = "f033c63bad3eee3f7d3bc02066a0fbc4d69c527081a37889cc42485da9fa955c"
    const val KVS_BASE = "docker.io/hardcoreeng/hulykvs@sha256:73f268e2f42ab9c41b805b574d9ab583cfab063e7d7573df450b00ebb895ff7e"
    const val KVS_IMAGE = "localhost/p0v3-huly-kvs@sha256:889f824034e49ce6b4666d3dcb343930e1b8b4f3bea3234cec9394bfef09d503"
    const val KVS_ID = "3e9534dc7a9d41510464518422d15f8d0a88b5ee1d0c336f1a5e061388592aef"
    const val CADDY_BASE = "docker.io/library/caddy@sha256:04913b1da43339a40ad1ea87827d70a576ac5aa6cf674c6e24fdca675887533a"
    const val CADDY_IMAGE = "localhost/p0v3-huly-caddy@sha256:12aaf65164cae642f31c1434d19ff3fd83cea5bb2e03ecaf473308b594ef47b9"
    const val CADDY_ID = "dba10c44979358e71c0e6893e72b8788724ba663786d3c09c12e353b41d47776"
    private fun resource(name: String): String = requireNotNull(javaClass.getResourceAsStream("/runtime/$name")).bufferedReader().use { it.readText() }
    fun spec(inventory: AcquiredInventory, name: String = "huly"): PrivateDeploymentSpec {
        fun image(product: String) = inventory.images.single { it.product == product }.also { require(it.os == "linux" && it.architecture == "amd64") }
        require(image("huly-elasticsearch").pinnedImage == SEARCH_BASE)
        require(image("huly-kvs").pinnedImage == KVS_BASE)
        require(image("caddy").pinnedImage == CADDY_BASE)
        fun files(vararg names: String) = names.map { RuntimeFile(it, "/run/secrets/$it") }
        fun tcp(port: Int) = listOf("node", "-e", "const s=require('node:net').connect($port,'127.0.0.1');s.on('connect',()=>{s.end();process.exit(0)});s.on('error',()=>process.exit(1));s.setTimeout(2000,()=>process.exit(1))")
        fun node(id: String, dependencies: List<String>, port: Int?): RuntimeProcess {
            val app = image("huly-$id"); val folder = if (id == "front") "/app" else "/usr/src/app"
            return RuntimeProcess(id, app.pinnedImage, app.imageId, 1000, dependencies = dependencies,
                entrypoint = "/usr/local/bin/node", command = (if (id == "account") listOf("--require", "/run/secrets/huly-timers.cjs") else emptyList()) + "$folder/bundle.js", environmentFile = "$id.env",
                files = files("backend-ca.pem") + (if (id == "account") files("huly-timers.cjs") else emptyList()),
                volumes = if (id == "workspace") listOf(RuntimeMount("workspace-logs", "$folder/upgrade-logs")) else emptyList(), tmpfs = listOf("/tmp", "$folder/logs"), apparmorProfile = "p0v3-private-v1",
                memoryMiB = if (id in setOf("workspace", "transactor", "rekoni")) 1024 else 512,
                readiness = port?.let(::tcp) ?: listOf("node", "-e", "process.kill(1,0)"))
        }
        val cr = image("huly-cockroach"); val objects = image("huly-objectstore"); val queue = image("huly-redpanda")
        val crFiles = listOf(RuntimeFile("cr-ca.pem", "/run/secrets/ca.crt"), RuntimeFile("cr-node.pem", "/run/secrets/node.crt"), RuntimeFile("cr-node-key.pem", "/run/secrets/node.key"))
        val elastic = RuntimeProcess("elastic", SEARCH_IMAGE, SEARCH_ID, 1000, dependencies = listOf("elastic-config-init"),
            entrypoint = "/bin/tini", command = listOf("--", "/usr/share/elasticsearch/bin/elasticsearch"), environmentFile = "elastic.env",
            files = listOf("es-ca.pem", "es-node.pem", "es-node-key.pem").map { RuntimeFile(it, "/configuration/$it") },
            volumes = listOf(RuntimeMount("elastic", "/usr/share/elasticsearch/data"), RuntimeMount("elastic-config", "/configuration")),
            apparmorProfile = "p0v3-private-v1", memoryMiB = 1536, tmpfs = listOf("/tmp", "/usr/share/elasticsearch/logs"),
            readiness = listOf("/bin/sh", "-ec", "test \"${'$'}(curl --cacert /configuration/es-ca.pem -s -o /dev/null -w '%{http_code}' https://elastic:9200/)\" = 401"))
        val account = node("account", listOf("account-bootstrap", "elastic-users", "objects", "redpanda", "stats"), 3000)
        return PrivateDeploymentSpec(name = name, volumes = listOf("cockroach", "objects", "redpanda", "elastic", "elastic-config", "workspace-logs").map { RuntimeVolume(it, 1000) }, processes = listOf(
            RuntimeProcess("cockroach", cr.pinnedImage, cr.imageId, 1000, entrypoint = "/cockroach/cockroach",
                command = listOf("start-single-node", "--store=/state", "--certs-dir=/run/secrets", "--listen-addr=0.0.0.0:26257", "--advertise-addr=cockroach:26257", "--http-addr=0.0.0.0:8080", "--cache=128MiB", "--max-sql-memory=128MiB", "--max-disk-temp-storage=128MiB", "--logtostderr=WARNING"),
                files = crFiles, volumes = listOf(RuntimeMount("cockroach", "/state")), environmentFile = "cockroach.env",
                apparmorProfile = "p0v3-private-v1", memoryMiB = 2048,
                readiness = listOf("/bin/sh", "-ec", "curl -fsS --cacert /run/secrets/ca.crt 'https://cockroach:8080/health?ready=1' >/dev/null")),
            RuntimeProcess("database-init", cr.pinnedImage, cr.imageId, 1000, dependencies = listOf("cockroach"), oneShot = true,
                entrypoint = "/cockroach/cockroach", command = listOf("sql", "--host=cockroach:26257", "--certs-dir=/run/secrets", "--file=/run/secrets/database.sql"),
                files = listOf(RuntimeFile("cr-ca.pem", "/run/secrets/ca.crt"), RuntimeFile("cr-root.pem", "/run/secrets/client.root.crt"), RuntimeFile("cr-root-key.pem", "/run/secrets/client.root.key"), RuntimeFile("database.sql", "/run/secrets/database.sql")), apparmorProfile = "p0v3-private-v1"),
            elastic.copy(id = "elastic-config-init", dependencies = emptyList(), oneShot = true, entrypoint = "/bin/sh", environmentFile = "elastic-bootstrap.env",
                volumes = listOf(RuntimeMount("elastic-config", "/configuration")), files = files("elasticsearch.yml"),
                command = listOf("-ec", "test -z \"${'$'}(ls -A /configuration)\"; umask 077; cp -R /usr/share/elasticsearch/config/. /configuration/; cp /run/secrets/elasticsearch.yml /configuration/elasticsearch.yml; sed -i 's/filecount=32,filesize=64m/filecount=4,filesize=8m/' /configuration/jvm.options; printf 'y\\n' | /usr/share/elasticsearch/bin/elasticsearch-keystore create; printf '%s' \"${'$'}ES_BOOTSTRAP_PASSWORD\" | /usr/share/elasticsearch/bin/elasticsearch-keystore add --stdin --force bootstrap.password; sync")),
            elastic,
            node("account", listOf("elastic"), null).copy(id = "elastic-users", oneShot = true, environmentFile = "search-init.env", command = listOf("/run/secrets/huly-search-init.js"), files = files("es-ca.pem", "search-bootstrap.json", "huly-search-init.js")),
            RuntimeProcess("objects", objects.pinnedImage, objects.imageId, 1000, entrypoint = "/usr/bin/silo",
                command = listOf("server", "/data", "--address=:9000", "--console-address=127.0.0.1:9001"), environmentFile = "objects.env",
                volumes = listOf(RuntimeMount("objects", "/data")), apparmorProfile = "p0v3-private-v1", memoryMiB = 1024, readinessHttpPort = 9000, readinessHttpPath = "/minio/health/live"),
            RuntimeProcess("redpanda", queue.pinnedImage, queue.imageId, 1000, entrypoint = "/opt/redpanda/bin/redpanda",
                command = listOf("--redpanda-cfg=/run/secrets/redpanda.yaml", "--overprovisioned", "--smp=1", "--memory=512M", "--reserve-memory=0M", "--lock-memory=false", "--unsafe-bypass-fsync=false", "--default-log-level=warn"),
                files = files("redpanda.yaml"), volumes = listOf(RuntimeMount("redpanda", "/state")), apparmorProfile = "p0v3-private-v1", memoryMiB = 1024,
                readinessHttpPort = 9644, readinessHttpPath = "/v1/status/ready"),
            node("stats", emptyList(), 4900),
            account.copy(id = "account-bootstrap", dependencies = listOf("database-init", "objects", "stats", "redpanda"), oneShot = true,
                files = files("backend-ca.pem", "bootstrap-users.json", "huly-bootstrap.js", "huly-loopback.cjs", "huly-timers.cjs"), command = listOf("/run/secrets/huly-bootstrap.js")),
            account,
            node("workspace", listOf("account"), null),
            node("transactor", listOf("account"), 3333),
            node("collaborator", listOf("transactor"), 3078),
            node("rekoni", emptyList(), 4004),
            node("fulltext", listOf("account", "rekoni", "elastic-users"), 4700),
            node("front", listOf("account", "transactor", "collaborator", "fulltext", "workspace"), 8080),
            RuntimeProcess("kvs", KVS_IMAGE, KVS_ID, 1000, dependencies = listOf("database-init"), environmentFile = "kvs.env", files = files("cr-ca.pem", "huly-kvs-proxy.cjs"),
                entrypoint = "/usr/local/bin/node", command = listOf("/run/secrets/huly-kvs-proxy.cjs"),
                apparmorProfile = "p0v3-private-v1", readinessHttpPort = 8094, readinessHttpPath = "/status"),
            RuntimeProcess("huly", CADDY_IMAGE, CADDY_ID, 1000, dependencies = listOf("front", "kvs"), entrypoint = "/usr/bin/caddy",
                command = listOf("run", "--config", "/run/secrets/caddyfile", "--adapter", "caddyfile"), environmentFile = "web.env",
                files = files("caddyfile", "ca.pem", "web.pem", "web-key.pem"), apparmorProfile = "p0v3-private-v1", readinessHttpPort = 8080, readinessHttpPath = "/healthz")
        )).also { PrivateDeployment.validate(it) }
    }
    fun inputs(
        web: () -> Map<String, String> = { PrivateWebPki.generate("huly") },
        database: () -> Map<String, String> = { PrivateSearchPki.generate("cockroach", "node", "root") },
        search: () -> Map<String, String> = { PrivateSearchPki.generate("elastic") },
        secret: () -> String = { HexFormat.of().formatHex(ByteArray(32).also { SecureRandom().nextBytes(it) }) }
    ): Map<String, String> {
        val secrets = List(9) { secret() }; require(secrets.toSet().size == secrets.size && secrets.all { it.matches(Regex("[a-f0-9]{64}")) })
        val (db, jwt, objectKey, esBootstrap, esAdmin) = secrets
        val esApp = secrets[5]; val cr = database(); val es = search()
        fun env(vararg pairs: Pair<String, String>) = pairs.joinToString("\n", postfix = "\n") { (key, value) -> require(!value.contains('\n') && !value.contains('\r')); "$key=$value" }
        val dbUrl = "postgresql://huly:$db@cockroach:26257/huly?sslmode=verify-full"
        val storage = "minio|objects?accessKey=p0v3huly&secretKey=$objectKey"
        val common = env("HOME" to "/tmp", "NODE_ENV" to "production", "NODE_EXTRA_CA_CERTS" to "/run/secrets/backend-ca.pem", "SERVER_SECRET" to jwt,
            "SECRET" to jwt, "QUEUE_CONFIG" to "redpanda:9092", "STATS_URL" to "http://stats:4900",
            "FRONT_URL" to "https://huly:8443", "ACCOUNTS_URL" to "http://account:3000", "MODEL_ENABLED" to "*", "DISABLE_SIGNUP" to "true",
            "OTEL_SDK_DISABLED" to "true", "OTEL_LOGGER_ENABLED" to "false", "ENABLE_CONSOLE" to "false")
        val result = linkedMapOf<String, String>()
        result.putAll(web())
        result.putAll(mapOf("cr-ca.pem" to cr.getValue("ca.pem"), "cr-node.pem" to cr.getValue("node.pem"), "cr-node-key.pem" to cr.getValue("node-key.pem"), "cr-root.pem" to cr.getValue("admin.pem"), "cr-root-key.pem" to cr.getValue("admin-key.pem"),
            "es-ca.pem" to es.getValue("ca.pem"), "es-node.pem" to es.getValue("node.pem"), "es-node-key.pem" to es.getValue("node-key.pem"), "backend-ca.pem" to (cr.getValue("ca.pem") + es.getValue("ca.pem"))))
        result["cockroach.env"] = env("HOME" to "/tmp", "GOMAXPROCS" to "2", "COCKROACH_SKIP_ENABLING_DIAGNOSTIC_REPORTING" to "true")
        result["database.sql"] = "SET CLUSTER SETTING diagnostics.reporting.enabled = false;\nCREATE USER huly WITH PASSWORD '$db';\nCREATE DATABASE huly OWNER huly;\n"
        result["elastic.env"] = env("ES_PATH_CONF" to "/configuration", "ES_JAVA_OPTS" to "-Xms512m -Xmx512m", "HOME" to "/tmp")
        result["elastic-bootstrap.env"] = result.getValue("elastic.env") + env("ES_BOOTSTRAP_PASSWORD" to esBootstrap)
        result["search-init.env"] = "HOME=/tmp\n"
        result["search-bootstrap.json"] = buildJsonObject { put("bootstrap", esBootstrap); put("admin", esAdmin); put("application", esApp) }.toString()
        result["elasticsearch.yml"] = """
            cluster.name: p0v3-private-huly
            network.host: 0.0.0.0
            discovery.type: single-node
            node.store.allow_mmap: false
            path.logs: /tmp/es-logs
            xpack.security.enabled: true
            xpack.security.http.ssl.enabled: true
            xpack.security.http.ssl.key: es-node-key.pem
            xpack.security.http.ssl.certificate: es-node.pem
            xpack.security.http.ssl.certificate_authorities: [es-ca.pem]
            xpack.security.transport.ssl.enabled: true
            xpack.security.transport.ssl.key: es-node-key.pem
            xpack.security.transport.ssl.certificate: es-node.pem
            xpack.security.transport.ssl.certificate_authorities: [es-ca.pem]
            xpack.ml.enabled: false
            xpack.monitoring.exporters.fixture_disabled.type: local
            xpack.monitoring.exporters.fixture_disabled.enabled: false
            ingest.geoip.downloader.enabled: false
        """.trimIndent() + "\n"
        result["objects.env"] = env("HOME" to "/tmp", "MINIO_ROOT_USER" to "p0v3huly", "MINIO_ROOT_PASSWORD" to objectKey, "MINIO_BROWSER" to "off", "MINIO_UPDATE" to "off", "MINIO_CALLHOME_ENABLE" to "off")
        result["redpanda.yaml"] = """
            redpanda:
              data_directory: /state
              node_id: 0
              seed_servers: []
              rpc_server: {address: 0.0.0.0, port: 33145}
              advertised_rpc_api: {address: redpanda, port: 33145}
              kafka_api: [{address: 0.0.0.0, port: 9092}]
              advertised_kafka_api: [{address: redpanda, port: 9092}]
              admin: [{address: 0.0.0.0, port: 9644}]
              developer_mode: true
              enable_metrics_reporter: false
              storage_min_free_bytes: 16777216
              default_topic_replications: 1
              default_topic_partitions: 1
        """.trimIndent() + "\n"
        for ((id, port) in mapOf("account" to 3000, "workspace" to 0, "transactor" to 3333, "collaborator" to 3078, "rekoni" to 4004, "fulltext" to 4700, "stats" to 4900, "front" to 8080)) {
            result["$id.env"] = common + env("SERVER_PORT" to port.toString(), "PORT" to port.toString(), "ACCOUNT_PORT" to port.toString(), "COLLABORATOR_PORT" to port.toString()) +
                if (id in setOf("account", "workspace", "transactor", "fulltext")) env("DB_URL" to dbUrl, "ACCOUNTS_DB_URL" to dbUrl, "TRANSACTOR_URL" to "ws://transactor:3333;wss://huly:8443/_transactor", "FULLTEXT_URL" to "http://fulltext:4700") else ""
        }
        for (id in listOf("account", "workspace", "transactor", "collaborator", "fulltext", "front")) result["$id.env"] = result.getValue("$id.env") + env("STORAGE_CONFIG" to storage)
        result["fulltext.env"] = result.getValue("fulltext.env") + env("FULLTEXT_DB_URL" to "https://huly:$esApp@elastic:9200", "ELASTIC_INDEX_NAME" to "huly_storage_index", "REKONI_URL" to "http://rekoni:4004")
        result["front.env"] = result.getValue("front.env").lineSequence().filter { it.isNotEmpty() && !it.startsWith("ACCOUNTS_URL=") && !it.startsWith("STATS_URL=") }.joinToString("\n", postfix = "\n") + env("ACCOUNTS_URL" to "https://huly:8443/_accounts", "ACCOUNTS_URL_INTERNAL" to "http://account:3000", "COLLABORATOR_URL" to "wss://huly:8443/_collaborator", "REKONI_URL" to "https://huly:8443/_rekoni", "STATS_URL" to "https://huly:8443/_stats", "UPLOAD_URL" to "/files", "TITLE" to "Private Huly Fixture", "DEFAULT_LANGUAGE" to "en", "DESKTOP_UPDATES_CHANNEL" to "0.7.426", "DISABLED_FEATURES" to "auto-translate,mailboxes", "GMAIL_URL" to "https://huly:8443/_unavailable/gmail", "CALENDAR_URL" to "https://huly:8443/_unavailable/calendar", "TELEGRAM_URL" to "https://huly:8443/_unavailable/telegram")
        result["kvs.env"] = env("HULY_DB_CONNECTION" to "postgresql://huly:$db@127.0.0.1:26257/huly?sslmode=disable", "HULY_TOKEN_SECRET" to jwt, "RUST_LOG" to "warn", "HOME" to "/tmp")
        result["bootstrap-users.json"] = buildJsonArray { listOf("owner", "reader", "outsider").forEachIndexed { index, id -> add(buildJsonObject { put("email", "$id@localhost.invalid"); put("password", secrets[6 + index]); put("firstName", "Synthetic"); put("lastName", id) }) } }.toString()
        for (file in listOf("huly-bootstrap.js", "huly-loopback.cjs", "huly-search-init.js", "huly-timers.cjs", "huly-kvs-proxy.cjs")) result[file] = resource(file)
        result["web.env"] = "HOME=/tmp\nXDG_DATA_HOME=/tmp/data\nXDG_CONFIG_HOME=/tmp/config\n"
        result["caddyfile"] = """
            {
              admin off
              auto_https off
              servers {
                strict_sni_host on
              }
            }
            http://:8080 {
              respond /healthz "ready" 200
              respond 404
            }
            https://huly:8443 {
              tls /run/secrets/web.pem /run/secrets/web-key.pem
              route {
              @foreign {
                header Origin *
                not header Origin https://huly:8443
              }
              respond @foreign 403
              handle /_unavailable/* {
                respond "Optional integration not deployed in this private fixture" 503
              }
              handle_path /_accounts* {
                reverse_proxy account:3000 {
                  header_up -X-Client-Network-Position
                  header_down Set-Cookie "(.*)" "${'$'}1; Secure"
                }
              }
              handle_path /_transactor/* {
                reverse_proxy transactor:3333
              }
              @collaboration path /_collaborator /_collaborator/*
              handle @collaboration {
                uri strip_prefix /_collaborator
                reverse_proxy collaborator:3078
              }
              handle_path /_rekoni/* {
                reverse_proxy rekoni:4004
              }
              handle_path /_stats/* {
                reverse_proxy stats:4900
              }
              handle {
                reverse_proxy front:8080
              }
              }
            }
        """.trimIndent() + "\n"
        return result
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "huly", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }
}
