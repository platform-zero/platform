package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put

/** Bounded native Hub spawning into separately confined, preallocated notebook containers. */
internal object JupyterHubRuntime {
    private val users = listOf("alice", "bob")
    private fun resource(name: String) = requireNotNull(javaClass.getResourceAsStream("/runtime/$name")).bufferedReader().use { it.readText() }
    fun spec(inventory: AcquiredInventory, name: String = "jupyterhub"): PrivateDeploymentSpec {
        fun image(product: String) = inventory.images.single { it.product == product }.also { require(it.os == "linux" && it.architecture == "amd64") }
        val hub = image("jupyterhub"); val notebook = image("jupyter-notebook")
        require(image("caddy").pinnedImage == HulyRuntime.CADDY_BASE)
        fun file(source: String, target: String = source) = RuntimeFile(source, "/run/secrets/$target")
        val processes = users.map { user ->
            RuntimeProcess(user, notebook.pinnedImage, notebook.imageId, 1000, environmentFile = "$user.env",
                entrypoint = "/opt/conda/bin/python", command = listOf("/run/secrets/hub-agent.py"),
                volumes = listOf(RuntimeMount(user, "/home/jovyan")), memoryMiB = 2048,
                files = listOf(file("hub-agent.py"), file("notebook.py"), file("$user-control", "control-key"), file("$user-web.pem", "web.pem"), file("$user-web-key.pem", "web-key.pem"), file("trust.pem")),
                apparmorProfile = "p0v3-private-v1", readiness = listOf("/opt/conda/bin/python", "-c", "import ssl,urllib.request; assert urllib.request.urlopen('https://$user:8444/health',context=ssl.create_default_context(cafile='/run/secrets/trust.pem'),timeout=3).status==200"))
        } + listOf(
            RuntimeProcess("hub", HulyRuntime.CADDY_IMAGE, HulyRuntime.CADDY_ID, 1000, entrypoint = "/usr/bin/caddy",
                command = listOf("run", "--config", "/run/secrets/caddyfile", "--adapter", "caddyfile"), environmentFile = "web.env",
                files = listOf(file("caddyfile"), file("hub-web.pem", "web.pem"), file("hub-web-key.pem", "web-key.pem")),
                apparmorProfile = "p0v3-private-v1", readinessHttpPort = 8080, readinessHttpPath = "/healthz"),
            RuntimeProcess("controller", hub.pinnedImage, hub.imageId, 1000, dependencies = users + "hub", environmentFile = "hub.env",
                entrypoint = "/srv/venv/bin/jupyterhub", command = listOf("-f", "/run/secrets/hub-config.py"),
                volumes = listOf(RuntimeMount("hub", "/state")), memoryMiB = 1536,
                files = listOf(file("hub-config.py"), file("hub-settings.json"), file("trust.pem")), apparmorProfile = "p0v3-private-v1",
                readiness = listOf("/srv/venv/bin/python", "-c", "import urllib.request; assert urllib.request.urlopen('http://127.0.0.1:8081/hub/api',timeout=3).status==200"))
        )
        return PrivateDeploymentSpec(name = name, volumes = (users + "hub").map { RuntimeVolume(it, 1000) }, processes = processes).also { PrivateDeployment.validate(it) }
    }
    fun inputs(pki: (String) -> Map<String, String> = { PrivateWebPki.generate(it, if (it == "hub") listOf("hub", "alice.hub", "bob.hub") else listOf(it, "$it.hub")) }): Map<String, String> {
        val result = linkedMapOf<String, String>()
        val certificates = (users + "hub").associateWith(pki)
        certificates.forEach { (host, entries) -> entries.forEach { (file, content) -> result["$host-$file"] = content } }
        // CA files are bundled; do not leave undeclared files in immutable runtime inputs.
        result.keys.filter { it.endsWith("-ca.pem") }.toList().forEach(result::remove)
        result["trust.pem"] = certificates.values.joinToString("") { it.getValue("ca.pem") }
        val tokens = users.associateWith { RuntimePreparation.password() }
        val keys = users.associateWith { RuntimePreparation.password() }
        result["hub-settings.json"] = buildJsonObject {
            put("proxyToken", RuntimePreparation.password())
            put("passwords", buildJsonObject { (users + "outsider").forEach { put(it, RuntimePreparation.password()) } })
            put("servers", buildJsonObject { users.forEach { user -> put(user, buildJsonObject { put("serverToken", tokens.getValue(user)); put("controlKey", keys.getValue(user)) }) } })
        }.toString() + "\n"
        users.forEach { user ->
            result["$user-control"] = keys.getValue(user) + "\n"
            result["$user.env"] = """
                HOME=/home/jovyan
                SSL_CERT_FILE=/run/secrets/trust.pem
                REQUESTS_CA_BUNDLE=/run/secrets/trust.pem
                JUPYTERHUB_API_TOKEN=${tokens.getValue(user)}
                JUPYTERHUB_API_URL=https://hub:8443/hub/api
                JUPYTERHUB_ACTIVITY_URL=https://hub:8443/hub/api/users/$user/activity
                JUPYTERHUB_BASE_URL=/
                JUPYTERHUB_SERVICE_PREFIX=/user/$user/
                JUPYTERHUB_SERVICE_URL=https://$user:8888
                JUPYTERHUB_USER=$user
                JUPYTERHUB_SERVER_NAME=
                JUPYTERHUB_CLIENT_ID=jupyterhub-user-$user
                JUPYTERHUB_OAUTH_CALLBACK_URL=https://$user.hub:8443/user/$user/oauth_callback
                JUPYTERHUB_HOST=https://hub:8443
                JUPYTERHUB_PUBLIC_URL=https://$user.hub:8443/user/$user/
                JUPYTERHUB_PUBLIC_HUB_URL=https://hub:8443/hub/
                JUPYTERHUB_OAUTH_ACCESS_SCOPES=["access:servers!server=$user/","access:servers!user=$user"]
                JUPYTERHUB_OAUTH_CLIENT_ALLOWED_SCOPES=[]
                JUPYTERHUB_COOKIE_HOST_PREFIX_ENABLED=1
                JUPYTERHUB_ROOT_DIR=/home/jovyan/work
                JUPYTERHUB_DEFAULT_URL=/lab
                JUPYTERHUB_DISABLE_USER_CONFIG=1
            """.trimIndent() + "\n"
        }
        result["hub.env"] = "HOME=/tmp\nSSL_CERT_FILE=/run/secrets/trust.pem\nNODE_EXTRA_CA_CERTS=/run/secrets/trust.pem\n"
        result["web.env"] = "HOME=/tmp\nXDG_DATA_HOME=/tmp/data\nXDG_CONFIG_HOME=/tmp/config\n"
        result["hub-agent.py"] = resource("hub-agent.py")
        result["hub-config.py"] = resource("hub-config.py")
        result["notebook.py"] = """
            c = get_config()
            c.ServerApp.ip = "0.0.0.0"
            c.ServerApp.port = 8888
            c.ServerApp.port_retries = 0
            c.ServerApp.root_dir = "/home/jovyan/work"
            c.ServerApp.open_browser = False
            c.ServerApp.certfile = "/run/secrets/web.pem"
            c.ServerApp.keyfile = "/run/secrets/web-key.pem"
            c.ServerApp.allow_unauthenticated_access = False
            c.ServerApp.disable_check_xsrf = False
            c.ServerApp.terminals_enabled = False
            c.ServerApp.log_level = "WARN"
            c.LabApp.extension_manager = "readonly"
        """.trimIndent() + "\n"
        result["caddyfile"] = """
            {
              admin off
              auto_https off
              servers {
                strict_sni_host on
              }
            }
            :8080 {
              respond /healthz "ready" 200
            }
            https://hub:8443 {
              tls /run/secrets/web.pem /run/secrets/web-key.pem
              @foreignOrigin {
                header Origin *
                not header Origin https://hub:8443
              }
              respond @foreignOrigin "Forbidden" 403
              @notebooks path /user /user/*
              respond @notebooks "Use the isolated notebook origin" 403
              reverse_proxy controller:8081
            }
        """.trimIndent() + "\n"
        result["caddyfile"] = result.getValue("caddyfile") + users.joinToString("\n") { user -> """
            https://$user.hub:8443 {
              tls /run/secrets/web.pem /run/secrets/web-key.pem
              @foreignOrigin {
                header Origin *
                not header Origin https://$user.hub:8443
              }
              route {
                respond @foreignOrigin "Forbidden" 403
                handle /user/$user/* {
                  reverse_proxy controller:8000
                }
                handle {
                  respond "Forbidden" 403
                }
              }
            }
        """.trimIndent() } + "\n"
        return result
    }
    /** One native Hub and two preallocated, separately owned single-user homes. No shared SQL/cache clone. */
    fun canonicalFragment(inventory: AcquiredInventory, name: String): CanonicalProviderFragment {
        val legacy = spec(inventory, name)
        val processes = legacy.processes.map { process ->
            val id = if (process.id == "controller") "hub-controller" else process.id
            process.copy(id = id, dependencies = process.dependencies.map { if (it == "controller") "hub-controller" else it },
                environmentFile = process.environmentFile?.let { "jupyterhub-$it" },
                files = process.files.map { it.copy(file = "jupyterhub-${it.file}") } +
                    if (process.id == "hub") listOf(RuntimeFile("jupyterhub-ca.pem", "/run/secrets/hub-ca.pem"))
                    else emptyList(),
                networks = if (process.id == "hub") listOf("hub-data", "hub-web") else listOf("hub-data"))
        }
        val partial = legacy.copy(store = RuntimeStore.CANONICAL_V2, processes = processes,
            networks = listOf("hub-data", "hub-web"))
        PrivateDeployment.validate(partial)
        return CanonicalProviderFragment("jupyterhub", partial, webNetworks = setOf("hub-web"))
    }

    fun canonicalInputs(onDemandGeneration: String? = null, pki: (String) -> Map<String, String> = {
        PrivateWebPki.generate(it, if (it == "hub") listOf("hub", "alice.hub", "bob.hub") else listOf(it, "$it.hub"))
    }): Map<String, String> {
        if (onDemandGeneration != null) require(onDemandGeneration.matches(Regex("q-[a-f0-9]{12}")))
        var hubCa: String? = null
        val original = inputs { host ->
            pki(host).also { if (host == "hub") hubCa = requireNotNull(it["ca.pem"]) }
        }
        // Only canonical V2 exposes the SAME source CA that signs the inner Hub
        // certificate. COORD copies these exact bytes into the Caddy member's
        // immutable hub-ca.pem input before sealing; never generate a second CA.
        val settings = if (onDemandGeneration != null) {
            val source = Json.parseToJsonElement(original.getValue("hub-settings.json")).jsonObject
            val servers = source.getValue("servers").jsonObject
            buildJsonObject {
                source.forEach { (key, value) -> if (key != "servers") put(key, value) }
                put("notebookGeneration", onDemandGeneration)
                put("servers", buildJsonObject { users.forEach { user ->
                    put(user, buildJsonObject {
                        servers.getValue(user).jsonObject.forEach { (key, value) -> put(key, value) }
                        put("parentControlKey", RuntimePreparation.password())
                    })
                } })
            }.toString() + "\n"
        } else original.getValue("hub-settings.json")
        return ((original + ("hub-settings.json" to settings)).mapKeys { (file, _) -> "jupyterhub-$file" } +
            ("jupyterhub-ca.pem" to requireNotNull(hubCa))).mapValues { (name, content) -> when (name) {
            "jupyterhub-caddyfile" -> content
                .replace(Regex("(?m)^\\s*@notebooks path /user /user/\\*\\n\\s*respond @notebooks \\\"Use the isolated notebook origin\\\" 403\\n"), "")
                .replace("reverse_proxy controller:8081", "reverse_proxy hub-controller:8000 {\n" +
                    "                header_up Host notebooks.datamancy.net\n" +
                    "                header_up X-Forwarded-Host notebooks.datamancy.net\n" +
                    "                header_up X-Forwarded-Proto https\n" +
                    "              }")
                .replace("not header Origin https://hub:8443", "not header Origin https://notebooks.datamancy.net")
            "jupyterhub-hub-config.py" -> (if (onDemandGeneration != null) resource("hub-config-r9.py") else content)
                .replace("c.JupyterHub.public_url = 'https://hub:8443/'",
                    "c.JupyterHub.public_url = 'https://notebooks.datamancy.net/'")
                .replace("c.JupyterHub.subdomain_host = 'https://hub:8443'",
                    "c.JupyterHub.subdomain_host = ''")
            "jupyterhub-alice.env", "jupyterhub-bob.env" -> content
                .replace("https://alice.hub:8443/", "https://notebooks.datamancy.net/")
                .replace("https://bob.hub:8443/", "https://notebooks.datamancy.net/")
                .replace("JUPYTERHUB_PUBLIC_HUB_URL=https://hub:8443/hub/",
                    "JUPYTERHUB_PUBLIC_HUB_URL=https://notebooks.datamancy.net/hub/")
            else -> content
        } }
    }

    fun coldRestoreFragment(fresh: CanonicalProviderFragment): CanonicalProviderFragment {
        require(fresh.product == "jupyterhub" && fresh.spec.processes.none { it.oneShot } &&
            fresh.spec.processes.map { it.id }.toSet() == setOf("alice", "bob", "hub", "hub-controller"))
        val projected = fresh.spec.copy(processes = fresh.spec.processes.map { process ->
            val guard = when (process.id) {
                "hub-controller" -> "test -s /state/hub.sqlite; test ! -L /state/hub.sqlite; test -s /state/cookie-secret; test ! -L /state/cookie-secret; "
                "alice", "bob" -> "test -d /home/jovyan/work; test ! -L /home/jovyan/work; " +
                    "test -f /home/jovyan/.p0-hub-state; test ! -L /home/jovyan/.p0-hub-state; " +
                    "grep -qx stopped /home/jovyan/.p0-hub-state; test ! -e /home/jovyan/.p0-hub-state.pending; " +
                    "test ! -L /home/jovyan/.p0-hub-state.pending; "
                else -> null
            }
            if (guard == null) process else process.copy(entrypoint = "/bin/sh", command = listOf("-ec",
                guard + "exec \"${'$'}@\"", "restored-hub", requireNotNull(process.entrypoint)) + process.command)
        })
        return fresh.copy(spec = projected).also { PrivateDeployment.validate(it.spec) }
    }

    /** Same-version cold restore only: no credential, database, home or lifecycle-state regeneration. */
    fun coldRestoreSpec(compiled: PrivateDeploymentSpec): PrivateDeploymentSpec {
        require(compiled.processes.none { it.oneShot } && compiled.processes.map { it.id }.toSet() == (users + listOf("hub", "controller")).toSet())
        return compiled.copy(processes = compiled.processes.map { p ->
            val guard = when (p.id) {
                "controller" -> {
                    require(p.entrypoint == "/srv/venv/bin/jupyterhub")
                    "test -s /state/hub.sqlite; test ! -L /state/hub.sqlite; test -s /state/cookie-secret; test ! -L /state/cookie-secret; "
                }
                in users -> {
                    require(p.entrypoint == "/opt/conda/bin/python" && p.command == listOf("/run/secrets/hub-agent.py"))
                    "test -d /home/jovyan/work; test ! -L /home/jovyan/work; test -f /home/jovyan/.p0-hub-state; test ! -L /home/jovyan/.p0-hub-state; grep -qx stopped /home/jovyan/.p0-hub-state; test ! -e /home/jovyan/.p0-hub-state.pending; test ! -L /home/jovyan/.p0-hub-state.pending; "
                }
                else -> null
            }
            if (guard == null) p else p.copy(entrypoint = "/bin/sh", command = listOf("-ec", guard + "exec \"${'$'}@\"", "restored-hub", requireNotNull(p.entrypoint)) + p.command)
        }).also { PrivateDeployment.validate(it) }
    }

    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "jupyterhub", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }
}
