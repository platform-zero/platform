package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.json.*

/** Private native SMTP/IMAP fixture; no public mail, relay, auto-updates or serving recovery administrator. */
internal object MailRuntime {
    const val IMAGE = "localhost/p0v3-mail-server@sha256:418138750a79ff8a41c33f6aa9bd3513c8986e4926423cbb9449ff34ba8ccad1"
    const val ID = "403ca11f84a0233623d5055a905af47a2ab805823dda9c525eac16ac9cc56a1b"
    const val INIT_IMAGE = "localhost/p0v3-mail-bootstrap@sha256:4bf167ae8a50da33fd8981247deda2195cf3cb835ecddfbb0a983ce74d8cff9c"
    const val INIT_ID = "2e5756b3310d047ff636e3c8bac4f50e2e64312309f3167cb93a181013374a41"
    fun spec(name: String = "mail"): PrivateDeploymentSpec {
        fun files(vararg names: String) = names.map { RuntimeFile(it, "/run/secrets/$it") }
        val data = listOf(RuntimeMount("mail", "/data"))
        return PrivateDeploymentSpec(name = name, volumes = listOf(RuntimeVolume("mail", 2000)), processes = listOf(
            RuntimeProcess("mail-init", INIT_IMAGE, INIT_ID, 2000, entrypoint = "/usr/bin/python3", command = listOf("/run/secrets/mail-bootstrap.py"),
                files = files("mail-bootstrap.py", "mail-seed.json", "users.json", "generation", "mail-store.json"), environmentFile = "bootstrap.env", volumes = data,
                oneShot = true, memoryMiB = 2048, apparmorProfile = "p0v3-private-v1"),
            RuntimeProcess("mail", IMAGE, ID, 2000, dependencies = listOf("mail-init"), entrypoint = "/bin/sh", command = listOf("-ec", "test -s /data/store/CURRENT; cmp /data/ready /run/secrets/generation; exec /usr/local/bin/stalwart --config /run/secrets/mail-store.json"),
                files = files("mail-store.json", "generation", "ca.pem"), environmentFile = "mail.env", volumes = data, memoryMiB = 2048, apparmorProfile = "p0v3-private-v1",
                readiness = listOf("/usr/bin/curl", "--fail", "--silent", "--max-time", "5", "--cacert", "/run/secrets/ca.pem", "https://mail:8443/healthz/live"))
        )).also { PrivateDeployment.validate(it) }
    }
    fun inputs(pki: () -> Map<String, String> = { PrivateWebPki.generate("mail") }): Map<String, String> {
        val certificates = pki()
        fun obj(text: String) = Json.parseToJsonElement(text).jsonObject
        val steps = mutableListOf<JsonObject>()
        fun step(type: String, operation: String, value: JsonObject) { steps += buildJsonObject { put("method", "x:$type/set"); putJsonObject("arguments") { put(operation, value) } } }
        fun update(type: String, text: String) = step(type, "update", buildJsonObject { put("singleton", obj(text)) })
        step("Domain", "create", obj("""{"domain":{"name":"p0v3.example.org","certificateManagement":{"@type":"Manual"},"dkimManagement":{"@type":"Manual"},"dnsManagement":{"@type":"Manual"}}}"""))
        step("Certificate", "create", buildJsonObject { putJsonObject("certificate") {
            putJsonObject("certificate") { put("@type", "Text"); put("value", certificates.getValue("web.pem")) }
            putJsonObject("privateKey") { put("@type", "Text"); put("secret", certificates.getValue("web-key.pem")) }
        } })
        update("SystemSettings", """{"defaultHostname":"mail.p0v3.example.org","defaultDomainId":"#domain","defaultCertificateId":"#certificate","maxConnections":128,"maxBufferedMemory":67108864,"includeSecrets":false}""")
        for (store in listOf("BlobStore", "InMemoryStore", "SearchStore")) update(store, """{"@type":"Default"}""")
        // Updating the synthesized Disabled default is a no-op and is not persisted in 1.0.1.
        step("Asn", "create", obj("""{"asn":{"@type":"Disabled"}}"""))
        update("SpamSettings", """{"enable":false,"spamFilterRulesUrl":null}""")
        steps += obj("""{"method":"x:Application/get","arguments":{},"bindBuiltinApplication":"builtin-ui"}""")
        step("Application", "update", obj("""{"#builtin-ui":{"enable":false}}"""))
        update("MtaStageAuth", """{"require":{"else":"true"},"mustMatchSender":{"else":"true"},"saslMechanisms":{"else":"[plain, login]"}}""")
        update("MtaStageRcpt", """{"allowRelaying":{"else":"false"},"maxRecipients":{"else":"5"}}""")
        step("Tracer", "create", obj("""{"console":{"@type":"Stdout","enable":true,"level":"info","ansi":false}}"""))
        step("MtaVirtualQueue", "create", obj("""{"queue":{"name":"local","threadsPerNode":2}}"""))
        step("MtaRoute", "create", obj("""{"local-route":{"@type":"Local","name":"local"}}"""))
        step("MtaDeliverySchedule", "create", obj("""{"local-schedule":{"name":"local","queueId":"#queue","expiry":{"@type":"Ttl"}}}"""))
        update("MtaOutboundStrategy", """{"route":{"else":"'local'"},"schedule":{"else":"'local'"}}""")
        step("NetworkListener", "create", buildJsonObject {
            for ((protocol, port) in listOf("smtp" to 2465, "imap" to 2993, "http" to 8443)) putJsonObject(protocol) {
                put("name", protocol); put("protocol", protocol); put("useTls", true); put("implicitTls", true); put("maxConnections", 64)
                putJsonObject("bind") { put("0.0.0.0:$port", true) }
            }
        })
        val permissions = listOf("authenticate", "emailSend", "emailReceive", "imapAuthenticate", "imapCapability", "imapId", "imapList", "imapLsub", "imapNamespace", "imapSelect", "imapExamine", "imapStatus", "imapSearch", "imapSort", "imapFetch", "imapStore", "imapAppend", "imapCreate", "imapDelete", "imapRename", "imapCopy", "imapMove", "imapExpunge", "imapSubscribe", "imapThread", "imapIdle", "imapEnable", "imapMyRights", "imapAclGet", "imapListRights", "imapMetadataGet", "imapMetadataPrivate")
        step("Account", "create", buildJsonObject {
            for (user in listOf("alice", "bob", "outsider")) putJsonObject(user) {
                put("@type", "User"); put("name", user); put("domainId", "#domain")
                putJsonObject("credentials") { putJsonObject("0") { put("@type", "Password"); put("secret", "@password:$user") } }
                putJsonObject("roles") { put("@type", "User") }
                putJsonObject("permissions") { put("@type", "Replace"); putJsonObject("enabledPermissions") { permissions.forEach { put(it, true) } } }
                putJsonObject("quotas") { put("maxDiskQuota", 33554432); put("maxEmails", 100) }
            }
        })
        // Native recovery inserts a WebUI before the API is available. Deny its HTTP fetch
        // at a closed loopback proxy, then disable that exact built-in object before serving.
        val offlineHttp = "HTTP_PROXY=http://127.0.0.1:9\nHTTPS_PROXY=http://127.0.0.1:9\nALL_PROXY=http://127.0.0.1:9\nNO_PROXY=127.0.0.1,localhost,mail\n"
        return mapOf("ca.pem" to certificates.getValue("ca.pem"), "mail-seed.json" to JsonArray(steps).toString(),
            "mail-store.json" to """{"@type":"RocksDb","path":"/data/store","poolWorkers":2}""",
            "generation" to RuntimePreparation.password() + "\n",
            "users.json" to buildJsonObject { listOf("alice", "bob", "outsider").forEach { put(it, RuntimePreparation.password()) } }.toString(),
            "bootstrap.env" to "STALWART_RECOVERY_MODE=1\nSTALWART_RECOVERY_ADMIN=admin:${RuntimePreparation.password()}\nSTALWART_RECOVERY_MODE_LOG_LEVEL=warn\nTOKIO_WORKER_THREADS=2\nHOME=/tmp\n" + offlineHttp,
            "mail.env" to "STALWART_HOSTNAME=mail\nSTALWART_PUBLIC_URL=https://mail:8443\nTOKIO_WORKER_THREADS=2\nHOME=/tmp\n" + offlineHttp,
            "mail-bootstrap.py" to requireNotNull(javaClass.getResourceAsStream("/runtime/mail-bootstrap.py")).bufferedReader().use { it.readText() })
    }
    fun prepare(base: Path = PrivateDeployment.BASE, name: String = "mail", store: RuntimeStore = RuntimeStore.LEGACY): Path = RuntimePreparation.prepare(spec(name).copy(store = store), base) { inputs() }
}
