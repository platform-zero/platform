package net.datamancy.platform

import java.io.ByteArrayInputStream
import java.nio.file.Path
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlinx.serialization.json.*

/** Generates native target metadata from the sealed member and original runtime inputs.
 * Context carries pins, never private key bytes or adapter-selected executable authority. */
internal object QualificationNativeContexts {
    internal fun merge(proposed: JsonObject, generated: JsonObject): JsonObject {
        generated.forEach { (key, value) ->
            require(proposed[key] == null || proposed[key] == value) { "Caller changed owner-derived native field: $key" }
        }
        return JsonObject(proposed + generated)
    }
    fun prepare(generation: String, pin: GenerationPin, service: String,
        read: (Path) -> ByteArray = { ReleasePrivateFiles.read(it, 65536) }): JsonObject {
        require(generation.matches(Regex("q-[a-f0-9]{12}")) && pin.spec.name == "$generation-v2" &&
            pin.member.name == pin.spec.name && pin.spec.store == RuntimeStore.CANONICAL_V2 &&
            PrivateDeployment.expectedFingerprint(pin.spec, pin.inputHashes) == pin.runtimeFingerprint)
        require(service in setOf("alloy", "loki", "node-exporter", "onlyoffice", "opensearch", "crowdsec", "qbittorrent", "mailserver"))
        val processId = when (service) {
            "node-exporter" -> "node"
            "onlyoffice" -> "seafile-backend"
            "mailserver" -> "mail"
            "crowdsec" -> "guard"
            else -> service
        }
        val process = pin.spec.processes.single { it.id == processId && !it.oneShot }
        return buildJsonObject {
            put("nativeTargets", buildJsonObject {
                for (target in if (service == "alloy") listOf("alloy", "loki") else listOf(service)) {
                    val targetProcess = if (target == service) processId else target
                    require(pin.spec.processes.single { it.id == targetProcess }.oneShot.not())
                    put(target, buildJsonObject {
                        put("targetMemberName", pin.spec.name); put("targetFingerprint", pin.runtimeFingerprint)
                        put("processId", targetProcess)
                    })
                }
            })
            if (service == "onlyoffice") {
                put("targetGeneration", generation); put("callbackDeploymentName", pin.spec.name)
                put("callbackRuntimeFingerprint", pin.runtimeFingerprint); put("backendImageId", process.imageId)
            }
            if (service == "mailserver") {
                val base = PrivateDeployment.BASE.resolve(pin.spec.name)
                val seed = read(base.resolve("mail-seed.json"))
                val ca = read(base.resolve("mail-ca.pem"))
                val users = read(base.resolve("mail-users.json"))
                require(ReleaseLocks.sha256(seed) == pin.inputHashes.getValue("mail-seed.json") &&
                    ReleaseLocks.sha256(ca) == pin.inputHashes.getValue("mail-ca.pem") &&
                    ReleaseLocks.sha256(users) == pin.inputHashes.getValue("mail-users.json"))
                val config = Json.parseToJsonElement(seed.decodeToString(throwOnInvalidSequence = true)).jsonArray
                val certificate = config.single { it.jsonObject["method"]?.jsonPrimitive?.content ==
                    "x:Certificate/set" }.jsonObject.getValue("arguments").jsonObject
                    .getValue("create").jsonObject.getValue("certificate").jsonObject
                    .getValue("certificate").jsonObject.getValue("value").jsonPrimitive.content
                val leaf = CertificateFactory.getInstance("X.509").generateCertificate(
                    ByteArrayInputStream(certificate.encodeToByteArray())) as X509Certificate
                require(leaf.subjectAlternativeNames.orEmpty().any { it[0] == 2 && it[1] == "mail" })
                val launchRoot = GenerationRuntime.BASE.resolve(generation)
                val stem = "quadlet-launch-${pin.spec.name}-mail"
                val result = Json.decodeFromString<QuadletLaunchResult>(read(launchRoot.resolve("$stem.result.json"))
                    .decodeToString(throwOnInvalidSequence = true))
                require(result.nativeAcknowledged && result.imageId == process.imageId &&
                    result.intentSha256 == ReleaseLocks.sha256(read(launchRoot.resolve("$stem.intent.json"))) &&
                    result.containerId.matches(Regex("[a-f0-9]{64}")))
                put("deploymentName",pin.spec.name); put("runtimeFingerprint",pin.runtimeFingerprint)
                put("containerId",result.containerId)
                put("hostname","mail"); put("approvedMailHost","mail")
                put("mailLeafSha256",ReleaseLocks.sha256(leaf.encoded))
                put("credentialsFile",base.resolve("mail-users.json").toString())
                put("smtpPort",2465); put("imapPort",2993)
                put("address",NamespaceCaddyTransport.ownedProcessAddress(pin.spec,
                    pin.runtimeFingerprint,"mail","mail-data"))
            }
            if (service == "node-exporter") {
                val prometheus = pin.spec.processes.single { it.id == "prometheus" && !it.oneShot }
                val files = linkedMapOf(
                    "ca" to process.files.single { it.target == "/run/secrets/ca.pem" }.file,
                    "clientCert" to prometheus.files.single { it.target == "/run/secrets/admin.pem" }.file,
                    "clientKey" to prometheus.files.single { it.target == "/run/secrets/admin-key.pem" }.file,
                    "serverCert" to process.files.single { it.target == "/run/secrets/node.pem" }.file)
                val bytes = files.mapValues { (_, file) ->
                    val raw = read(PrivateDeployment.BASE.resolve(pin.spec.name).resolve(file))
                    require(raw.size in 1..65536 && ReleaseLocks.sha256(raw) == pin.inputHashes.getValue(file)) {
                        "Native node credential differs from sealed input"
                    }
                    raw
                }
                val leaf = CertificateFactory.getInstance("X.509").generateCertificate(
                    ByteArrayInputStream(bytes.getValue("serverCert"))) as X509Certificate
                require(leaf.basicConstraints == -1 && leaf.subjectAlternativeNames.orEmpty().any {
                    it[0] == 2 && it[1] == "node"
                }) { "Native node server identity differs from sealed TLS role" }
                put("nodeTls", buildJsonObject {
                    files.filterKeys { it != "serverCert" }.forEach { (key, file) ->
                        put("${key}File", PrivateDeployment.BASE.resolve(pin.spec.name).resolve(file).toString())
                        put("${key}Sha256", ReleaseLocks.sha256(bytes.getValue(key)))
                    }
                    put("serverLeafSha256", ReleaseLocks.sha256(leaf.encoded))
                })
            }
            if (service == "opensearch") {
                val files = linkedMapOf("ca" to "ca.pem", "adminCert" to "admin.pem",
                    "adminKey" to "admin-key.pem", "nodeCert" to "node.pem", "nodeKey" to "node-key.pem")
                val bytes = files.mapValues { (_, name) ->
                    val source = "opensearch-$name"
                    val raw = read(PrivateDeployment.BASE.resolve(pin.spec.name).resolve(source))
                    require(raw.size in 1..65536 && ReleaseLocks.sha256(raw) == pin.inputHashes.getValue(source)) {
                        "Native OpenSearch credential differs from sealed input"
                    }
                    raw
                }
                val leaf = CertificateFactory.getInstance("X.509").generateCertificate(
                    ByteArrayInputStream(bytes.getValue("nodeCert"))) as X509Certificate
                require(leaf.basicConstraints == -1 && leaf.subjectAlternativeNames.orEmpty().any {
                    it[0] == 2 && it[1] == "opensearch"
                }) { "Native OpenSearch server identity differs from sealed TLS role" }
                put("opensearchNative", buildJsonObject {
                    files.forEach { (key, name) ->
                        put("${key}File", PrivateDeployment.BASE.resolve(pin.spec.name).resolve("opensearch-$name").toString())
                        put("${key}Sha256", ReleaseLocks.sha256(bytes.getValue(key)))
                    }
                    put("serverLeafSha256", ReleaseLocks.sha256(leaf.encoded))
                })
            }
        }
    }
}
