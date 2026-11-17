package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** Owner-only fixed private-provider actions. No adapter-selected socket, credential, URL,
 * command, operation ID or POST body crosses the case-control boundary. */
internal object QualificationObservabilityActor {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }

    /** Public Alertmanager's RESTORE original is a silence on the imported state
     * volume, never an expired alert in the ephemeral in-memory alert map. This
     * pure selected-input guard does not grant the private OBSERVABILITY spool a
     * public HTTP write capability. */
    internal fun durableAlertmanagerReceiver(pin: GenerationPin): JsonArray {
        val spec = pin.spec
        val daemon = spec.processes.single { it.id == "alertmanager" && !it.oneShot }
        require(spec.volumes.any { it.id == "alertmanager" } &&
            daemon.volumes.single { it.target == "/alertmanager" }.volume == "alertmanager" &&
            daemon.files.single { it.target == "/etc/alertmanager/alertmanager.yml" }.file ==
                "alertmanager.yml")
        val bytes = ReleasePrivateFiles.read(PrivateDeployment.BASE.resolve(spec.name)
            .resolve("alertmanager.yml"),65536)
        require(ReleaseLocks.sha256(bytes) == pin.inputHashes.getValue("alertmanager.yml"))
        val selected = bytes.decodeToString(throwOnInvalidSequence = true)
        require(selected.contains("receiver: private-inert") && selected.contains("- name: private-inert") &&
            listOf("email_configs:","smtp_","webhook_configs:","pagerduty_configs:",
                "opsgenie_configs:","sns_configs:","slack_configs:","msteams_configs:").none {
                    it in selected })
        return JsonArray(listOf(JsonPrimitive("private-inert")))
    }

    internal data class Operation(val id: String, val action: String, val attempt: Int? = null)
    internal fun operation(invocation: String, service: String, phase: String, request: JsonObject): Operation {
        require(invocation.matches(Regex("case-[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}")) &&
            phase in setOf("INSTALL", "RESTORE"))
        val action = request.getValue("action").jsonPrimitive.also { require(it.isString) }.content
        val attempt = if (service == "alloy" && action == "READ_LOG") {
            require(request.keys == setOf("action", "attempt"))
            request.getValue("attempt").jsonPrimitive.also { require(!it.isString) }.int.also { require(it in 0..7) }
        } else { require(request.keys == setOf("action")); null }
        val tag = when (service) {
            "alloy" -> when (action) {
                "APPEND_LOG" -> { require(phase == "INSTALL"); "owned-source-log-push" }
                "READ_LOG" -> "owned-log-readback-$attempt"
                "DENY_NETWORK" -> "foreign-source-denial"
                else -> error("Unknown fixed Alloy action")
            }
            "loki" -> when (action) {
                "READ_LOG" -> "original-stream-readback"
                "DENY_NETWORK" -> "unprivileged-network-denial"
                else -> error("Unknown fixed Loki action")
            }
            "node-exporter" -> when (action) {
                "SCRAPE" -> "original-textfile-scrape"
                "DENY_MTLS" -> "foreign-client-mtls-denial"
                else -> error("Unknown fixed node action")
            }
            else -> error("No private observability capability")
        }
        return Operation("nq-" + ReleaseLocks.sha256("$invocation\n$service\n$tag".encodeToByteArray()).take(12), action, attempt)
    }

    internal fun query(run: String, stamp: Long): String {
        require(run.matches(Regex("obs-[a-f0-9]{12}")) && stamp > 1_000_000_000L)
        return "/loki/api/v1/query_range?query=%7Bjob%3D%22p0v3-acceptance%22%2Crun%3D%22$run%22%7D" +
            "&start=${stamp - 1_000_000_000L}&end=${Math.addExact(stamp, 5_000_000_000L)}&limit=10"
    }

    /** Matches the original sorted Python fixture bytes, not a replacement timestamp/body. */
    internal fun appendBody(invocation: String, source: JsonObject): ByteArray {
        val run = "obs-" + ReleaseLocks.sha256(invocation.encodeToByteArray()).take(12)
        require(source.keys == setOf("schemaVersion", "run", "stamp", "bodySha256") &&
            source.getValue("schemaVersion").jsonPrimitive.int == 1 &&
            source.getValue("run").jsonPrimitive.content == run)
        val stamp = source.getValue("stamp").jsonPrimitive.also { require(!it.isString) }.long
        query(run, stamp)
        val body = buildJsonObject {
            putJsonArray("streams") { addJsonObject {
                putJsonObject("stream") { put("job", "p0v3-acceptance"); put("run", run) }
                putJsonArray("values") { addJsonArray { add(stamp.toString()); add("P0 private original Alloy log $run") } }
            } }
        }.toString().encodeToByteArray()
        require(ReleaseLocks.sha256(body) == source.getValue("bodySha256").jsonPrimitive.content) {
            "Original Alloy append bytes changed; no new timestamp or body"
        }
        return body
    }

    private fun document(path: Path, maximum: Int = 1048576): JsonObject = json.parseToJsonElement(
        ReleasePrivateFiles.read(path, maximum).decodeToString(throwOnInvalidSequence = true)).jsonObject

    private fun originalLog(binding: NativeQualificationCaseBinding, context: JsonObject): JsonObject {
        if (binding.phase == "INSTALL" && binding.serviceId == "alloy") {
            return document(Path.of(binding.caseDirectory).resolve("alloy-source-log.intent.json"), 8192).also {
                appendBody(binding.invocationId, it)
            }
        }
        val observation = Path.of(context.getValue(if (binding.phase == "RESTORE")
            "sourceObservation" else "alloySourceObservationFile").jsonPrimitive.content)
        val observedBytes = ReleasePrivateFiles.read(observation, 1048576)
        val observed = json.parseToJsonElement(observedBytes.decodeToString()).jsonObject
        val oraclePath = observation.parent.resolve("oracle.json")
        val oracleBytes = ReleasePrivateFiles.read(oraclePath, 8192)
        require(observation.fileName.toString() == "native-result.json" &&
            ReleaseLocks.sha256(oracleBytes) == observed.getValue("artifacts").jsonObject
                .getValue("oracle.json").jsonPrimitive.content)
        if (binding.phase == "INSTALL") require(oraclePath.toString() ==
            context.getValue("alloySourceOracleFile").jsonPrimitive.content &&
            ReleaseLocks.sha256(oracleBytes) == context.getValue("alloySourceOracleSha256").jsonPrimitive.content &&
            ReleaseLocks.sha256(observedBytes) == context.getValue("alloySourceObservationSha256").jsonPrimitive.content)
        // NativeQualificationClient independently checks completed predecessor/original trial,
        // sealed claim and stopped-source authority before any native effect.
        return json.parseToJsonElement(oracleBytes.decodeToString()).jsonObject
    }

    internal fun requireEmptyPrevious(binding: NativeQualificationCaseBinding, selected: Operation,
        home: Path, expectedPath: String) {
        val attempt = selected.attempt ?: return
        if (attempt == 0) return
        val previous = operation(binding.invocationId, binding.serviceId, binding.phase,
            buildJsonObject { put("action", "READ_LOG"); put("attempt", attempt - 1) })
        val bytes = ReleasePrivateFiles.read(home.resolve("${previous.id}.request.json"), 65536)
        val request = json.decodeFromString<NativeQualificationRequest>(bytes.decodeToString())
        val result = json.decodeFromString<NativeQualificationResult>(
            ReleasePrivateFiles.read(home.resolve("${previous.id}.result.json"), 65536).decodeToString())
        val response = ReleasePrivateFiles.read(home.resolve("${previous.id}.response"), 1048576)
        require(request.operation == previous.id && request.invocationId == binding.invocationId &&
            request.generationId == binding.generationId && request.phase == binding.phase &&
            request.caseDirectory == binding.caseDirectory && request.caseIntentSha256 == binding.caseIntentSha256 &&
            request.caseClaimSha256 == binding.caseClaimSha256 && request.serviceId == "alloy" &&
            request.targetMemberName == binding.targetMemberName && request.targetFingerprint == binding.targetFingerprint &&
            request.method == "GET" && request.path == expectedPath && request.assertion == "POSITIVE" &&
            result.operation == previous.id && result.requestSha256 == ReleaseLocks.sha256(bytes) &&
            result.responseFile == home.resolve("${previous.id}.response").toString() &&
            result.responseSha256 == ReleaseLocks.sha256(response) && result.status == 200 && result.responseKind == "HTTP")
        val data = json.parseToJsonElement(response.decodeToString()).jsonObject
        require(data.getValue("status").jsonPrimitive.content == "success" &&
            data.getValue("data").jsonObject.getValue("resultType").jsonPrimitive.content == "streams" &&
            data.getValue("data").jsonObject.getValue("result").jsonArray.isEmpty()) {
            "Only an acknowledged empty Loki query permits the next bounded readback"
        }
    }

    fun execute(binding: NativeQualificationCaseBinding, spec: PrivateDeploymentSpec,
        request: JsonObject, sourceStopped: ActivationInput?, sourceStoppedProofSha256: String?): JsonObject {
        require(binding.targetMemberName == spec.name)
        val selected = operation(binding.invocationId, binding.serviceId, binding.phase, request)
        val context = NativeQualificationClaims.read(binding).context
        val generation = GenerationRuntime.BASE.resolve(binding.generationId)
        val home = privateControlDirectory(privateControlDirectory(generation.resolve("native-qualification"))
            .resolve(binding.invocationId))
        require(!Files.exists(home.resolve("${selected.id}.request.json"), NOFOLLOW_LINKS) &&
            !Files.exists(home.resolve("pending.json"), NOFOLLOW_LINKS)) {
            "Original observability action already attempted or uncertain; no new sequence workaround"
        }
        require((binding.phase == "RESTORE") == (sourceStopped != null && sourceStoppedProofSha256 != null))
        if (binding.phase == "INSTALL") require(sourceStopped == null && sourceStoppedProofSha256 == null)
        val log = if (binding.serviceId != "node-exporter") originalLog(binding, context) else null
        val path = if (selected.action == "APPEND_LOG") "/loki/api/v1/push" else if (log == null) "/metrics"
            else query(log.getValue("run").jsonPrimitive.content, log.getValue("stamp").jsonPrimitive.long)
        requireEmptyPrevious(binding, selected, home, path)
        val body = if (selected.action == "APPEND_LOG") {
            val bytes = appendBody(binding.invocationId, requireNotNull(log))
            val file = home.resolve("${selected.id}.body.json")
            ReleasePrivateFiles.save(file, bytes)
            ActivationInput(file.toString(), ReleaseLocks.sha256(bytes))
        } else null
        val tls = if (binding.serviceId == "node-exporter") context.getValue("nodeTls").jsonObject else null
        fun credential(key: String): ActivationInput? = tls?.let {
            val file = Path.of(it.getValue("${key}File").jsonPrimitive.content)
            require(file.parent == PrivateDeployment.BASE.resolve(spec.name))
            ActivationInput(file.toString(), it.getValue("${key}Sha256").jsonPrimitive.content)
        }
        val process = if (tls != null) "node" else if (body != null) "alloy" else "loki"
        val native = NativeQualificationRequest(selected.id, binding.generationId, binding.targetMemberName,
            binding.targetFingerprint, binding.invocationId, binding.caseDirectory, binding.caseIntentSha256,
            binding.caseClaimSha256, binding.phase, binding.serviceId, process, if (body != null) "POST" else "GET", path,
            when (selected.action) { "DENY_NETWORK" -> "PRIVATE_NETWORK_DENIAL"; "DENY_MTLS" -> "TLS_CLIENT_DENIAL"; else -> "POSITIVE" },
            body = body, ca = credential("ca"),
            clientCert = if (selected.action == "DENY_MTLS") null else credential("clientCert"),
            clientKey = if (selected.action == "DENY_MTLS") null else credential("clientKey"),
            originalLeafSha256 = tls?.getValue("serverLeafSha256")?.jsonPrimitive?.content,
            sourceStopped = sourceStopped, sourceStoppedProofSha256 = sourceStoppedProofSha256,
            responseFile = home.resolve("${selected.id}.response").toString())
        val rawRequest = json.encodeToString(native).encodeToByteArray()
        ReleasePrivateFiles.save(home.resolve("${selected.id}.request.json"), rawRequest)
        val result = NativeQualificationClient.real(generation, spec, binding.targetFingerprint).request(native)
        val rawResult = ReleasePrivateFiles.read(home.resolve("${selected.id}.result.json"), 65536)
        require(json.decodeFromString<NativeQualificationResult>(rawResult.decodeToString()) == result &&
            result.requestSha256 == ReleaseLocks.sha256(rawRequest) && result.responseFile == native.responseFile)
        require(Files.size(Path.of(result.responseFile)) > 0 || selected.action == "APPEND_LOG" &&
            result.responseKind == "HTTP" && result.status in setOf(200, 202, 204))
        return QualificationOpenSearchActor.project(Path.of(binding.caseDirectory), home, selected.id,
            rawRequest, rawResult, result.responseSha256)
    }
}
