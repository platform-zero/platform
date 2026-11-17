package net.datamancy.platform

import java.net.InetAddress
import java.nio.file.Path
import java.math.BigInteger
import java.util.UUID
import kotlinx.serialization.json.*

/** Owner-thread fixed Matrix Android native observations. No QClient host authority or
 * caller-selected command, SQL, path, PID, secret, network or URL crosses the spool. */
internal object QualificationMatrixActor {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private val hash = Regex("[a-f0-9]{64}")
    internal fun selectedProcess(spec: PrivateDeploymentSpec, fingerprint: String, process: String): JsonObject {
        val definition = spec.processes.single { it.id == process }
        val audit = PrivateDeployment.real(mapOf(spec.name to fingerprint)).audit(spec)
        require(audit.name == spec.name && audit.fingerprint == fingerprint && audit.maintenanceId == null &&
            audit.statuses.single { it.id == process }.state == "running")
        val result = PrivateRootfulCommands(30, spec.store).run(listOf("inspect", "--type", "container",
            "p0v3-live-${spec.name}-$process"))
        require(result.exitCode == 0 && result.output.length in 1..4194304)
        val entries = json.parseToJsonElement(result.output).jsonArray
        require(entries.size == 1)
        val raw = entries.single().jsonObject
        val labels = raw.getValue("Config").jsonObject.getValue("Labels").jsonObject
        val state = raw.getValue("State").jsonObject
        val image = raw.getValue("Image").jsonPrimitive.content.removePrefix("sha256:")
        val id = raw.getValue("Id").jsonPrimitive.content
        require(id.matches(hash) && raw.getValue("Name").jsonPrimitive.content.removePrefix("/") ==
            "p0v3-live-${spec.name}-$process" && image == definition.imageId &&
            labels["io.p0v3.private-deployment"] == JsonPrimitive(spec.name) &&
            labels["io.p0v3.runtime-fingerprint"] == JsonPrimitive(fingerprint) &&
            state.getValue("Running").jsonPrimitive.boolean &&
            state.getValue("Pid").jsonPrimitive.int > 1)
        val networks = raw.getValue("NetworkSettings").jsonObject.getValue("Networks").jsonObject
        require(networks.keys == definition.networks.map { "p0v3-live-${spec.name}-$it" }.toSet())
        val addresses = buildJsonObject {
            networks.forEach { (name, network) ->
                val address = network.jsonObject.getValue("IPAddress").jsonPrimitive.content
                require(address.matches(Regex("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) &&
                    InetAddress.getByName(address).isSiteLocalAddress)
                put(name, address)
            }
        }
        return buildJsonObject {
            put("process", process); put("deployment", spec.name); put("containerId", id)
            put("imageId", image); put("running", true); put("networks", addresses)
            put("pid", state.getValue("Pid").jsonPrimitive.int)
        }
    }
    internal fun fixedProviderUuid(): String {
        val alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
        var value = BigInteger.ZERO
        for (char in "01HFVBY12TMNTYTBV8W921M5FA")
            value = value.shiftLeft(5).or(BigInteger.valueOf(alphabet.indexOf(char).also { require(it >= 0) }.toLong()))
        require(value.bitLength() <= 128)
        val hex = value.toString(16).padStart(32, '0')
        return UUID.fromString("${hex.substring(0,8)}-${hex.substring(8,12)}-${hex.substring(12,16)}-" +
            "${hex.substring(16,20)}-${hex.substring(20,32)}").toString()
    }
    /** Fixed read-only MAS query; no SQL or credential is accepted from an adapter. */
    internal fun parseMasLinks(raw: String): JsonObject {
        require(raw.length in 1..32767)
        val rows = raw.trimEnd('\n').split('\n')
        require(rows.size == 2)
        val subjects = linkedMapOf<String, JsonElement>()
        for (line in rows) {
            val fields = line.split('\t')
            require(fields.size == 5 && fields[0] in setOf("owner", "reader") && fields[0] !in subjects &&
                fields[4] == "f" && fields[3] == fixedProviderUuid())
            val upstream = UUID.fromString(fields[1]).toString()
            val native = UUID.fromString(fields[2]).toString()
            require(upstream == fields[1] && native == fields[2] && upstream != native)
            subjects[fields[0]] = buildJsonObject {
                put("upstreamSubject", upstream); put("nativeSubject", native)
            }
        }
        require(subjects.keys == setOf("owner", "reader") &&
            subjects.getValue("owner").jsonObject.getValue("upstreamSubject") !=
                subjects.getValue("reader").jsonObject.getValue("upstreamSubject") &&
            subjects.getValue("owner").jsonObject.getValue("nativeSubject") !=
                subjects.getValue("reader").jsonObject.getValue("nativeSubject"))
        return JsonObject(subjects)
    }
    private fun masLinks(spec: PrivateDeploymentSpec, fingerprint: String): JsonObject {
        val postgres = selectedProcess(spec, fingerprint, "postgres")
        val statement = "SELECT u.username,l.subject,u.user_id::text,l.upstream_oauth_provider_id::text,u.can_request_admin " +
            "FROM users u JOIN upstream_oauth_links l ON l.user_id=u.user_id ORDER BY u.username"
        val answer = PrivateRootfulCommands(30, spec.store).run(listOf("exec", "--user", "999",
            "p0v3-live-${spec.name}-postgres", "psql", "-X", "-U", "postgres", "-d", "mas",
            "-At", "-F", "\t", "-c", statement))
        require(answer.exitCode == 0)
        return buildJsonObject {
            put("containerId", postgres.getValue("containerId"))
            put("subjects", parseMasLinks(answer.output))
        }
    }
    internal fun ownerMasSubject(spec: PrivateDeploymentSpec, fingerprint: String): String =
        masLinks(spec, fingerprint).getValue("subjects").jsonObject.getValue("owner")
            .jsonObject.getValue("nativeSubject").jsonPrimitive.content
    internal fun stoppedSource(context: JsonObject, source: RestoredOwnerScope): JsonObject {
        val original = json.parseToJsonElement(ReleasePrivateFiles.read(Path.of(context.getValue(
            "originalMatrixOracleFile").jsonPrimitive.content), 1048576).decodeToString(
                throwOnInvalidSequence = true)).jsonObject
        val spec = source.sourcePin.spec
        val ids = original.getValue("sourceContainers").jsonObject
        require(spec.name == source.source.id + "-v2" &&
            original.getValue("sourceGenerationId").jsonPrimitive.content == source.source.id &&
            original.getValue("sourceDeployment").jsonPrimitive.content == spec.name &&
            original.getValue("sourceRecipeSha256").jsonPrimitive.content == source.sourcePin.manifestSha256 &&
            source.listener.sourceGeneration == source.source.id &&
            source.listener.targetGeneration == source.target.id &&
            source.listener.sourceStoppedProofSha256.matches(hash) && ids.isNotEmpty() &&
            ids.keys.all { key -> spec.processes.any { it.id == key && !it.oneShot } })
        val observations = buildJsonObject {
            for ((process, expectedId) in ids) {
                val name = "p0v3-live-${spec.name}-$process"
                val result = PrivateRootfulCommands(30, spec.store).run(listOf("inspect", "--type", "container", name))
                require(result.exitCode == 0 && result.output.length in 1..4194304)
                val objects = json.parseToJsonElement(result.output).jsonArray
                require(objects.size == 1)
                val raw = objects.single().jsonObject
                val labels = raw.getValue("Config").jsonObject.getValue("Labels").jsonObject
                val state = raw.getValue("State").jsonObject
                val cid = raw.getValue("Id").jsonPrimitive.content
                require(cid == expectedId.jsonPrimitive.content && cid.matches(hash) &&
                    raw.getValue("Name").jsonPrimitive.content.removePrefix("/") == name &&
                    labels["io.p0v3.private-deployment"] == JsonPrimitive(spec.name) &&
                    labels["io.p0v3.runtime-fingerprint"] == JsonPrimitive(source.sourcePin.runtimeFingerprint) &&
                    !state.getValue("Running").jsonPrimitive.boolean && state.getValue("Pid").jsonPrimitive.int == 0)
                putJsonObject(process) { put("id", cid); put("running", false); put("pid", 0) }
            }
        }
        return buildJsonObject {
            put("sourceGenerationId", source.source.id); put("sourceDeployment", spec.name)
            put("sourceRecipeSha256", source.sourcePin.manifestSha256)
            put("sourceStoppedProofSha256", source.listener.sourceStoppedProofSha256)
            put("sourceContainers", ids); put("stoppedContainers", observations)
        }
    }
    fun execute(action: JsonObject, generation: String, phase: String, invocation: String,
        spec: PrivateDeploymentSpec, manifestSha: String, fingerprint: String,
        request: QualificationClientRequest, runtime: QualificationClientRuntime,
        client: QualificationClientNative, context: JsonObject, source: RestoredOwnerScope?,
        pin: GenerationPin, capture: QualificationMatrixCaptureActor,
        roots: ActivationInput, bundle: GenerationBundle, bundleSha: String): JsonObject {
        val verb = action.getValue("action").jsonPrimitive.also { require(it.isString) }.content
        require(generation == request.generationId && phase == request.phase &&
            invocation == request.invocationId && request.surface == "ANDROID" &&
            request.variant in setOf("API34", "API36") && request.serviceId in setOf(
                "element", "synapse", "matrix-authentication-service", "livekit") &&
            spec.name == "$generation-v2" && manifestSha.matches(hash) && fingerprint.matches(hash) &&
            client.containerId.matches(hash) && client.pid > 1 && client.netnsInode > 1)
        val caseDir = Path.of(request.caseDirectory)
        val caseFiles = mapOf("originalMatrixOracleFile" to "original-matrix-oracle.json",
            "nativeObservationFile" to "matrix-native-observation.json",
            "freshOriginalSessionFile" to "matrix-original-owner-session.token",
            "freshOriginalSessionReceiptFile" to "matrix-original-owner-session.json",
            "sourceIsolationReceiptFile" to "matrix-source-isolation.json")
        val ownerContext = JsonObject(context + caseFiles.filterKeys { it in context }.mapValues { (field, name) ->
            require(context.getValue(field).jsonPrimitive.content == "/case/owner-proofs/$name") {
                "Only exact selected Matrix QClient case paths may enter owner custody"
            }
            JsonPrimitive(caseDir.resolve("owner-proofs/$name").toString())
        })
        val issuedContext = if (verb == "REFRESH_OWNER_SESSION") ownerContext else
            QualificationMatrixSessionProducer.current(caseDir,ownerContext)
        val result = when (verb) {
            "READ_TARGET" -> {
                require(action.keys == setOf("action", "process"))
                val process = action.getValue("process").jsonPrimitive.also { require(it.isString) }.content
                require(process in setOf("postgres", "livekit"))
                selectedProcess(spec, fingerprint, process)
            }
            "READ_MAS_LINKS" -> {
                require(action.keys == setOf("action"))
                masLinks(spec, fingerprint)
            }
            "READ_SOURCE_STOPPED" -> {
                require(action.keys == setOf("action") && phase == "RESTORE")
                stoppedSource(ownerContext, requireNotNull(source))
            }
            "REFRESH_OWNER_SESSION" -> {
                require(action.keys == setOf("action", "priorSessionReceiptSha256"))
                QualificationMatrixSessionProducer.renew(caseDir,ownerContext,
                    action.getValue("priorSessionReceiptSha256").jsonPrimitive.content,
                    generation,invocation,phase,pin,roots,bundle,bundleSha)
            }
            "DEVICE_BASELINE", "READ_ANDROID_DEVICE" -> QualificationMatrixDeviceActor.execute(verb, action,
                caseDir, issuedContext, phase, generation, invocation, pin,
                roots, bundle, bundleSha, source)
            "ENSURE_ROOM" -> {
                val baseline = json.parseToJsonElement(ReleasePrivateFiles.read(Path.of(request.caseDirectory)
                    .resolve("owner-proofs/matrix-device-baseline.json"), 65536)
                    .decodeToString(throwOnInvalidSequence = true)).jsonObject
                val digest = ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(request.caseDirectory)
                    .resolve("owner-proofs/matrix-device-baseline.json"), 65536))
                require(baseline.getValue("generationId").jsonPrimitive.content == generation)
                val fresh = QualificationMatrixDeviceActor.execute("READ_ANDROID_DEVICE", buildJsonObject {
                    put("action", "READ_ANDROID_DEVICE"); put("baselineSha256", digest)
                }, caseDir, issuedContext, phase, generation, invocation, pin,
                    roots, bundle, bundleSha, source)
                require(fresh.getValue("deviceId") == action.getValue("ownerDeviceId"))
                QualificationMatrixRoomActor.execute(action, caseDir, issuedContext, spec, pin, phase)
            }
            "CAPTURE_BEGIN" -> capture.begin(action, Path.of(request.caseDirectory), context,
                pin, client, invocation)
            "CAPTURE_END" -> capture.end(action, Path.of(request.caseDirectory))
            "READ_GUEST_BRIDGE" -> {
                require(action.keys == setOf("action", "role"))
                val role = action.getValue("role").jsonPrimitive.also { require(it.isString) }.content
                val bridge = runtime.auditGuest(request, role)
                require(bridge.containerId == client.containerId && bridge.containerPid == client.pid &&
                    bridge.containerNetnsInode == client.netnsInode)
                val journal = GenerationRuntime.BASE.resolve(generation).resolve("qualification-client/$invocation")
                val bridgeBytes = ReleasePrivateFiles.read(journal.resolve(if (role == "owner")
                    "guest-bridge.json" else "guest-bridge-reader.json"), 65536)
                require(json.decodeFromString<QualificationGuestBridge>(bridgeBytes.decodeToString(
                    throwOnInvalidSequence = true)) == bridge)
                val policyBytes = ReleasePrivateFiles.read(journal.resolve("turn-policy.json"), 65536)
                val policy = json.decodeFromString<QualificationTurnPolicy>(policyBytes.decodeToString(
                    throwOnInvalidSequence = true))
                require(policy.containerId == client.containerId && policy.containerNetnsInode == client.netnsInode &&
                    policy.rtcHost == "matrix-rtc.datamancy.net")
                JsonObject(json.encodeToJsonElement(bridge).jsonObject + mapOf(
                    "guestBridgeSha256" to JsonPrimitive(ReleaseLocks.sha256(bridgeBytes)),
                    "policySha256" to JsonPrimitive(ReleaseLocks.sha256(policyBytes))))
            }
            else -> error("Unknown fixed Matrix action")
        }
        return JsonObject(result + mapOf("generationId" to JsonPrimitive(generation),
            "phase" to JsonPrimitive(phase), "invocationId" to JsonPrimitive(invocation),
            "manifestSha256" to JsonPrimitive(manifestSha),
            "runtimeFingerprint" to JsonPrimitive(fingerprint)))
    }
}
