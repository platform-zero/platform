package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** Host-side case authority is minted only after the acceptance executor has saved the
 * immutable case context/intent and its admitted phase intent. Neither record can include
 * this claim's SHA: the response envelope, not the hashed record, carries that digest.
 * The protected Main entrypoint must restrict this operation to the release controller;
 * a runner cannot be allowed to invoke a general claim publisher as a socket hook. */
@Serializable internal data class NativeCaseBeginRequest(val caseDirectory: String,
    val phaseIntent: ActivationInput, val journalFile: String, val journalHeadSha256: String,
    val bundleSha256: String, val targetMemberName: String, val targetFingerprint: String)
@Serializable internal data class NativeCaseCompletionRequest(val caseDirectory: String,
    val claimSha256: String, val resultSha256: String)
@Serializable internal data class NativeCaseClaimEnvelope(val invocationId: String, val generationId: String,
    val serviceId: String, val trialId: String, val candidate: JsonObject, val manifestSha256: String,
    val targetMemberName: String, val targetFingerprint: String, val phase: String,
    val caseIntentSha256: String, val contextSha256: String, val claimSha256: String)
@Serializable internal data class NativeCaseCompletionEnvelope(val invocationId: String,
    val claimSha256: String, val resultSha256: String)
@Serializable internal data class NativeCaseCompletionRecord(val invocationId: String,
    val claimSha256: String, val caseResultSha256: String, val nativeObservationSha256: String,
    val originalOracleSha256: String, val phaseIntentSha256: String)

internal object NativeQualificationCasePublisher {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private val sha = Regex("[a-f0-9]{64}")
    private val gen = Regex("q-[a-f0-9]{12}")
    private val invocation = Regex("case-[a-f0-9-]{36}")
    private val mode = PosixFilePermissions.fromString("rwx------")

    private fun caseRoot(path: String): Path = Path.of(path).also {
        require(it.isAbsolute && it.normalize() == it && Files.isDirectory(it, NOFOLLOW_LINKS) && it.toRealPath() == it &&
            Files.getPosixFilePermissions(it, NOFOLLOW_LINKS) == mode)
    }
    private fun objectBytes(path: Path, maximum: Int = 1048576): Pair<ByteArray, JsonObject> {
        val bytes = ReleasePrivateFiles.read(path, maximum)
        return bytes to json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
    }
    private fun name(objectValue: JsonObject, field: String) = objectValue.getValue(field).jsonPrimitive.content
    private fun admittedPhase(request: NativeCaseBeginRequest, case: Path, intent: JsonObject): String {
        require(request.phaseIntent.sha256.matches(sha) && request.journalHeadSha256.matches(sha) &&
            request.bundleSha256.matches(sha))
        val phaseFile = Path.of(request.phaseIntent.path)
        val journalFile = Path.of(request.journalFile)
        require(journalFile.isAbsolute && journalFile.normalize() == journalFile &&
            phaseFile.isAbsolute && phaseFile.normalize() == phaseFile &&
            phaseFile.parent == journalFile.parent && journalFile.toRealPath() == journalFile &&
            Files.getPosixFilePermissions(journalFile, NOFOLLOW_LINKS) ==
                PosixFilePermissions.fromString("rw-------"))
        val (bytes, phase) = objectBytes(phaseFile)
        require(ReleaseLocks.sha256(bytes) == request.phaseIntent.sha256)
        val binding = intent.getValue("binding").jsonObject
        val trial = name(binding, "trialId")
        val generationId = name(binding, "generationId")
        val phaseName = name(binding, "phase")
        val stage = phase["stagedOnly"]?.jsonPrimitive?.boolean ?: false
        require(phaseFile.fileName.toString() ==
            "${if (stage) "staged" else "phase"}-$trial-${phaseName.lowercase()}.intent.json" &&
            phase.getValue("binding") == intent.getValue("binding") &&
            name(phase, "journalHead") == request.journalHeadSha256 &&
            Path.of(name(phase, "artifactRoot")) == case.parent)
        val journal = ReleasePrivateFiles.read(journalFile, 16 * 1024 * 1024)
        require(journal.last() == '\n'.code.toByte())
        val lines = journal.decodeToString(throwOnInvalidSequence = true).dropLast(1).split('\n')
        require(lines.size in 1..10000)
        var previous = "0".repeat(64)
        var last: JsonObject? = null
        lines.forEachIndexed { index, line ->
            val entry = json.parseToJsonElement(line).jsonObject
            val stamp = name(entry, "sha256")
            require(entry.getValue("sequence").jsonPrimitive.int == index + 1 &&
                name(entry, "previousSha256") == previous && stamp.matches(sha) &&
                ReleaseLocks.sha256(JsonObject(entry + ("sha256" to JsonPrimitive("")))
                    .toString().encodeToByteArray()) == stamp) { "Changed qualification journal chain" }
            previous = stamp; last = entry
        }
        val latest = requireNotNull(last)
        val trialRecord = latest.getValue("trial").jsonObject
        require(previous == request.journalHeadSha256 && name(latest, "event") == "BEGIN" &&
            name(trialRecord, "outcome") == "RUNNING" && name(trialRecord, "id") == trial &&
            trialRecord.getValue("candidate") == binding.getValue("candidate") &&
            (if (phaseName == "INSTALL") name(trialRecord, "installId") == generationId else
                name(trialRecord, "restoreId") == generationId || stage))
        return request.phaseIntent.sha256
    }
    private fun sealedTarget(request: NativeCaseBeginRequest, intent: JsonObject,
        context: JsonObject): Pair<String, String> {
        val binding = intent.getValue("binding").jsonObject
        val generationId = name(binding, "generationId")
        require(generationId.matches(gen) && request.targetMemberName.startsWith("$generationId-") &&
            request.targetFingerprint.matches(sha))
        val bundleBytes = ReleasePrivateFiles.read(GenerationRuntime.BASE.resolve(generationId).resolve("bundle.json"))
        require(ReleaseLocks.sha256(bundleBytes) == request.bundleSha256)
        val bundle = json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString(throwOnInvalidSequence = true))
        SiteOwnerships.checkSealed(bundle)
        val pin = bundle.members.single { it.member.name == request.targetMemberName }
        require(pin.runtimeFingerprint == request.targetFingerprint && pin.spec.name == pin.member.name &&
            PrivateDeployment.expectedFingerprint(pin.spec, pin.inputHashes) == pin.runtimeFingerprint)
        val service = name(intent, "serviceId")
        val process = when (service) {
            "node-exporter" -> "node"
            "crowdsec" -> "guard"
            "onlyoffice" -> "seafile-backend"
            else -> service
        }
        require(service in setOf("alloy", "loki", "node-exporter", "onlyoffice", "opensearch", "crowdsec", "qbittorrent") &&
            name(intent, "surface") == "HEADLESS" && name(intent, "variant") == "NATIVE")
        val target = context.getValue("nativeTargets").jsonObject.getValue(service).jsonObject
        require(target.keys == setOf("targetMemberName", "targetFingerprint", "processId") &&
            name(target, "targetMemberName") == request.targetMemberName &&
            name(target, "targetFingerprint") == request.targetFingerprint &&
            name(target, "processId") == process &&
            pin.spec.processes.count { it.id == process && !it.oneShot } == 1)
        if (service == "onlyoffice") require(name(context, "targetGeneration") == generationId &&
            name(context, "callbackDeploymentName") == request.targetMemberName &&
            name(context, "callbackRuntimeFingerprint") == request.targetFingerprint &&
            pin.spec.processes.single { it.id == process }.imageId == name(context, "backendImageId"))
        return generationId to service
    }
    fun begin(request: NativeCaseBeginRequest, activePhaseClaimSha256: String? = null): NativeCaseClaimEnvelope {
        val case = caseRoot(request.caseDirectory)
        val (intentBytes, intent) = objectBytes(case.resolve("intent.json"), 65536)
        val (contextBytes, context) = objectBytes(case.resolve("context.json"), 4194304)
        val id = name(intent, "invocationId")
        require(id.matches(invocation) &&
            case.fileName.toString() == "${name(intent, "serviceId")}--${name(intent, "journey")}--headless--native" &&
            name(intent, "contextSha256") == ReleaseLocks.sha256(contextBytes) &&
            "caseClaimSha256" !in context && "caseIntentSha256" !in context)
        val (generationId, service) = sealedTarget(request, intent, context)
        val phaseSha = admittedPhase(request, case, intent)
        val generationRoot = GenerationRuntime.BASE.resolve(generationId)
        if (activePhaseClaimSha256 == null) RssQualificationIntents.requireClear(generationRoot)
        else RssQualificationIntents.requireNativePhase(generationRoot, activePhaseClaimSha256,
            name(intent.getValue("binding").jsonObject, "trialId"),
            name(intent.getValue("binding").jsonObject, "phase"), case.parent, request.phaseIntent)
        val binding = intent.getValue("binding").jsonObject
        val record = buildJsonObject {
            put("invocationId", id); put("generationId", generationId); put("serviceId", service)
            put("phase", name(binding, "phase")); put("trialId", name(binding, "trialId"))
            put("candidate", binding.getValue("candidate")); put("manifestSha256", name(intent, "manifestSha256"))
            put("targetMemberName", request.targetMemberName); put("targetFingerprint", request.targetFingerprint)
            put("caseIntentSha256", ReleaseLocks.sha256(intentBytes))
            put("contextSha256", ReleaseLocks.sha256(contextBytes))
            put("phaseIntentSha256", phaseSha); put("journalHeadSha256", request.journalHeadSha256)
            put("bundleSha256", request.bundleSha256)
        }
        val root = GenerationRuntime.BASE.resolve(generationId).resolve("native-qualification-claims")
        ReleasePrivateFiles.directory(root.parent)
        if (!Files.exists(root, NOFOLLOW_LINKS)) {
            Files.createDirectory(root, PosixFilePermissions.asFileAttribute(mode)); ReleasePrivateFiles.sync(root.parent)
        }
        val bytes = record.toString().encodeToByteArray()
        ReleasePrivateFiles.locked(root) { ReleasePrivateFiles.save(root.resolve("$id.json"), bytes) }
        return NativeCaseClaimEnvelope(id, generationId, service, name(binding, "trialId"),
            binding.getValue("candidate").jsonObject, name(intent, "manifestSha256"),
            request.targetMemberName, request.targetFingerprint, name(binding, "phase"),
            ReleaseLocks.sha256(intentBytes), ReleaseLocks.sha256(contextBytes), ReleaseLocks.sha256(bytes))
    }
    fun complete(request: NativeCaseCompletionRequest): NativeCaseCompletionEnvelope {
        val case = caseRoot(request.caseDirectory)
        val (intentBytes, intent) = objectBytes(case.resolve("intent.json"), 65536)
        val (contextBytes, context) = objectBytes(case.resolve("context.json"), 4194304)
        val binding = intent.getValue("binding").jsonObject
        val generationId = name(binding, "generationId")
        val id = name(intent, "invocationId")
        require(id.matches(invocation) && generationId.matches(gen) &&
            case.fileName.toString() == "${name(intent, "serviceId")}--${name(intent, "journey")}--headless--native" &&
            request.claimSha256.matches(sha) && request.resultSha256.matches(sha) &&
            name(intent, "contextSha256") == ReleaseLocks.sha256(contextBytes))
        val root = GenerationRuntime.BASE.resolve(generationId).resolve("native-qualification-claims")
        val bytes = ReleasePrivateFiles.read(root.resolve("$id.json"), 8192)
        require(ReleaseLocks.sha256(bytes) == request.claimSha256)
        val claim = json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        NativeQualificationClaims.read(NativeQualificationCaseBinding(generationId, id, case.toString(),
            ReleaseLocks.sha256(intentBytes), request.claimSha256, name(intent, "serviceId"),
            name(binding, "phase"), name(claim, "targetMemberName"), name(claim, "targetFingerprint")))
        val (resultBytes, result) = objectBytes(case.resolve("result.json"))
        val (observedBytes, observed) = objectBytes(case.resolve("native-result.json"))
        require(ReleaseLocks.sha256(resultBytes) == request.resultSha256 &&
            result.getValue("passed").jsonPrimitive.boolean && result.getValue("finished").jsonPrimitive.boolean &&
            result.getValue("exitCode").jsonPrimitive.int == 0 && result.getValue("invocation") == intent &&
            result.getValue("observationSha256").jsonPrimitive.content == ReleaseLocks.sha256(observedBytes) &&
            name(observed, "invocationId") == id && name(observed, "serviceId") == name(intent, "serviceId") &&
            name(observed, "generationId") == generationId && name(observed, "phase") == name(binding, "phase") &&
            observed.getValue("schemaVersion").jsonPrimitive.int == 2 &&
            observed.getValue("assertions").jsonObject.keys ==
                intent.getValue("requiredAssertions").jsonArray.map { it.jsonPrimitive.content }.toSet() &&
            observed.getValue("assertions").jsonObject.values.all { it.jsonPrimitive.boolean })
        val oracle = observed.getValue("artifacts").jsonObject.getValue("oracle.json").jsonPrimitive.content
        require(oracle.matches(sha) && ReleaseLocks.sha256(ReleasePrivateFiles.read(case.resolve("oracle.json"))) == oracle)
        val completion = NativeCaseCompletionRecord(id, request.claimSha256, request.resultSha256,
            ReleaseLocks.sha256(observedBytes), oracle, name(claim, "phaseIntentSha256"))
        ReleasePrivateFiles.locked(root) {
            ReleasePrivateFiles.save(root.resolve("$id.complete.json"), json.encodeToString(completion).encodeToByteArray())
        }
        return NativeCaseCompletionEnvelope(id, request.claimSha256, request.resultSha256)
    }
}
