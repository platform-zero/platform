package net.datamancy.platform

import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** Fixed owner-thread adapter for the existing native actuator. No caller-selected URLs,
 * credentials, paths, operation identifiers or native command execution. */
internal object QualificationOpenSearchActor {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    internal data class Operation(val id: String, val action: String, val role: String)
    internal fun operation(invocation: String, phase: String, request: JsonObject): Operation {
        require(invocation.matches(Regex("case-[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}")) &&
            phase in setOf("INSTALL", "RESTORE") && request.keys == setOf("action"))
        val action = request.getValue("action").jsonPrimitive.also { require(it.isString) }.content
        val tag = when (action) {
            "CREATE" -> { require(phase == "INSTALL"); "original-create" }
            "DOCUMENT" -> "original-get"
            "HISTORY" -> "original-history"
            "DENY" -> "node-denial"
            else -> error("Unknown fixed OpenSearch action")
        }
        return Operation("nq-" + ReleaseLocks.sha256("$invocation\nopensearch\n$tag".encodeToByteArray()).take(12),
            action, if (action == "DENY") "NODE" else "ADMIN")
    }

    fun execute(binding: NativeQualificationCaseBinding, spec: PrivateDeploymentSpec,
        request: JsonObject, sourceStopped: ActivationInput?, sourceStoppedProofSha256: String?): JsonObject {
        require(binding.serviceId == "opensearch" && binding.targetMemberName == spec.name)
        val selected = operation(binding.invocationId, binding.phase, request)
        val sealed = NativeQualificationClaims.read(binding)
        val context = sealed.context
        val metadata = context.getValue("opensearchNative").jsonObject
        val generation = GenerationRuntime.BASE.resolve(binding.generationId)
        val home = privateControlDirectory(privateControlDirectory(generation.resolve("native-qualification"))
            .resolve(binding.invocationId))
        val nativeRequestPath = home.resolve("${selected.id}.request.json")
        // All actions have stable IDs, so changing the spool sequence cannot replay an action.
        require(!Files.exists(nativeRequestPath, NOFOLLOW_LINKS) &&
            !Files.exists(home.resolve("pending.json"), NOFOLLOW_LINKS)) {
            "Original OpenSearch action already attempted or uncertain; no new sequence workaround"
        }
        fun pin(name: String, filename: String): ActivationInput {
            val path = PrivateDeployment.BASE.resolve(spec.name).resolve("opensearch-$filename")
            require(metadata.getValue("${name}File").jsonPrimitive.content == path.toString())
            return ActivationInput(path.toString(), metadata.getValue("${name}Sha256").jsonPrimitive.content)
        }
        val original = if (binding.phase == "INSTALL") {
            require(sourceStopped == null && sourceStoppedProofSha256 == null)
            buildJsonObject {
                put("privateText", "a12-original-native-search-${binding.invocationId}")
                put("sourceGeneration", binding.generationId); put("version", 1)
            }
        } else {
            require(sourceStopped != null && sourceStoppedProofSha256 != null)
            val observedPath = Path.of(context.getValue("sourceObservation").jsonPrimitive.content)
            val observed = json.parseToJsonElement(ReleasePrivateFiles.read(observedPath, 1048576)
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
            val oracle = ReleasePrivateFiles.read(observedPath.parent.resolve("oracle.json"), 1048576)
            require(ReleaseLocks.sha256(oracle) == observed.getValue("artifacts").jsonObject
                .getValue("oracle.json").jsonPrimitive.content)
            json.parseToJsonElement(oracle.decodeToString(throwOnInvalidSequence = true)).jsonObject
                .getValue("originalDocument").jsonObject
        }
        val body = json.encodeToString(JsonObject.serializer(), original).encodeToByteArray()
        require(body.size in 1..8192)
        val bodyPin = if (selected.action == "CREATE") {
            val path = home.resolve("${selected.id}.body.json")
            ReleasePrivateFiles.save(path, body)
            ActivationInput(path.toString(), ReleaseLocks.sha256(body))
        } else null
        val native = OpenSearchNativeQualificationRequest(selected.id, binding, selected.role, selected.action,
            pin("ca", "ca.pem"), pin("adminCert", "admin.pem"), pin("adminKey", "admin-key.pem"),
            pin("nodeCert", "node.pem"), pin("nodeKey", "node-key.pem"),
            metadata.getValue("serverLeafSha256").jsonPrimitive.content, ReleaseLocks.sha256(body), bodyPin,
            sourceStopped, sourceStoppedProofSha256, home.resolve("${selected.id}.response").toString())
        val rawRequest = json.encodeToString(native).encodeToByteArray()
        require(rawRequest.size <= 65536)
        ReleasePrivateFiles.save(nativeRequestPath, rawRequest)
        val result = OpenSearchNativeQualificationClient.real(generation, spec, binding.targetFingerprint).request(native)
        val rawResult = ReleasePrivateFiles.read(home.resolve("${selected.id}.result.json"), 65536)
        require(json.decodeFromString<OpenSearchNativeQualificationResult>(rawResult.decodeToString()) == result &&
            result.requestSha256 == ReleaseLocks.sha256(rawRequest) &&
            result.responseFile == native.responseFile && result.operation == selected.id)
        return project(Path.of(binding.caseDirectory), home, selected.id, rawRequest, rawResult, result.responseSha256)
    }

    /** Copies have no authority of their own: exact protected bytes are reopened against their
     * hashes, including a legitimate empty HTTP denial body, before CREATE_NEW publication. */
    internal fun project(case: Path, home: Path, operation: String, request: ByteArray,
        result: ByteArray, responseSha256: String): JsonObject {
        require(operation.matches(Regex("nq-[a-f0-9]{12}")))
        ReleasePrivateFiles.directory(case)
        val names = linkedMapOf("nativeRequest" to "$operation.request.json",
            "nativeResult" to "$operation.result.json", "response" to "$operation.response")
        val hashes = mapOf(names.getValue("nativeRequest") to ReleaseLocks.sha256(request),
            names.getValue("nativeResult") to ReleaseLocks.sha256(result), names.getValue("response") to responseSha256)
        val original = QualificationSuitePin(home,
            ActivationInput(home.resolve(names.getValue("nativeRequest")).toString(), ReleaseLocks.sha256(request)), hashes)
        val destination = privateControlDirectory(case.resolve("owner-native"))
        return buildJsonObject {
            put("schemaVersion", 2)
            for ((field, name) in names) {
                val bytes = QualificationSuiteClosure.readPinnedSource(original, name)
                require(bytes.size <= if (field == "response") 1048576 else 65536)
                val path = destination.resolve(name)
                if (bytes.isEmpty()) {
                    require(field == "response")
                    FileChannel.open(path, setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS),
                        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))).use { it.force(true) }
                    ReleasePrivateFiles.sync(destination)
                } else ReleasePrivateFiles.save(path, bytes)
                put(field, buildJsonObject {
                    put("relativePath", "owner-native/$name"); put("sha256", hashes.getValue(name))
                })
            }
        }
    }
}
