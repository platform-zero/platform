package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

@Serializable internal data class QuadletResourceIntent(val schemaVersion: Int = 1,
    val member: String, val fingerprint: String, val kind: String, val resource: String,
    val sourceSha256: String? = null)
@Serializable internal data class QuadletResourceResult(val schemaVersion: Int = 1,
    val intentSha256: String, val observedId: String, val observedLabelsSha256: String)

/** Prepares graph-declared Podman *resources*, never a process. Each network, volume or
 * secret gets one fsynced original effect; missing ACK cannot be bypassed by a second
 * create. Owner holds generation + member locks for the entire resource phase.
 */
internal class RuntimeQuadletResources(private val generationRoot: Path, private val runtimeRoot: Path,
    private val commands: RuntimeCommands = PrivateRootfulCommands(60, RuntimeStore.CANONICAL_V2)) {
    private val json = Json { encodeDefaults = true }
    /** Recovered targets must audit original resources, NEVER call provision again. */
    fun auditProvisioned(spec: PrivateDeploymentSpec, fingerprint: String,
        inputHashes: Map<String, String>): List<QuadletResourceResult> {
        require(PrivateDeployment.expectedFingerprint(spec, inputHashes) == fingerprint &&
            spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2)
        val memberRoot = runtimeRoot.resolve(spec.name)
        ReleasePrivateFiles.directory(memberRoot)
        inputHashes.forEach { (file, sha) ->
            require(ReleaseLocks.sha256(ReleasePrivateFiles.read(memberRoot.resolve(file))) == sha)
        }
        val items = buildList {
            spec.networks.forEach { add(Triple("network", it, null)) }
            spec.volumes.forEach { add(Triple("volume", "volume-${it.id}", null)) }
            spec.processes.flatMap { it.files }.map { it.file }.distinct().sorted().forEach {
                add(Triple("secret", "file-$it", it))
            }
        }
        return items.map { (kind, id, source) ->
            val name = "p0v3-live-${spec.name}-$id"
            val original = ReleasePrivateFiles.read(generationRoot.resolve("quadlet-resource-$kind-$id.intent.json"), 8192)
            val intent = json.decodeFromString<QuadletResourceIntent>(original.decodeToString())
            val result = json.decodeFromString<QuadletResourceResult>(ReleasePrivateFiles.read(
                generationRoot.resolve("quadlet-resource-$kind-$id.result.json"), 8192).decodeToString())
            require(intent.schemaVersion == 1 && intent.member == spec.name && intent.fingerprint == fingerprint &&
                intent.kind == kind && intent.resource == name && intent.sourceSha256 == source?.let(inputHashes::getValue) &&
                result.schemaVersion == 1 && result.intentSha256 == ReleaseLocks.sha256(original))
            val native = commands.run(listOf(kind, "inspect", name))
            require(native.exitCode == 0 && native.output.toByteArray().size in 1..65536)
            val observed = json.parseToJsonElement(native.output).jsonArray.single().jsonObject
            val values = if (kind == "secret") observed.getValue("Spec").jsonObject else observed
            val nativeName = values.getValue(if (kind == "network") "name" else "Name").jsonPrimitive.content
            val labels = values.getValue(if (kind == "network") "labels" else "Labels").jsonObject
            val nativeId = when (kind) {
                "network" -> values.getValue("id").jsonPrimitive.content
                "secret" -> observed.getValue("ID").jsonPrimitive.content
                else -> name
            }
            require(nativeName == name && nativeId == result.observedId &&
                labels.getValue("io.p0v3.private-deployment").jsonPrimitive.content == spec.name &&
                labels.getValue("io.p0v3.runtime-fingerprint").jsonPrimitive.content == fingerprint &&
                result.observedLabelsSha256 == ReleaseLocks.sha256(labels.toString().toByteArray())) {
                "Recovered Quadlet resource changed since its original create ACK"
            }
            result
        }
    }
    fun provision(spec: PrivateDeploymentSpec, fingerprint: String, inputHashes: Map<String, String>): List<QuadletResourceResult> {
        RuntimeQuadlets.render(spec)
        require(PrivateDeployment.expectedFingerprint(spec, inputHashes) == fingerprint &&
            spec.ingress == null && spec.nativeIngress == null)
        ReleasePrivateFiles.directory(generationRoot)
        val memberRoot = runtimeRoot.resolve(spec.name)
        ReleasePrivateFiles.directory(memberRoot)
        require(!Files.exists(memberRoot.resolve("runtime.owner"), NOFOLLOW_LINKS) &&
            RuntimeMaintenance.read(memberRoot, fingerprint) == null)
        // Check *every* protected source before the first native effect, not just as its
        // secret is reached. No source is generated, rewritten or renamed here.
        inputHashes.forEach { (name, expected) ->
            require(ReleaseLocks.sha256(ReleasePrivateFiles.read(memberRoot.resolve(name))) == expected) {
                "Protected Quadlet input changed"
            }
        }
        val items = buildList {
            spec.networks.forEach { add(Triple("network", it, null)) }
            spec.volumes.forEach { add(Triple("volume", "volume-${it.id}", null)) }
            spec.processes.flatMap { it.files }.map { it.file }.distinct().sorted().forEach { file ->
                add(Triple("secret", "file-$file", file))
            }
        }
        return items.map { (kind, id, source) ->
            val name = "p0v3-live-${spec.name}-$id"
            val intentPath = generationRoot.resolve("quadlet-resource-$kind-$id.intent.json")
            val resultPath = generationRoot.resolve("quadlet-resource-$kind-$id.result.json")
            require(!Files.exists(intentPath, NOFOLLOW_LINKS) && !Files.exists(resultPath, NOFOLLOW_LINKS)) {
                "Original Quadlet resource effect already attempted; reconcile, do not recreate"
            }
            val exists = commands.run(listOf(kind, "exists", name))
            require(exists.exitCode == 1 && exists.output.toByteArray().size <= 4096) {
                "Owned resource already exists or absence is uncertain"
            }
            val original = QuadletResourceIntent(member = spec.name, fingerprint = fingerprint, kind = kind,
                resource = name, sourceSha256 = source?.let(inputHashes::getValue))
            val bytes = json.encodeToString(original).toByteArray()
            ReleasePrivateFiles.save(intentPath, bytes)
            val labels = listOf("--label=io.p0v3.private-deployment=${spec.name}",
                "--label=io.p0v3.runtime-fingerprint=$fingerprint")
            val args = when (kind) {
                "network" -> listOf("network", "create", "--internal") + labels + name
                "volume" -> listOf("volume", "create") + labels + name
                "secret" -> listOf("secret", "create") + labels + listOf(name, memberRoot.resolve(requireNotNull(source)).toString())
                else -> error("Undeclared resource kind")
            }
            val created = commands.run(args)
            require(created.exitCode == 0 && created.output.toByteArray().size <= 4096) {
                "Original resource create ACK missing; original intent retained"
            }
            val reply = commands.run(listOf(kind, "inspect", name))
            require(reply.exitCode == 0 && reply.output.toByteArray().size in 1..65536)
            val observed = json.parseToJsonElement(reply.output).jsonArray.single().jsonObject
            val actualName = when (kind) {
                "secret" -> observed.getValue("Spec").jsonObject.getValue("Name").jsonPrimitive.content
                "network" -> observed.getValue("name").jsonPrimitive.content
                else -> observed.getValue("Name").jsonPrimitive.content
            }
            val actualLabels = when (kind) {
                "secret" -> observed.getValue("Spec").jsonObject.getValue("Labels").jsonObject
                "network" -> observed.getValue("labels").jsonObject
                else -> observed.getValue("Labels").jsonObject
            }
            require(actualName == name && actualLabels.getValue("io.p0v3.private-deployment").jsonPrimitive.content == spec.name &&
                actualLabels.getValue("io.p0v3.runtime-fingerprint").jsonPrimitive.content == fingerprint) {
                "Foreign Podman resource after original create"
            }
            val observedId = when (kind) {
                "secret" -> observed.getValue("ID").jsonPrimitive.content
                "network" -> observed.getValue("id").jsonPrimitive.content
                else -> actualName // Podman volume inspect has no separate ID.
            }
            require(if (kind == "secret") observedId.matches(Regex("[a-f0-9]{25}"))
                else if (kind == "network") observedId.matches(Regex("[a-f0-9]{64}"))
                else observedId == name) { "Invalid native resource identity" }
            val result = QuadletResourceResult(intentSha256 = ReleaseLocks.sha256(bytes),
                observedId = observedId, observedLabelsSha256 = ReleaseLocks.sha256(actualLabels.toString().toByteArray()))
            ReleasePrivateFiles.save(resultPath, json.encodeToString(result).toByteArray())
            result
        }
    }
}
