package net.datamancy.platform

import java.io.InputStream
import java.io.RandomAccessFile
import java.nio.file.Files
import java.util.zip.GZIPInputStream
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/** Fixed, generation-local components. Neither a command nor a mount can be supplied by a caller. */
@Serializable internal enum class ManagedLaneKind { WORKLANE, TUIOS, PI }
@Serializable internal data class ManagedLaneSpec(
    val kind: ManagedLaneKind, val laneId: String, val subject: String, val session: String,
    val home: String, val workspace: String, val memoryMiB: Int, val diskMiB: Int
)
@Serializable internal data class ManagedBrokerServiceBinding(val controllerSha256: String,
    val executableSha256: String, val configuration: ActivationInput)
@Serializable internal data class ManagedLaneImageBinding(val archive: ActivationInput, val archiveBytes: Long,
    val maximumUnpackedBytes: Long, val expectedImageId: String, val sourceImageReference: String,
    val expectedManifestDigest: String, val expectedLayerDiffIds: List<String>)
@Serializable internal data class ManagedLaneHostBinding(val worklane: ActivationInput, val podman: ActivationInput,
    val manifest: ActivationInput, val storageConfig: ActivationInput,
    val broker: ManagedBrokerServiceBinding? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val brokerHost: ManagedBrokerHostBinding? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val imageArchive: ManagedLaneImageBinding? = null)
@Serializable internal data class ManagedLanePlan(val generation: String, val lanes: List<ManagedLaneSpec>,
    val native: ManagedLaneHostBinding, val provider: String = "openai", val model: String = "gpt-6-sol",
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val readerSubject: String? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val ownerSubject: String? = null) {
    /** One physical lane plus one separately supervised host-side broker (256 MiB / 64 tasks). */
    val memoryReservationMiB: Long get() = lanes.single { it.kind == ManagedLaneKind.WORKLANE }.memoryMiB.toLong() + 256
    val diskReservationMiB: Long get() = lanes.single { it.kind == ManagedLaneKind.WORKLANE }.diskMiB.toLong() + 128 +
        (native.imageArchive?.let { Math.addExact(it.archiveBytes, it.maximumUnpackedBytes).let { bytes ->
            Math.addExact(bytes, 1048575) / 1048576 } } ?: 0L)
    val pidsReservation: Long get() = 256 + 64 // Podman lane cgroup plus supervised host broker.
    val capabilities: Set<String> get() = setOf("worklane", "tuios", "pi")
    fun validate(generation: String) {
        require(this.generation == generation && generation.matches(Regex("q-[a-f0-9]{12}")) &&
            provider == "openai" && model == "gpt-6-sol")
        native.brokerHost?.validate(generation)
        require(listOf(native.worklane, native.podman, native.storageConfig, native.manifest).all {
            it.sha256.matches(Regex("[a-f0-9]{64}")) && Path.of(it.path).isAbsolute &&
                Path.of(it.path).normalize() == Path.of(it.path)
        } && native.worklane.path.endsWith("/worklane") && native.podman.path.endsWith("/podman") &&
            native.manifest.path.endsWith("/$generation/managed/inputs/target-lane.toml") &&
            native.storageConfig.path.endsWith("/$generation/managed/control/storage.conf") &&
            native.broker?.let { broker -> broker.controllerSha256.matches(Regex("[a-f0-9]{64}")) &&
                broker.executableSha256.matches(Regex("[a-f0-9]{64}")) &&
                broker.configuration.sha256.matches(Regex("[a-f0-9]{64}")) &&
                broker.configuration.path.endsWith("/$generation/managed/inputs/broker.json") } == true &&
            native.imageArchive?.let { image -> image.archive.sha256.matches(Regex("[a-f0-9]{64}")) &&
                Path.of(image.archive.path).isAbsolute && Path.of(image.archive.path).normalize() == Path.of(image.archive.path) &&
                image.archiveBytes in 1024..RecoveryCapsule.MAX_TOTAL &&
                image.maximumUnpackedBytes in 1024..RecoveryCapsule.MAX_TOTAL &&
                image.expectedImageId.matches(Regex("sha256:[a-f0-9]{64}")) &&
                image.expectedManifestDigest.matches(Regex("sha256:[a-f0-9]{64}")) &&
                image.expectedLayerDiffIds.size in 1..128 &&
                image.expectedLayerDiffIds.all { it.matches(Regex("sha256:[a-f0-9]{64}")) } &&
                image.sourceImageReference.matches(Regex("[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}")) } != false)
        require(lanes.size == 3 && lanes.map { it.kind } == listOf(ManagedLaneKind.WORKLANE, ManagedLaneKind.TUIOS, ManagedLaneKind.PI))
        ownerSubject?.let { owner -> require(
            runCatching { java.util.UUID.fromString(owner).toString() }.getOrNull() == owner &&
                owner !in lanes.map { it.subject } && owner != readerSubject
        ) { "The human owner cannot be the managed lane's service principal" } }
        readerSubject?.let { reader -> require(
            runCatching { java.util.UUID.fromString(reader).toString() }.getOrNull() == reader &&
                reader != lanes.first().subject
        ) }
        require(lanes.map { it.laneId }.distinct().size == 1 && lanes.map { it.session }.distinct().size == 1 &&
            lanes.map { it.subject }.distinct().size == 1 &&
            lanes.map { it.home }.distinct().size == 1 && lanes.map { it.workspace }.distinct().size == 1)
        lanes.forEach { lane ->
            require(lane.laneId.matches(Regex("[a-f0-9]{8}-[a-f0-9]{4}-[345][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}")) &&
                lane.subject.matches(Regex("[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}")) &&
                lane.session.matches(Regex("[a-z][a-z0-9-]{0,40}")) &&
                lane.home == "home" && lane.workspace == "home/workspace" &&
                (if (lane.kind == ManagedLaneKind.WORKLANE) lane.memoryMiB in 256..65536 &&
                    lane.diskMiB in 1024..1048576 else lane.memoryMiB == 0 && lane.diskMiB == 0))
        }
    }
}

@Serializable internal enum class ManagedLaneOperation { PREPARE, START, ISOLATE, CAPTURE, IMPORT }
@Serializable internal data class ManagedLaneIntent(val generation: String, val laneId: String,
    val operation: ManagedLaneOperation, val operationId: String, val planSha256: String,
    val sourceCaptureSha256: String? = null,
    val deadlineEpochMillis: Long? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val maximumBytes: Long? = null)
@Serializable internal data class ManagedLaneEvidence(val generation: String, val laneId: String,
    val operation: ManagedLaneOperation, val operationId: String, val intentSha256: String,
    val ownershipSha256: String, val resultSha256: String, val isolated: Boolean,
    val observedAtEpochSeconds: Long)
@Serializable internal data class ManagedLanePayloadRecord(val oracle: ManagedLaneCaptureOracle,
    val archiveRoot: String)

/** Effects must perform native identity and ownership readback. No success flag or callback return constitutes evidence. */
internal interface ManagedLaneBackend {
    fun preflight(lane: ManagedLaneSpec, root: Path, operation: ManagedLaneOperation, transfer: Path?,
        sourceCaptureSha256: String?, deadlineEpochMillis: Long?) {}
    fun prepare(lane: ManagedLaneSpec, root: Path, intent: ManagedLaneIntent, intentHash: String): ManagedLaneEvidence
    fun start(lane: ManagedLaneSpec, root: Path, intent: ManagedLaneIntent, intentHash: String): ManagedLaneEvidence
    fun isolate(lane: ManagedLaneSpec, root: Path, intent: ManagedLaneIntent, intentHash: String): ManagedLaneEvidence
    fun capture(lane: ManagedLaneSpec, root: Path, destination: Path, intent: ManagedLaneIntent, intentHash: String): ManagedLaneEvidence
    fun import(lane: ManagedLaneSpec, root: Path, projection: Path, intent: ManagedLaneIntent, intentHash: String): ManagedLaneEvidence
    fun attest(lane: ManagedLaneSpec, root: Path, evidence: ManagedLaneEvidence): ManagedLaneEvidence
}

/** Append-only effects: a partial intent permanently fences a possibly executed operation. */
internal class ManagedLaneRuntime(private val root: Path, private val plan: ManagedLanePlan,
    private val backend: ManagedLaneBackend) {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    init { plan.validate(plan.generation) }
    /** Read-only actual Worklane/TUIOS Pi window, never a caller-supplied ID. */
    fun piWindowReadback(): JsonObject {
        val pi = plan.lanes.single { it.kind == ManagedLaneKind.PI }
        val native = backend as? NativeManagedLaneBackend
            ?: error("Only selected native Worklane owner may read a Pi window")
        return native.piWindow(pi,root)
    }
    companion object {
        fun real(generationRoot: Path, plan: ManagedLanePlan): ManagedLaneRuntime {
            require(generationRoot.fileName.toString() == plan.generation && generationRoot.isAbsolute &&
                generationRoot.normalize() == generationRoot)
            val root = generationRoot.resolve("managed")
            require(Path.of(plan.native.manifest.path) == root.resolve("inputs/target-lane.toml") &&
                Path.of(plan.native.storageConfig.path) == root.resolve("control/storage.conf"))
            val control = root.resolve("control")
            val image = requireNotNull(plan.native.imageArchive) {
                "Fresh Worklane graph requires a pinned externally verified local OCI archive"
            }
            return ManagedLaneRuntime(root, plan, NativeManagedLaneBackend(
                Path.of(plan.native.worklane.path), Path.of(plan.native.podman.path),
                Path.of(plan.native.storageConfig.path), Path.of(plan.native.manifest.path), control.resolve("home"),
                control.resolve("config"), control.resolve("data"), control.resolve("run"), image,
                mapOf("worklane" to plan.native.worklane.sha256, "podman" to plan.native.podman.sha256,
                    "storageConfig" to plan.native.storageConfig.sha256, "manifest" to plan.native.manifest.sha256,
                    "imageArchive" to image.archive.sha256)))
        }
    }

    private fun safeRoot(path: Path) = ReleasePrivateFiles.directory(path)
    private fun create(path: Path, bytes: ByteArray) {
        require(bytes.size in 1..1048576 && path.parent.toRealPath() == path.parent && !Files.exists(path, NOFOLLOW_LINKS))
        ReleasePrivateFiles.save(path, bytes)
    }
    private fun digest(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(value).joinToString("") { "%02x".format(it) }
    private fun validEvidence(value: ManagedLaneEvidence, intent: ManagedLaneIntent, intentHash: String) {
        require(value.generation == plan.generation && value.laneId == intent.laneId &&
            value.operation == intent.operation && value.operationId == intent.operationId &&
            value.intentSha256 == intentHash && value.ownershipSha256.matches(Regex("[a-f0-9]{64}")) &&
            value.resultSha256.matches(Regex("[a-f0-9]{64}")) && value.observedAtEpochSeconds > 0 &&
            (intent.operation != ManagedLaneOperation.ISOLATE || value.isolated)) {
            "Backend failed to attest the bound managed operation"
        }
    }
    /** Caller owns controller exclusion and ordered generation locks before invoking any effect. */
    fun operate(lane: ManagedLaneSpec, operation: ManagedLaneOperation, operationId: String,
        sourceCaptureSha256: String? = null, transfer: Path? = null,
        deadlineEpochMillis: Long? = null, maximumBytes: Long? = null): ManagedLaneEvidence {
        require(lane in plan.lanes && operationId.matches(Regex("[a-z0-9-]{1,64}")) &&
            (sourceCaptureSha256 == null || sourceCaptureSha256.matches(Regex("[a-f0-9]{64}"))))
        safeRoot(root)
        val directory = root.resolve(lane.kind.name.lowercase())
        safeRoot(directory)
        require((operation == ManagedLaneOperation.CAPTURE || operation == ManagedLaneOperation.IMPORT) == (transfer != null) &&
            (operation == ManagedLaneOperation.IMPORT) == (sourceCaptureSha256 != null))
        transfer?.let { require(it.isAbsolute && it.normalize() == it && it.parent.toRealPath() == it.parent &&
            (operation != ManagedLaneOperation.IMPORT || Files.isDirectory(it, NOFOLLOW_LINKS) && it.toRealPath() == it)) }
        require((transfer != null) == (maximumBytes != null) &&
            (maximumBytes == null || (maximumBytes >= ManagedLaneRecovery.METADATA_RESERVE_BYTES + 4096 &&
                maximumBytes <= RecoveryCapsule.MAX_TOTAL))) {
            "Aggregate managed capture/import scratch allowance required before intent"
        }
        if (transfer != null || operation == ManagedLaneOperation.PREPARE && plan.native.imageArchive != null)
            require(deadlineEpochMillis != null && deadlineEpochMillis > System.currentTimeMillis() &&
                deadlineEpochMillis - System.currentTimeMillis() <= TimeUnit.HOURS.toMillis(8)) {
                "Bound release deadline required before managed transfer or local image import intent"
            }
        RecoveryDeadline.remainingSecondsIfBound() // Never extend parent operation through a new UTC projection.
        plan.lanes.forEach { component ->
            val componentRoot = root.resolve(component.kind.name.lowercase())
            safeRoot(componentRoot)
            Files.list(componentRoot).use { entries ->
                require(entries.noneMatch { file -> file.fileName.toString().endsWith(".intent.json") &&
                    !Files.exists(componentRoot.resolve(file.fileName.toString().removeSuffix(".intent.json") + ".result.json"), NOFOLLOW_LINKS) }) {
                    "Uncertain managed effect remains fenced; reconcile before another operation"
                }
            }
        }
        backend.preflight(lane, directory, operation, transfer, sourceCaptureSha256, deadlineEpochMillis)
        val intent = ManagedLaneIntent(plan.generation, lane.laneId, operation, operationId,
            digest(json.encodeToString(plan).toByteArray()), sourceCaptureSha256, deadlineEpochMillis, maximumBytes)
        val name = "${operation.name.lowercase()}-$operationId"
        val encoded = json.encodeToString(intent).toByteArray()
        val intentHash = digest(encoded)
        create(directory.resolve("$name.intent.json"), encoded)
        val observed = when (operation) {
            ManagedLaneOperation.PREPARE -> backend.prepare(lane, directory, intent, intentHash)
            ManagedLaneOperation.START -> backend.start(lane, directory, intent, intentHash)
            ManagedLaneOperation.ISOLATE -> backend.isolate(lane, directory, intent, intentHash)
            ManagedLaneOperation.CAPTURE -> backend.capture(lane, directory, requireNotNull(transfer), intent, intentHash)
            ManagedLaneOperation.IMPORT -> backend.import(lane, directory, requireNotNull(transfer), intent, intentHash)
        }
        validEvidence(observed, intent, intentHash)
        // An independent readback prevents a backend from returning a fabricated transient success.
        val attested = backend.attest(lane, directory, observed)
        require(attested == observed) { "Native state changed after managed operation" }
        create(directory.resolve("$name.result.json"), json.encodeToString(attested).toByteArray())
        return attested
    }
    /** Native Worklane's own one-use credential write precedes its Podman delivery.
     * Caller holds the separately sealed broker-delivery intent. */
    fun deliverBroker(lane: ManagedLaneSpec, token: String, operationId: String): ManagedLaneInitialDeliveryReceipt {
        require(lane in plan.lanes && lane.kind == ManagedLaneKind.PI &&
            backend is NativeManagedLaneBackend && operationId.matches(Regex("[a-z0-9-]{1,64}")))
        safeRoot(root)
        recorded(plan.lanes.single { it.kind == ManagedLaneKind.WORKLANE }, ManagedLaneOperation.START, operationId)
        return backend.deliverBroker(lane, token, operationId)
    }

    /** Independent native Worklane/Podman readback for typed parent START/STOP. */
    fun physicalRunning(): Boolean {
        require(backend is NativeManagedLaneBackend)
        val lane = plan.lanes.single { it.kind == ManagedLaneKind.WORKLANE }
        return backend.physicalRunning(lane, root.resolve("worklane"))
    }

    /** A single real Pi RPC turn, inside this generation's assigned physical lane.
     * This is NOT a model-broker call. Worklane writes a one-use prompt intent
     * before spawning its in-lane Pi subprocess; an uncertain turn is never retried.
     */
    fun chat(owner: String, intentId: String, message: String): String {
        require(plan.ownerSubject == owner &&
            intentId.matches(Regex("[a-f0-9]{32}")) && message.isNotBlank() &&
            message.toByteArray(Charsets.UTF_8).size <= 4096 && backend is NativeManagedLaneBackend)
        return backend.chat(plan.lanes.single { it.kind == ManagedLaneKind.WORKLANE }, owner, intentId, message)
    }

    fun recorded(lane: ManagedLaneSpec, operation: ManagedLaneOperation, operationId: String): ManagedLaneEvidence {
        require(lane in plan.lanes && operationId.matches(Regex("[a-z0-9-]{1,64}")))
        val directory = root.resolve(lane.kind.name.lowercase()); safeRoot(directory)
        val name = "${operation.name.lowercase()}-$operationId"
        val intentPath = directory.resolve("$name.intent.json")
        val resultPath = directory.resolve("$name.result.json")
        val intentBytes = ReleasePrivateFiles.read(intentPath, 1048576)
        val intent = json.decodeFromString<ManagedLaneIntent>(intentBytes.decodeToString(throwOnInvalidSequence = true))
        val evidence = json.decodeFromString<ManagedLaneEvidence>(ReleasePrivateFiles.read(resultPath, 1048576)
            .decodeToString(throwOnInvalidSequence = true))
        require(intent.generation == plan.generation && intent.planSha256 == digest(json.encodeToString(plan).toByteArray()))
        validEvidence(evidence, intent, digest(intentBytes))
        require(intent.operationId == operationId && intent.operation == operation && intent.laneId == lane.laneId)
        require(backend.attest(lane, directory, evidence) == evidence)
        return evidence
    }
}

/** Pinned native Worklane/Podman control. Each subprocess has a private rootless store and no ambient secrets. */
/** PREPARE cannot claim source isolation from a mutable Worklane registry alone.
 * The fresh rootless target graph must have NO native container before START. */
internal fun managedPrepareNativeIsolation(status: JsonObject, nativeContainers: kotlinx.serialization.json.JsonArray): Boolean =
    status["state"]?.jsonPrimitive?.content in setOf("cold-unregistered", "absent", "created", "stopped", "exited") &&
        nativeContainers.isEmpty()

/** RecoverySegments materializes ONE authenticated logical tar per component, not flat capture copies. */
internal fun managedLogicalImportArchive(transfer: Path, component: String): Path {
    require(component in setOf("home", "workspace", "manifests", "transcripts") &&
        transfer.isAbsolute && transfer.toRealPath() == transfer && Files.isDirectory(transfer, NOFOLLOW_LINKS))
    val directory = transfer.resolve(component)
    require(directory.toRealPath() == directory && Files.isDirectory(directory, NOFOLLOW_LINKS))
    return directory.resolve("tree.tar").also { archive ->
        require(archive.toRealPath() == archive && Files.isRegularFile(archive, NOFOLLOW_LINKS)) {
            "Only the authenticated logical managed component archive can be imported"
        }
    }
}

internal class NativeManagedLaneBackend(private val worklane: Path, private val podman: Path,
    private val storageConfig: Path, private val sourceManifest: Path, private val home: Path, private val configHome: Path,
    private val dataHome: Path, private val runtimeDir: Path, private val image: ManagedLaneImageBinding,
    private val expectedHashes: Map<String, String>) : ManagedLaneBackend {
    private val json = Json { ignoreUnknownKeys = false }
    private fun digest(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it) }
    private fun digestFile(path: Path, deadlineEpochMillis: Long? = null): String {
        val hash = MessageDigest.getInstance("SHA-256")
        Files.newInputStream(path, NOFOLLOW_LINKS).use { input ->
            val buffer = ByteArray(65536)
            while (true) {
                RecoveryDeadline.remainingSecondsIfBound()
                require(deadlineEpochMillis == null || System.currentTimeMillis() < deadlineEpochMillis)
                val count = input.read(buffer); if (count < 0) break; hash.update(buffer, 0, count)
            }
        }
        return hash.digest().joinToString("") { "%02x".format(it) }
    }
    /** Narrow TOML v5 profile parser, before any manifest materialization/import/credential effect. */
    internal fun validateTargetManifest(bytes: ByteArray, lane: ManagedLaneSpec, root: Path) {
        require(bytes.size in 1..1048576)
        val sections = mutableMapOf("" to mutableMapOf<String, String>())
        var section = ""
        val linePattern = Regex("^([a-z_]+) = (true|false|[0-9]+|\\[\\]|\"[^\"\\r\\n]*\"|'[^'\\r\\n]*')$")
        bytes.decodeToString(throwOnInvalidSequence = true).lines().forEach { raw ->
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) return@forEach
            if (line in setOf("[profile]", "[[profile.mounts]]")) {
                section = if (line == "[profile]") "profile" else "mount"
                require(section !in sections) { "Duplicate managed manifest section" }
                sections[section] = mutableMapOf()
            } else {
                val match = requireNotNull(linePattern.matchEntire(line)) { "Unsafe TOML expression in managed manifest" }
                val key = match.groupValues[1]
                val value = match.groupValues[2].removeSurrounding("\"").removeSurrounding("'")
                require(sections.getValue(section).putIfAbsent(key, value) == null) { "Duplicate managed manifest key" }
            }
        }
        val top = sections.getValue("")
        val profile = sections["profile"] ?: error("Missing managed native profile")
        val mount = sections["mount"] ?: error("Missing fixed broker socket mount")
        require(top.keys.all { it in setOf("schema_version", "id", "name", "container_name", "session_name",
            "container_home", "profile_name", "created_at", "image_digest") } &&
            profile.keys.all { it in setOf("image", "agent", "terminal_backend", "build_context", "containerfile",
                "embedded_containerfile", "network", "runtime", "devices", "mount_codex_credentials",
                "mount_gh_credentials") } && mount.keys == setOf("source", "target", "read_only"))
        require(top["schema_version"] == "5" && top["id"] == lane.laneId &&
            top["session_name"] == lane.session && top["container_name"] == "worklane-${lane.session}-${lane.laneId}" &&
            top["container_home"] == "/home/dev" && top["name"] == lane.session &&
            profile["agent"] == "pi" && profile["terminal_backend"] == "tuios-v3" &&
            profile["embedded_containerfile"] == "false" && profile["mount_codex_credentials"] == "false" &&
            profile["mount_gh_credentials"] == "false" && profile["network"] == "none" &&
            profile["devices"] in setOf(null, "[]") && profile["runtime"] == "systemd" &&
            profile["build_context"] in setOf(null, "project") &&
            profile["containerfile"] in setOf(null, "Containerfile.v3") &&
            mount["source"] == root.parent.resolve("control/run/broker.sock").toString() &&
            mount["target"] == "/run/worklane-pi/broker.sock" && mount["read_only"] == "true") {
            "Foreign or privilege-escalating managed lane manifest"
        }
        val pinnedImage = requireNotNull(profile["image"])
        require(pinnedImage == image.expectedImageId && top["image_digest"] == image.expectedImageId) {
            "Managed profile image and native image ID must match the immutable local archive binding"
        }
    }
    /** Read-only terminal observation of an imported native image. It is not
     * itself an ACK; q9b's distinct original PREPARE results remain authoritative. */
    internal fun uncertainImportedImage(root: Path): JsonObject {
        require(root.fileName.toString()=="worklane" && root.parent.parent.fileName.toString() in
            setOf("q-4d3c1cb287e5",Q273UncertainManagedImportTerminal.generation,
                GenerationAfterQ583Lineage.generation))
        pinned(worklane,"worklane"); pinned(podman,"podman")
        pinned(storageConfig,"storageConfig"); pinned(sourceManifest,"manifest")
        val store=pm("info","--format","json")
        val native=store.getValue("store").jsonObject
        val security=store.getValue("host").jsonObject.getValue("security").jsonObject
        val actualGraph=root.parent.resolve("control/data/containers/storage")
        val actualRun=root.parent.resolve("control/run/containers")
        require(security.getValue("rootless").jsonPrimitive.boolean &&
            native.getValue("graphDriverName").jsonPrimitive.content=="vfs" &&
            native.getValue("graphRoot").jsonPrimitive.content==actualGraph.toString() &&
            native.getValue("runRoot").jsonPrimitive.content==actualRun.toString() &&
            native.getValue("containerStore").jsonObject.getValue("number").jsonPrimitive.int==0 &&
            native.getValue("imageStore").jsonObject.getValue("number").jsonPrimitive.int==1 &&
            Files.isDirectory(actualGraph,NOFOLLOW_LINKS) && actualGraph.toRealPath()==actualGraph &&
            Files.isDirectory(actualRun,NOFOLLOW_LINKS) && actualRun.toRealPath()==actualRun) {
            "Uncertain native import cannot be claimed absent or assigned a foreign graph" }
        // Imported rootless VFS layers can contain subuid-owned 0700 directories.
        // A separate bounded root-scoped read-only census under the same native
        // lock attests allocated bytes; host Files.walk would misreport absence.
        val observed=pm("image","inspect",image.expectedImageId)
        require(observed.getValue("Id").jsonPrimitive.content==image.expectedImageId.removePrefix("sha256:") &&
            observed.getValue("RootFS").jsonObject.getValue("Layers").jsonArray.map { it.jsonPrimitive.content }==image.expectedLayerDiffIds &&
            observed.getValue("Size").jsonPrimitive.long in 1..image.maximumUnpackedBytes) {
            "Native Worklane image is not the original content-addressed archive" }
        return observed
    }
    /** Separately journaled isolated source probe, never a generation PREPARE.
     * Actual scoped Podman is invoked only from this pinned backend once after
     * an append-only probe intent; its imported graph cannot serve a release. */
    internal fun probeRootlessImage(dataRoot:Path,runRoot:Path):JsonObject {
        val archive=Path.of(image.archive.path)
        require(archive.isAbsolute && archive.toRealPath()==archive &&
            Files.isRegularFile(archive,NOFOLLOW_LINKS) &&
            Files.size(archive)==image.archiveBytes &&
            Files.getPosixFilePermissions(archive)==PosixFilePermissions.fromString("r--------") &&
            digestFile(archive)==image.archive.sha256)
        val before=pm("info","--format","json")
        val source=before.getValue("store").jsonObject
        val security=before.getValue("host").jsonObject.getValue("security").jsonObject
        require(security.getValue("rootless").jsonPrimitive.boolean &&
            source.getValue("graphDriverName").jsonPrimitive.content=="vfs" &&
            source.getValue("graphRoot").jsonPrimitive.content==dataRoot.toString() &&
            source.getValue("runRoot").jsonPrimitive.content==runRoot.toString() &&
            source.getValue("containerStore").jsonObject.getValue("number").jsonPrimitive.int==0 &&
            source.getValue("imageStore").jsonObject.getValue("number").jsonPrimitive.int==0) {
            "Fresh isolated rootless graph differs before native probe import" }
        command(podman,listOf("load","--input",archive.toString()),600000)
        val after=pm("info","--format","json").getValue("store").jsonObject
        val result=pm("image","inspect",image.expectedImageId)
        require(after.getValue("graphRoot").jsonPrimitive.content==dataRoot.toString() &&
            after.getValue("runRoot").jsonPrimitive.content==runRoot.toString() &&
            after.getValue("containerStore").jsonObject.getValue("number").jsonPrimitive.int==0 &&
            after.getValue("imageStore").jsonObject.getValue("number").jsonPrimitive.int==1 &&
            result.getValue("Id").jsonPrimitive.content==image.expectedImageId.removePrefix("sha256:") &&
            result.getValue("RootFS").jsonObject.getValue("Layers").jsonArray.map { it.jsonPrimitive.content }==image.expectedLayerDiffIds &&
            result.getValue("Size").jsonPrimitive.long in 1..image.maximumUnpackedBytes) {
            "Isolated native image bytes/graph identity differ; retain intent, never retry" }
        return result
    }
    private fun importedImage() {
        val observed = pm("image", "inspect", image.expectedImageId)
        val id = observed["Id"]?.jsonPrimitive?.content
        val layers = observed["RootFS"]?.jsonObject?.get("Layers")?.jsonArray?.map { it.jsonPrimitive.content }
        val size = observed["Size"]?.jsonPrimitive?.content?.toLongOrNull()
        // The isolated native probe returned a BARE 64-hex Podman Id. Compare
        // exactly to the content digest, not to a prefixed string or a tag.
        require(id == image.expectedImageId.removePrefix("sha256:") && layers == image.expectedLayerDiffIds &&
            size != null && size in 1..image.maximumUnpackedBytes) {
            "Fresh rootless graph has no exact pinned Worklane image digest/ID/size"
        }
    }
    private fun pinned(path: Path, key: String, deadlineEpochMillis: Long? = null) {
        require(path.isAbsolute && path.normalize() == path && path.toRealPath() == path &&
            Files.isRegularFile(path, NOFOLLOW_LINKS) && digestFile(path, deadlineEpochMillis) == expectedHashes[key]) {
            "Changed or unpinned native managed component input"
        }
    }
    private fun remaining(deadlineEpochMillis: Long): Long = minOf(
        deadlineEpochMillis - System.currentTimeMillis(),
        RecoveryDeadline.remainingSecondsIfBound()?.let { TimeUnit.SECONDS.toMillis(it) } ?: Long.MAX_VALUE)
    private fun command(executable: Path, args: List<String>, timeoutMillis: Long = 90000,
        input: ByteArray? = null): String {
        pinned(worklane, "worklane"); pinned(podman, "podman"); pinned(storageConfig, "storageConfig")
        listOf(home, configHome, dataHome, runtimeDir).forEach {
            require(it.isAbsolute && it.normalize() == it && it.toRealPath() == it &&
                Files.isDirectory(it, NOFOLLOW_LINKS) && Files.getPosixFilePermissions(it) ==
                PosixFilePermissions.fromString("rwx------")) { "Managed lane requires private rootless roots" }
        }
        val effective = minOf(timeoutMillis,
            RecoveryDeadline.remainingSecondsIfBound()?.let { TimeUnit.SECONDS.toMillis(it) } ?: Long.MAX_VALUE)
        require(effective in 1..TimeUnit.HOURS.toMillis(8))
        val process = ProcessBuilder(listOf(executable.toString()) + args).apply {
            environment().clear()
            environment().putAll(mapOf("HOME" to home.toString(), "XDG_CONFIG_HOME" to configHome.toString(),
                "XDG_DATA_HOME" to dataHome.toString(), "XDG_RUNTIME_DIR" to runtimeDir.toString(),
                "CONTAINERS_STORAGE_CONF" to storageConfig.toString(), "PATH" to "${podman.parent}:/usr/bin:/bin",
                "LANG" to "C.UTF-8"))
            redirectError(ProcessBuilder.Redirect.DISCARD)
        }.start()
        try {
            val output = java.util.concurrent.CompletableFuture.supplyAsync { process.inputStream.readNBytes(1048577) }
            process.outputStream.use { stdin -> if (input != null) {
                require(input.size in 1..8192)
                stdin.write(input); stdin.flush()
            } }
            require(process.waitFor(effective, TimeUnit.MILLISECONDS)) {
                "Native managed operation timed out; intent remains fenced"
            }
            val bytes = output.get(5, TimeUnit.SECONDS)
            require(bytes.size <= 1048576 && process.exitValue() == 0) {
                "Native managed operation failed; intent remains fenced"
            }
            return bytes.decodeToString(throwOnInvalidSequence = true)
        } finally {
            if (process.isAlive) process.destroyForcibly()
        }
    }
    override fun preflight(lane: ManagedLaneSpec, root: Path, operation: ManagedLaneOperation, transfer: Path?,
        sourceCaptureSha256: String?, deadlineEpochMillis: Long?) {
        pinned(worklane, "worklane"); pinned(podman, "podman"); pinned(storageConfig, "storageConfig")
        pinned(sourceManifest, "manifest")
        validateTargetManifest(ReleasePrivateFiles.read(sourceManifest, 1048576), lane, root)
        if (lane.kind == ManagedLaneKind.WORKLANE && operation == ManagedLaneOperation.PREPARE) {
            val archive = Path.of(image.archive.path)
            require(archive.isAbsolute && archive.normalize() == archive &&
                !archive.startsWith(root.parent.resolve("control")) &&
                Files.isRegularFile(archive, NOFOLLOW_LINKS) && Files.size(archive) == image.archiveBytes &&
                Files.getPosixFilePermissions(archive).none { it.name.endsWith("WRITE") } &&
                Files.getFileStore(root.parent).usableSpace >=
                    Math.addExact(image.maximumUnpackedBytes, 10L * 1024 * 1024 * 1024)) {
                "Local Worklane OCI archive or admitted VFS graph/headroom missing"
            }
            pinned(archive, "imageArchive", deadlineEpochMillis)
            ManagedLaneOciArchive.inspect(archive, image, requireNotNull(deadlineEpochMillis),
                Files.getFileStore(root.parent).blockSize) // Actual target block-size bound BEFORE load intent.
        }
        if (lane.kind == ManagedLaneKind.WORKLANE && operation == ManagedLaneOperation.START) {
            importedImage() // A missing image would trigger Podman's network pull; refuse first.
            verifySelectedGraph(root)
        }
        if (operation == ManagedLaneOperation.CAPTURE) {
            require(transfer != null && (if (lane.kind == ManagedLaneKind.WORKLANE)
                !Files.exists(transfer, NOFOLLOW_LINKS) else Files.isDirectory(transfer, NOFOLLOW_LINKS)))
            components(lane.kind).forEach { component ->
                val source = componentRoot(root, component, source = true)
                require(source.toRealPath() == source && Files.isDirectory(source, NOFOLLOW_LINKS))
            }
        }
        if (operation == ManagedLaneOperation.IMPORT) {
            require(transfer != null && sourceCaptureSha256 != null)
            val oracleBytes = ReleasePrivateFiles.read(transfer.resolve("oracle.json"), 1048576)
            require(digest(oracleBytes) == sourceCaptureSha256)
            val oracle = Json.decodeFromString<ManagedLaneCaptureOracle>(oracleBytes.decodeToString(throwOnInvalidSequence = true))
            require(oracle.sourceGeneration != root.parent.parent.fileName.toString() &&
                oracle.sourceLaneId != lane.laneId && oracle.sourceSession != lane.session &&
                oracle.archives.keys == components(lane.kind).toSet() &&
                digest(ReleasePrivateFiles.read(transfer.resolve("source-manifest.toml"), 1048576)) ==
                    oracle.sourceManifestSha256)
            components(lane.kind).forEach { component ->
                val file = managedLogicalImportArchive(transfer, component)
                require(ManagedLaneRecovery.archive(file) == oracle.archives.getValue(component))
            }
        }
    }
    /** Called only after a sealed broker delivery intent and the original Worklane START
     * result. The credential travels over stdin; the Worklane CLI writes its own
     * one-use in-lane receipt before calling rootless Podman exec. Never retry on
     * missing/failed native readback, including a process timeout or lost stdout. */
    fun deliverBroker(lane: ManagedLaneSpec, token: String, operationId: String): ManagedLaneInitialDeliveryReceipt {
        require(lane.kind == ManagedLaneKind.PI && operationId.matches(Regex("[a-z0-9-]{1,64}")) &&
            token.length in 32..4096 && token.split('.').size == 3 &&
            token.all { it.isLetterOrDigit() || it in "-_." })
        val expiry = Json.parseToJsonElement(java.util.Base64.getUrlDecoder().decode(token.split('.')[1])
            .decodeToString(throwOnInvalidSequence = true)).jsonObject["exp"]?.jsonPrimitive?.content?.toLongOrNull()
        require(expiry != null && expiry - java.time.Instant.now().epochSecond in 1..300)
        val scope = kotlinx.serialization.json.buildJsonObject {
            put("schema_version", 1); put("lane_id", lane.laneId); put("session", lane.session)
            put("subject", lane.subject); put("provider", "openai"); put("model", "gpt-6-sol")
            put("expires_at", expiry); put("generation", planGeneration())
        }
        val request = kotlinx.serialization.json.buildJsonObject {
            put("scope", scope); put("broker_token", token)
            if (operationId != "managed-start") put("operation_id", operationId)
        }.toString().toByteArray()
        val observed = json.parseToJsonElement(command(worklane,
            listOf("--json", "lane", "pi-broker", lane.laneId), 90000, request)).jsonObject
        val native = observed["nativeReadbackSha256"]?.jsonPrimitive?.content
        val hash = digest(token.toByteArray(Charsets.UTF_8))
        require(observed.keys == setOf("scope", "nativeReadbackSha256") && native == hash &&
            observed.getValue("scope").jsonObject == scope) {
            "Native in-lane Pi credential readback differs from scoped host issuance"
        }
        return ManagedLaneInitialDeliveryReceipt(planGeneration(), lane.laneId, lane.session,
            operationId, hash, expiry, requireNotNull(native))
    }

    /** Worklane alone can execute the fixed, tool-free Pi RPC subprocess in its owned lane.
     * The same pinned worklane/rootless Podman environment applies as for START.
     */
    fun chat(lane: ManagedLaneSpec, owner: String, intentId: String, message: String): String {
        require(lane.kind == ManagedLaneKind.WORKLANE &&
            owner.matches(Regex("[a-f0-9-]{36}")) && intentId.matches(Regex("[a-f0-9]{32}")) &&
            message.toByteArray(Charsets.UTF_8).size in 1..4096)
        val request = kotlinx.serialization.json.buildJsonObject {
            put("generation", planGeneration()); put("lane_id", lane.laneId); put("session", lane.session)
            put("owner_subject", owner); put("intent_id", intentId); put("message", message)
        }.toString().toByteArray(Charsets.UTF_8)
        val reply = json.parseToJsonElement(command(worklane,
            listOf("--json", "lane", "pi-chat", lane.laneId), 170000, request)).jsonObject
        require(reply.keys == setOf("generation", "lane_id", "session", "intent_id", "message") &&
            reply.getValue("generation").jsonPrimitive.content == planGeneration() &&
            reply.getValue("lane_id").jsonPrimitive.content == lane.laneId &&
            reply.getValue("session").jsonPrimitive.content == lane.session &&
            reply.getValue("intent_id").jsonPrimitive.content == intentId) {
            "Foreign Pi RPC completion"
        }
        return reply.getValue("message").jsonPrimitive.content.also {
            require(it.isNotBlank() && it.toByteArray(Charsets.UTF_8).size <= 32768)
        }
    }

    private fun planGeneration(): String = sourceManifest.parent.parent.parent.fileName.toString().also {
        require(it.matches(Regex("q-[a-f0-9]{12}")))
    }

    private fun wl(vararg args: String): JsonObject = json.parseToJsonElement(command(worklane,
        listOf("--json", "lane") + args)).jsonObject
    private fun pm(vararg args: String): JsonObject {
        val reply = json.parseToJsonElement(command(podman, args.toList()))
        return if (reply is JsonObject) reply else reply.jsonArray.single().jsonObject
    }
    fun physicalRunning(lane: ManagedLaneSpec, root: Path): Boolean {
        require(lane.kind == ManagedLaneKind.WORKLANE)
        return when (inspect(lane, root).getValue("state").jsonPrimitive.content) {
            "running" -> true
            "stopped", "exited", "created" -> false
            else -> throw IllegalStateException("Ambiguous native managed lane state")
        }
    }
    private fun selectedGraph(root:Path):Path = root.parent.resolve(if (
        root.parent.parent.fileName.toString() in setOf("q-c3a7a9e29391",
            GenerationAfterCapacityRefusalLineage.generation,GenerationAfterQ273Lineage.generation,
            GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
            GenerationAfterQ07Lineage.generation,WorklaneFullPrepareReturnProbe.generation))
        "control/data/containers/storage" else "control/podman-graph")
    private fun selectedRun(root:Path):Path = root.parent.resolve(if (
        root.parent.parent.fileName.toString() in setOf("q-c3a7a9e29391",
            GenerationAfterCapacityRefusalLineage.generation,GenerationAfterQ273Lineage.generation,
            GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
            GenerationAfterQ07Lineage.generation,WorklaneFullPrepareReturnProbe.generation))
        "control/run/containers" else "control/podman-run")
    private fun verifySelectedGraph(root:Path,deadline:Long?=null) {
        val selected=selectedGraph(root)
        if (root.parent.parent.fileName.toString() in setOf("q-c3a7a9e29391",
                GenerationAfterCapacityRefusalLineage.generation,GenerationAfterQ273Lineage.generation,
                GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
                GenerationAfterQ07Lineage.generation,WorklaneFullPrepareReturnProbe.generation))
            RootlessVfsGraphCensus.observe(selected,image.maximumUnpackedBytes)
        else ManagedLaneOciArchive.verifyGraph(selected,image.maximumUnpackedBytes,deadline)
    }
    private fun inspect(lane: ManagedLaneSpec, root: Path): JsonObject {
        val info = pm("info", "--format", "json")
        require(info["host"]!!.jsonObject["security"]!!.jsonObject["rootless"]!!.jsonPrimitive.content == "true" &&
            Path.of(info["store"]!!.jsonObject["graphRoot"]!!.jsonPrimitive.content).toRealPath() ==
                selectedGraph(root).toRealPath() &&
            Path.of(info["store"]!!.jsonObject["runRoot"]!!.jsonPrimitive.content).toRealPath() ==
                selectedRun(root).toRealPath()) { "Foreign rootless image store" }
        val status = wl("inspect", lane.laneId, "--readonly")
        val activeManifest = root.parent.resolve("home/.worklane/lane.toml")
        require(activeManifest.toRealPath() == activeManifest && digestFile(activeManifest) == expectedHashes["manifest"]) {
            "Native lane manifest changed from the sealed generation input"
        }
        val spec = status["spec"]!!.jsonObject
        require(spec["id"]!!.jsonPrimitive.content == lane.laneId &&
            spec["host"]!!.jsonPrimitive.content == "local" &&
            spec["session_name"]!!.jsonPrimitive.content == lane.session &&
            spec["profile"]!!.jsonObject["terminal_backend"]!!.jsonPrimitive.content == "tuios-v3" &&
            spec["profile"]!!.jsonObject["agent"]!!.jsonPrimitive.content == "pi" &&
            Path.of(spec["project_path"]!!.jsonPrimitive.content).toRealPath() == root.parent.resolve(lane.home).toRealPath() &&
            spec["profile"]!!.jsonObject["mount_codex_credentials"]!!.jsonPrimitive.content == "false" &&
            spec["profile"]!!.jsonObject["mount_gh_credentials"]!!.jsonPrimitive.content == "false")
        return status
    }
    private fun evidence(lane: ManagedLaneSpec, root: Path, operation: ManagedLaneOperation,
        intent: ManagedLaneIntent, hash: String, isolated: Boolean): ManagedLaneEvidence {
        if (lane.kind == ManagedLaneKind.WORKLANE && operation == ManagedLaneOperation.PREPARE)
            importedImage() // Independent post-effect readback; no transient return as proof.
        val status = if (operation == ManagedLaneOperation.IMPORT) null else inspect(lane, root)
        if (operation == ManagedLaneOperation.PREPARE) {
            // wl inspect only describes persisted registry state. Independently enumerate
            // the entire fresh native VFS graph; one existing (including running) Podman
            // container forbids a cold PREPARE receipt before source release.
            val containers = json.parseToJsonElement(command(podman,
                listOf("ps", "--all", "--format", "json"))).jsonArray
            require(managedPrepareNativeIsolation(requireNotNull(status), containers)) {
                "Native managed container exists or target registry is running after PREPARE"
            }
        }
        val spec = status?.get("spec")?.jsonObject
        val ownership = if (spec == null) digest(listOf(lane.laneId, lane.session,
            sourceManifest.toString(), expectedHashes.getValue("manifest")).joinToString("|").toByteArray()) else
            digest(listOf(lane.laneId, lane.session, spec["project_path"]!!.jsonPrimitive.content,
                spec["profile"]!!.jsonObject["image"]!!.jsonPrimitive.content).joinToString("|").toByteArray())
        val state = status?.get("state")?.jsonPrimitive?.content ?: "cold-unregistered"
        require((isolated && state != "running") || (!isolated && state == "running")) {
            "Native lane did not reach required state"
        }
        val payloadPath = root.resolve("${operation.name.lowercase()}-${intent.operationId}.payload.json")
        val payloadHash = if (operation in setOf(ManagedLaneOperation.CAPTURE, ManagedLaneOperation.IMPORT)) {
            val record = Json.decodeFromString<ManagedLanePayloadRecord>(ReleasePrivateFiles.read(payloadPath, 1048576)
                .decodeToString(throwOnInvalidSequence = true))
            require(record.oracle.archives.keys == components(lane.kind).toSet() &&
                Path.of(record.archiveRoot).isAbsolute && Path.of(record.archiveRoot).toRealPath() == Path.of(record.archiveRoot))
            record.oracle.archives.forEach { (component, archived) ->
                val file = if (operation == ManagedLaneOperation.IMPORT)
                    root.parent.resolve("worklane/${intent.operationId}-$component.readback.tar")
                else Path.of(record.archiveRoot).resolve("$component.tar")
                require(ManagedLaneRecovery.archive(file).let { it.metadataSha256 == archived.metadataSha256 &&
                    (operation == ManagedLaneOperation.IMPORT || it == archived) })
            }
            digestFile(payloadPath)
        } else "none"
        val stable = digest("${lane.kind}|$operation|$ownership|$state|$payloadHash".toByteArray())
        return ManagedLaneEvidence(intent.generation, lane.laneId, operation, intent.operationId,
            hash, ownership, stable, isolated, java.time.Instant.now().epochSecond)
    }
    override fun prepare(lane: ManagedLaneSpec, root: Path, intent: ManagedLaneIntent, intentHash: String): ManagedLaneEvidence {
        if (lane.kind == ManagedLaneKind.WORKLANE) {
            // The PREPARE intent is already durable. Podman load never pulls or builds;
            // the graphRoot belongs to the fresh target generation, not to source Kopia.
            val deadline = requireNotNull(intent.deadlineEpochMillis)
            val remaining = remaining(deadline)
            require(remaining in 1..TimeUnit.HOURS.toMillis(8))
            command(podman, listOf("load", "--input", image.archive.path), remaining)
            importedImage()
            verifySelectedGraph(root,deadline)
            ReleasePrivateFiles.directory(root.parent)
            listOf("home", "home/workspace", "home/.pi", "home/.pi/agent",
                "home/.pi/agent/sessions", "manifests", "control/data/worklane").forEach { name ->
                val state = root.parent.resolve(name)
                if (!Files.exists(state, NOFOLLOW_LINKS))
                    Files.createDirectory(state,
                        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
                require(Files.isDirectory(state, NOFOLLOW_LINKS) && state.toRealPath() == state &&
                    Files.getPosixFilePermissions(state) == PosixFilePermissions.fromString("rwx------"))
            }
            val manifest = root.parent.resolve("home/.worklane/lane.toml")
            val bytes = ReleasePrivateFiles.read(sourceManifest, 1048576)
            validateTargetManifest(bytes, lane, root)
            val homeDirectory = root.parent.resolve("home")
            require(homeDirectory.toRealPath() == homeDirectory && Files.isDirectory(homeDirectory, NOFOLLOW_LINKS))
            val manifestDirectory = homeDirectory.resolve(".worklane")
            if (!Files.exists(manifestDirectory, NOFOLLOW_LINKS))
                Files.createDirectory(manifestDirectory,
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            require(manifestDirectory.toRealPath() == manifestDirectory &&
                Files.isDirectory(manifestDirectory, NOFOLLOW_LINKS) &&
                Files.getPosixFilePermissions(manifestDirectory).none { it.name == "GROUP_WRITE" || it.name == "OTHERS_WRITE" } &&
                (Files.getAttribute(manifestDirectory, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() ==
                    com.sun.security.auth.module.UnixSystem().uid)
            java.nio.channels.FileChannel.open(manifest,
                setOf(java.nio.file.StandardOpenOption.CREATE_NEW, java.nio.file.StandardOpenOption.WRITE, NOFOLLOW_LINKS),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))).use { file ->
                val buffer = java.nio.ByteBuffer.wrap(bytes)
                while (buffer.hasRemaining()) file.write(buffer)
                file.force(true)
            }
            java.nio.channels.FileChannel.open(manifestDirectory, java.nio.file.StandardOpenOption.READ).use { it.force(true) }
            wl("import", manifest.toString())
        }
        return evidence(lane, root, intent.operation, intent, intentHash, true)
    }
    fun piWindow(lane: ManagedLaneSpec, root: Path): JsonObject {
        require(lane.kind == ManagedLaneKind.PI && lane.laneId.matches(Regex("[a-f0-9]{8}-[a-f0-9]{4}-[345][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}")))
        val owned = inspect(lane,root)
        require(owned.getValue("state").jsonPrimitive.content == "running")
        val current = wl("pi-inspect",lane.laneId)
        require(current.getValue("lane_id").jsonPrimitive.content == lane.laneId &&
            current.getValue("session").jsonPrimitive.content == lane.session &&
            current.getValue("observation_only").jsonPrimitive.boolean &&
            current.getValue("proof").jsonObject.getValue("window_id").jsonPrimitive.content.isNotBlank()) {
            "Selected Worklane owner has no actual native TUIOS Pi window" }
        return current
    }
    override fun start(lane: ManagedLaneSpec, root: Path, intent: ManagedLaneIntent, intentHash: String): ManagedLaneEvidence {
        if (lane.kind == ManagedLaneKind.WORKLANE) wl("start", lane.laneId)
        if (lane.kind == ManagedLaneKind.TUIOS) {
            val status = inspect(lane, root)
            require(status["state"]!!.jsonPrimitive.content == "running")
            // Native daemon is queried via the selected owned container, not its restored title.
            val native = json.parseToJsonElement(command(podman, listOf("exec", "--user", "dev",
                "--env", "XDG_RUNTIME_DIR=/run/user/1000",
                status["spec"]!!.jsonObject["container_name"]!!.jsonPrimitive.content,
                "tuios", "list-sessions", "--json"))).jsonObject
            require(native["success"]!!.jsonPrimitive.content == "true" &&
                native["sessions"] is kotlinx.serialization.json.JsonArray)
        }
        if (lane.kind == ManagedLaneKind.PI) {
            wl("open", lane.laneId) // Fresh target process; restored windows and tool transcripts remain inert.
            wl("pi-inspect", lane.laneId)
        }
        return evidence(lane, root, intent.operation, intent, intentHash, false)
    }
    override fun isolate(lane: ManagedLaneSpec, root: Path, intent: ManagedLaneIntent, intentHash: String): ManagedLaneEvidence {
        if (lane.kind == ManagedLaneKind.WORKLANE) wl("stop", lane.laneId)
        return evidence(lane, root, intent.operation, intent, intentHash, true)
    }
    private fun componentRoot(root: Path, name: String, source: Boolean = false): Path = root.parent.resolve(when (name) {
        "workspace" -> "home/workspace"
        "transcripts" -> "home/.pi/agent/sessions"
        "manifests" -> if (source) "control/data/worklane" else "manifests" // Historical SQLite index is nonauthority.
        else -> name
    })
    private fun components(kind: ManagedLaneKind): List<String> =
        listOf("home", "workspace", "manifests", "transcripts")
    private fun payloadRecord(root: Path, intent: ManagedLaneIntent, oracle: ManagedLaneCaptureOracle,
        archiveRoot: Path) {
        val record = root.resolve("${intent.operation.name.lowercase()}-${intent.operationId}.payload.json")
        ReleasePrivateFiles.save(record, Json.encodeToString(ManagedLanePayloadRecord(oracle, archiveRoot.toString())).toByteArray())
    }
    override fun capture(lane: ManagedLaneSpec, root: Path, destination: Path,
        intent: ManagedLaneIntent, intentHash: String): ManagedLaneEvidence {
        require(destination.isAbsolute && destination.normalize() == destination)
        val status = inspect(lane, root)
        require(status["state"]!!.jsonPrimitive.content != "running")
        ReleasePrivateFiles.directory(destination.parent)
        if (lane.kind == ManagedLaneKind.WORKLANE) {
            var remaining = requireNotNull(intent.maximumBytes) - ManagedLaneRecovery.METADATA_RESERVE_BYTES
            require(remaining >= 4096)
            require(!Files.exists(destination, NOFOLLOW_LINKS))
            Files.createDirectory(destination, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            val payloads = components(lane.kind).associateWith { component ->
                val descriptor = ManagedLaneRecovery.exportTar(componentRoot(root, component, source = true),
                    destination.resolve("$component.tar"), component, requireNotNull(intent.deadlineEpochMillis), remaining)
                remaining -= descriptor.bytes
                descriptor
            }
            val originalManifest = root.parent.resolve("home/.worklane/lane.toml")
            val originalBytes = ReleasePrivateFiles.read(originalManifest, 1048576)
            require(originalBytes.isNotEmpty())
            ReleasePrivateFiles.save(destination.resolve("source-manifest.toml"), originalBytes)
            val oracle = ManagedLaneCaptureOracle(intent.generation, lane.laneId, lane.session,
                digest(originalBytes), payloads,
                ManagedLaneRecovery.originalUncertainToolCalls(componentRoot(root, "transcripts")))
            val oracleBytes = Json.encodeToString(oracle).toByteArray()
            require(originalBytes.size.toLong() + oracleBytes.size <= ManagedLaneRecovery.METADATA_RESERVE_BYTES)
            ReleasePrivateFiles.save(destination.resolve("oracle.json"), oracleBytes)
        }
        val oracle = ManagedLaneRecovery.captureOracle(destination, intent.generation, lane.laneId, lane.session)
        payloadRecord(root, intent, oracle, destination)
        return evidence(lane, root, intent.operation, intent, intentHash, true)
    }
    override fun import(lane: ManagedLaneSpec, root: Path, projection: Path,
        intent: ManagedLaneIntent, intentHash: String): ManagedLaneEvidence {
        require(intent.sourceCaptureSha256 != null && projection.isAbsolute && projection.toRealPath() == projection &&
            Files.isDirectory(projection, NOFOLLOW_LINKS))
        val oracleBytes = ReleasePrivateFiles.read(projection.resolve("oracle.json"), 1048576)
        val oracle = Json.decodeFromString<ManagedLaneCaptureOracle>(oracleBytes.decodeToString(throwOnInvalidSequence = true))
        require(digest(oracleBytes) == intent.sourceCaptureSha256 && oracle.sourceGeneration != intent.generation &&
            oracle.sourceLaneId != lane.laneId && oracle.sourceSession != lane.session &&
            oracle.archives.keys == components(lane.kind).toSet() &&
            digest(ReleasePrivateFiles.read(projection.resolve("source-manifest.toml"), 1048576)) ==
                oracle.sourceManifestSha256) { "Target must not adopt source authority" }
        var remaining = requireNotNull(intent.maximumBytes) - ManagedLaneRecovery.METADATA_RESERVE_BYTES
        components(lane.kind).forEach { component ->
            val archive = managedLogicalImportArchive(projection, component)
            require(ManagedLaneRecovery.archive(archive) == oracle.archives.getValue(component) &&
                oracle.archives.getValue(component).bytes <= remaining)
            val readback = root.parent.resolve("worklane/${intent.operationId}-$component.readback.tar")
            if (lane.kind == ManagedLaneKind.WORKLANE)
                ManagedLaneRecovery.importTar(archive, componentRoot(root, component), readback,
                    component, requireNotNull(intent.deadlineEpochMillis), remaining)
            val observed = ManagedLaneRecovery.archive(readback)
            require(observed.metadataSha256 == oracle.archives.getValue(component).metadataSha256)
            remaining -= observed.bytes
        }
        payloadRecord(root, intent, oracle, projection)
        return evidence(lane, root, intent.operation, intent, intentHash, true)
    }
    override fun attest(lane: ManagedLaneSpec, root: Path, evidence: ManagedLaneEvidence): ManagedLaneEvidence {
        val intent = ManagedLaneIntent(evidence.generation, lane.laneId, evidence.operation,
            evidence.operationId, "", null)
        return this.evidence(lane, root, evidence.operation, intent, evidence.intentSha256, evidence.isolated)
            .copy(observedAtEpochSeconds = evidence.observedAtEpochSeconds)
    }
}

/** Read-only fixed OCI archive census; never extracts a layer or reuses the source graph. */
internal object ManagedLaneOciArchive {
    private data class Blob(val offset: Long, val size: Long)
    private val digest = Regex("sha256:[a-f0-9]{64}")
    private fun hex(bytes: ByteArray): String = "sha256:" + MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it) }
    private fun octal(bytes: ByteArray): Long {
        val text = bytes.toString(Charsets.US_ASCII).trim('\u0000', ' ')
        require(text.isNotEmpty() && text.all { it in '0'..'7' })
        return text.toLong(8)
    }
    private fun boundedObject(raf: RandomAccessFile, blob: Blob, limit: Long): ByteArray {
        require(blob.size in 1..limit && limit <= 1048576L)
        raf.seek(blob.offset)
        return ByteArray(blob.size.toInt()).also { raf.readFully(it) }
    }
    private fun selected(raf: RandomAccessFile, entries: Map<String, Blob>, digestValue: String): ByteArray {
        require(digest.matches(digestValue))
        val body = boundedObject(raf, requireNotNull(entries["blobs/sha256/${digestValue.removePrefix("sha256:")}"]), 1048576)
        require(hex(body) == digestValue) { "Changed OCI manifest or image config" }
        return body
    }
    private class Slice(private val raf: RandomAccessFile, private var left: Long) : InputStream() {
        override fun read(): Int {
            if (left == 0L) return -1
            val byte = raf.read(); require(byte >= 0); left--; return byte
        }
        override fun read(bytes: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            if (left == 0L) return -1
            val count = raf.read(bytes, off, minOf(len.toLong(), left).toInt())
            require(count > 0); left -= count; return count
        }
    }
    private class LayerReader(private val stream: InputStream, private val hash: MessageDigest,
        private val limit: Long, private val deadline: Long) {
        var bytes = 0L; private set
        private fun check(count: Int) {
            RecoveryDeadline.remainingSecondsIfBound()
            require(System.currentTimeMillis() < deadline)
            bytes = Math.addExact(bytes, count.toLong()); require(bytes <= limit)
        }
        fun readBlock(): ByteArray? {
            val block = ByteArray(512); var read = 0
            while (read < block.size) {
                check(0)
                val count = stream.read(block, read, block.size - read)
                if (read == 0 && count < 0) return null
                require(count > 0) { "Truncated OCI layer tar block" }
                check(count); hash.update(block, read, count); read += count
            }
            return block
        }
        fun contents(size: Long, capture: Int = 0): ByteArray {
            require(size >= 0 && size <= limit && capture in 0..65536 && (capture == 0 || size <= capture))
            val result = if (capture > 0) ByteArray(size.toInt()) else ByteArray(0)
            val buffer = ByteArray(65536); var consumed = 0L
            val padded = Math.multiplyExact((Math.addExact(size, 511L) / 512L), 512L)
            while (consumed < padded) {
                check(0)
                val n = stream.read(buffer, 0, minOf(buffer.size.toLong(), padded - consumed).toInt())
                require(n > 0) { "Truncated OCI layer tar payload" }
                check(n); hash.update(buffer, 0, n)
                if (capture > 0 && consumed < size) {
                    val used = minOf(n.toLong(), size - consumed).toInt()
                    buffer.copyInto(result, consumed.toInt(), 0, used)
                }
                consumed += n
            }
            return result
        }
    }
    private fun nativeNumber(bytes: ByteArray): Long {
        if (bytes.isNotEmpty() && bytes[0].toInt() and 128 != 0) {
            val copy = bytes.copyOf(); copy[0] = (copy[0].toInt() and 127).toByte()
            return java.math.BigInteger(1, copy).longValueExact().also {
                require(it in 0..RecoveryCapsule.MAX_TOTAL)
            }
        }
        return octal(bytes)
    }
    private fun tarName(bytes: ByteArray): String {
        val raw = bytes.takeWhile { it != 0.toByte() }.toByteArray().decodeToString(throwOnInvalidSequence = true)
        require(raw.length <= 4096 && raw.none { it.code < 32 || it.code == 127 })
        return raw
    }
    private fun pax(bytes: ByteArray): Map<String, String> {
        val fields = linkedMapOf<String, String>(); var cursor = 0
        while (cursor < bytes.size) {
            var delimiter = cursor
            while (delimiter < bytes.size && bytes[delimiter] != 32.toByte()) delimiter++
            require(delimiter in (cursor + 1)..(cursor + 8))
            val length = bytes.copyOfRange(cursor, delimiter).decodeToString().toInt()
            require(length in 4..65536 && cursor + length <= bytes.size)
            val item = bytes.copyOfRange(delimiter + 1, cursor + length - 1)
                .decodeToString(throwOnInvalidSequence = true)
            require(bytes[cursor + length - 1] == 10.toByte() && '=' in item)
            val key = item.substringBefore('='); val value = item.substringAfter('=')
            require(key.length in 1..128 && value.length <= 8192 &&
                !key.startsWith("GNU.sparse") && !key.startsWith("SCHILY.realsize") &&
                key !in setOf("GNU.sparse.size", "GNU.sparse.realsize") && fields.putIfAbsent(key, value) == null)
            cursor += length
        }
        return fields
    }
    private fun removeTree(tree: java.util.TreeMap<String, Long>, path: String,
        protected: Set<String> = emptySet()): Long {
        var removed = 0L
        val entries = tree.tailMap(path).entries.iterator()
        while (entries.hasNext()) {
            val item = entries.next()
            if (item.key != path && !item.key.startsWith("$path/")) break
            if (item.key !in protected) {
                removed = Math.addExact(removed, item.value); entries.remove()
            }
        }
        return removed
    }
    internal fun censusLayer(stream: InputStream, uncompressedHash: MessageDigest,
        tree: java.util.TreeMap<String, Long>, previousBytes: Long,
        blockSize: Long, limit: Long, deadline: Long): Pair<Long, Long> {
        val reader = LayerReader(stream, uncompressedHash, limit, deadline)
        var footprint = previousBytes; var localEntries = 0; var longName: String? = null
        val createdThisLayer = mutableSetOf<String>()
        var longLink: String? = null
        var pendingPax = emptyMap<String, String>(); var globalPax = emptyMap<String, String>()
        var pendingPaxBytes = 0L; var globalPaxBytes = 0L
        while (true) {
            val header = reader.readBlock() ?: break
            if (header.all { it == 0.toByte() }) {
                while (true) {
                    val tail = reader.readBlock() ?: break
                    require(tail.all { it == 0.toByte() }) { "Nonzero OCI layer tar trailer" }
                }
                break
            }
            require(++localEntries <= 1000000 && header.sliceArray(257..261).toString(Charsets.US_ASCII) == "ustar")
            val checked = header.copyOf().also { for (i in 148..155) it[i] = 32 }
            require(octal(header.sliceArray(148..155)) == checked.sumOf { it.toInt() and 255 }.toLong())
            val headerSize = nativeNumber(header.sliceArray(124..135))
            val kind = header[156].toInt().toChar()
            if (kind == 'x' || kind == 'g') {
                require(headerSize in 1..65536)
                val fields = pax(reader.contents(headerSize, 65536))
                if (kind == 'x') {
                    require(pendingPax.isEmpty()); pendingPax = fields; pendingPaxBytes = headerSize
                } else {
                    require(fields.keys.none { it in setOf("path", "size", "linkpath") })
                    globalPaxBytes = Math.addExact(globalPaxBytes, headerSize)
                    require(globalPaxBytes <= 65536)
                    globalPax = globalPax + fields
                }
                continue
            }
            if (kind == 'L' || kind == 'K') {
                require(headerSize in 1..8192 && (if (kind == 'L') longName == null else longLink == null))
                val value = reader.contents(headerSize, 8192).takeWhile { it != 0.toByte() }
                    .toByteArray().decodeToString(throwOnInvalidSequence = true).trimEnd('\n')
                if (kind == 'L') longName = value else longLink = value
                continue
            }
            require(kind in setOf('\u0000', '0', '1', '2', '5') && tree.size <= 1000000)
            val prefix = tarName(header.sliceArray(345..499))
            val shortName = tarName(header.sliceArray(0..99))
            val path = (pendingPax["path"] ?: longName ?: if (prefix.isEmpty()) shortName else "$prefix/$shortName")
                .removePrefix("./").removeSuffix("/")
            // OCI layers may include the metadata-only tar root directory as
            // `.` or `./`. It cannot write a file, resolve a link, or consume
            // payload; do not mistake that safe root marker for traversal.
            if (path in setOf("", ".") && shortName in setOf(".", "./") && kind == '5' &&
                headerSize == 0L) {
                require(pendingPax.isEmpty() && longName == null && longLink == null &&
                    tarName(header.sliceArray(157..256)).isEmpty())
                pendingPax = emptyMap(); pendingPaxBytes = 0L; longName = null; longLink = null; continue
            }
            val parts = path.split('/')
            require(path.isNotEmpty() && !path.startsWith('/') && path.length <= 4096 && parts.size in 1..64 &&
                parts.all { it.isNotEmpty() && it.toByteArray(Charsets.UTF_8).size <= 255 && it != "." && it != ".." &&
                    it.none { char -> char.code < 32 || char.code == 127 } })
            val size = pendingPax["size"]?.let { numeric ->
                require(numeric.matches(Regex("0|[1-9][0-9]{0,18}"))) { "Invalid OCI PAX size override" }
                numeric.toLong()
            } ?: headerSize
            require(size in 0..limit && (kind == '\u0000' || kind == '0' || kind == '5' || size == 0L))
            reader.contents(size)
            val name = path.substringAfterLast('/'); val folder = path.substringBeforeLast('/', "")
            val link = (pendingPax["linkpath"] ?: longLink ?: tarName(header.sliceArray(157..256)))
            if (kind == '1' || kind == '2') {
                // Image symlinks may be absolute *within the container root*
                // (e.g. Debian alternatives) or relative through `..`. Never
                // follow them on the host: normalize a virtual-root path and
                // reject every escape. Tar hardlinks remain root-relative to
                // an already observed member; an absolute hardlink is refused.
                val absolute = link.startsWith('/')
                val target = if (absolute && kind == '2') link.removePrefix("/") else link
                require(link.isNotEmpty() && link.length <= 4096 && !(kind == '1' && absolute) &&
                    target.isNotEmpty() && !target.endsWith('/') &&
                    link.none { it.code < 32 || it.code == 127 } &&
                    target.split('/').all { it.isNotEmpty() && it.toByteArray(Charsets.UTF_8).size <= 255 })
                val resolved = java.nio.file.Path.of(if (kind == '1' || absolute) target else
                    if (folder.isEmpty()) target else "$folder/$target").normalize()
                require(!resolved.isAbsolute && !resolved.startsWith("..") &&
                    resolved.toString() != "." && resolved.nameCount <= 64)
                if (kind == '1') require(tree.containsKey(resolved.toString())) {
                    "OCI hardlink target absent from census"
                }
            } else require(link.isEmpty() && pendingPax["linkpath"] == null && longLink == null) {
                "Unexpected OCI link metadata"
            }
            if (name.startsWith(".wh.")) {
                require(kind == '0' || kind == '\u0000')
                val target = if (name == ".wh..wh..opq") folder else
                    (if (folder.isEmpty()) "" else "$folder/") + name.removePrefix(".wh.")
                if (name == ".wh..wh..opq") {
                    val descendants = tree.tailMap(if (folder.isEmpty()) "" else "$folder/").entries.iterator()
                    while (descendants.hasNext()) {
                        val entry = descendants.next()
                        if (folder.isNotEmpty() && !entry.key.startsWith("$folder/")) break
                        if (entry.key !in createdThisLayer) {
                            footprint = Math.subtractExact(footprint, entry.value); descendants.remove()
                        }
                    }
                } else {
                    require(name.removePrefix(".wh.").isNotEmpty())
                    footprint = Math.subtractExact(footprint, removeTree(tree, target, createdThisLayer))
                }
            } else {
                val metadata = Math.addExact(Math.addExact(blockSize * 2, 65536L),
                    Math.addExact(globalPaxBytes, pendingPaxBytes))
                for (depth in 1 until parts.size) {
                    val parent = parts.take(depth).joinToString("/")
                    createdThisLayer += parent
                    if (tree.putIfAbsent(parent, metadata) == null)
                        footprint = Math.addExact(footprint, metadata)
                }
                if (kind != '5') footprint = Math.subtractExact(footprint, removeTree(tree, path))
                val contentBytes = when (kind) {
                    '0', '\u0000' -> Math.multiplyExact((Math.addExact(size, blockSize - 1) / blockSize), blockSize)
                    '1' -> tree.getValue(java.nio.file.Path.of(link).normalize().toString()) // Account for a native copy of the hardlink target.
                    else -> 0L
                }
                val allocated = Math.addExact(contentBytes, metadata)
                createdThisLayer += path
                val prior = tree.put(path, allocated) ?: 0L
                footprint = Math.addExact(Math.subtractExact(footprint, prior), allocated)
                require(footprint <= limit)
            }
            pendingPax = emptyMap(); pendingPaxBytes = 0L; longName = null; longLink = null
        }
        require(pendingPax.isEmpty() && longName == null && longLink == null && globalPax.size <= 128)
        return reader.bytes to footprint
    }
    fun inspect(archive: Path, bound: ManagedLaneImageBinding, deadlineEpochMillis: Long, blockSize: Long = 4096L) {
        require(blockSize in 4096L..65536L && blockSize.countOneBits() == 1 &&
            deadlineEpochMillis > System.currentTimeMillis() &&
            deadlineEpochMillis - System.currentTimeMillis() <= TimeUnit.HOURS.toMillis(8) &&
            Files.isRegularFile(archive, NOFOLLOW_LINKS) && Files.size(archive) == bound.archiveBytes &&
            bound.maximumUnpackedBytes in 1024..RecoveryCapsule.MAX_TOTAL)
        RandomAccessFile(archive.toFile(), "r").use { raf ->
            val entries = linkedMapOf<String, Blob>(); var cursor = 0L
            while (cursor < raf.length()) {
                RecoveryDeadline.remainingSecondsIfBound()
                require(System.currentTimeMillis() < deadlineEpochMillis &&
                    cursor <= bound.archiveBytes - 512 && entries.size < 1024)
                raf.seek(cursor); val header = ByteArray(512); raf.readFully(header)
                if (header.all { it == 0.toByte() }) {
                    // Exactly the end of a USTAR archive; no hidden appended payload.
                    var tail = cursor
                    while (tail < raf.length()) {
                        require(System.currentTimeMillis() < deadlineEpochMillis)
                        raf.seek(tail); val block = ByteArray(minOf(65536L, raf.length() - tail).toInt())
                        raf.readFully(block); require(block.all { it == 0.toByte() }); tail += block.size
                    }
                    break
                }
                require(header.sliceArray(257..261).toString(Charsets.US_ASCII) == "ustar" &&
                    header.sliceArray(345..499).all { it == 0.toByte() } &&
                    header.sliceArray(0..99).all { it == 0.toByte() || it.toInt() in 32..126 })
                val checked = header.copyOf().also { for (i in 148..155) it[i] = 32 }
                require(octal(header.sliceArray(148..155)) == checked.sumOf { it.toInt() and 255 }.toLong())
                val name = header.sliceArray(0..99).toString(Charsets.US_ASCII).trimEnd('\u0000')
                val normalized = name.removePrefix("./").removeSuffix("/")
                require(normalized == "index.json" || normalized == "oci-layout" ||
                    normalized == "blobs" || normalized == "blobs/sha256" ||
                    normalized.matches(Regex("blobs/sha256/[a-f0-9]{64}")))
                val length = octal(header.sliceArray(124..135))
                val next = Math.addExact(cursor, Math.addExact(512L,
                    Math.multiplyExact((Math.addExact(length, 511L) / 512L), 512L)))
                require(next <= bound.archiveBytes && length <= bound.archiveBytes)
                when (header[156].toInt().toChar()) {
                    '\u0000', '0' -> require(entries.putIfAbsent(normalized, Blob(cursor + 512, length)) == null)
                    '5' -> require(length == 0L && normalized in setOf("blobs", "blobs/sha256"))
                    else -> error("Unsafe OCI archive entry kind")
                }
                cursor = next
            }
            require(entries.keys.count { it == "index.json" } == 1 && entries.keys.count { it == "oci-layout" } == 1)
            val json = Json { ignoreUnknownKeys = false }
            val layout = json.parseToJsonElement(boundedObject(raf, entries.getValue("oci-layout"), 1024).decodeToString(throwOnInvalidSequence = true)).jsonObject
            require(layout["imageLayoutVersion"]?.jsonPrimitive?.content == "1.0.0")
            val index = json.parseToJsonElement(boundedObject(raf, entries.getValue("index.json"), 1048576).decodeToString(throwOnInvalidSequence = true)).jsonObject
            require(index["schemaVersion"]?.jsonPrimitive?.content == "2")
            val sourceDigest = bound.sourceImageReference.substringAfterLast('@')
            require(digest.matches(sourceDigest))
            if (sourceDigest != bound.expectedManifestDigest) {
                // Keep the ORIGINAL multiarch index blob under its original digest.
                // A local single-platform index.json may be repacked, but cannot
                // silently invent the chain from original ref to selected manifest.
                val originalIndex = json.parseToJsonElement(selected(raf, entries, sourceDigest)
                    .decodeToString(throwOnInvalidSequence = true)).jsonObject
                require(originalIndex["schemaVersion"]?.jsonPrimitive?.content == "2" &&
                    requireNotNull(originalIndex["manifests"]) { "Original image reference is not an OCI index" }.jsonArray.count { entry ->
                        val descriptor = entry.jsonObject
                        val platform = descriptor["platform"]?.jsonObject
                        platform?.get("os")?.jsonPrimitive?.content == "linux" &&
                            platform?.get("architecture")?.jsonPrimitive?.content == "amd64" &&
                            descriptor["digest"]?.jsonPrimitive?.content == bound.expectedManifestDigest
                    } == 1) { "Original indexed image reference does not bind selected OCI manifest" }
            }
            val possible = index.getValue("manifests").jsonArray.filter {
                val platform = it.jsonObject["platform"]?.jsonObject
                platform?.get("os")?.jsonPrimitive?.content == "linux" &&
                    platform?.get("architecture")?.jsonPrimitive?.content == "amd64"
            }
            require(possible.size == 1) { "OCI archive must select exactly one linux/amd64 image" }
            val manifestChoice = possible.single().jsonObject
            require(manifestChoice["mediaType"]?.jsonPrimitive?.content == "application/vnd.oci.image.manifest.v1+json" &&
                manifestChoice["digest"]?.jsonPrimitive?.content == bound.expectedManifestDigest)
            val manifest = json.parseToJsonElement(selected(raf, entries, bound.expectedManifestDigest)
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
            require(manifest["schemaVersion"]?.jsonPrimitive?.content == "2")
            val config = manifest.getValue("config").jsonObject
            require(config["mediaType"]?.jsonPrimitive?.content == "application/vnd.oci.image.config.v1+json" &&
                config["digest"]?.jsonPrimitive?.content == bound.expectedImageId)
            val content = json.parseToJsonElement(selected(raf, entries, bound.expectedImageId)
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
            require(content["os"]?.jsonPrimitive?.content == "linux" &&
                content["architecture"]?.jsonPrimitive?.content == "amd64" &&
                content["rootfs"]!!.jsonObject["diff_ids"]!!.jsonArray.map { it.jsonPrimitive.content } ==
                    bound.expectedLayerDiffIds)
            val layers = manifest.getValue("layers").jsonArray
            require(layers.size == bound.expectedLayerDiffIds.size && layers.size in 1..128)
            var uncompressed = 0L
            var graphBound = 0L
            var currentTreeBytes = 0L
            val tree = java.util.TreeMap<String, Long>()
            for ((layerIndex, layer) in layers.withIndex()) {
                require(System.currentTimeMillis() < deadlineEpochMillis)
                val descriptor = layer.jsonObject
                val layerDigest = descriptor["digest"]!!.jsonPrimitive.content
                require(digest.matches(layerDigest))
                val entry = requireNotNull(entries["blobs/sha256/${layerDigest.removePrefix("sha256:")}"])
                require(entry.size == descriptor["size"]!!.jsonPrimitive.content.toLong())
                val media = descriptor["mediaType"]!!.jsonPrimitive.content
                require(media in setOf("application/vnd.oci.image.layer.v1.tar+gzip",
                    "application/vnd.oci.image.layer.v1.tar"))
                raf.seek(entry.offset)
                val hash = MessageDigest.getInstance("SHA-256")
                val raw = java.security.DigestInputStream(Slice(raf, entry.size), hash)
                val unpackedHash = MessageDigest.getInstance("SHA-256")
                val contentStream: InputStream = if (media.endsWith("+gzip")) GZIPInputStream(raw, 65536) else raw
                contentStream.use { stream ->
                    val (rawBytes, treeBytes) = censusLayer(stream, unpackedHash, tree, currentTreeBytes,
                        blockSize, bound.maximumUnpackedBytes, deadlineEpochMillis)
                    uncompressed = Math.addExact(uncompressed, rawBytes)
                    require(uncompressed <= bound.maximumUnpackedBytes) {
                        "Cumulative OCI unpack scratch exceeds prewrite budget"
                    }
                    currentTreeBytes = treeBytes
                    // VFS stores an independent full tree for every ancestry layer.
                    graphBound = Math.addExact(graphBound, currentTreeBytes)
                    require(graphBound <= bound.maximumUnpackedBytes)
                    if (media.endsWith("+gzip")) {
                        val buffer = ByteArray(65536)
                        while (true) {
                            RecoveryDeadline.remainingSecondsIfBound()
                            require(System.currentTimeMillis() < deadlineEpochMillis)
                            if (raw.read(buffer) < 0) break // Include trailing bytes in compressed digest.
                        }
                    }
                }
                require("sha256:" + hash.digest().joinToString("") { "%02x".format(it) } == layerDigest &&
                    "sha256:" + unpackedHash.digest().joinToString("") { "%02x".format(it) } ==
                        bound.expectedLayerDiffIds[layerIndex]) { "Changed OCI compressed layer or rootfs diff ID" }
            }
            // Native writable container root may copy the complete last tree, plus metadata,
            // compressed graph objects and original OCI archive staging. Never infer VFS
            // capacity from compressed bytes or image-inspect Size after the write.
            val total = Math.addExact(Math.addExact(graphBound, Math.multiplyExact(currentTreeBytes, 2)),
                Math.addExact(Math.addExact(bound.archiveBytes, uncompressed), 512L * 1024 * 1024))
            require(uncompressed > 0 && total <= bound.maximumUnpackedBytes) {
                "OCI layered VFS tree/writable-root bound underadmitted BEFORE load"
            }
        }
    }
    fun verifyGraph(graph: Path, bound: Long, deadlineEpochMillis: Long? = null) {
        require(Files.isDirectory(graph, NOFOLLOW_LINKS) && graph.toRealPath() == graph &&
            bound in 1024..RecoveryCapsule.MAX_TOTAL)
        var files = 0L; var allocated = 0L
        Files.walk(graph).use { paths -> paths.forEach { path ->
            RecoveryDeadline.remainingSecondsIfBound()
            require(deadlineEpochMillis == null || System.currentTimeMillis() < deadlineEpochMillis)
            require(++files <= 4000000)
            val blocks = (Files.getAttribute(path, "unix:blocks", NOFOLLOW_LINKS) as Number).toLong()
            require(blocks >= 0)
            allocated = Math.addExact(allocated, Math.multiplyExact(blocks, 512L))
            require(allocated <= bound) { "Native VFS layer/root storage exceeded admitted immutable image bound" }
        } }
        require(files > 1)
    }
}
