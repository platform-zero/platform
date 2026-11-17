package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.security.MessageDigest
import java.util.UUID
import com.sun.security.auth.module.UnixSystem
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive

@Serializable internal data class ManagedLaneArchive(val sha256: String, val bytes: Long, val metadataSha256: String)
@Serializable internal data class ManagedLaneCaptureOracle(val sourceGeneration: String, val sourceLaneId: String,
    val sourceSession: String, val sourceManifestSha256: String, val archives: Map<String, ManagedLaneArchive>,
    val uncertainToolCalls: List<String> = emptyList())

internal data class ManagedLaneProjectionInputs(val plan: ManagedLanePlan, val targetManifestBytes: ByteArray,
    val targetStorageConfigBytes: ByteArray, val targetBrokerConfigBytes: ByteArray,
    val sourceManifestSha256: String)

@Serializable internal data class ManagedLaneSourceOracle(val sourceGeneration: String, val sourceLaneId: String,
    val captureSha256: String, val paths: Map<String, String>, val uncertainToolCalls: List<String>,
    val sourceSession: String)
@Serializable internal data class ManagedLaneProjection(val targetGeneration: String, val targetLaneId: String,
    val targetSession: String, val source: ManagedLaneSourceOracle, val paths: Map<String, String>,
    val toolReplayPermitted: Boolean = false, val sourceIdentityAdopted: Boolean = false)

/** Source history is inert data. Never import /run credentials, launch proofs, timers or captured process identities. */
internal object ManagedLaneRecovery {
    private val digest = Regex("[a-f0-9]{64}")
    private val identity = Regex("q-[a-f0-9]{12}")
    internal val allowedTop = setOf("home", "workspace", "manifests", "transcripts")
    internal const val METADATA_RESERVE_BYTES = 16L * 1024 * 1024
    // Exact generation-local live authority, never a basename or a user's ordinary dotfile.
    // Pi auth is deliberately NOT a durable transcript/home payload; immutable source
    // Worklane manifest is captured separately as nonauthority, then projected anew.
    private val livePaths = setOf("home/.pi/agent/auth.json", "home/.pi/agent/auth.json.lock",
        "home/.worklane/lane.toml", "home/run/worklane-pi/broker.sock")
    private val liveDirectories = setOf("home/.local/share/worklane/agent-work",
        "manifests/v3-pi-process")
    private fun liveAuthority(name: String): Boolean = name in livePaths ||
        liveDirectories.any { name == it || name.startsWith("$it/") }

    fun allowedPath(name: String): Boolean {
        val pieces = name.split('/')
        return pieces.size in 2..20 && pieces.first() in allowedTop && !liveAuthority(name) && pieces.all {
            it.isNotEmpty() && it != "." && it != ".." &&
                it.matches(Regex("[A-Za-z0-9_.-]{1,128}"))
        }
    }

    /** Pure feature-owned cold projection: source IDs and source rootless graph are never adopted. */
    fun projectPlan(sourcePlan: ManagedLanePlan, targetGeneration: String,
        sourceManifestBytes: ByteArray, targetImage: ManagedLaneImageBinding): ManagedLaneProjectionInputs {
        sourcePlan.validate(sourcePlan.generation)
        require(identity.matches(targetGeneration) && targetGeneration != sourcePlan.generation &&
            sourceManifestBytes.size in 1..1048576 &&
            targetImage.expectedImageId.matches(Regex("sha256:[a-f0-9]{64}")) &&
            targetImage.sourceImageReference.matches(Regex("[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}")) &&
            targetImage.expectedManifestDigest.matches(Regex("sha256:[a-f0-9]{64}")) &&
            targetImage.expectedLayerDiffIds.size in 1..128 &&
            targetImage.expectedLayerDiffIds.all { it.matches(Regex("sha256:[a-f0-9]{64}")) } &&
            targetImage.archive.sha256.matches(digest) && Path.of(targetImage.archive.path).isAbsolute &&
            Path.of(targetImage.archive.path).normalize() == Path.of(targetImage.archive.path) &&
            targetImage.archiveBytes in 1024..RecoveryCapsule.MAX_TOTAL &&
            targetImage.maximumUnpackedBytes in 1024..RecoveryCapsule.MAX_TOTAL) {
            "Externally verified local Worklane OCI archive binding required"
        }
        val source = sourcePlan.lanes.first()
        val sourceRoot = Path.of(sourcePlan.native.manifest.path).parent.parent.parent
        require(sourceRoot.fileName.toString() == sourcePlan.generation && sourceRoot.isAbsolute &&
            sourceRoot.normalize() == sourceRoot)
        val targetRoot = sourceRoot.parent.resolve(targetGeneration)
        val targetLaneId = UUID.nameUUIDFromBytes(
            "p0v3:managed-lane:$targetGeneration:${source.laneId}".toByteArray()).toString()
        val targetSession = "managed-${targetGeneration.removePrefix("q-")}"
        val lines = sourceManifestBytes.decodeToString(throwOnInvalidSequence = true)
        require('\r' !in lines)
        val allowedTopKeys = setOf("schema_version", "id", "name", "container_name", "session_name",
            "container_home", "profile_name", "created_at", "image_digest")
        val allowedProfileKeys = setOf("image", "agent", "terminal_backend", "build_context", "containerfile",
            "embedded_containerfile", "network", "runtime", "devices", "mount_codex_credentials",
            "mount_gh_credentials")
        val value = Regex("^([a-z_]+) = (true|false|[0-9]+|\\[\\]|\"[^\"\\r\\n]*\"|'[^'\\r\\n]*')$")
        val seen = mutableSetOf<String>()
        var section = ""
        val transformed = lines.lines().map { original ->
            val line = original.trim()
            if (line.isEmpty() || line.startsWith("#")) return@map original
            if (line == "[profile]") { require("profile" !in seen); section = "profile"; seen += "profile"; return@map original }
            if (line == "[[profile.mounts]]") { require("mount" !in seen); section = "mount"; seen += "mount"; return@map original }
            val match = requireNotNull(value.matchEntire(line)) { "Unsupported source lane TOML expression" }
            val key = match.groupValues[1]; val unquoted = match.groupValues[2].removeSurrounding("\"").removeSurrounding("'")
            require("$section:$key" !in seen && key in when (section) {
                "" -> allowedTopKeys; "profile" -> allowedProfileKeys; "mount" -> setOf("source", "target", "read_only")
                else -> emptySet()
            }) { "Duplicate or unsupported source lane field" }
            seen += "$section:$key"
            val replacement = when ("$section:$key") {
                ":schema_version" -> { require(unquoted == "5"); null }
                ":id" -> { require(unquoted == source.laneId); targetLaneId }
                ":session_name" -> { require(unquoted == source.session); targetSession }
                ":name" -> targetSession
                ":container_name" -> {
                    require(unquoted == "worklane-${source.session}-${source.laneId}")
                    "worklane-$targetSession-$targetLaneId"
                }
                ":container_home" -> { require(unquoted == "/home/dev"); null }
                ":image_digest" -> {
                    require(unquoted == targetImage.expectedImageId); null
                }
                "profile:image" -> {
                    val previous = sourcePlan.native.imageArchive
                    val exactSecondHop = unquoted == targetImage.expectedImageId && previous != null &&
                        previous.expectedImageId == targetImage.expectedImageId &&
                        previous.sourceImageReference == targetImage.sourceImageReference &&
                        previous.expectedManifestDigest == targetImage.expectedManifestDigest &&
                        previous.expectedLayerDiffIds == targetImage.expectedLayerDiffIds
                    require(unquoted == targetImage.sourceImageReference || exactSecondHop) {
                        "Second-hop local image ID lacks authenticated original image binding"
                    }
                    targetImage.expectedImageId
                }
                "profile:runtime" -> { require(unquoted == "systemd"); null }
                "profile:devices" -> { require(unquoted == "[]"); null }
                "profile:build_context" -> { require(unquoted == "project"); null }
                "profile:containerfile" -> { require(unquoted == "Containerfile.v3"); null }
                "profile:agent" -> { require(unquoted == "pi"); null }
                "profile:terminal_backend" -> { require(unquoted == "tuios-v3"); null }
                "profile:network" -> { require(unquoted == "none"); null }
                "profile:mount_codex_credentials", "profile:mount_gh_credentials",
                "profile:embedded_containerfile" -> { require(unquoted == "false"); null }
                "mount:source" -> {
                    require(unquoted == sourceRoot.resolve("managed/control/run/broker.sock").toString())
                    targetRoot.resolve("managed/control/run/broker.sock").toString()
                }
                "mount:target" -> { require(unquoted == "/run/worklane-pi/broker.sock"); null }
                "mount:read_only" -> { require(unquoted == "true"); null }
                else -> null
            }
            if (replacement == null) original else "$key = \"$replacement\""
        }
        require(seen.containsAll(setOf(":schema_version", ":id", ":session_name", ":container_name",
            "profile:image", "profile:agent", "profile:terminal_backend", "profile:network", "profile:runtime",
            "profile:mount_codex_credentials", "profile:mount_gh_credentials",
            "mount:source", "mount:target", "mount:read_only")))
        val targetLines = if (":image_digest" in seen) transformed else {
            val profileStart = transformed.indexOfFirst { it.trim() == "[profile]" }
            require(profileStart > 0)
            transformed.toMutableList().also { it.add(profileStart, "image_digest = \"${targetImage.expectedImageId}\"") }
        }
        val manifest = (targetLines.joinToString("\n").trimEnd('\n') + "\n").toByteArray()
        val storage = """[storage]
            driver = "vfs"
            graphroot = "${targetRoot.resolve("managed/control/podman-graph")}" 
            runroot = "${targetRoot.resolve("managed/control/podman-run")}" 
        """.trimIndent().replace(" \n", "\n").toByteArray() + byteArrayOf(10)
        val broker = Json.encodeToString(ManagedBrokerConfiguration(targetGeneration, targetLaneId,
            targetSession, source.subject, "https://auth.datamancy.net/realms/p0v3"))
            .toByteArray()
        fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }
        require(sha(sourceManifestBytes) == sourcePlan.native.manifest.sha256) {
            "Source manifest differs from immutable generation input; preserve uncertainty"
        }
        // A restored target cannot reuse source host/issuer/model secret paths.
        // This target-only authority must be provisioned independently before
        // import; its model key is never copied from source Pi authentication.
        val targetHost = sourcePlan.native.brokerHost?.let {
            val authority=targetRoot.parent.parent.resolve("release-bootstrap-anchors/managed-lanes")
                .resolve(targetGeneration).resolve("recovery-broker-host.json")
            val bytes=ReleasePrivateFiles.read(authority,65536)
            Json.decodeFromString<ManagedBrokerHostBinding>(bytes.decodeToString(throwOnInvalidSequence=true))
                .also { host -> host.validate(targetGeneration)
                    require(host.graphOwnedLatePublicTrust)
                    GenerationR9ManagedRecoveryAuthority.verify(sourcePlan,targetGeneration,host) }
        }
        val projected = sourcePlan.copy(generation = targetGeneration,
            lanes = sourcePlan.lanes.map { it.copy(laneId = targetLaneId, session = targetSession) },
            native = sourcePlan.native.copy(
                manifest = ActivationInput(targetRoot.resolve("managed/inputs/target-lane.toml").toString(), sha(manifest)),
                storageConfig = ActivationInput(targetRoot.resolve("managed/control/storage.conf").toString(), sha(storage)),
                broker = requireNotNull(sourcePlan.native.broker).copy(configuration = ActivationInput(
                    targetRoot.resolve("managed/inputs/broker.json").toString(), sha(broker))),
                imageArchive = targetImage, brokerHost = targetHost))
        projected.validate(targetGeneration)
        return ManagedLaneProjectionInputs(projected, manifest, storage, broker, sha(sourceManifestBytes))
    }

    /** Archive only a fixed component state root, preserving original metadata through strict tar inspection. */
    /** Pure, read-only captured original-state oracle. No generic path map or process proof. */
    /** Native Pi JSONL is original history, not authority to replay an unacknowledged tool. */
    fun originalUncertainToolCalls(sessions: Path): List<String> {
        require(sessions.isAbsolute && sessions.normalize() == sessions && sessions.toRealPath() == sessions &&
            Files.isDirectory(sessions, NOFOLLOW_LINKS))
        val attempted = mutableSetOf<String>()
        val acknowledged = mutableSetOf<String>()
        Files.walk(sessions).use { files -> files.forEach file@{ path ->
            if (path == sessions) return@file
            require(!Files.isSymbolicLink(path) && allowedPath("transcripts/${sessions.relativize(path)}"))
            if (Files.isDirectory(path, NOFOLLOW_LINKS)) return@file
            require(Files.isRegularFile(path, NOFOLLOW_LINKS) && Files.size(path) <= 8388608)
            if (!path.fileName.toString().endsWith(".jsonl")) return@file
            require(Files.size(path) > 0 &&
                path.fileName.toString().matches(Regex("[A-Za-z0-9_.-]{1,128}\\.jsonl")))
            Files.newBufferedReader(path).useLines { lines -> lines.forEach line@{ line ->
                require(line.length <= 1048576)
                val record = Json.parseToJsonElement(line).jsonObject
                if (record["type"]?.jsonPrimitive?.content != "message") return@line
                val message = record["message"]?.jsonObject ?: return@line
                if (message["role"]?.jsonPrimitive?.content == "assistant") {
                    message["content"]?.jsonArray?.forEach { part ->
                        val entry = part.jsonObject
                        if (entry["type"]?.jsonPrimitive?.content == "toolCall") {
                            val id = entry["id"]!!.jsonPrimitive.content
                            require(id.matches(Regex("[A-Za-z0-9_-]{1,128}")))
                            attempted += id
                        }
                    }
                } else if (message["role"]?.jsonPrimitive?.content == "toolResult") {
                    val id = message["toolCallId"]!!.jsonPrimitive.content
                    require(id.matches(Regex("[A-Za-z0-9_-]{1,128}")))
                    acknowledged += id
                }
            } }
        } }
        require(attempted.size <= 1024 && acknowledged.size <= 1024)
        return (attempted - acknowledged).sorted()
    }
    fun captureOracle(plan: ManagedLanePlan, managedRoot: Path, captureRoot: Path): ManagedLaneCaptureOracle {
        plan.validate(plan.generation)
        require(managedRoot.isAbsolute && managedRoot.fileName.toString() == "managed" &&
            managedRoot.parent.fileName.toString() == plan.generation && managedRoot.toRealPath() == managedRoot)
        val lane = plan.lanes.first()
        return captureOracle(captureRoot, plan.generation, lane.laneId, lane.session)
    }
    fun captureOracle(captureRoot: Path, generation: String, laneId: String,
        session: String): ManagedLaneCaptureOracle {
        ReleasePrivateFiles.directory(captureRoot)
        val bytes = ReleasePrivateFiles.read(captureRoot.resolve("oracle.json"), 1048576)
        val oracle = Json.decodeFromString<ManagedLaneCaptureOracle>(bytes.decodeToString(throwOnInvalidSequence = true))
        require(oracle.sourceGeneration == generation && oracle.sourceLaneId == laneId &&
            oracle.sourceSession == session && digest.matches(oracle.sourceManifestSha256) &&
            MessageDigest.getInstance("SHA-256").digest(ReleasePrivateFiles.read(
                captureRoot.resolve("source-manifest.toml"), 1048576)).joinToString("") { "%02x".format(it) } ==
                oracle.sourceManifestSha256 &&
            oracle.archives.keys == allowedTop && oracle.archives.all { (component, descriptor) ->
                descriptor == archive(captureRoot.resolve("$component.tar"))
            }) { "Managed original-state oracle or archives changed" }
        return oracle
    }
    fun archive(path: Path): ManagedLaneArchive {
        val owner = UnixSystem().uid.toInt()
        val entries = VolumeTar.inspect(path, owner)
        val metadata = kotlinx.serialization.json.Json.encodeToString(
            kotlinx.serialization.builtins.ListSerializer(VolumeTarEntry.serializer()), entries)
        val hash = MessageDigest.getInstance("SHA-256")
        Files.newInputStream(path, NOFOLLOW_LINKS).use { input ->
            val buffer = ByteArray(65536)
            while (true) {
                RecoveryDeadline.remainingSecondsIfBound()
                val size = input.read(buffer); if (size < 0) break; hash.update(buffer, 0, size)
            }
        }
        fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }
        return ManagedLaneArchive(hex(hash.digest()), Files.size(path),
            hex(MessageDigest.getInstance("SHA-256").digest(metadata.toByteArray())))
    }
    private fun remainingMillis(deadlineEpochMillis: Long): Long = minOf(
        deadlineEpochMillis - System.currentTimeMillis(),
        RecoveryDeadline.remainingSecondsIfBound()?.let { TimeUnit.SECONDS.toMillis(it) } ?: Long.MAX_VALUE)
    fun exportTar(source: Path, output: Path, component: String, deadlineEpochMillis: Long,
        maximumBytes: Long): ManagedLaneArchive {
        require(maximumBytes in 1024..RecoveryCapsule.MAX_TOTAL &&
            deadlineEpochMillis > System.currentTimeMillis() && component in allowedTop && source.isAbsolute && source.normalize() == source &&
            source.toRealPath() == source && Files.isDirectory(source, NOFOLLOW_LINKS) &&
            output.isAbsolute && output.normalize() == output && !Files.exists(output, NOFOLLOW_LINKS))
        Files.walk(source).use { stream -> stream.forEach { path ->
            require(remainingMillis(deadlineEpochMillis) > 0) { "Managed capture deadline exhausted" }
            if (path == source) return@forEach
            val relative = source.relativize(path).toString()
            if (component == "home" && (relative == "workspace" || relative.startsWith("workspace/") ||
                    relative == ".pi/agent/sessions" || relative.startsWith(".pi/agent/sessions/"))) return@forEach
            if (liveAuthority("$component/$relative")) return@forEach
            require(allowedPath("$component/$relative") &&
                (Files.isRegularFile(path, NOFOLLOW_LINKS) || Files.isDirectory(path, NOFOLLOW_LINKS) ||
                    Files.isSymbolicLink(path))) { "Unsafe managed capture entry" }
            if (Files.isSymbolicLink(path)) {
                val link = Files.readSymbolicLink(path)
                require(!link.isAbsolute && !link.toString().contains("..") &&
                    path.parent.resolve(link).normalize().startsWith(source)) { "Symlink escapes managed state" }
            }
            if (Files.isRegularFile(path, NOFOLLOW_LINKS)) require(Files.size(path) <= 1L shl 30)
        } }
        ReleasePrivateFiles.directory(output.parent)
        Files.createFile(output, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        val exclusions = when (component) {
            "home" -> listOf("--anchored",
                "--exclude=./.pi/agent/auth.json", "--exclude=./.pi/agent/auth.json.lock",
                "--exclude=./.worklane/lane.toml", "--exclude=./run/worklane-pi/broker.sock",
                "--exclude=./.local/share/worklane/agent-work",
                "--exclude=./workspace", "--exclude=./.pi/agent/sessions")
            "manifests" -> listOf("--anchored", "--exclude=./v3-pi-process")
            else -> emptyList()
        }
        val wait = remainingMillis(deadlineEpochMillis)
        require(wait in 1..TimeUnit.HOURS.toMillis(8))
        val process = ProcessBuilder(listOf("/usr/bin/prlimit", "--fsize=$maximumBytes:$maximumBytes", "--",
            "/usr/bin/tar", "--create", "--format=pax", "--pax-option=delete=atime,delete=ctime", "--acls",
            "--xattrs", "--xattrs-include=user.*", "--file=$output", "--directory=$source") + exclusions + listOf(".")).apply {
            environment().clear(); environment()["PATH"] = "/usr/bin:/bin"; environment()["LANG"] = "C.UTF-8"
            redirectError(ProcessBuilder.Redirect.DISCARD); redirectOutput(ProcessBuilder.Redirect.DISCARD)
        }.start()
        try { require(process.waitFor(wait, TimeUnit.MILLISECONDS) &&
            process.exitValue() == 0) { "Native managed export failed or deadline exhausted" } }
        finally { if (process.isAlive) process.destroyForcibly() }
        require(Files.size(output) in 1024..maximumBytes)
        return archive(output)
    }

    /** Import only into a fresh target directory; independently compare complete metadata/content descriptors. */
    fun importTar(sourceArchive: Path, target: Path, readbackArchive: Path, component: String,
        deadlineEpochMillis: Long, maximumReadbackBytes: Long) {
        require(deadlineEpochMillis > System.currentTimeMillis() && component in allowedTop && sourceArchive.isAbsolute && sourceArchive.toRealPath() == sourceArchive &&
            target.isAbsolute && target.normalize() == target && target.parent.toRealPath() == target.parent &&
            readbackArchive.isAbsolute &&
            readbackArchive.parent.toRealPath() == readbackArchive.parent && !Files.exists(readbackArchive, NOFOLLOW_LINKS))
        val owner = UnixSystem().uid.toInt()
        val entries = VolumeTar.inspect(sourceArchive, owner)
        require(entries.isNotEmpty() && entries.all { entry ->
            entry.uid == owner && entry.gid == owner &&
                (entry.path == "." || allowedPath("$component/${entry.path}"))
        }) { "Unmapped owner or unsafe lane payload" }
        if (!Files.exists(target, NOFOLLOW_LINKS))
            Files.createDirectory(target, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        else {
            require(component == "home" && target.toRealPath() == target && Files.isDirectory(target, NOFOLLOW_LINKS))
            Files.walk(target).use { existing -> existing.forEach { file ->
                val name = target.relativize(file).toString()
                require(name in setOf("", ".worklane", ".worklane/lane.toml")) { "Target home not pristine" }
            } }
        }
        val wait = remainingMillis(deadlineEpochMillis)
        require(wait in 1..TimeUnit.HOURS.toMillis(8))
        val process = ProcessBuilder("/usr/bin/tar", "--extract", "--no-same-owner", "--same-permissions",
            "--acls", "--xattrs", "--xattrs-include=user.*", "--file=$sourceArchive", "--directory=$target").apply {
            environment().clear(); environment()["PATH"] = "/usr/bin:/bin"; environment()["LANG"] = "C.UTF-8"
            redirectError(ProcessBuilder.Redirect.DISCARD); redirectOutput(ProcessBuilder.Redirect.DISCARD)
        }.start()
        try { require(process.waitFor(wait, TimeUnit.MILLISECONDS) &&
            process.exitValue() == 0) { "Native managed import uncertain or deadline exhausted" } }
        finally { if (process.isAlive) process.destroyForcibly() }
        exportTar(target, readbackArchive, component, deadlineEpochMillis, maximumReadbackBytes)
        ColdVolumeImport.verifyImported(sourceArchive, readbackArchive, owner)
    }

    fun project(source: ManagedLaneSourceOracle, targetGeneration: String, targetLaneId: String,
        targetSession: String): ManagedLaneProjection {
        require(identity.matches(source.sourceGeneration) && identity.matches(targetGeneration) &&
            source.sourceGeneration != targetGeneration && source.sourceLaneId != targetLaneId &&
            source.sourceSession != targetSession && UUID.fromString(source.sourceLaneId).toString() == source.sourceLaneId &&
            UUID.fromString(targetLaneId).toString() == targetLaneId && digest.matches(source.captureSha256) &&
            source.paths.isNotEmpty() && source.paths.size <= 100000 &&
            source.paths.all { (path, value) -> allowedPath(path) && digest.matches(value) } &&
            source.uncertainToolCalls.distinct().size == source.uncertainToolCalls.size &&
            source.uncertainToolCalls.all { it.matches(Regex("[a-zA-Z0-9:_-]{1,128}")) }) {
            "Unsafe, foreign or self-targeting managed recovery projection"
        }
        return ManagedLaneProjection(targetGeneration, targetLaneId, targetSession, source, source.paths.toSortedMap())
    }

    /** Read back the original captured bytes; no recreated fixtures, simulated completion or source process proof. */
    fun verifyOriginal(projection: ManagedLaneProjection, restoredRoot: Path) {
        require(!projection.toolReplayPermitted && !projection.sourceIdentityAdopted &&
            restoredRoot.isAbsolute && restoredRoot.normalize() == restoredRoot &&
            Files.isDirectory(restoredRoot, NOFOLLOW_LINKS) && restoredRoot.toRealPath() == restoredRoot)
        val expected = projection.source.paths
        require(projection.paths == expected.toSortedMap())
        Files.walk(restoredRoot).use { paths ->
            val observed = mutableMapOf<String, String>()
            paths.forEach { file ->
                if (file == restoredRoot) return@forEach
                require(!Files.isSymbolicLink(file)) { "Captured managed state must not follow symlinks" }
                val relative = restoredRoot.relativize(file).toString()
                if (Files.isDirectory(file, NOFOLLOW_LINKS)) return@forEach
                require(allowedPath(relative) && Files.isRegularFile(file, NOFOLLOW_LINKS) &&
                    Files.size(file) <= 1L shl 30 && relative in expected) { "Unexpected or unsafe restored managed file" }
                val hash = MessageDigest.getInstance("SHA-256")
                Files.newInputStream(file, NOFOLLOW_LINKS).use { input ->
                    val buffer = ByteArray(65536)
                    while (true) { val count = input.read(buffer); if (count < 0) break; hash.update(buffer, 0, count) }
                }
                observed[relative] = hash.digest().joinToString("") { "%02x".format(it) }
            }
            require(observed == expected) { "Original managed data differs from source capture" }
        }
    }
}
