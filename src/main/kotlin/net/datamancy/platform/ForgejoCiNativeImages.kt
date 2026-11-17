package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Dedicated UID 784 rootless Podman store, never the canonical rootful store.
 * Each OCI archive load has its own sealed intent, native result and exact
 * image/layer readback; a missing result is uncertain, not permission to load
 * the same archive under a fresh operation ID. This is an internal owner, not
 * a direct-backend fallback or independently deployable CI cohort.
 */
@Serializable internal data class ForgejoCiImageLoadIntent(val generation: String,
    val bundleSha256: String, val kind: String, val archiveSha256: String,
    val imageId: String, val accountUid: Int = 784,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val priorOwnerResultSha256: String? = null)
@Serializable internal data class ForgejoCiImageLoadResult(val intentSha256: String,
    val imageId: String, val rootlessGraph: String, val nativeSize: Long,
    val layerDiffIds: List<String>)

internal object ForgejoCiNativeImages {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private fun command(plan: ForgejoCiSourcePlan, vararg args: String) = ProcessBuilder(
        listOf("/usr/bin/sudo", "-n", "-u", plan.dedicatedAccount, "--",
            plan.rootlessPodman.path) + args.toList()).apply {
        environment()["XDG_RUNTIME_DIR"] = "/run/user/784"
        environment()["HOME"] = "/home/webservices-lab-ci-runner"
    }
    private fun checkedOutput(builder: ProcessBuilder, seconds: Long = 40): String {
        val child = builder.redirectError(ProcessBuilder.Redirect.DISCARD).start()
        try {
            require(child.waitFor(seconds, TimeUnit.SECONDS) && child.exitValue() == 0) {
                "Rootless CI native observation unavailable"
            }
            val bytes = child.inputStream.readNBytes(1048577)
            require(bytes.size <= 1048576)
            return bytes.decodeToString(throwOnInvalidSequence = true)
        } finally { if (child.isAlive) child.destroyForcibly() }
    }
    private fun rootlessGraph(plan: ForgejoCiSourcePlan): String {
        val info = json.parseToJsonElement(checkedOutput(command(plan, "info", "--format", "json"))).jsonObject
        val host = info.getValue("host").jsonObject
        val store = info.getValue("store").jsonObject
        val graph = store.getValue("graphRoot").jsonPrimitive.content
        require(host.getValue("security").jsonObject.getValue("rootless").jsonPrimitive.content == "true" &&
            graph == "/home/webservices-lab-ci-runner/.local/share/containers/storage" &&
            store.getValue("graphDriverName").jsonPrimitive.content in setOf("overlay", "vfs")) {
            "Rootless worker does not own a separate bounded store"
        }
        return graph
    }
    private fun priorOwner(image: ManagedLaneImageBinding, kind: String, current: String): String {
        val base = GenerationRuntime.BASE
        val matches = Files.list(base).use { dirs -> dirs.filter { dir ->
            dir.fileName.toString().matches(Regex("q-[a-f0-9]{12}")) &&
                dir.fileName.toString() != current && Files.isDirectory(dir, NOFOLLOW_LINKS)
        }.limit(257).toList() }
        require(matches.size <= 256)
        val receipts = matches.mapNotNull { dir ->
            val ci = dir.resolve("ci")
            val intent = ci.resolve("image-$kind.intent.json")
            val result = ci.resolve("image-$kind.result.json")
            if (!Files.exists(intent, NOFOLLOW_LINKS)) null else {
                val bytes = ReleasePrivateFiles.read(intent, 8192)
                val original = json.decodeFromString<ForgejoCiImageLoadIntent>(bytes.decodeToString())
                if (original.imageId != image.expectedImageId || original.archiveSha256 != image.archive.sha256 ||
                    original.priorOwnerResultSha256 != null) null
                else {
                    require(Files.exists(result, NOFOLLOW_LINKS)) {
                        "Uncertain original CI image import cannot be legitimized by image presence"
                    }
                    val native = ReleasePrivateFiles.read(result, 8192)
                    val ack = json.decodeFromString<ForgejoCiImageLoadResult>(native.decodeToString())
                    require(original.kind == kind && original.generation == dir.fileName.toString() &&
                        ack.intentSha256 == ReleaseLocks.sha256(bytes) && ack.imageId == image.expectedImageId &&
                        ack.layerDiffIds == image.expectedLayerDiffIds &&
                        ack.rootlessGraph == "/home/webservices-lab-ci-runner/.local/share/containers/storage")
                    ReleaseLocks.sha256(native)
                }
            }
        }
        require(receipts.isNotEmpty()) { "Existing rootless image has no original native image-load ACK" }
        return receipts.sorted().first()
    }
    private fun readback(plan: ForgejoCiSourcePlan, image: ManagedLaneImageBinding): ForgejoCiImageLoadResult {
        val graph = rootlessGraph(plan)
        val response = json.parseToJsonElement(checkedOutput(command(plan, "image", "inspect",
            image.expectedImageId, "--format", "json"))).jsonArray.single().jsonObject
        val id = response.getValue("Id").jsonPrimitive.content
        val size = response.getValue("Size").jsonPrimitive.content.toLong()
        val layers = response.getValue("RootFS").jsonObject.getValue("Layers").jsonArray
            .map { it.jsonPrimitive.content }
        require(id == image.expectedImageId && layers == image.expectedLayerDiffIds &&
            size in 1..image.maximumUnpackedBytes) { "CI native image differs from authenticated OCI archive" }
        return ForgejoCiImageLoadResult("", id, graph, size, layers)
    }
    fun import(plan: ForgejoCiSourcePlan, root: Path, bundleSha256: String): Map<String, ForgejoCiImageLoadResult> {
        plan.validate(plan.generation)
        require(root == GenerationRuntime.BASE.resolve(plan.generation) &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"), 4194304)) == bundleSha256)
        val bundle = json.decodeFromString<GenerationBundle>(ReleasePrivateFiles.read(root.resolve("bundle.json"), 4194304)
            .decodeToString(throwOnInvalidSequence = true))
        require((bundle.request.forgejoCi == plan && bundle.request.recoveredForgejoCi == null &&
            bundle.recoverySourceKopia == null) ||
            (bundle.request.recoveredForgejoCiTarget == plan && bundle.request.forgejoCi == null &&
                bundle.request.ciRecoveryGrant?.targetPlan(requireNotNull(bundle.request.recoveredForgejoCi)) == plan &&
                bundle.recoverySourceKopia != null))
        SiteOwnerships.checkSealed(bundle)
        val ci = root.resolve("ci")
        ReleasePrivateFiles.directory(ci)
        val podman = Path.of(plan.rootlessPodman.path)
        require(Files.isRegularFile(podman, NOFOLLOW_LINKS) && Files.isExecutable(podman) &&
            RecoveryCapsule.fileHash(podman) == plan.rootlessPodman.sha256)
        val images = linkedMapOf("runner" to requireNotNull(plan.runnerImage),
            "job" to plan.jobArchive, "transport" to requireNotNull(plan.transportImage))
        // Inspect *both* complete archives and reserve space on the actual
        // rootless account graph filesystem, not the canonical media volume.
        val store = Files.getFileStore(Path.of("/home/webservices-lab-ci-runner"))
        val unpacked = images.values.fold(0L) { size, image ->
            Math.addExact(size, Math.addExact(image.archiveBytes, image.maximumUnpackedBytes))
        }
        require(store.usableSpace > Math.addExact(unpacked, 10L * 1024 * 1024 * 1024))
        images.values.forEach { image ->
            val archive = Path.of(image.archive.path)
            require(Files.isRegularFile(archive, NOFOLLOW_LINKS) && Files.size(archive) == image.archiveBytes)
            ManagedLaneOciArchive.inspect(archive, image, System.currentTimeMillis() + 600000L,
                store.blockSize)
        }
        rootlessGraph(plan) // Native store and account must be readable before any import intent.
        val current = json.parseToJsonElement(checkedOutput(command(plan, "image", "ls", "--all",
            "--format", "json"))).jsonArray.map { it.jsonObject.getValue("Id").jsonPrimitive.content }.toSet()
        val results = linkedMapOf<String, ForgejoCiImageLoadResult>()
        for ((kind, image) in images) {
            val reused = if (image.expectedImageId in current) priorOwner(image, kind, plan.generation) else null
            val intent = ForgejoCiImageLoadIntent(plan.generation, bundleSha256, kind,
                image.archive.sha256, image.expectedImageId, priorOwnerResultSha256 = reused)
            val target = ci.resolve("image-$kind")
            require(!Files.exists(target.resolveSibling("image-$kind.intent.json"), NOFOLLOW_LINKS) &&
                !Files.exists(target.resolveSibling("image-$kind.result.json"), NOFOLLOW_LINKS)) {
                "CI image import was already attempted; preserve original native effect"
            }
            val bytes = json.encodeToString(intent).toByteArray()
            ReleasePrivateFiles.save(ci.resolve("image-$kind.intent.json"), bytes)
            if (reused == null) {
                val child = command(plan, "load").redirectOutput(ProcessBuilder.Redirect.DISCARD)
                    .redirectError(ProcessBuilder.Redirect.DISCARD).start()
                try {
                    Files.newInputStream(Path.of(image.archive.path)).use { stream ->
                        child.outputStream.use { stdin -> stream.copyTo(stdin, 65536) }
                    }
                    require(child.waitFor(600, TimeUnit.SECONDS) && child.exitValue() == 0) {
                        "Rootless CI image load has no original ACK; never replay"
                    }
                } finally { if (child.isAlive) child.destroyForcibly() }
            }
            val observed = readback(plan, image).copy(intentSha256 = ReleaseLocks.sha256(bytes))
            ReleasePrivateFiles.save(ci.resolve("image-$kind.result.json"), json.encodeToString(observed).toByteArray())
            results[kind] = observed
        }
        return results
    }
}
