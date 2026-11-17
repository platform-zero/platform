package net.datamancy.platform

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions

/** Explicit non-authority controller data. Never snapshots timers, activation permits, live locks or auth sockets. */
internal object RecoveryControllerPayloads {
    private val mode = PosixFilePermissions.fromString("rw-------")
    private val directoryMode = PosixFilePermissions.fromString("rwx------")
    private fun allowed(name: String): Boolean {
        val parts = name.split('/')
        if (name.length > 200 || parts.size !in 4..5 || parts.take(2) != listOf("controller", "rss-qualification") ||
            parts[2].length !in 1..128 ||
            parts.any { !it.matches(Regex("[a-zA-Z0-9_.-]+")) || it in setOf(".", "..") }) return false
        return when (parts.size) {
            4 -> parts.last() in setOf("feed-items.json", "synthetic-observation.json", "fixture-ca.pem", "mastodon-ca.pem",
                "native-fixture-binding.json", "native-fixture-state.json", "native-accepted.json",
                "native-receipt.json", "native-remote-evidence.json", "native-pending.json")
            5 -> parts[3] in setOf("state", "synthetic-state") &&
                parts.last() in setOf("rss-state.json", "rss-state.previous", "rss-state.lock")
            else -> false
        }
    }
    private fun directory(path: Path) {
        require(path.isAbsolute && path.normalize() == path && path.toRealPath() == path && Files.isDirectory(path, NOFOLLOW_LINKS) &&
            Files.getPosixFilePermissions(path) == directoryMode &&
            (Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == com.sun.security.auth.module.UnixSystem().uid)
    }
    fun validate(manifest: CapsuleManifest) {
        require(manifest.controllerFiles.size <= 2048 && manifest.controllerFiles.distinct().size == manifest.controllerFiles.size &&
            manifest.files.filter { it.name.startsWith("controller/") }.map { it.name }.toSet() == manifest.controllerFiles.toSet() &&
            manifest.controllerFiles.all { manifest.files.count { file -> file.name == it } == 1 } &&
            manifest.controllerFiles.filterNot { it.startsWith("controller/rss/") ||
                it in setOf("controller/ci-original/cold-custody.json",
                    "controller/ci-original/original-job.result.json", "controller/ci-original/original-job-run.json",
                    "controller/ci-original/original-job-job.json") }.all { allowed(it) || RecoveryActorCustody.allowed(it) } &&
            manifest.controllerFiles.count { it == "controller/ci-original/cold-custody.json" } <= 1 &&
            listOf("original-job.result.json", "original-job-run.json", "original-job-job.json").all { file ->
                manifest.controllerFiles.count { it == "controller/ci-original/$file" } <= 1 } &&
            manifest.controllerFiles.intersect(setOf("controller/ci-original/original-job.result.json",
                "controller/ci-original/original-job-run.json", "controller/ci-original/original-job-job.json")).let { jobs ->
                jobs.isEmpty() || jobs.size == 3 &&
                    "controller/ci-original/cold-custody.json" in manifest.controllerFiles }) {
            "Unknown, duplicate or missing controller recovery payload"
        }
        RssControllerPayloads.validate(manifest)
        RecoveryActorCustody.validate(manifest)
    }
    fun capture(generationRoot: Path, payloads: MutableMap<String, Path>): List<String> {
        directory(generationRoot)
        val root = generationRoot.resolve("rss-qualification")
        val selected = linkedMapOf<String, Path>()
        if (Files.exists(root, NOFOLLOW_LINKS)) {
        directory(root)
        var visited = 0
        Files.walk(root).use { paths -> paths.forEach { path ->
            if (Thread.currentThread().isInterrupted) throw InterruptedException("Controller capture interrupted")
            require(++visited <= 4096 && generationRoot.relativize(path).nameCount <= 7) { "Controller tree bound exceeded" }
            if (Files.isDirectory(path, NOFOLLOW_LINKS)) directory(path)
            else if (path.fileName.toString() == "rss-state.lock") {
                // Only the fixed RssStateStore local lock is excluded; unknown lock-like files
                // are not a wildcard for smuggling unchecked state through the capture walk.
                require(path.parent.fileName.toString() in setOf("state", "synthetic-state"))
                RecoveryCapsule.guard(path, 1048576)
            } else {
                RecoveryCapsule.guard(path, 1048576)
                val name = "controller/" + generationRoot.relativize(path).toString()
                require(allowed(name) && selected.size < 2048 && name !in payloads)
                selected[name] = path
            }
        } }
        }
        payloads.putAll(selected)
        val source = generationRoot.resolve("bundle.json")
        val sealed = kotlinx.serialization.json.Json.decodeFromString<GenerationBundle>(
            ReleasePrivateFiles.read(source, 4194304).decodeToString(throwOnInvalidSequence = true))
        if (sealed.request.forgejoCi != null || sealed.request.recoveredForgejoCiTarget != null) {
            val custody = generationRoot.resolve("ci/cold-custody.json")
            RecoveryCapsule.guard(custody, 1048576)
            val original = kotlinx.serialization.json.Json.decodeFromString<ForgejoCiOriginalCustody>(
                ReleasePrivateFiles.read(custody, 1048576).decodeToString(throwOnInvalidSequence = true))
            require(original.sourceGeneration == sealed.request.id &&
                original.sourceBundleSha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(source, 4194304)) &&
                original.stopResultSha256.keys == setOf("runner", "guard", "transport", "egress", "internal") &&
                original.jobStateSha256.size <= 128 &&
                original.jobStateSha256.keys.containsAll(setOf("create.intent.json", "create.result.json",
                    "start.intent.json", "start.result.json")) &&
                original.jobStateSha256.keys.any { it in setOf("wait.result.json", "stop.result.json") } &&
                original.jobStateSha256.keys.any { it.startsWith("exec-start-") && it.endsWith(".result.json") }) {
                "Original rootless CI job has no complete create/start/terminal/step custody"
            }
            selected["controller/ci-original/cold-custody.json"] = custody
            payloads["controller/ci-original/cold-custody.json"] = custody
            if (sealed.request.forgejoCi != null) {
                ForgejoCiOriginalJob.verifyForCapture(sealed, generationRoot, original)
                for (file in listOf("original-job.result.json", "original-job-run.json", "original-job-job.json")) {
                    val job = generationRoot.resolve("ci/$file")
                    RecoveryCapsule.guard(job, 8192)
                    selected["controller/ci-original/$file"] = job
                    payloads["controller/ci-original/$file"] = job
                }
            }
        }
        val actors = RecoveryActorCustody.capture(generationRoot, payloads)
        val rss = RssControllerPayloads.capture(generationRoot, payloads)
        require((rss + actors).none { it in selected } && rss.size + actors.size + selected.size <= 2048 &&
            (rss + actors).all { it in payloads })
        return (selected.keys + actors + rss).sorted()
    }
    /** Authenticated extraction only. Target is a fresh generation; CREATE_NEW forbids replay/overwrite. */
    fun restore(recovered: RecoveredGeneration, targetRoot: Path) {
        validate(recovered.manifest); directory(targetRoot)
        if (recovered.manifest.controllerFiles.isEmpty()) return
        val qualificationFiles = recovered.manifest.controllerFiles.filter { allowed(it) || RecoveryActorCustody.allowed(it) ||
            it in setOf("controller/ci-original/original-job.result.json",
                "controller/ci-original/original-job-run.json", "controller/ci-original/original-job-job.json") }
            .filterNot { it.endsWith(".lock") }
        require(qualificationFiles.none { it.startsWith("controller/rss-qualification/") } ||
            !Files.exists(targetRoot.resolve("rss-qualification"), NOFOLLOW_LINKS)) { "Controller payload already imported; no replay" }
        require(qualificationFiles.none { RecoveryActorCustody.allowed(it) } ||
            !Files.exists(targetRoot.resolve("qualification-actors"), NOFOLLOW_LINKS)) { "Original actor grants already imported; no replay" }
        val declared = recovered.manifest.files.associateBy { it.name }
        for (name in qualificationFiles.sorted()) {
            if (Thread.currentThread().isInterrupted) throw InterruptedException("Controller import interrupted")
            val source = recovered.root.resolve(name)
            val expected = declared.getValue(name)
            RecoveryCapsule.guard(source, 1048576)
            require(Files.size(source) == expected.bytes && RecoveryCapsule.fileHash(source) == expected.sha256)
            val destination = targetRoot.resolve(name.removePrefix("controller/"))
            var parent = targetRoot
            for (component in name.removePrefix("controller/").split('/').dropLast(1)) {
                parent = parent.resolve(component)
                if (!Files.exists(parent, NOFOLLOW_LINKS)) {
                    Files.createDirectory(parent, PosixFilePermissions.asFileAttribute(directoryMode))
                    FileChannel.open(parent.parent, READ).use { it.force(true) }
                }
                directory(parent)
            }
            val data = Files.readAllBytes(source)
            require(data.size.toLong() == expected.bytes && ReleaseLocks.sha256(data) == expected.sha256)
            FileChannel.open(destination, setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS), PosixFilePermissions.asFileAttribute(mode)).use { output ->
                val bytes = ByteBuffer.wrap(data); while (bytes.hasRemaining()) output.write(bytes); output.force(true)
            }
            FileChannel.open(destination.parent, READ).use { it.force(true) }
        }
        // Recreate target-local lock descriptors only after all authenticated state bytes were
        // imported. Old lock payloads are validated for historical capsules but never copied.
        qualificationFiles.filter { it.endsWith("/rss-state.json") }.forEach { name ->
            val parent = targetRoot.resolve(name.removePrefix("controller/")).parent
            directory(parent)
            val lock = parent.resolve("rss-state.lock")
            FileChannel.open(lock, setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS), PosixFilePermissions.asFileAttribute(mode)).use { output ->
                val bytes = ByteBuffer.wrap("rss-state-lock-v1\n".toByteArray())
                while (bytes.hasRemaining()) output.write(bytes)
                output.force(true)
            }
            FileChannel.open(parent, READ).use { it.force(true) }
        }
        RssControllerPayloads.restore(recovered, targetRoot)
        if (qualificationFiles.any { RecoveryActorCustody.allowed(it) }) {
            val sourceBundle = recovered.manifest.bundleSha256
            RecoveryActorCustody.verify(targetRoot, recovered.manifest.generation, sourceBundle)
        }
    }
}
