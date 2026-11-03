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
    private fun allowed(name: String): Boolean = name.startsWith("controller/rss-qualification/") &&
        name.length <= 200 && name.split('/').size in 4..8 && name.split('/').all { it.matches(Regex("[a-zA-Z0-9_.-]+")) && it !in setOf(".", "..") }
    private fun directory(path: Path) {
        require(path.isAbsolute && path.normalize() == path && path.toRealPath() == path && Files.isDirectory(path, NOFOLLOW_LINKS) &&
            Files.getPosixFilePermissions(path) == directoryMode &&
            (Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == com.sun.security.auth.module.UnixSystem().uid)
    }
    fun validate(manifest: CapsuleManifest) {
        require(manifest.controllerFiles.size <= 2048 && manifest.controllerFiles.distinct().size == manifest.controllerFiles.size &&
            manifest.controllerFiles.all { allowed(it) && manifest.files.count { file -> file.name == it } == 1 }) {
            "Unknown, duplicate or missing controller recovery payload"
        }
    }
    fun capture(generationRoot: Path, payloads: MutableMap<String, Path>): List<String> {
        directory(generationRoot)
        val root = generationRoot.resolve("rss-qualification")
        if (!Files.exists(root, NOFOLLOW_LINKS)) return emptyList()
        directory(root)
        val selected = linkedMapOf<String, Path>()
        var visited = 0
        Files.walk(root).use { paths -> paths.forEach { path ->
            if (Thread.currentThread().isInterrupted) throw InterruptedException("Controller capture interrupted")
            require(++visited <= 4096 && generationRoot.relativize(path).nameCount <= 7) { "Controller tree bound exceeded" }
            if (Files.isDirectory(path, NOFOLLOW_LINKS)) directory(path)
            else {
                RecoveryCapsule.guard(path, 1048576)
                val name = "controller/" + generationRoot.relativize(path).toString()
                require(allowed(name) && selected.size < 2048 && name !in payloads)
                selected[name] = path
            }
        } }
        payloads.putAll(selected)
        return selected.keys.sorted()
    }
    /** Authenticated extraction only. Target is a fresh generation; CREATE_NEW forbids replay/overwrite. */
    fun restore(recovered: RecoveredGeneration, targetRoot: Path) {
        validate(recovered.manifest); directory(targetRoot)
        if (recovered.manifest.controllerFiles.isEmpty()) return
        require(!Files.exists(targetRoot.resolve("rss-qualification"), NOFOLLOW_LINKS)) { "Controller payload already imported; no replay" }
        val declared = recovered.manifest.files.associateBy { it.name }
        for (name in recovered.manifest.controllerFiles.sorted()) {
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
    }
}
