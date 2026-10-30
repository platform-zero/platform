package net.datamancy.platform

import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.StandardOpenOption.WRITE

/** Offline Quadlet staging only: never writes to Quadlet search paths or invokes Podman/systemd. */
object IsolatedStage {
    private const val MARKER = ".p0v3-site"
    private val allowed = setOf(MARKER, "current", "previous")

    private fun workspace(path: Path): Path {
        require(!Files.isSymbolicLink(path)) { "Symlink workspace rejected" }
        val real = path.toRealPath()
        val temp = Path.of(System.getProperty("java.io.tmpdir")).toRealPath()
        require(real.startsWith(temp) && real != temp && Files.isDirectory(real, NOFOLLOW_LINKS)) {
            "Staging requires an existing directory beneath the system temp directory"
        }
        return real
    }

    private fun checksum(content: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(content).joinToString("") { "%02x".format(it) }

    private fun inspect(dir: Path, siteId: String) {
        require(Files.isDirectory(dir, NOFOLLOW_LINKS)) { "Not a staged directory" }
        val files = Files.list(dir).use { it.toList() }
        val manifest = dir.resolve(".manifest")
        require(Files.isRegularFile(manifest, NOFOLLOW_LINKS) && Files.size(manifest) <= 16384) { "Missing or oversized stage manifest" }
        val containers = files.filter { it != manifest }.sortedBy { it.fileName.toString() }
        require(containers.isNotEmpty() && containers.all { file ->
            file.fileName.toString().matches(Regex("p0v3-$siteId-[a-z][a-z0-9-]{0,29}\\.container")) &&
                Files.isRegularFile(file, NOFOLLOW_LINKS) && Files.size(file) <= 16384
        }) { "Unexpected staged file" }
        val expected = containers.joinToString("") { file ->
            "${checksum(Files.readAllBytes(file))} ${file.fileName}\n"
        }
        require(Files.readString(manifest) == expected) { "Stage content changed" }
    }

    private fun check(root: Path, siteId: String) {
        require(Files.isRegularFile(root.resolve(MARKER), NOFOLLOW_LINKS) &&
            Files.readString(root.resolve(MARKER)) == "$siteId\n") { "Workspace belongs to another site" }
        Files.list(root).use { entries ->
            require(entries.allMatch { it.fileName.toString() in allowed }) { "Unexpected workspace entry" }
        }
        listOf("current", "previous").forEach { name ->
            val dir = root.resolve(name)
            if (Files.exists(dir, NOFOLLOW_LINKS)) inspect(dir, siteId)
        }
    }

    private fun <T> locked(root: Path, siteId: String, action: () -> T): T {
        require(Files.isRegularFile(root.resolve(MARKER), NOFOLLOW_LINKS)) { "Missing workspace marker" }
        FileChannel.open(root.resolve(MARKER), WRITE).use { channel ->
            channel.lock().use {
                check(root, siteId)
                return action()
            }
        }
    }

    fun stage(sites: Sites, siteId: String, path: Path) {
        sites.validate()
        val plan = RenderPlan.forSite(sites.select(siteId))
        val root = workspace(path)
        Files.list(root).use { entries ->
            if (entries.findAny().isEmpty) Files.writeString(root.resolve(MARKER), "$siteId\n", CREATE_NEW, WRITE)
        }
        locked(root, siteId) {
            require(!Files.exists(root.resolve("previous"), NOFOLLOW_LINKS)) { "Restore or discard previous stage first" }
            val pending = Files.createTempDirectory(root, ".pending-")
            try {
                plan.files.forEach { file -> Files.writeString(pending.resolve(file.name), file.content, CREATE_NEW, WRITE) }
                val manifest = plan.files.joinToString("") { file ->
                    "${checksum(file.content.toByteArray(StandardCharsets.UTF_8))} ${file.name}\n"
                }
                Files.writeString(pending.resolve(".manifest"), manifest, CREATE_NEW, WRITE)
                val current = root.resolve("current")
                val previous = root.resolve("previous")
                if (Files.exists(current, NOFOLLOW_LINKS)) Files.move(current, previous, ATOMIC_MOVE)
                try {
                    Files.move(pending, current, ATOMIC_MOVE)
                } catch (e: Exception) {
                    if (Files.exists(previous, NOFOLLOW_LINKS)) Files.move(previous, current, ATOMIC_MOVE)
                    throw e
                }
            } finally {
                if (Files.exists(pending, NOFOLLOW_LINKS)) deleteDirectory(pending)
            }
        }
    }

    fun restore(path: Path, siteId: String) {
        val root = workspace(path)
        locked(root, siteId) {
            val current = root.resolve("current")
            val previous = root.resolve("previous")
            require(Files.exists(current, NOFOLLOW_LINKS)) { "No stage to restore" }
            // A rollback of the first stage restores the initial empty workspace.
            val discard = root.resolve(".discard")
            Files.move(current, discard, ATOMIC_MOVE)
            try {
                if (Files.exists(previous, NOFOLLOW_LINKS)) Files.move(previous, current, ATOMIC_MOVE)
            } catch (e: Exception) {
                Files.move(discard, current, ATOMIC_MOVE)
                throw e
            }
            deleteDirectory(discard)
        }
    }

    private fun deleteDirectory(dir: Path) {
        require(Files.isDirectory(dir, NOFOLLOW_LINKS)) { "Not a stage directory" }
        Files.list(dir).use { entries ->
            entries.forEach { file ->
                require(Files.isRegularFile(file, NOFOLLOW_LINKS)) { "Unsafe staged file" }
                Files.delete(file)
            }
        }
        Files.delete(dir)
    }
}
