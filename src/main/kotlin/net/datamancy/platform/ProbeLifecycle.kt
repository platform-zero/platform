package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

/** One opt-in probe only. No catalog, routes, host account operations, systemd, or port bindings. */
data class ProbeSelection(val site: String, val imageId: String) {
    init {
        require(Regex("[a-z][a-z0-9-]{0,23}").matches(site)) { "Invalid probe site" }
        require(Regex("sha256:[a-f0-9]{64}").matches(imageId)) { "Probe requires an immutable local image ID" }
    }
}

internal interface ProbeCommands { fun invoke(arguments: List<String>): String }

/** All Podman state is redirected into a site-private vfs store. No registry pulls. */
internal class RootlessPodman(private val siteRoot: Path) : ProbeCommands {
    override fun invoke(arguments: List<String>): String {
        require(com.sun.security.auth.module.UnixSystem().uid != 0L) { "Rootless Podman required" }
        val command = listOf("podman", "--remote=false", "--root=${siteRoot.resolve("podman-root")}",
            "--runroot=${siteRoot.resolve("podman-run")}", "--storage-driver=vfs",
            "--events-backend=file", "--cgroup-manager=cgroupfs") + arguments
        val builder = ProcessBuilder(command).redirectErrorStream(true)
        listOf("CONTAINER_HOST", "CONTAINER_CONNECTION", "DOCKER_HOST", "PODMAN_HOST").forEach(builder.environment()::remove)
        val process = builder.start()
        if (!process.waitFor(60, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            throw IllegalStateException("Isolated Podman command timed out")
        }
        val text = process.inputStream.bufferedReader().readText().take(4096)
        check(process.exitValue() == 0) { "Isolated Podman failed: $text" }
        return text.trim()
    }
}

/** Real side effects are limited to the dedicated v3 sandbox and isolated Podman storage. */
internal class ProbeLifecycle(private val base: Path, private val commands: (Path) -> ProbeCommands) {
    companion object {
        val PRODUCTION_BASE: Path = Path.of("/mnt/media/p0-v3/platform-lifecycle-sandbox")
        fun real(): ProbeLifecycle = ProbeLifecycle(PRODUCTION_BASE, ::RootlessPodman)
    }

    private val perms = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE)
    private val allowed = setOf(".probe-owner", "data", "snapshots", "restores", "podman-root", "podman-run")
    private fun root(site: String) = base.resolve("probe-$site")
    private fun name(site: String) = "p0v3-isolated-probe-$site"

    private fun guarded(selection: ProbeSelection, initialize: Boolean = false): Path {
        require(base == PRODUCTION_BASE || base.toRealPath().startsWith(Path.of(System.getProperty("java.io.tmpdir")).toRealPath())) {
            "Only the fixed v3 sandbox or a test temp directory is allowed"
        }
        val parent = base.parent.toRealPath()
        require(parent == Path.of("/mnt/media/p0-v3") || (base != PRODUCTION_BASE &&
            parent.startsWith(Path.of(System.getProperty("java.io.tmpdir")).toRealPath()))) { "Unsafe sandbox parent" }
        require(!Files.isSymbolicLink(base) && Files.isDirectory(base, NOFOLLOW_LINKS) &&
            Files.getPosixFilePermissions(base) == perms) { "Sandbox must be an existing owner-only real directory" }
        require(Files.getAttribute(base, "unix:uid", NOFOLLOW_LINKS) == com.sun.security.auth.module.UnixSystem().uid.toInt()) {
            "Sandbox not owned by invoking user"
        }
        val dir = root(selection.site)
        if (initialize && !Files.exists(dir, NOFOLLOW_LINKS)) {
            Files.createDirectory(dir)
            Files.setPosixFilePermissions(dir, perms)
            Files.writeString(dir.resolve(".probe-owner"), "${selection.site}\n${selection.imageId}\n", CREATE_NEW)
            Files.createDirectory(dir.resolve("data"))
            Files.createDirectory(dir.resolve("snapshots"))
            Files.createDirectory(dir.resolve("restores"))
        }
        require(Files.isDirectory(dir, NOFOLLOW_LINKS) && Files.getPosixFilePermissions(dir) == perms &&
            Files.getAttribute(dir, "unix:uid", NOFOLLOW_LINKS) == com.sun.security.auth.module.UnixSystem().uid.toInt()) {
            "Missing or unowned probe directory"
        }
        val marker = dir.resolve(".probe-owner")
        require(Files.isRegularFile(marker, NOFOLLOW_LINKS) &&
            Files.readString(marker) == "${selection.site}\n${selection.imageId}\n") { "Probe image or ownership mismatch" }
        Files.list(dir).use { entries -> require(entries.allMatch { it.fileName.toString() in allowed }) { "Unexpected probe entry" } }
        listOf("data", "snapshots", "restores").forEach {
            require(Files.isDirectory(dir.resolve(it), NOFOLLOW_LINKS)) { "Missing or linked probe storage" }
        }
        return dir
    }

    /** Create the empty, private site namespace before an operator preloads its immutable image. */
    fun prepare(selection: ProbeSelection) { guarded(selection, true) }

    fun install(selection: ProbeSelection) {
        val dir = guarded(selection, true)
        val cmd = commands(dir)
        val container = name(selection.site)
        // image exists is strictly local to this isolated store; never pull by tag or digest.
        cmd.invoke(listOf("image", "exists", selection.imageId))
        require(cmd.invoke(listOf("ps", "-a", "--filter", "name=^$container$", "--format", "{{.Names}}")).isBlank()) {
            "Probe already exists; no replacement"
        }
        cmd.invoke(listOf("create", "--name", container, "--pull=never", "--network=none", "--read-only",
            "--cap-drop=all", "--security-opt=no-new-privileges", "--pids-limit=64", "--memory=128m",
            "--volume=${dir.resolve("data")}:/data:rw", selection.imageId, "/bin/sleep", "300"))
        cmd.invoke(listOf("start", container))
    }

    fun stop(selection: ProbeSelection) {
        val dir = guarded(selection)
        val cmd = commands(dir)
        require(cmd.invoke(listOf("ps", "-a", "--filter", "name=^${name(selection.site)}$", "--format", "{{.Names}}")).trim() == name(selection.site)) {
            "Probe not present"
        }
        cmd.invoke(listOf("stop", "--time=5", name(selection.site)))
    }

    fun remove(selection: ProbeSelection) {
        stop(selection)
        commands(guarded(selection)).invoke(listOf("rm", name(selection.site)))
        // Data and snapshots remain: never automatically delete a backup or a sibling site.
    }

    private fun digest(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it) }

    private fun dataFiles(dir: Path, allowManifest: Boolean = false): List<Path> {
        require(Files.isDirectory(dir, NOFOLLOW_LINKS)) { "Not a probe data directory" }
        return Files.list(dir).use { it.toList() }.sortedBy { it.fileName.toString() }.also { files ->
            require(files.size <= 32 && files.all {
                (it.fileName.toString().matches(Regex("[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}")) ||
                    (allowManifest && it.fileName.toString() == ".manifest")) &&
                    Files.isRegularFile(it, NOFOLLOW_LINKS) && Files.size(it) <= 1048576
            }) { "Only small regular probe files are supported" }
        }
    }

    /** Caller must stop the container first. Only small, flat fake-data fixtures are supported. */
    fun snapshot(selection: ProbeSelection, snapshotId: String) {
        require(Regex("[a-z][a-z0-9-]{0,23}").matches(snapshotId)) { "Invalid snapshot ID" }
        val dir = guarded(selection)
        val cmd = commands(dir)
        require(cmd.invoke(listOf("ps", "--filter", "name=^${name(selection.site)}$", "--format", "{{.Names}}")).isBlank()) {
            "Stop probe before snapshot"
        }
        val files = dataFiles(dir.resolve("data"))
        val snapshots = dir.resolve("snapshots")
        val target = snapshots.resolve(snapshotId)
        require(!Files.exists(target, NOFOLLOW_LINKS)) { "Snapshot already exists" }
        val pending = Files.createTempDirectory(snapshots, ".pending-")
        try {
            val manifest = files.joinToString("") { file ->
                val bytes = Files.readAllBytes(file)
                Files.write(pending.resolve(file.fileName), bytes, CREATE_NEW)
                "${digest(bytes)} ${file.fileName}\n"
            }
            Files.writeString(pending.resolve(".manifest"), manifest, CREATE_NEW)
            Files.move(pending, target, ATOMIC_MOVE)
        } finally {
            if (Files.exists(pending, NOFOLLOW_LINKS)) eraseFlat(pending)
        }
    }

    /** Verifies the snapshot, then copies only to a fresh isolated restore directory; never overwrites live data. */
    fun restoreIsolated(selection: ProbeSelection, snapshotId: String) {
        require(Regex("[a-z][a-z0-9-]{0,23}").matches(snapshotId)) { "Invalid snapshot ID" }
        val dir = guarded(selection)
        val source = dir.resolve("snapshots").resolve(snapshotId)
        val files = dataFiles(source, true).filter { it.fileName.toString() != ".manifest" }
        val manifest = source.resolve(".manifest")
        require(Files.isRegularFile(manifest, NOFOLLOW_LINKS) && Files.size(manifest) <= 8192 &&
            Files.readString(manifest) == files.joinToString("") { "${digest(Files.readAllBytes(it))} ${it.fileName}\n" }) {
            "Missing or corrupted snapshot manifest"
        }
        val target = dir.resolve("restores").resolve(snapshotId)
        require(!Files.exists(target, NOFOLLOW_LINKS)) { "Isolated restore already exists" }
        val pending = Files.createTempDirectory(dir.resolve("restores"), ".pending-")
        try {
            files.forEach { Files.copy(it, pending.resolve(it.fileName)) }
            Files.writeString(pending.resolve(".manifest"), Files.readString(manifest), CREATE_NEW)
            require(dataFiles(pending, true).filter { it.fileName.toString() != ".manifest" }.joinToString("") {
                "${digest(Files.readAllBytes(it))} ${it.fileName}\n"
            } == Files.readString(manifest)) { "Isolated restore failed verification" }
            Files.move(pending, target, ATOMIC_MOVE)
        } finally {
            if (Files.exists(pending, NOFOLLOW_LINKS)) eraseFlat(pending)
        }
    }

    private fun eraseFlat(dir: Path) {
        dataFiles(dir, true).forEach(Files::delete)
        Files.delete(dir)
    }
}
