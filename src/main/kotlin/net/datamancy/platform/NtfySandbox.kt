package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest

/** Exactly one explicitly selected inventory module, in dedicated rootless stores. Not a general module executor. */
internal class NtfySandbox(private val base: Path, private val backups: Path, private val commands: (Path) -> ProbeCommands) {
    companion object {
        const val IMAGE = "docker.io/binwiederhier/ntfy@sha256:8a3e2036faf218acefd3c25b16659e846df39814d2e3caae1a1ac4e737ee4f2d"
        private val BASE = ProbeLifecycle.PRODUCTION_BASE
        private val BACKUP = Path.of("/mnt/media/p0-v3/backup")
        fun real() = NtfySandbox(BASE, BACKUP, ::RootlessPodman)
    }

    private val perms = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE)
    private val id = "fixture" // never infer any other catalog service from this one
    private val container = "p0v3-sandbox-ntfy-$id"
    private val root get() = base.resolve("ntfy-$id")
    private val archive get() = backups.resolve("ntfy-$id")

    private fun checkParent(path: Path, expected: Path) {
        require(path == expected || path.toRealPath().startsWith(Path.of(System.getProperty("java.io.tmpdir")).toRealPath())) {
            "Only fixed v3 or temporary test sandbox allowed"
        }
        require(path.parent.toRealPath() == Path.of("/mnt/media/p0-v3") ||
            (path != expected && path.parent.toRealPath().startsWith(Path.of(System.getProperty("java.io.tmpdir")).toRealPath()))) {
            "Unsafe sandbox parent"
        }
        require(Files.isDirectory(path, NOFOLLOW_LINKS) && Files.getPosixFilePermissions(path) == perms &&
            Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) == com.sun.security.auth.module.UnixSystem().uid.toInt()) {
            "Sandbox root must be a private owner-owned directory"
        }
    }

    private fun owned(dir: Path, marker: String, allowed: (String) -> Boolean) {
        require(Files.isDirectory(dir, NOFOLLOW_LINKS) && Files.getPosixFilePermissions(dir) == perms &&
            Files.isRegularFile(dir.resolve(marker), NOFOLLOW_LINKS) &&
            Files.readString(dir.resolve(marker)) == "$id\n$IMAGE\n") { "Unowned namespace" }
        Files.list(dir).use { entries -> require(entries.allMatch { allowed(it.fileName.toString()) }) { "Unexpected namespace entry" } }
    }

    fun prepare() {
        checkParent(base, BASE)
        checkParent(backups, BACKUP)
        if (!Files.exists(root, NOFOLLOW_LINKS)) {
            Files.createDirectory(root)
            Files.setPosixFilePermissions(root, perms)
            Files.writeString(root.resolve(".ntfy-owner"), "$id\n$IMAGE\n", CREATE_NEW)
            Files.createDirectory(root.resolve("data"))
            Files.createDirectory(root.resolve("restores"))
        }
        if (!Files.exists(archive, NOFOLLOW_LINKS)) {
            Files.createDirectory(archive)
            Files.setPosixFilePermissions(archive, perms)
            Files.writeString(archive.resolve(".ntfy-owner"), "$id\n$IMAGE\n", CREATE_NEW)
        }
        guard()
    }

    private fun guard(): Path {
        checkParent(base, BASE)
        checkParent(backups, BACKUP)
        owned(root, ".ntfy-owner") { it in setOf(".ntfy-owner", "data", "restores", "podman-root", "podman-run") }
        owned(archive, ".ntfy-owner") { it == ".ntfy-owner" || Regex("[a-z][a-z0-9-]{0,23}").matches(it) }
        require(Files.isDirectory(root.resolve("data"), NOFOLLOW_LINKS) &&
            Files.isDirectory(root.resolve("restores"), NOFOLLOW_LINKS)) { "Missing data namespace" }
        return root
    }

    private fun podman(args: List<String>) = commands(guard()).invoke(args)
    private fun names(runningOnly: Boolean) = podman(listOf("ps") + (if (runningOnly) emptyList() else listOf("-a")) +
        listOf("--filter", "name=^$container$", "--format", "{{.Names}}"))

    private fun create(name: String, data: Path, port: Int) {
        require(podman(listOf("ps", "-a", "--filter", "name=^$name$", "--format", "{{.Names}}")).isBlank()) { "Container already exists" }
        podman(listOf("image", "exists", IMAGE))
        podman(listOf("create", "--name", name, "--pull=never", "--publish=127.0.0.1:$port:8080/tcp",
            "--read-only", "--tmpfs=/tmp:rw,nosuid,noexec,size=16m", "--cap-drop=all",
            "--security-opt=no-new-privileges", "--pids-limit=128", "--memory=256m",
            "--volume=$data:/var/cache/ntfy:rw", IMAGE, "serve", "--listen-http", ":8080", "--cache-file", "/var/cache/ntfy/cache.db"))
        podman(listOf("start", name))
        require(podman(listOf("ps", "--filter", "name=^$name$", "--format", "{{.Names}}")).trim() == name) {
            "ntfy exited immediately after start"
        }
    }

    fun install() { create(container, guard().resolve("data"), 18486) }
    fun requireRunning() { require(names(true).trim() == container) { "Primary ntfy sandbox not running" } }
    fun stop() {
        require(names(false).trim() == container) { "Primary ntfy container absent" }
        podman(listOf("stop", "--time=10", container))
    }
    fun start() {
        require(names(false).trim() == container && names(true).isBlank()) { "Primary ntfy must be stopped" }
        podman(listOf("start", container))
        require(names(true).trim() == container) { "Primary ntfy failed to restart" }
    }
    fun remove() { stop(); podman(listOf("rm", container)) }

    private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    private fun stateFiles(path: Path, withManifest: Boolean = false): List<Path> {
        require(Files.isDirectory(path, NOFOLLOW_LINKS)) { "Missing state directory" }
        val files = Files.list(path).use { it.toList() }.sortedBy { it.fileName.toString() }
        require(files.size <= 4 && files.all {
            it.fileName.toString() in (setOf("cache.db", "cache.db-shm", "cache.db-wal") +
                if (withManifest) setOf(".manifest") else emptySet()) &&
                Files.isRegularFile(it, NOFOLLOW_LINKS) && Files.size(it) <= 64L * 1024 * 1024
        } && files.any { it.fileName.toString() == "cache.db" }) { "Unexpected or missing SQLite cache state" }
        return files.filter { it.fileName.toString() != ".manifest" }
    }

    private fun manifest(files: List<Path>): String = files.joinToString("") { "${sha(Files.readAllBytes(it))} ${it.fileName}\n" }
    private fun snapshotId(value: String) { require(Regex("[a-z][a-z0-9-]{0,23}").matches(value)) { "Invalid snapshot ID" } }

    fun snapshot(value: String) {
        snapshotId(value)
        guard()
        require(names(true).isBlank()) { "Stop ntfy before snapshotting SQLite" }
        val files = stateFiles(root.resolve("data"))
        val target = archive.resolve(value)
        require(!Files.exists(target, NOFOLLOW_LINKS)) { "Backup already exists" }
        val pending = Files.createTempDirectory(archive, ".pending-")
        try {
            files.forEach { Files.copy(it, pending.resolve(it.fileName)) }
            Files.writeString(pending.resolve(".manifest"), manifest(stateFiles(pending)), CREATE_NEW)
            Files.move(pending, target, ATOMIC_MOVE)
        } finally { if (Files.exists(pending, NOFOLLOW_LINKS)) discard(pending) }
    }

    fun restore(value: String) {
        snapshotId(value)
        guard()
        val source = archive.resolve(value)
        val files = stateFiles(source, true)
        val recorded = source.resolve(".manifest")
        require(Files.isRegularFile(recorded, NOFOLLOW_LINKS) && Files.size(recorded) <= 512 &&
            Files.readString(recorded) == manifest(files)) { "Backup hash mismatch" }
        val target = root.resolve("restores").resolve(value)
        require(!Files.exists(target, NOFOLLOW_LINKS)) { "Restore target already exists" }
        val pending = Files.createTempDirectory(root.resolve("restores"), ".pending-")
        try {
            files.forEach { Files.copy(it, pending.resolve(it.fileName)) }
            require(manifest(stateFiles(pending)) == Files.readString(recorded)) { "Restored bytes mismatch" }
            Files.move(pending, target, ATOMIC_MOVE)
        } finally { if (Files.exists(pending, NOFOLLOW_LINKS)) discard(pending) }
        create("$container-restore-$value", target, 18487)
    }

    fun removeRestore(value: String) {
        snapshotId(value)
        val name = "$container-restore-$value"
        require(podman(listOf("ps", "-a", "--filter", "name=^$name$", "--format", "{{.Names}}")).trim() == name) {
            "No isolated restore container"
        }
        podman(listOf("stop", "--time=10", name))
        podman(listOf("rm", name))
    }

    private fun discard(path: Path) {
        stateFiles(path, true).forEach(Files::delete)
        Files.deleteIfExists(path.resolve(".manifest"))
        Files.delete(path)
    }
}
