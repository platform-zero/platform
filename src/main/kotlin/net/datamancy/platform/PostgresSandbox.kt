package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import java.security.SecureRandom

/** Only the official postgres inventory module; no system databases, live services, or arbitrary SQL input. */
internal class PostgresSandbox(private val base: Path, private val backups: Path, private val commands: (Path) -> ProbeCommands,
    private val settle: () -> Unit = { Thread.sleep(2000) }) {
    companion object {
        const val IMAGE = "docker.io/library/postgres@sha256:2c42c21a8909d1b656ac93348db2862b6bad38091a9b0d3d1485479465802013"
        private val BASE = ProbeLifecycle.PRODUCTION_BASE
        private val BACKUP = Path.of("/mnt/media/p0-v3/backup")
        fun real() = PostgresSandbox(BASE, BACKUP, ::RootlessPodman)
    }
    private val owner = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE)
    private val ownerFile = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
    private val marker = "fixture\n$IMAGE\n"
    private val name = "p0v3-sandbox-postgres-fixture"
    private val root get() = base.resolve("postgres-fixture")
    private val archive get() = backups.resolve("postgres-fixture")
    private val secrets get() = root.resolve("secrets")
    private val password get() = secrets.resolve("fake-password")

    private fun parent(path: Path, expected: Path) {
        require(path == expected || path.toRealPath().startsWith(Path.of(System.getProperty("java.io.tmpdir")).toRealPath())) {
            "Not a v3 sandbox or temporary test root"
        }
        require(path.parent.toRealPath() == Path.of("/mnt/media/p0-v3") ||
            (path != expected && path.parent.toRealPath().startsWith(Path.of(System.getProperty("java.io.tmpdir")).toRealPath()))) {
            "Unsafe parent"
        }
        require(Files.isDirectory(path, NOFOLLOW_LINKS) && Files.getPosixFilePermissions(path) == owner &&
            Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) == com.sun.security.auth.module.UnixSystem().uid.toInt()) {
            "Root must be private and owned by invoking user"
        }
    }

    private fun scope(dir: Path, names: (String) -> Boolean) {
        val binding = dir.resolve(".postgres-owner")
        require(Files.isDirectory(dir, NOFOLLOW_LINKS) && Files.getPosixFilePermissions(dir) == owner &&
            Files.isRegularFile(binding, NOFOLLOW_LINKS) && Files.readString(binding) == marker) { "Unowned postgres namespace" }
        Files.list(dir).use { entries -> require(entries.allMatch { names(it.fileName.toString()) }) { "Unexpected postgres entry" } }
    }

    fun prepare() {
        parent(base, BASE)
        parent(backups, BACKUP)
        if (!Files.exists(root, NOFOLLOW_LINKS)) {
            Files.createDirectory(root)
            Files.setPosixFilePermissions(root, owner)
            Files.writeString(root.resolve(".postgres-owner"), marker, CREATE_NEW)
            listOf("data", "restores", "secrets").forEach {
                Files.createDirectory(root.resolve(it))
                Files.setPosixFilePermissions(root.resolve(it), owner)
            }
            val random = ByteArray(32).also(SecureRandom()::nextBytes)
            Files.writeString(password, random.joinToString("") { "%02x".format(it) }, CREATE_NEW)
            Files.setPosixFilePermissions(password, ownerFile)
            random.fill(0)
        }
        if (!Files.exists(archive, NOFOLLOW_LINKS)) {
            Files.createDirectory(archive)
            Files.setPosixFilePermissions(archive, owner)
            Files.writeString(archive.resolve(".postgres-owner"), marker, CREATE_NEW)
        }
        guard()
    }

    private fun guard(): Path {
        parent(base, BASE)
        parent(backups, BACKUP)
        scope(root) { it in setOf(".postgres-owner", "secrets", "data", "restores", "podman-root", "podman-run") }
        scope(archive) { it == ".postgres-owner" || Regex("[a-z][a-z0-9-]{0,23}").matches(it) ||
            Regex("\\.pending-[a-zA-Z0-9_-]+").matches(it) }
        require(Files.isDirectory(secrets, NOFOLLOW_LINKS) && Files.getPosixFilePermissions(secrets) == owner &&
            Files.isRegularFile(password, NOFOLLOW_LINKS) && Files.getPosixFilePermissions(password) == ownerFile &&
            Files.size(password) == 64L && Files.isDirectory(root.resolve("data"), NOFOLLOW_LINKS) &&
            Files.isDirectory(root.resolve("restores"), NOFOLLOW_LINKS)) { "Missing or unsafe fake credentials or data" }
        return root
    }

    private fun podman(args: List<String>) = commands(guard()).invoke(args)
    private fun present(container: String, runningOnly: Boolean = false): Boolean =
        podman(listOf("ps") + (if (runningOnly) emptyList() else listOf("-a")) +
            listOf("--filter", "name=^$container$", "--format", "{{.Names}}")).trim() == container

    private fun launch(container: String, data: Path, port: Int, dump: Path? = null) {
        require(!present(container)) { "Postgres container already exists" }
        podman(listOf("image", "exists", IMAGE))
        val mounts = listOf("--volume=$data:/var/lib/postgresql/data:rw",
            "--volume=$password:/run/secrets/p0v3-password:ro") +
            (if (dump == null) emptyList() else listOf("--volume=$dump:/restore/backup.dump:ro"))
        podman(listOf("create", "--name", container, "--pull=never", "--publish=127.0.0.1:$port:5432/tcp",
            "--read-only", "--tmpfs=/tmp:rw,mode=1777,size=64m", "--tmpfs=/var/run/postgresql:rw,mode=1777,size=16m",
            "--pids-limit=128", "--memory=512m", "--security-opt=no-new-privileges",
            "--env=POSTGRES_PASSWORD_FILE=/run/secrets/p0v3-password") + mounts + listOf(IMAGE))
        podman(listOf("start", container))
        require(present(container, true)) { "Postgres exited immediately" }
    }

    private fun awaitReady(container: String) {
        val check = listOf("exec", container, "psql", "-U", "postgres", "-d", "postgres", "-tA", "-c", "SELECT 1")
        repeat(40) {
            if (runCatching { podman(check).trim() == "1" }.getOrDefault(false)) {
                // Official entrypoint briefly runs a temporary server before the final postmaster.
                settle()
                if (runCatching { podman(check).trim() == "1" }.getOrDefault(false)) return
            }
            Thread.sleep(500)
        }
        error("Isolated postgres never became stably ready")
    }

    fun install() { launch(name, guard().resolve("data"), 15432); awaitReady(name) }
    fun stop() {
        require(present(name)) { "Primary postgres absent" }
        podman(listOf("stop", "--time=10", name))
    }
    fun remove() { stop(); podman(listOf("rm", name)) }

    /** Fixed, harmless SQL fixture; no arbitrary SQL or password passes through the CLI. */
    fun writeFixture() {
        require(present(name, true)) { "Primary postgres not running" }
        podman(listOf("exec", name, "psql", "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1",
            "-c", "CREATE TABLE IF NOT EXISTS p0v3_sandbox_rows (id integer PRIMARY KEY, note text NOT NULL)",
            "-c", "INSERT INTO p0v3_sandbox_rows VALUES (1, 'first') ON CONFLICT (id) DO NOTHING"))
    }

    fun query(restored: String? = null): String {
        val container = if (restored == null) name else "$name-restore-${snapshotId(restored)}"
        require(present(container, true)) { "Postgres not running" }
        return podman(listOf("exec", container, "psql", "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1",
            "-tA", "-c", "SELECT id || ':' || note FROM p0v3_sandbox_rows ORDER BY id"))
    }

    fun writeRestored(value: String) {
        val container = "$name-restore-${snapshotId(value)}"
        require(present(container, true)) { "Isolated postgres not running" }
        podman(listOf("exec", container, "psql", "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1",
            "-c", "INSERT INTO p0v3_sandbox_rows VALUES (2, 'restored') ON CONFLICT (id) DO NOTHING"))
    }

    private fun snapshotId(value: String): String {
        require(Regex("[a-z][a-z0-9-]{0,23}").matches(value)) { "Invalid snapshot ID" }
        return value
    }
    private fun sha(path: Path) = MessageDigest.getInstance("SHA-256")
        .digest(Files.readAllBytes(path)).joinToString("") { "%02x".format(it) }

    /** pg_dump -Fc uses a consistent MVCC snapshot while this tiny single database is online. */
    fun backup(value: String) {
        snapshotId(value)
        guard()
        require(present(name, true)) { "Primary postgres not running" }
        val target = archive.resolve(value)
        require(!Files.exists(target, NOFOLLOW_LINKS)) { "Backup already exists" }
        val pending = Files.createTempDirectory(archive, ".pending-")
        try {
            podman(listOf("exec", name, "pg_dump", "-U", "postgres", "-d", "postgres", "-Fc",
                "--no-owner", "--no-acl", "--file=/tmp/p0v3.dump"))
            podman(listOf("cp", "$name:/tmp/p0v3.dump", pending.resolve("backup.dump").toString()))
            val dump = pending.resolve("backup.dump")
            require(Files.isRegularFile(dump, NOFOLLOW_LINKS) && Files.size(dump) in 1..67108864) { "Invalid pg_dump" }
            Files.writeString(pending.resolve(".sha256"), "${sha(dump)}  backup.dump\n", CREATE_NEW)
            Files.move(pending, target, ATOMIC_MOVE)
        } finally { if (Files.exists(pending, NOFOLLOW_LINKS)) discardPending(pending) }
    }

    /** Start with a fresh isolated PGDATA and restore the verified dump there, never over primary PGDATA. */
    fun restore(value: String) {
        snapshotId(value)
        guard()
        val source = archive.resolve(value)
        val dump = source.resolve("backup.dump")
        val hash = source.resolve(".sha256")
        require(Files.isDirectory(source, NOFOLLOW_LINKS) && Files.isRegularFile(dump, NOFOLLOW_LINKS) &&
            Files.size(dump) in 1..67108864 && Files.isRegularFile(hash, NOFOLLOW_LINKS) &&
            Files.size(hash) <= 100 && Files.readString(hash) == "${sha(dump)}  backup.dump\n") { "Missing or modified pg_dump" }
        val target = root.resolve("restores").resolve(value)
        require(!Files.exists(target, NOFOLLOW_LINKS)) { "Restore already exists" }
        Files.createDirectory(target)
        Files.setPosixFilePermissions(target, owner)
        Files.createDirectory(target.resolve("data"))
        Files.setPosixFilePermissions(target.resolve("data"), owner)
        val restored = "$name-restore-$value"
        launch(restored, target.resolve("data"), 15433, dump)
        awaitReady(restored)
        podman(listOf("exec", restored, "pg_restore", "-U", "postgres", "-d", "postgres",
            "--exit-on-error", "--no-owner", "--no-acl", "/restore/backup.dump"))
    }

    fun removeRestore(value: String) {
        val restored = "$name-restore-${snapshotId(value)}"
        require(present(restored)) { "Isolated postgres absent" }
        podman(listOf("stop", "--time=10", restored))
        podman(listOf("rm", restored))
    }

    private fun discardPending(path: Path) {
        Files.deleteIfExists(path.resolve("backup.dump"))
        Files.deleteIfExists(path.resolve(".sha256"))
        Files.delete(path)
    }
}
