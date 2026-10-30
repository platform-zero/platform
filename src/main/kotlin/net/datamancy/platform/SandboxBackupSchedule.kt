package net.datamancy.platform

import java.net.HttpURLConnection
import java.net.Proxy
import java.net.URI
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import java.time.Instant

/** Deliberately only the two already reviewed sandbox modules. No systemd timer or background daemon. */
internal data class NtfyBackupOps(
    val prepare: () -> Unit, val requireRunning: () -> Unit, val stop: () -> Unit,
    val snapshot: (String) -> Unit, val start: () -> Unit,
    val restore: (String) -> Unit, val removeRestore: (String) -> Unit
)
internal data class PostgresBackupOps(
    val prepare: () -> Unit, val writeFixture: () -> Unit, val query: (String?) -> String,
    val backup: (String) -> Unit, val restore: (String) -> Unit,
    val writeRestored: (String) -> Unit, val removeRestore: (String) -> Unit
)
internal interface TopicCheck {
    fun publishAndRead(port: Int, topic: String, message: String)
    fun assertCached(port: Int, topic: String, message: String)
}

internal class LoopbackTopicCheck(private val request: (Int, String, String?) -> String = ::realRequest) : TopicCheck {
    companion object {
    private fun realRequest(port: Int, path: String, message: String?): String {
        require(port == 18486 || port == 18487) { "Only fixed loopback ports permitted" }
        val connection = URI("http://127.0.0.1:$port/$path").toURL().openConnection(Proxy.NO_PROXY) as HttpURLConnection
        connection.connectTimeout = 1000
        connection.readTimeout = 3000
        if (message != null) {
            connection.requestMethod = "POST"
            connection.doOutput = true
            connection.outputStream.use { it.write(message.toByteArray()) }
        }
        try {
            check(connection.responseCode == 200) { "ntfy functional request failed" }
            return connection.inputStream.bufferedReader().use { it.readText() }
        } finally { connection.disconnect() }
    }
    }

    private fun awaitHealth(port: Int) {
        require(port == 18486 || port == 18487) { "Only fixed loopback ports permitted" }
        var ready = false
        repeat(20) {
            if (!ready) {
                ready = runCatching { request(port, "v1/health", null).contains("\"healthy\":true") }.getOrDefault(false)
                if (!ready) Thread.sleep(500)
            }
        }
        check(ready) { "ntfy not healthy on loopback" }
    }

    override fun publishAndRead(port: Int, topic: String, message: String) {
        require(Regex("p0v3-schedule-h[a-z0-9]{1,15}").matches(topic) &&
            Regex("(before|after)-h[a-z0-9]{1,15}").matches(message)) { "Unsafe functional probe" }
        awaitHealth(port)
        check(request(port, topic, message).contains("\"message\":\"$message\"")) { "ntfy publish failed" }
        assertCached(port, topic, message)
    }

    override fun assertCached(port: Int, topic: String, message: String) {
        require(Regex("p0v3-schedule-h[a-z0-9]{1,15}").matches(topic) &&
            Regex("(before|after)-h[a-z0-9]{1,15}").matches(message)) { "Unsafe cached probe" }
        awaitHealth(port)
        check(request(port, "$topic/json?poll=1", null).contains("\"message\":\"$message\"")) { "ntfy cached read failed" }
    }
}

/** A bounded synchronous scheduler: one due UTC slot per call, at most two calls per opt-in loop. */
internal class SandboxBackupSchedule(
    private val backupBase: Path, private val ntfy: NtfyBackupOps, private val postgres: PostgresBackupOps,
    private val topic: TopicCheck, private val clock: () -> Instant = Instant::now,
    private val periodSeconds: Long = 3600, private val pause: (Long) -> Unit = Thread::sleep
) {
    companion object {
        private val BACKUP = Path.of("/mnt/media/p0-v3/backup")
        fun real(periodSeconds: Long = 3600): SandboxBackupSchedule {
            val n = NtfySandbox.real()
            val p = PostgresSandbox.real()
            return SandboxBackupSchedule(BACKUP,
                NtfyBackupOps(n::prepare, n::requireRunning, n::stop, n::snapshot, n::start, n::restore, n::removeRestore),
                PostgresBackupOps(p::prepare, p::writeFixture, p::query, p::backup, p::restore, p::writeRestored, p::removeRestore),
                LoopbackTopicCheck(), periodSeconds = periodSeconds)
        }
    }

    init { require(periodSeconds in 2..3600) { "Schedule interval must be bounded" } }
    private val perms = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE)
    private val filePerms = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
    private val schedule get() = backupBase.resolve("sandbox-schedule")
    private fun sha(path: Path) = MessageDigest.getInstance("SHA-256")
        .digest(Files.readAllBytes(path)).joinToString("") { "%02x".format(it) }

    private fun checkRoot() {
        require(backupBase == BACKUP || backupBase.toRealPath().startsWith(Path.of(System.getProperty("java.io.tmpdir")).toRealPath())) {
            "Only the dedicated backup root or test temp root allowed"
        }
        require(backupBase.parent.toRealPath() == Path.of("/mnt/media/p0-v3") ||
            (backupBase != BACKUP && backupBase.parent.toRealPath().startsWith(Path.of(System.getProperty("java.io.tmpdir")).toRealPath()))) {
            "Unsafe backup parent"
        }
        require(Files.isDirectory(backupBase, NOFOLLOW_LINKS) && Files.getPosixFilePermissions(backupBase) == perms &&
            Files.getAttribute(backupBase, "unix:uid", NOFOLLOW_LINKS) == com.sun.security.auth.module.UnixSystem().uid.toInt()) {
            "Unowned backup root"
        }
        if (!Files.exists(schedule, NOFOLLOW_LINKS)) {
            Files.createDirectory(schedule)
            Files.setPosixFilePermissions(schedule, perms)
            Files.writeString(schedule.resolve(".owner"), "p0v3-two-sandbox-backup-v1\n", CREATE_NEW)
            Files.setPosixFilePermissions(schedule.resolve(".owner"), filePerms)
        }
        require(Files.isDirectory(schedule, NOFOLLOW_LINKS) && Files.getPosixFilePermissions(schedule) == perms &&
            Files.isRegularFile(schedule.resolve(".owner"), NOFOLLOW_LINKS) &&
            Files.getPosixFilePermissions(schedule.resolve(".owner")) == filePerms &&
            Files.readString(schedule.resolve(".owner")) == "p0v3-two-sandbox-backup-v1\n") { "Unowned schedule" }
    }

    private fun verifyBackup(id: String): String {
        val cache = backupBase.resolve("ntfy-fixture/$id/cache.db")
        val ntfyManifest = cache.parent.resolve(".manifest")
        val dump = backupBase.resolve("postgres-fixture/$id/backup.dump")
        val pgManifest = dump.parent.resolve(".sha256")
        require(Files.isDirectory(cache.parent, NOFOLLOW_LINKS) && Files.isDirectory(dump.parent, NOFOLLOW_LINKS) &&
            listOf(cache, ntfyManifest, dump, pgManifest).all { Files.isRegularFile(it, NOFOLLOW_LINKS) } &&
            Files.size(cache) in 1..67108864 && Files.size(dump) in 1..67108864 &&
            Files.size(ntfyManifest) <= 512 && Files.size(pgManifest) <= 100 &&
            Files.readString(ntfyManifest).contains("${sha(cache)} cache.db\n") &&
            Files.readString(pgManifest) == "${sha(dump)}  backup.dump\n") { "Incomplete or tampered module backup" }
        return "$id\nntfy=${sha(cache)}\npostgres=${sha(dump)}\n"
    }

    fun runDue(): Boolean {
        checkRoot()
        val marker = schedule.resolve(".owner")
        FileChannel.open(marker, WRITE).use { channel -> channel.lock().use {
            checkRoot()
            val entries = Files.list(schedule).use { it.toList() }
            require(entries.all { it.fileName.toString() == ".owner" ||
                Regex("h[a-z0-9]{1,15}\\.(started|ok)").matches(it.fileName.toString()) &&
                Files.isRegularFile(it, NOFOLLOW_LINKS) && Files.getPosixFilePermissions(it) == filePerms }) {
                "Unexpected schedule entry"
            }
            require(entries.none { it.fileName.toString().endsWith(".started") }) { "Incomplete prior slot requires review" }
            val id = "h${Math.floorDiv(clock().epochSecond, periodSeconds).toString(36)}"
            require(Regex("h[a-z0-9]{1,15}").matches(id)) { "Unsupported schedule epoch" }
            if (Files.exists(schedule.resolve("$id.ok"), NOFOLLOW_LINKS)) return false
            ntfy.prepare()
            postgres.prepare()
            ntfy.requireRunning()
            val started = schedule.resolve("$id.started")
            Files.writeString(started, "started $id\n", CREATE_NEW)
            Files.setPosixFilePermissions(started, filePerms)
            val probe = "p0v3-schedule-$id"
            postgres.writeFixture()
            check(postgres.query(null).trim() == "1:first") { "Primary SQL fixture absent" }
            topic.publishAndRead(18486, probe, "before-$id")
            ntfy.stop()
            try { ntfy.snapshot(id) } finally { ntfy.start() }
            ntfy.requireRunning()
            topic.assertCached(18486, probe, "before-$id")
            postgres.backup(id)
            val receipt = verifyBackup(id)
            var ntfyRestoring = false
            var pgRestoring = false
            try {
                ntfyRestoring = true
                ntfy.restore(id)
                topic.assertCached(18487, probe, "before-$id")
                topic.publishAndRead(18487, probe, "after-$id")
                pgRestoring = true
                postgres.restore(id)
                check(postgres.query(id).trim() == "1:first") { "Restored SQL row missing" }
                postgres.writeRestored(id)
                check(postgres.query(id).trim() == "1:first\n2:restored") { "Isolated SQL write failed" }
                check(postgres.query(null).trim() == "1:first") { "Restored write changed primary" }
            } finally {
                val pgFailure = if (pgRestoring) runCatching { postgres.removeRestore(id) }.exceptionOrNull() else null
                val ntfyFailure = if (ntfyRestoring) runCatching { ntfy.removeRestore(id) }.exceptionOrNull() else null
                check(pgFailure == null && ntfyFailure == null) { "Isolated restore container cleanup failed" }
            }
            Files.writeString(started, receipt)
            Files.move(started, schedule.resolve("$id.ok"), ATOMIC_MOVE)
            return true
        } }
    }

    /** No daemon: only runs while explicitly invoked, and stops after at most two successful slots. */
    fun runBounded(maxRuns: Int = 2, maxWaitSeconds: Long = 120): Int {
        require(maxRuns in 1..2 && maxWaitSeconds in 1..120) { "Unbounded scheduler refused" }
        val deadline = System.nanoTime() + maxWaitSeconds * 1_000_000_000L
        var completed = 0
        while (completed < maxRuns && System.nanoTime() < deadline) {
            if (runDue()) completed++ else pause(250)
        }
        check(completed == maxRuns) { "Not all bounded slots became due" }
        return completed
    }
}
