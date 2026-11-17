package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable

@Serializable internal data class QuadletSystemdServingObservation(val unit: String, val loadState: String,
    val activeState: String, val subState: String, val type: String, val notifyAccess: String,
    val restart: String, val mainPid: Long, val controlGroup: String,
    val mainPidInUnitCgroup: Boolean, val mainPidKind: String,
    val mainPidBoundToOriginalCid: Boolean)
internal class QuadletServingProofFailure(val observation: QuadletSystemdServingObservation) :
    IllegalStateException("Actual notify MainPID or readiness proof failed")

internal fun interface QuadletUnitManager { fun change(action: String, unit: String) }

/** Fixed system-manager Unit API. Never enable, restart, reload a service, or execute a
 * Podman process from the owner. Systemd owns the sole process lifecycle.
 */
internal object RuntimeQuadletSystemd : QuadletUnitManager {
    /** Conmon's READY must have made the real notify unit active, and systemd
     * must retain a live MainPID in its own unit cgroup. A Podman inspect alone
     * cannot prove the helper/sudo/conmon notification chain is functioning.
     */
    internal fun conmonBound(argv: List<String>, cid: String, store: RuntimeStore): Boolean {
        if (argv.firstOrNull() != "/usr/bin/conmon" ||
            !cid.matches(Regex("[a-f0-9]{64}"))) return false
        fun flag(name: String): String? {
            val positions = argv.indices.filter { argv[it] == name }
            return positions.singleOrNull()?.let { argv.getOrNull(it + 1) }
        }
        return flag("-c") == cid &&
            flag("-b") == "${store.graph}/overlay-containers/$cid/userdata"
    }
    /** A delegated supervisor may be moved further into its own runtime child by
     * Podman; neither the unit root nor a sibling service is an authorized MainPID.
     */
    internal fun delegatedMainPid(unit: String, unitCgroup: String, procCgroup: String): Boolean {
        require(unit.matches(Regex("p0v3-q-[a-f0-9]{12}-[a-z0-9-]+\\.service")))
        return unitCgroup == "/system.slice/$unit" && procCgroup.lineSequence().any { line ->
            line.startsWith("0::$unitCgroup/p0v3-supervisor/") ||
                line == "0::$unitCgroup/p0v3-supervisor"
        }
    }
    fun requireServing(unit: String, originalCid: String, store: RuntimeStore): QuadletSystemdServingObservation {
        require(unit.matches(Regex("p0v3-q-[a-f0-9]{12}-[a-z0-9-]+\\.service")) &&
            originalCid.matches(Regex("[a-f0-9]{64}")))
        val child = ProcessBuilder("/usr/bin/systemctl", "show", "--no-pager",
            "--property=LoadState,ActiveState,SubState,Type,NotifyAccess,Restart,MainPID,ControlGroup", unit)
            .redirectErrorStream(true).apply { environment().clear() }.start()
        try {
            require(child.waitFor(20, TimeUnit.SECONDS) && child.exitValue() == 0)
            val text = child.inputStream.use { it.readNBytes(8193) }.also { require(it.size in 1..8192) }
                .decodeToString(throwOnInvalidSequence = true)
            val fields = text.lineSequence().filter { it.contains('=') }
                .associate { it.substringBefore('=') to it.substringAfter('=') }
            val pid = fields["MainPID"]?.toLongOrNull() ?: 0
            val cgroup = fields["ControlGroup"] ?: ""
            val pidGroupMatches = pid > 1 && runCatching {
                val bytes = Files.newInputStream(java.nio.file.Path.of("/proc/$pid/cgroup")).use {
                    it.readNBytes(4097)
                }
                require(bytes.size in 1..4096)
                delegatedMainPid(unit, cgroup, bytes.decodeToString(throwOnInvalidSequence = true))
            }.getOrDefault(false)
            val processKind = if (pid > 1) runCatching {
                val first = Files.readAllBytes(java.nio.file.Path.of("/proc/$pid/cmdline"))
                    .takeWhile { it.toInt() != 0 }.toByteArray().decodeToString().substringAfterLast('/')
                when (first) { "java", "conmon", "podman" -> first; else -> "other" }
            }.getOrDefault("missing") else "missing"
            // Podman --sdnotify=conmon sends READY and MAINPID=<conmon PID>.
            // With --cgroups=split, conmon is intentionally outside the service
            // cgroup. Do not silently accept an arbitrary PID: bind root conmon's
            // exact -c CID and -b canonical bundle path to the original launch ACK.
            val boundConmon = if (pid > 1 && processKind == "conmon") runCatching {
                val raw = Files.readAllBytes(java.nio.file.Path.of("/proc/$pid/cmdline"))
                require(raw.size in 32..8192)
                val argv = raw.toString(Charsets.UTF_8).split('\u0000').filter { it.isNotEmpty() }
                val uid = Files.readAllLines(java.nio.file.Path.of("/proc/$pid/status"))
                    .single { it.startsWith("Uid:") }.trim().split(Regex("\\s+"))[1].toLong()
                uid == 0L && conmonBound(argv, originalCid, store)
            }.getOrDefault(false) else false
            val observation = QuadletSystemdServingObservation(unit, fields["LoadState"] ?: "",
                fields["ActiveState"] ?: "", fields["SubState"] ?: "", fields["Type"] ?: "",
                fields["NotifyAccess"] ?: "", fields["Restart"] ?: "", pid, cgroup,
                pidGroupMatches, processKind, boundConmon)
            if (!(observation.loadState == "loaded" && observation.activeState == "active" &&
                observation.subState == "running" && observation.type == "notify" &&
                observation.notifyAccess == "all" && observation.restart == "no" &&
                ((pidGroupMatches && processKind == "java") || boundConmon))) {
                throw QuadletServingProofFailure(observation)
            }
            return observation
        } finally { if (child.isAlive) child.destroyForcibly() }
    }
    override fun change(action: String, unit: String) {
        require(action in setOf("start", "stop") &&
            unit.matches(Regex("p0v3-q-[a-f0-9]{12}-[a-z0-9-]+\\.service")))
        val log = Files.createTempFile("p0v3-quadlet-systemd-", ".log",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        try {
            val child = ProcessBuilder("/usr/bin/sudo", "-n", "/usr/bin/systemctl", action, unit)
                .redirectErrorStream(true).redirectOutput(log.toFile()).apply { environment().clear() }.start()
            try {
                require(child.waitFor(if (action == "start") 740 else 180, TimeUnit.SECONDS) &&
                    child.exitValue() == 0 && Files.size(log) <= 8192) {
                    "Original systemd unit operation uncertain; reconcile, never replay"
                }
            } finally {
                if (child.isAlive) {
                    child.toHandle().descendants().use { children ->
                        children.toList().asReversed().forEach { it.destroyForcibly() }
                    }
                    child.destroyForcibly().waitFor()
                }
            }
        } finally { Files.deleteIfExists(log) }
    }
}
