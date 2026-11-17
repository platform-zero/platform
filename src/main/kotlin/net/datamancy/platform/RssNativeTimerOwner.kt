package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** One owner for a generation's *system* timer. Unit text alone is not a
 * schedule. Intent precedes each native mutation; a missing result is never
 * reconstructed from `systemctl show`, nor retried under another operation.
 */
@Serializable internal data class RssTimerNativeIntent(val action: String, val generation: String,
    val bindingSha256: String, val units: Map<String, String>)
internal object RssNativeTimerOwner {
    private val json = Json { encodeDefaults = true }
    private val hex = Regex("[a-f0-9]{64}")
    private fun command(vararg args: String): String {
        val log = Files.createTempFile("p0v3-rss-systemd-", ".log")
        try {
            val child = ProcessBuilder(listOf("/usr/bin/sudo", "-n") + args.toList())
                .redirectErrorStream(true).redirectOutput(log.toFile()).start()
            try {
                require(child.waitFor(90, TimeUnit.SECONDS) && child.exitValue() == 0) {
                    "Unacknowledged RSS system-manager effect; retain original intent"
                }
                require(Files.size(log) <= 8192)
                return Files.readString(log)
            } finally { if (child.isAlive) child.destroyForcibly() }
        } finally { Files.deleteIfExists(log) }
    }
    private fun state(unit: String): Map<String, String> = command("/usr/bin/systemctl", "show", "--no-pager",
        "--property=LoadState,ActiveState,UnitFileState", unit).lineSequence().filter { '=' in it }
        .associate { it.substringBefore('=') to it.substringAfter('=') }
    private fun custody(root: Path, expected: String): Pair<Path, Map<String, String>> {
        require(hex.matches(expected) && root.parent.fileName.toString() == "rss" &&
            root.parent.parent.parent == GenerationRuntime.BASE &&
            root.parent.parent.fileName.toString().matches(Regex("q-[a-f0-9]{12}")))
        val units = RssSchedule.real().units(root, expected)
        val generation = root.parent.parent.fileName.toString()
        require(units.keys == setOf("p0v3-rss-$generation.service", "p0v3-rss-$generation.timer"))
        val dir = root.resolve("native-timer")
        if (!Files.exists(dir, NOFOLLOW_LINKS)) {
            Files.createDirectory(dir, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(root)
        }
        ReleasePrivateFiles.directory(dir)
        return dir to units
    }
    fun start(root: Path, expected: String) {
        val (dir, units) = custody(root, expected)
        require(ReleasePrivateFiles.read(root.resolve("enabled")).decodeToString() == expected)
        val generation = root.parent.parent.fileName.toString()
        val original = RssTimerNativeIntent("start", generation, expected,
            units.mapValues { ReleaseLocks.sha256(it.value.toByteArray()) })
        val intentPath = dir.resolve("start.intent.json")
        val resultPath = dir.resolve("start.result.json")
        if (Files.exists(intentPath, NOFOLLOW_LINKS)) {
            require(Files.exists(resultPath, NOFOLLOW_LINKS) &&
                ReleasePrivateFiles.read(intentPath).contentEquals(json.encodeToString(original).toByteArray()) &&
                ReleasePrivateFiles.read(resultPath).contentEquals(json.encodeToString(original).toByteArray()) &&
                state("p0v3-rss-$generation.timer").let { it["LoadState"] == "loaded" &&
                    it["ActiveState"] == "active" && it["UnitFileState"] == "enabled" }) {
                "Original RSS timer start remains uncertain; no replay"
            }
            RssActivationAuthority().verify(RssSchedule.decode(ReleasePrivateFiles.read(root.resolve("binding.json"))), true)
            return
        }
        RssActivationAuthority().verify(RssSchedule.decode(ReleasePrivateFiles.read(root.resolve("binding.json"))), false)
        val source = dir.resolve("source")
        require(!Files.exists(source, NOFOLLOW_LINKS))
        Files.createDirectory(source, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
            java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.sync(dir)
        // Preflight ALL destinations before the first effect; an existing unit
        // belongs to its original owner even when its bytes happen to match.
        for ((name, text) in units) {
            require(!Files.exists(Path.of("/etc/systemd/system/$name"), NOFOLLOW_LINKS))
            ReleasePrivateFiles.save(source.resolve(name), text.toByteArray())
        }
        ReleasePrivateFiles.save(intentPath, json.encodeToString(original).toByteArray())
        for ((name, text) in units) {
            val dest = Path.of("/etc/systemd/system/$name")
            command("/usr/bin/install", "-m", "0644", "--", source.resolve(name).toString(), dest.toString())
            require(Files.isRegularFile(dest, NOFOLLOW_LINKS) && Files.readAllBytes(dest).contentEquals(text.toByteArray()))
        }
        command("/usr/bin/systemctl", "daemon-reload")
        val timer = "p0v3-rss-$generation.timer"
        require(state(timer)["LoadState"] == "loaded" && state("p0v3-rss-$generation.service")["LoadState"] == "loaded")
        command("/usr/bin/systemctl", "enable", "--now", timer)
        require(state(timer).let { it["LoadState"] == "loaded" && it["ActiveState"] == "active" &&
            it["UnitFileState"] == "enabled" })
        ReleasePrivateFiles.save(resultPath, json.encodeToString(original).toByteArray())
    }
    fun stopIfOwned(root: Path, expected: String): Boolean {
        val (dir, units) = custody(root, expected)
        val start = dir.resolve("start.result.json")
        if (!Files.exists(start, NOFOLLOW_LINKS)) {
            require(!Files.exists(dir.resolve("start.intent.json"), NOFOLLOW_LINKS)) {
                "Uncertain original RSS timer start; no stop ACK or guessed cleanup"
            }
            return false
        }
        val generation = root.parent.parent.fileName.toString()
        val original = RssTimerNativeIntent("start", generation, expected,
            units.mapValues { ReleaseLocks.sha256(it.value.toByteArray()) })
        require(ReleasePrivateFiles.read(start).contentEquals(json.encodeToString(original).toByteArray()))
        val intent = dir.resolve("stop.intent.json")
        val stop = original.copy(action = "stop")
        val bytes = json.encodeToString(stop).toByteArray()
        val timer = "p0v3-rss-$generation.timer"
        val result = dir.resolve("stop.result.json")
        if (Files.exists(result, NOFOLLOW_LINKS)) {
            require(ReleasePrivateFiles.read(intent).contentEquals(bytes) &&
                ReleasePrivateFiles.read(result).contentEquals(bytes) &&
                state(timer).let { it["ActiveState"] == "inactive" && it["UnitFileState"] == "disabled" } &&
                state("p0v3-rss-$generation.service")["ActiveState"] == "inactive")
            return true
        }
        require(!Files.exists(intent, NOFOLLOW_LINKS)) { "Original RSS stop intent retained; never replay" }
        ReleasePrivateFiles.save(intent, bytes)
        command("/usr/bin/systemctl", "disable", "--now", timer)
        command("/usr/bin/systemctl", "stop", "p0v3-rss-$generation.service")
        require(state(timer).let { it["ActiveState"] == "inactive" && it["UnitFileState"] == "disabled" } &&
            state("p0v3-rss-$generation.service")["ActiveState"] == "inactive")
        ReleasePrivateFiles.save(result, bytes)
        return true
    }
}
