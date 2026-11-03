package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** Reuses the immutable root-owned distribution format of private boot supervision. */
internal object PinnedBackupController {
    @Serializable data class FilePin(val mode: Int, val sha256: String)
    fun verify(expected: String) {
        require(expected.matches(Regex("[a-f0-9]{64}")))
        verifyTree(Path.of("/mnt/media/p0-v3/runtime-supervision/releases/$expected"), expected,
            Path.of(PinnedBackupController::class.java.protectionDomain.codeSource.location.toURI()), 0)
    }
    internal fun verifyTree(root: Path, expected: String, currentJar: Path, owner: Long) {
        verifyDistribution(root, expected, "p0-v3-platform", owner)
        require(currentJar == root.resolve("lib/p0-v3-platform.jar")) { "Scheduled operation must use its pinned controller" }
    }
    internal fun verifyDistribution(root: Path, expected: String, application: String, owner: Long = 0) {
        require(application in setOf("p0-v3-platform", "p0-v3-acceptance") && expected.matches(Regex("[a-f0-9]{64}")))
        fun guard(path: Path, mode: Int, directory: Boolean) {
            require(path.isAbsolute && path.normalize() == path && path.toRealPath() == path &&
                (Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == owner &&
                (Files.getAttribute(path, "unix:mode", NOFOLLOW_LINKS) as Number).toInt().and(4095) == mode &&
                if (directory) Files.isDirectory(path, NOFOLLOW_LINKS) else Files.isRegularFile(path, NOFOLLOW_LINKS) &&
                    (Files.getAttribute(path, "unix:nlink", NOFOLLOW_LINKS) as Number).toInt() == 1) { "Pinned controller ownership or mode changed" }
        }
        guard(root, 493, true); guard(root.resolve("bin"), 493, true); guard(root.resolve("lib"), 493, true)
        val descriptor = root.resolve("controller.json"); guard(descriptor, 420, false)
        require(Files.size(descriptor) in 1..1048576)
        val bytes = Files.readAllBytes(descriptor)
        require(ReleaseLocks.sha256(bytes) == expected) { "Controller tree binding changed" }
        val pins = Json.decodeFromString<Map<String, FilePin>>(bytes.decodeToString())
        require(pins.size in 2..32 && pins.keys.all { it.matches(Regex("(bin|lib)/[A-Za-z0-9_.-]+")) } &&
            "bin/$application" in pins && "lib/$application.jar" in pins &&
            Json.encodeToString<Map<String, FilePin>>(pins.toSortedMap()).toByteArray().contentEquals(bytes)) { "Noncanonical controller descriptor" }
        val entries = Files.walk(root).use { stream -> stream.limit(38).toList().map { root.relativize(it).toString() }.toSet() }
        require(entries == pins.keys + setOf("", "bin", "lib", "controller.json")) { "Undeclared pinned controller files" }
        for ((name, pin) in pins) {
            require(pin.mode == if (name == "bin/$application") 493 else 420)
            val path = root.resolve(name); guard(path, pin.mode, false)
            require(Files.size(path) in 1..268435456 && RecoveryCapsule.fileHash(path) == pin.sha256) { "Pinned controller bytes changed" }
        }
    }
}
