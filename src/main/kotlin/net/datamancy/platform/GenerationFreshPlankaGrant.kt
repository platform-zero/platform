package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/** Source-only, once-issued Planka r2 actors for one NEW generation. Not a signup,
 * user ID, cookie, RESTORE replay, or qualification ACK. The bootstrap password
 * remains a separate per-member original input, never in this source record. */
@Serializable internal data class FreshPlankaGrantSource(val schemaVersion: Int = 1,
    val generation: String, val owner: ActivationInput, val outsider: ActivationInput,
    val selectedIndexSha256: String)

internal object GenerationFreshPlankaGrant {
    private val root = Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/planka")
    private val json = Json { ignoreUnknownKeys = false; encodeDefaults = true }
    private val hash = Regex("[a-f0-9]{64}")
    private val mode = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
    private fun generation(value: String) = require(value.matches(Regex("q-[a-f0-9]{12}")))

    fun issue(value: String): ActivationInput {
        generation(value)
        GenerationPreparationTerminalDisposition.requireClosedForNewSource(value)
        val selected = PackagedGraphFragment.pendingV3R10().second.getValue("canonical/r10/index.yaml")
        val identity = Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/identity/fresh/$value.json")
        require(Files.isRegularFile(identity, NOFOLLOW_LINKS) &&
            !Files.exists(GenerationRuntime.BASE.resolve(value), NOFOLLOW_LINKS)) {
            "Original Planka source must precede first generation bundle or actor effect"
        }
        return ReleasePrivateFiles.locked(root.parent) {
            if (!Files.exists(root, NOFOLLOW_LINKS)) {
                Files.createDirectory(root, mode); ReleasePrivateFiles.sync(root.parent)
            }
            ReleasePrivateFiles.directory(root)
            val dir = root.resolve(value)
            require(!Files.exists(dir, NOFOLLOW_LINKS)) { "Planka original actor grant attempted; never reissue" }
            Files.createDirectory(dir, mode); ReleasePrivateFiles.sync(root)
            val random = SecureRandom()
            fun secret(name: String): ActivationInput {
                val raw = ByteArray(32).also(random::nextBytes)
                val text = raw.joinToString("") { "%02x".format(it.toInt() and 0xff) } + "\n"
                raw.fill(0)
                val path = dir.resolve(name)
                ReleasePrivateFiles.save(path, text.encodeToByteArray())
                return ActivationInput(path.toString(), ReleaseLocks.sha256(text.encodeToByteArray()))
            }
            val owner = secret("owner.password")
            val outsider = secret("outsider.password")
            require(owner.sha256 != outsider.sha256)
            val file = dir.resolve("grant.json")
            val bytes = json.encodeToString(FreshPlankaGrantSource(generation = value,
                owner = owner, outsider = outsider, selectedIndexSha256 = selected)).encodeToByteArray()
            ReleasePrivateFiles.save(file, bytes)
            ActivationInput(file.toString(), ReleaseLocks.sha256(bytes))
        }
    }

    /** Prepare reads only the same exact original input pair; RESTORE must not
     * call this producer or mount its bootstrap-dependent enrollment env. */
    fun original(value: String, pin: ActivationInput): FreshPlankaActorGrant {
        generation(value)
        val dir = root.resolve(value)
        val path = dir.resolve("grant.json")
        require(pin.path == path.toString() && pin.sha256.matches(hash))
        val bytes = ReleasePrivateFiles.read(path, 8192)
        require(ReleaseLocks.sha256(bytes) == pin.sha256)
        val record = json.decodeFromString<FreshPlankaGrantSource>(bytes.decodeToString(throwOnInvalidSequence = true))
        require(record.schemaVersion == 1 && record.generation == value &&
            record.selectedIndexSha256 == PackagedGraphFragment.pendingV3R10()
                .second.getValue("canonical/r10/index.yaml"))
        fun secret(name: String, input: ActivationInput): String {
            val file = dir.resolve(name)
            require(input.path == file.toString() && input.sha256.matches(hash))
            val raw = ReleasePrivateFiles.read(file, 128)
            require(ReleaseLocks.sha256(raw) == input.sha256)
            return raw.decodeToString(throwOnInvalidSequence = true).removeSuffix("\n").also {
                require(it.matches(hash) && raw.contentEquals((it + "\n").encodeToByteArray()))
            }
        }
        return FreshPlankaActorGrant(value, secret("owner.password", record.owner),
            secret("outsider.password", record.outsider))
    }
}
