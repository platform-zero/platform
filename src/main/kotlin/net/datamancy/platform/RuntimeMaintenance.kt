package net.datamancy.platform

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.StandardOpenOption.*
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.attribute.PosixFilePermissions
import java.util.UUID
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable internal data class MaintenanceFence(val fingerprint: String, val id: String,
    val reason: String, val stageTarget: String? = null, val checksum: String = "")

/** All callers hold the deployment lock. Presence blocks normal startup; corrupt or partial state fails closed. */
internal object RuntimeMaintenance {
    const val FILE = "runtime.maintenance"
    const val TEMP = "runtime.maintenance.tmp"
    private val json = Json { ignoreUnknownKeys = false }
    fun validate(reason: String) { require(reason in setOf("backup", "restore", "update")) { "Unknown maintenance reason" } }
    private fun bytes(fence: MaintenanceFence): ByteArray {
        val hash = ReleaseLocks.sha256(json.encodeToString(fence.copy(checksum = "")).toByteArray())
        return json.encodeToString(fence.copy(checksum = hash)).toByteArray()
    }
    fun read(root: Path, hash: String): MaintenanceFence? {
        require(!Files.exists(root.resolve(TEMP), NOFOLLOW_LINKS)) { "Incomplete maintenance write; state retained" }
        val path = root.resolve(FILE)
        if (!Files.exists(path, NOFOLLOW_LINKS)) return null
        val data = ReleaseLocks.privateBytes(path)
        val fence = json.decodeFromString<MaintenanceFence>(data.decodeToString())
        validate(fence.reason)
        require(fence.fingerprint == hash && UUID.fromString(fence.id).toString() == fence.id && bytes(fence).contentEquals(data)) {
            "Corrupt or foreign maintenance fence; state retained"
        }
        return fence
    }
    fun create(root: Path, hash: String, reason: String, target: String?): MaintenanceFence {
        validate(reason)
        read(root, hash)?.let {
            require(it.reason == reason && it.stageTarget == target) { "Different maintenance operation already active" }
            return it
        }
        val fence = MaintenanceFence(hash, UUID.randomUUID().toString(), reason, target)
        val temp = root.resolve(TEMP)
        FileChannel.open(temp, setOf(CREATE_NEW, WRITE), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))).use {
            val buffer = ByteBuffer.wrap(bytes(fence)); while (buffer.hasRemaining()) it.write(buffer); it.force(true)
        }
        Files.move(temp, root.resolve(FILE), ATOMIC_MOVE)
        FileChannel.open(root, READ).use { it.force(true) }
        return requireNotNull(read(root, hash))
    }
    fun remove(root: Path, hash: String, id: String) {
        val fence = requireNotNull(read(root, hash)) { "No active maintenance fence" }
        require(fence.id == id) { "Maintenance generation mismatch" }
        Files.delete(root.resolve(FILE))
        FileChannel.open(root, READ).use { it.force(true) }
    }
}
