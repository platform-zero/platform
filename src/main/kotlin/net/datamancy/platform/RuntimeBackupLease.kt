package net.datamancy.platform

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable internal data class RuntimeBackupAccess(val generation: String, val operation: String, val bundleSha256: String) {
    fun validate() {
        require(generation.matches(Regex("q-[a-f0-9]{12}")) && operation.matches(Regex("cap-[a-f0-9]{12}")) &&
            bundleSha256.matches(Regex("[a-f0-9]{64}"))) { "Invalid backup operation authority" }
    }
}
@Serializable internal data class RuntimeBackupLease(val access: RuntimeBackupAccess, val name: String, val fingerprint: String)

/** An operation-bound boot/start exclusion, separate from the temporary stopped-state fence.
 * All callers hold the member lock. A partial/foreign marker blocks effects; it is never reconstructed. */
internal object RuntimeBackupLeases {
    const val FILE = "runtime.backup"
    fun read(root: Path, name: String, fingerprint: String): RuntimeBackupLease? {
        val path = root.resolve(FILE)
        if (!Files.exists(path, NOFOLLOW_LINKS)) return null
        RecoveryCapsule.guard(path, 1048576)
        val bytes = Files.readAllBytes(path)
        val lease = Json.decodeFromString<RuntimeBackupLease>(bytes.decodeToString())
        lease.access.validate()
        require(lease.name == name && name.startsWith(lease.access.generation + "-") && lease.fingerprint == fingerprint &&
            Json.encodeToString(lease).toByteArray().contentEquals(bytes)) { "Foreign or partial backup lease" }
        return lease
    }
    fun create(root: Path, name: String, fingerprint: String, access: RuntimeBackupAccess) {
        access.validate()
        require(name.startsWith(access.generation + "-") && read(root, name, fingerprint) == null) { "Backup requires a fresh member lease" }
        val bytes = Json.encodeToString(RuntimeBackupLease(access, name, fingerprint)).toByteArray()
        FileChannel.open(root.resolve(FILE), setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))).use {
            val buffer = ByteBuffer.wrap(bytes); while (buffer.hasRemaining()) it.write(buffer); it.force(true)
        }
        FileChannel.open(root, READ).use { it.force(true) }
    }
    fun remove(root: Path, name: String, fingerprint: String, access: RuntimeBackupAccess) {
        require(read(root, name, fingerprint)?.access == access) { "Backup lease mismatch; no release authorized" }
        Files.delete(root.resolve(FILE))
        FileChannel.open(root, READ).use { it.force(true) }
    }
}
