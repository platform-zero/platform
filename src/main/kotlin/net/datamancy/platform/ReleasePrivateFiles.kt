package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions

/** Bounded private control records, not a backup format. All operations are caller-owned and no-follow. */
internal object ReleasePrivateFiles {
    private val directoryMode = PosixFilePermissions.fromString("rwx------")
    private val fileMode = PosixFilePermissions.fromString("rw-------")
    fun directory(path: Path) {
        require(path.isAbsolute && path.normalize() == path && path.toRealPath() == path &&
            Files.isDirectory(path, NOFOLLOW_LINKS) && Files.getPosixFilePermissions(path) == directoryMode &&
            (Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == UnixSystem().uid) { "Owned private control directory required" }
    }
    private fun file(path: Path) {
        directory(path.parent)
        require(path.toRealPath() == path && Files.isRegularFile(path, NOFOLLOW_LINKS) &&
            Files.getPosixFilePermissions(path) == fileMode &&
            (Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == UnixSystem().uid &&
            (Files.getAttribute(path, "unix:nlink", NOFOLLOW_LINKS) as Number).toLong() == 1L) { "Owned single-link control file required" }
    }
    fun read(path: Path, maximum: Int = 4 * 1024 * 1024): ByteArray {
        require(maximum in 1..64 * 1024 * 1024); file(path)
        return Files.newInputStream(path, NOFOLLOW_LINKS).use { it.readNBytes(maximum + 1) }.also {
            require(it.size in 1..maximum) { "Empty or oversized control record" }
        }
    }
    fun sync(directory: Path) = FileChannel.open(directory, READ).use { it.force(true) }
    fun save(path: Path, bytes: ByteArray) {
        directory(path.parent); require(bytes.size in 1..4 * 1024 * 1024)
        FileChannel.open(path, setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS), PosixFilePermissions.asFileAttribute(fileMode)).use {
            val buffer = ByteBuffer.wrap(bytes); while (buffer.hasRemaining()) it.write(buffer); it.force(true)
        }
        sync(path.parent)
    }
    fun removeExact(path: Path, expected: ByteArray) {
        require(read(path).contentEquals(expected)) { "Changed control claim; reconciliation required" }
        Files.delete(path); sync(path.parent)
    }
    fun <T> locked(root: Path, action: () -> T): T {
        directory(root)
        val lock = root.resolve("control.lock")
        FileChannel.open(lock, setOf(CREATE, READ, WRITE, NOFOLLOW_LINKS), PosixFilePermissions.asFileAttribute(fileMode)).use { channel ->
            file(lock)
            channel.lock().use { return action() }
        }
    }
}
