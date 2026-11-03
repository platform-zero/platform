package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.io.FilterInputStream
import java.io.FilterOutputStream
import java.io.InputStream
import java.nio.channels.Channels
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable internal data class CapsuleFile(val name: String, val bytes: Long, val sha256: String)
@Serializable internal data class CapsuleManifest(val schemaVersion: Int = 1, val id: String, val generation: String,
    val bundleSha256: String, val members: List<FrozenRuntimeObservation>, val files: List<CapsuleFile>,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val volumes: List<RecoveryVolume> = emptyList(),
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val controllerFiles: List<String> = emptyList())
@Serializable internal data class CapsuleVerification(val id: String, val generation: String, val bundleSha256: String,
    val archiveSha256: String, val manifestSha256: String, val files: Int, val plaintextBytes: Long,
    val authenticated: Boolean = true, val functionalRestoreVerified: Boolean = false)

/** Streaming encrypt-then-MAC: independent AES-256-CTR/HMAC-SHA256 keys, fresh IV and key per capsule.
 * Authentication of the complete ciphertext precedes ZIP parsing. Extraction is fresh/private only; this never imports runtime state.
 */
internal object RecoveryCapsule {
    const val MAX_FILE = 1073741824L
    const val MAX_TOTAL = 8589934592L
    private val magic = "P0V3CAP1".toByteArray(Charsets.US_ASCII)
    private val json = Json { ignoreUnknownKeys = false; encodeDefaults = true }
    private val mode = PosixFilePermissions.fromString("rw-------")
    private val digest = Regex("[a-f0-9]{64}")
    private fun name(value: String): Boolean = value.length in 1..200 && !value.startsWith('/') &&
        value.split('/').size <= 8 && value.split('/').all { it !in setOf("", ".", "..") && it.matches(Regex("[a-zA-Z0-9_.-]+")) } && value.substringBefore('/') != "manifest.json"
    fun guard(file: Path, max: Long = MAX_FILE) {
        require(file.isAbsolute && file.normalize() == file && file.toRealPath() == file && Files.isRegularFile(file, NOFOLLOW_LINKS) &&
            Files.size(file) in 1..max && (Files.getAttribute(file, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == UnixSystem().uid &&
            (Files.getAttribute(file, "unix:nlink", NOFOLLOW_LINKS) as Number).toInt() == 1 &&
            Files.getPosixFilePermissions(file).none { it.name.startsWith("GROUP_") || it.name.startsWith("OTHERS_") }) { "Unsafe capsule input" }
    }
    fun fileHash(file: Path): String {
        require(Files.size(file) <= MAX_TOTAL + 16777248) { "Digest input exceeds capsule bound" }
        var bytes = 0L
        val hash = MessageDigest.getInstance("SHA-256")
        Files.newInputStream(file, READ, NOFOLLOW_LINKS).use { input ->
            val buffer = ByteArray(65536)
            while (true) {
                val count = input.read(buffer); if (count < 0) break
                bytes += count; require(bytes <= MAX_TOTAL + 16777248) { "Digest input grew beyond bound" }
                hash.update(buffer, 0, count)
            }
        }
        return java.util.HexFormat.of().formatHex(hash.digest())
    }
    fun describe(payloads: Map<String, Path>): List<CapsuleFile> {
        require(payloads.size in 1..4096 && payloads.keys.all(::name)) { "Invalid capsule payload set" }
        val result = payloads.toSortedMap().map { (name, path) -> guard(path); CapsuleFile(name, Files.size(path), fileHash(path)) }
        require(result.sumOf { it.bytes } <= MAX_TOTAL && noFileParents(result.map { it.name })) { "Capsule payload budget or path hierarchy invalid" }
        return result
    }
    private fun noFileParents(names: List<String>): Boolean {
        val files = names.toSet()
        return names.all { path -> path.indices.filter { path[it] == '/' }.none { path.substring(0, it) in files } }
    }
    private fun validate(manifest: CapsuleManifest) {
        RecoverySegments.validate(manifest)
        RecoveryControllerPayloads.validate(manifest)
        require(manifest.schemaVersion == 1 && manifest.id.matches(Regex("cap-[a-f0-9]{12}")) &&
            manifest.generation.matches(Regex("q-[a-f0-9]{12}")) && digest.matches(manifest.bundleSha256) &&
            manifest.members.isNotEmpty() && manifest.members.size <= 64 &&
            manifest.members.map { it.name }.distinct().size == manifest.members.size && manifest.members.all {
                it.name.startsWith(manifest.generation + "-") && digest.matches(it.fingerprint) && digest.matches(it.jobsSha256) &&
                    it.fenceId.isNotBlank() && it.statuses.isNotEmpty() && it.statuses.all { s ->
                        s.state in setOf("exited", "completed") && s.exitCode in setOf(0, 143)
                    }
            } && manifest.files.size in 1..4096 && manifest.files.map { it.name }.distinct().size == manifest.files.size &&
            manifest.files.all { name(it.name) && it.bytes in 1..MAX_FILE && digest.matches(it.sha256) } &&
            manifest.files.sumOf { it.bytes } <= MAX_TOTAL && noFileParents(manifest.files.map { it.name })) { "Invalid capsule manifest" }
    }
    private fun parent(path: Path) {
        val p = path.parent
        require(path.isAbsolute && path.normalize() == path && p.toRealPath() == p &&
            Files.isDirectory(p, NOFOLLOW_LINKS) && Files.getPosixFilePermissions(p) == PosixFilePermissions.fromString("rwx------") &&
            (Files.getAttribute(p, "unix:uid") as Number).toLong() == UnixSystem().uid) { "Private capsule parent required" }
    }
    private fun sync(path: Path) { FileChannel.open(path, READ).use { it.force(true) } }
    fun create(archive: Path, keyFile: Path, manifest: CapsuleManifest, payloads: Map<String, Path>): CapsuleVerification {
        validate(manifest); parent(archive); parent(keyFile)
        require(!keyFile.startsWith(archive.parent) && payloads.values.none { it == keyFile } &&
            manifest.files == describe(payloads)) { "Capsule custody or payload mismatch" }
        val key = ByteArray(64).also { SecureRandom().nextBytes(it) }
        val iv = ByteArray(16).also { SecureRandom().nextBytes(it) }
        try {
            FileChannel.open(keyFile, setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS), PosixFilePermissions.asFileAttribute(mode)).use { channel ->
                val bytes = java.nio.ByteBuffer.wrap(key); while (bytes.hasRemaining()) channel.write(bytes); channel.force(true)
            }
            sync(keyFile.parent)
            val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key.copyOfRange(32, 64), "HmacSHA256")) }
            val cipher = Cipher.getInstance("AES/CTR/NoPadding").apply {
                init(Cipher.ENCRYPT_MODE, SecretKeySpec(key.copyOfRange(0, 32), "AES"), IvParameterSpec(iv))
            }
            FileChannel.open(archive, setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS), PosixFilePermissions.asFileAttribute(mode)).use { channel ->
                val output = Channels.newOutputStream(channel)
                val authenticated = object : FilterOutputStream(output) {
                    var count = 0L
                    override fun write(value: Int) = write(byteArrayOf(value.toByte()), 0, 1)
                    override fun write(bytes: ByteArray, offset: Int, length: Int) {
                        count += length
                        require(count <= MAX_TOTAL + 16777216) { "Encrypted capsule bound exceeded" }
                        mac.update(bytes, offset, length); out.write(bytes, offset, length)
                    }
                    override fun close() { flush() } // Keep the file open for the trailing MAC and fsync.
                }
                authenticated.write(magic); authenticated.write(iv)
                ZipOutputStream(CipherOutputStream(authenticated, cipher)).use { zip ->
                    zip.setLevel(0)
                    for (entry in manifest.files) {
                        zip.putNextEntry(ZipEntry(entry.name).apply { time = 0 })
                        val hash = MessageDigest.getInstance("SHA-256"); var count = 0L
                        Files.newInputStream(payloads.getValue(entry.name), READ, NOFOLLOW_LINKS).use { input ->
                            val buffer = ByteArray(65536)
                            while (true) {
                                val n = input.read(buffer); if (n < 0) break
                                count += n; require(count <= entry.bytes) { "Payload grew during encryption" }
                                hash.update(buffer, 0, n); zip.write(buffer, 0, n)
                            }
                        }
                        require(count == entry.bytes && java.util.HexFormat.of().formatHex(hash.digest()) == entry.sha256) { "Payload changed during encryption" }
                        zip.closeEntry()
                    }
                    val text = json.encodeToString(manifest).toByteArray()
                    require(text.size <= 1048576) { "Capsule manifest bound exceeded" }
                    zip.putNextEntry(ZipEntry("manifest.json").apply { time = 0 }); zip.write(text); zip.closeEntry()
                }
                output.write(mac.doFinal()); output.flush(); channel.force(true)
            }
            sync(archive.parent)
            return verify(archive, keyFile, manifest.id, manifest.generation, manifest.bundleSha256)
        } finally { key.fill(0) }
    }
    fun verify(archive: Path, keyFile: Path, expectedId: String, expectedGeneration: String, expectedBundle: String): CapsuleVerification =
        inspect(archive, keyFile, expectedId, expectedGeneration, expectedBundle, null).first

    fun extract(archive: Path, keyFile: Path, expectedId: String, expectedGeneration: String, expectedBundle: String,
        destination: Path, availableBytes: (Path) -> Long = { Files.getFileStore(it).usableSpace }): CapsuleManifest {
        val original = verify(archive, keyFile, expectedId, expectedGeneration, expectedBundle) // No plaintext writes before full authentication/validation.
        parent(destination)
        require(availableBytes(destination.parent) >= original.plaintextBytes + 536870912L + 10737418240L) {
            "Insufficient extraction space and protected headroom"
        }
        Files.createDirectory(destination, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        sync(destination.parent)
        val (verified, manifest) = inspect(archive, keyFile, expectedId, expectedGeneration, expectedBundle, destination, original.archiveSha256)
        require(verified == original && verified.manifestSha256 == ReleaseLocks.sha256(Files.readAllBytes(destination.resolve("manifest.json")))) { "Capsule changed between validation and extraction" }
        sync(destination)
        return manifest
    }
    private fun extractedFile(destination: Path, name: String): FileChannel {
        var directory = destination
        val parts = name.split('/')
        for (part in parts.dropLast(1)) {
            directory = directory.resolve(part)
            if (!Files.exists(directory, NOFOLLOW_LINKS)) {
                Files.createDirectory(directory, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
                sync(directory.parent)
            }
            require(directory.toRealPath() == directory && Files.isDirectory(directory, NOFOLLOW_LINKS) &&
                Files.getPosixFilePermissions(directory) == PosixFilePermissions.fromString("rwx------")) { "Unsafe extraction directory" }
        }
        return FileChannel.open(directory.resolve(parts.last()), setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS), PosixFilePermissions.asFileAttribute(mode))
    }
    private fun inspect(archive: Path, keyFile: Path, expectedId: String, expectedGeneration: String, expectedBundle: String,
        destination: Path?, expectedArchiveHash: String? = null): Pair<CapsuleVerification, CapsuleManifest> {
        guard(archive, MAX_TOTAL + 16777248); guard(keyFile, 64); require(Files.size(keyFile) == 64L) { "Invalid custody key" }
        val key = Files.readAllBytes(keyFile)
        try {
            FileChannel.open(archive, READ, NOFOLLOW_LINKS).use { channel ->
                val size = channel.size(); require(size > magic.size + 16 + 32) { "Truncated capsule" }
                val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key.copyOfRange(32, 64), "HmacSHA256")) }
                val authenticatedDigest = MessageDigest.getInstance("SHA-256")
                val input = Channels.newInputStream(channel)
                val header = input.readNBytes(magic.size + 16)
                require(header.copyOfRange(0, magic.size).contentEquals(magic)) { "Unknown capsule format" }
                mac.update(header); authenticatedDigest.update(header)
                var remaining = size - header.size - 32
                val buffer = ByteArray(65536)
                while (remaining > 0) {
                    val count = input.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
                    require(count > 0) { "Truncated ciphertext" }
                    mac.update(buffer, 0, count); authenticatedDigest.update(buffer, 0, count); remaining -= count
                }
                val tag = input.readNBytes(32)
                require(MessageDigest.isEqual(mac.doFinal(), tag) && input.read() == -1) { "Capsule authentication failed" }
                authenticatedDigest.update(tag)
                val authenticatedHash = java.util.HexFormat.of().formatHex(authenticatedDigest.digest())
                require(expectedArchiveHash == null || authenticatedHash == expectedArchiveHash) { "Capsule changed before extraction" }
                channel.position(header.size.toLong())
                val limited = object : FilterInputStream(input) {
                    var left = size - header.size - 32
                    override fun read(): Int { if (left == 0L) return -1; val value = `in`.read(); if (value >= 0) left--; return value }
                    override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
                        if (left == 0L) return -1
                        val count = `in`.read(bytes, offset, minOf(length.toLong(), left).toInt()); if (count > 0) left -= count
                        return count
                    }
                }
                val cipher = Cipher.getInstance("AES/CTR/NoPadding").apply {
                    init(Cipher.DECRYPT_MODE, SecretKeySpec(key.copyOfRange(0, 32), "AES"), IvParameterSpec(header.copyOfRange(magic.size, header.size)))
                }
                val found = mutableListOf<CapsuleFile>(); var total = 0L
                var manifestBytes: ByteArray? = null
                ZipInputStream(CipherInputStream(limited, cipher)).use { zip ->
                    while (true) {
                        val entry = zip.nextEntry ?: break
                        require(!entry.isDirectory && manifestBytes == null && found.size <= 4096) { "Unexpected capsule entry" }
                        if (entry.name == "manifest.json") {
                            val bytes = zip.readNBytes(1048577); require(bytes.size <= 1048576 && zip.read() == -1) { "Oversized manifest" }
                            manifestBytes = bytes
                        } else {
                            require(name(entry.name) && found.none { it.name == entry.name }) { "Unsafe or duplicate capsule path" }
                            val hash = MessageDigest.getInstance("SHA-256"); var count = 0L
                            val target = destination?.let { extractedFile(it, entry.name) }
                            try {
                                while (true) {
                                    val n = zip.read(buffer); if (n < 0) break
                                    count += n; total += n; require(count <= MAX_FILE && total <= MAX_TOTAL) { "Capsule expansion bound exceeded" }
                                    hash.update(buffer, 0, n)
                                    target?.let { channel -> val bytes = java.nio.ByteBuffer.wrap(buffer, 0, n); while (bytes.hasRemaining()) channel.write(bytes) }
                                }
                                target?.force(true)
                            } finally { target?.close() }
                            destination?.let { sync(it.resolve(entry.name).parent) }
                            found += CapsuleFile(entry.name, count, java.util.HexFormat.of().formatHex(hash.digest()))
                        }
                        zip.closeEntry()
                    }
                }
                val bytes = requireNotNull(manifestBytes) { "Missing capsule manifest" }
                val manifest = json.decodeFromString<CapsuleManifest>(bytes.decodeToString(throwOnInvalidSequence = true)); validate(manifest)
                require(manifest.id == expectedId && manifest.generation == expectedGeneration && manifest.bundleSha256 == expectedBundle &&
                    manifest.files == found) { "Capsule scope or payload mismatch" }
                require(fileHash(archive) == authenticatedHash) { "Capsule changed during verification" }
                destination?.let { extractedFile(it, "manifest.json").use { channel ->
                    val buffer = java.nio.ByteBuffer.wrap(bytes); while (buffer.hasRemaining()) channel.write(buffer); channel.force(true)
                } }
                return CapsuleVerification(manifest.id, manifest.generation, manifest.bundleSha256, authenticatedHash,
                    ReleaseLocks.sha256(bytes), found.size, total) to manifest
            }
        } finally { key.fill(0) }
    }
}
