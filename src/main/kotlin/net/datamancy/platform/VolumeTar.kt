package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import kotlinx.serialization.Serializable

@Serializable internal data class VolumeTarEntry(val path: String, val directory: Boolean, val mode: Int,
    val uid: Int, val gid: Int, val size: Long, val sha256: String, val modifiedSeconds: Long = 0,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val modifiedNanos: Int = 0,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val linkTarget: String? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val linkKind: String? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val accessAcl: String? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val defaultAcl: String? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val userXattrs: Map<String, String> = emptyMap())

/** Unix timestamps use floor seconds plus positive nanoseconds, including times before the epoch. */
internal data class VolumeTimestamp(val seconds: Long, val nanos: Int = 0) {
    init { require(seconds in -8589934591L..8589934591L && nanos in 0..999999999) { "Unsupported volume timestamp" } }
    fun decimal(): String = java.math.BigDecimal.valueOf(seconds).add(java.math.BigDecimal.valueOf(nanos.toLong(), 9))
        .stripTrailingZeros().toPlainString()
    companion object {
        fun parse(value: String): VolumeTimestamp {
            require(value.matches(Regex("-?[0-9]{1,10}(\\.[0-9]{1,9})?"))) { "Unsupported PAX timestamp" }
            val decimal = java.math.BigDecimal(value)
            val seconds = decimal.setScale(0, java.math.RoundingMode.FLOOR).longValueExact()
            return VolumeTimestamp(seconds, decimal.subtract(java.math.BigDecimal.valueOf(seconds)).movePointRight(9).intValueExact())
        }
    }
}

/** Strict read-only USTAR/PAX inspection before native import. Bounded local links and approved metadata only; no devices, sparse files or privilege bits. */
internal object VolumeTar {
    /** Podman exports children, not the mount root. Prepend the observed root without rewriting source data. */
    const val MAX_ROOT_PREFIX = 1536L
    const val MAX_METADATA_PREFIX = 65536L
    /** Absolute image-local links require a separately reviewed, version-pinned allowlist.
     * No version-specific exception is currently approved, so none may be imported.
     */
    private val absoluteLinkAllowlist = emptySet<Pair<String, String>>()
    private fun safeAcl(value: String, users: Set<Long>, groups: Set<Long>) {
        val entries = value.trimEnd('\n').split(',', '\n')
        require(entries.size in 3..64 && entries.distinct().size == entries.size)
        val tag = Regex("(user|group|other|mask):([0-9]{1,5})?:([r-][w-][x-])")
        val parsed = entries.map { requireNotNull(tag.matchEntire(it)) { "Unsupported POSIX ACL identity" } }
        require(listOf("user::", "group::", "other::").all { required ->
            entries.count { it.startsWith(required) } == 1
        } && parsed.all { m ->
            val principal = m.groupValues[2]
            principal.isEmpty() || when (m.groupValues[1]) {
                "user" -> principal.toLong() in users
                "group" -> principal.toLong() in groups
                else -> false
            }
        }) {
            "Unmapped ACL principal or incomplete owner triplet"
        }
    }
    private fun safeLink(name: String, target: String, hard: Boolean, prior: Map<String, VolumeTarEntry>, uid: Long, gid: Long) {
        require(target.isNotEmpty() && target.length <= 1024 && '\\' !in target && target.none { it.code < 32 })
        if (hard) {
            val normalized = target.removePrefix("./")
            require(!normalized.startsWith('/') && normalized.split('/').all { it !in setOf("", ".", "..") } &&
                prior[normalized]?.let { !it.directory && it.linkKind == null && it.uid.toLong() == uid && it.gid.toLong() == gid } == true) {
                "Hardlinks must target an earlier regular file in the same volume"
            }
        } else if (target.startsWith('/')) {
            require(name to target in absoluteLinkAllowlist) { "Unpinned absolute symlink" }
        } else {
            val resolved = java.nio.file.Path.of(name).parent?.resolve(target)?.normalize() ?: java.nio.file.Path.of(target).normalize()
            require(resolved.toString() != "." && !resolved.isAbsolute && !resolved.startsWith("..") &&
                target.split('/').none { it.isEmpty() || it == ".." }) { "Symlink escapes its volume" }
        }
    }
    fun prependRoot(path: Path, uid: Int, gid: Int, mode: Int, modifiedSeconds: Long, modifiedNanos: Int = 0,
        accessAcl: String? = null, defaultAcl: String? = null, userXattrs: Map<String, String> = emptyMap()) {
        RecoveryCapsule.guard(path, RecoveryCapsule.MAX_TOTAL)
        require(uid in 0..65534 && gid in 0..65534 && mode in 0..4095)
        val timestamp = VolumeTimestamp(modifiedSeconds, modifiedNanos)
        fun header(name: String, kind: Char, bytes: Int, permissions: Int): ByteArray {
            val header = ByteArray(512)
            fun text(offset: Int, value: String) { value.toByteArray(Charsets.US_ASCII).copyInto(header, offset) }
            fun octal(offset: Int, length: Int, value: Long) {
                val encoded = value.toString(8); require(encoded.length < length)
                text(offset, encoded.padStart(length - 1, '0'))
            }
            text(0, name); octal(100, 8, permissions.toLong()); octal(108, 8, uid.toLong()); octal(116, 8, gid.toLong())
            octal(124, 12, bytes.toLong()); octal(136, 12, maxOf(0, modifiedSeconds)); header[156] = kind.code.toByte()
            text(257, "ustar"); text(263, "00")
            for (i in 148..155) header[i] = 32
            val checksum = header.sumOf { it.toInt() and 255 }
            for (i in 148..155) header[i] = 0
            octal(148, 8, checksum.toLong())
            return header
        }
        val root = header("./", '5', 0, mode)
        val metadata = linkedMapOf<String, ByteArray>()
        if (modifiedNanos != 0 || modifiedSeconds < 0) metadata["mtime"] = timestamp.decimal().toByteArray(Charsets.US_ASCII)
        accessAcl?.let {
            require(it.length in 1..4096 && it.matches(Regex("[a-zA-Z0-9_:,\\n-]+")))
            metadata["SCHILY.acl.access"] = it.toByteArray(Charsets.US_ASCII)
        }
        defaultAcl?.let {
            require(it.length in 1..4096 && it.matches(Regex("[a-zA-Z0-9_:,\\n-]+")))
            metadata["SCHILY.acl.default"] = it.toByteArray(Charsets.US_ASCII)
        }
        for ((name, value) in userXattrs.toSortedMap()) {
            require(name.matches(Regex("user\\.[a-zA-Z0-9_.-]{1,96}")) && value.matches(Regex("0x(?:[a-f0-9]{2}){0,4096}")))
            metadata["SCHILY.xattr.$name"] = java.util.HexFormat.of().parseHex(value.removePrefix("0x"))
        }
        val prefix = if (metadata.isEmpty()) root else {
            val pax = metadata.entries.fold(ByteArray(0)) { bytes, (key, value) ->
                val body = "$key=".toByteArray(Charsets.US_ASCII) + value + byteArrayOf(10)
                var length = body.size + 3
                while (length != body.size + length.toString().length + 1) length = body.size + length.toString().length + 1
                bytes + "$length ".toByteArray(Charsets.US_ASCII) + body
            }
            require(pax.size in 1..(MAX_METADATA_PREFIX - 1024).toInt()) { "Mount-root metadata exceeds approved bound" }
            header("PaxHeaders/root", 'x', pax.size, 384) + pax + ByteArray((512 - pax.size % 512) % 512) + root
        }
        require(prefix.size.toLong() <= MAX_METADATA_PREFIX)
        val size = Files.size(path)
        require(size in 1024..(RecoveryCapsule.MAX_TOTAL - prefix.size) && size % 512 == 0L) { "Invalid native tar size" }
        java.nio.channels.FileChannel.open(path, java.nio.file.StandardOpenOption.READ, java.nio.file.StandardOpenOption.WRITE,
            java.nio.file.LinkOption.NOFOLLOW_LINKS).use { channel ->
            var end = size
            while (end > 0) {
                val n = minOf(end, 65536L).toInt(); val buffer = java.nio.ByteBuffer.allocate(n)
                channel.position(end - n)
                while (buffer.hasRemaining()) require(channel.read(buffer) > 0) { "Truncated native tar" }
                buffer.flip(); channel.position(end - n + prefix.size)
                while (buffer.hasRemaining()) channel.write(buffer)
                end -= n
            }
            channel.position(0); val buffer = java.nio.ByteBuffer.wrap(prefix)
            while (buffer.hasRemaining()) channel.write(buffer)
            channel.force(true)
        }
    }
    fun inspect(path: Path, owner: Int, mappedOwners: Set<Pair<Int, Int>> = emptySet()): List<VolumeTarEntry> {
        require(owner in 1..65534 && mappedOwners.size <= 64 && mappedOwners.all { (uid, gid) -> uid in 0..65534 && gid in 0..65534 })
        val admitted = (mappedOwners + (owner to owner)).map { it.first.toLong() to it.second.toLong() }.toSet()
        val admittedUsers = admitted.map { it.first }.toSet()
        val admittedGroups = admitted.map { it.second }.toSet()
        RecoveryCapsule.guard(path, RecoveryCapsule.MAX_TOTAL)
        require(Files.size(path) % 512 == 0L) { "Tar block alignment required" }
        val entries = linkedMapOf<String, VolumeTarEntry>()
        var pax = emptyMap<String, String>()
        var headers = 0
        var total = 0L
        fun text(bytes: ByteArray, start: Int, length: Int): String = bytes.copyOfRange(start, start + length)
            .takeWhile { it != 0.toByte() }.toByteArray().decodeToString(throwOnInvalidSequence = true)
        fun number(bytes: ByteArray, start: Int, length: Int): Long {
            val value = text(bytes, start, length).trim()
            require(value.all { it in '0'..'7' }) { "Unsupported tar numeric encoding" }
            return if (value.isEmpty()) 0 else value.toLong(8)
        }
        fun normalized(raw: String, directory: Boolean): String {
            require(raw.isNotEmpty() && raw.length <= 1024 && !raw.startsWith('/') && '\\' !in raw && raw.none { it.code < 32 }) { "Unsafe tar path" }
            var value = raw.removePrefix("./")
            if (directory) value = value.removeSuffix("/")
            if (value in setOf("", ".")) { require(directory); return "." }
            require(value.split('/').all { it !in setOf("", ".", "..") } && !value.endsWith('/')) { "Tar traversal or ambiguous path" }
            return value
        }
        Files.newInputStream(path).use { input ->
            fun padding(size: Long) {
                val bytes = input.readNBytes(((512 - size % 512) % 512).toInt())
                require(bytes.size == ((512 - size % 512) % 512).toInt() && bytes.all { it == 0.toByte() }) { "Invalid tar padding" }
            }
            while (true) {
                val header = input.readNBytes(512)
                require(header.size == 512) { "Truncated tar header" }
                if (header.all { it == 0.toByte() }) {
                    require(pax.isEmpty()) { "Dangling tar metadata" }
                    val second = input.readNBytes(512)
                    require(second.size == 512 && second.all { it == 0.toByte() }) { "Truncated tar terminator" }
                    val buffer = ByteArray(65536)
                    while (true) { val n = input.read(buffer); if (n < 0) break; require(buffer.take(n).all { it == 0.toByte() }) { "Trailing tar data" } }
                    break
                }
                require(++headers <= 200000 && text(header, 257, 5) == "ustar") { "Unsupported tar header" }
                val sum = header.indices.sumOf { if (it in 148..155) 32 else header[it].toInt() and 255 }.toLong()
                require(sum == number(header, 148, 8)) { "Tar checksum mismatch" }
                val kind = header[156].toInt().toChar()
                val rawSize = number(header, 124, 12)
                require(rawSize in 0..RecoveryCapsule.MAX_TOTAL)
                if (kind == 'x') {
                    require(pax.isEmpty() && rawSize in 1..1048576) { "Unsupported tar metadata" }
                    val bytes = input.readNBytes(rawSize.toInt()); require(bytes.size == rawSize.toInt()); padding(rawSize)
                    val values = linkedMapOf<String, String>(); var offset = 0
                    while (offset < bytes.size) {
                        var space = offset
                        while (space < bytes.size && bytes[space] != 32.toByte()) space++
                        require(space > offset && space < bytes.size)
                        val length = bytes.copyOfRange(offset, space).decodeToString().toInt()
                        require(length > space - offset + 2 && length <= bytes.size - offset && bytes[offset + length - 1] == 10.toByte())
                        val record = bytes.copyOfRange(space + 1, offset + length - 1)
                        val delimiter = record.indexOf(61.toByte())
                        require(delimiter > 0)
                        val key = record.copyOfRange(0, delimiter).decodeToString(throwOnInvalidSequence = true)
                        val originalValue = record.copyOfRange(delimiter + 1, record.size)
                        val value = if (key.startsWith("SCHILY.xattr.user."))
                            "0x" + java.util.HexFormat.of().formatHex(originalValue)
                        else originalValue.decodeToString(throwOnInvalidSequence = true)
                        require((key in setOf("path", "size", "uid", "gid", "mtime", "atime", "ctime", "uname", "gname", "SCHILY.acl.access", "SCHILY.acl.default") ||
                            key.matches(Regex("SCHILY\\.xattr\\.user\\.[a-zA-Z0-9_.-]{1,96}"))) && key !in values) {
                            "Unsupported PAX attribute, capability or security label"
                        }
                        if (key in setOf("SCHILY.acl.access", "SCHILY.acl.default")) require(value.length in 1..4096 &&
                            value.matches(Regex("[a-zA-Z0-9_:,\\n-]+")) && value.contains("user::") && value.contains("group::") && value.contains("other::")) {
                            "Unsupported or incomplete POSIX ACL"
                        }
                        if (key.startsWith("SCHILY.xattr.user.")) require(originalValue.size <= 4096) {
                            "Oversized user xattr"
                        }
                        if (key in setOf("mtime", "atime", "ctime")) VolumeTimestamp.parse(value)
                        if (key in setOf("uname", "gname")) require(value.length <= 256 && value.none { it.code < 32 }) { "Invalid PAX owner name" }
                        values[key] = value; offset += length
                    }
                    pax = values
                    continue
                }
                require(kind in setOf('\u0000', '0', '5', '1', '2')) { "Tar device or special file refused" }
                val directory = kind == '5'
                val hard = kind == '1'; val symbolic = kind == '2'
                val prefix = text(header, 345, 155)
                val rawName = if (prefix.isEmpty()) text(header, 0, 100) else prefix + "/" + text(header, 0, 100)
                require("atime" !in pax && "ctime" !in pax) { "Unrestorable access/change timestamps refused" }
                val name = normalized(pax["path"] ?: rawName, directory)
                val size = pax["size"]?.toLong() ?: rawSize
                val uid = pax["uid"]?.toLong() ?: number(header, 108, 8)
                val gid = pax["gid"]?.toLong() ?: number(header, 116, 8)
                val mode = number(header, 100, 8)
                require((uid to gid) in admitted && (name != "." || uid == owner.toLong() && gid == owner.toLong()) &&
                    mode in 0..511 && size in 0..RecoveryCapsule.MAX_TOTAL &&
                    (!(directory || hard || symbolic) || size == 0L) && name !in entries) { "Tar ownership, mode, size or duplicate path refused" }
                val link = text(header, 157, 100).takeIf { hard || symbolic }
                if (hard || symbolic) safeLink(name, requireNotNull(link), hard, entries, uid, gid)
                else require(text(header, 157, 100).isEmpty()) { "Unexpected link target" }
                val modified = pax["mtime"]?.let(VolumeTimestamp::parse) ?: VolumeTimestamp(number(header, 136, 12))
                val accessAcl = pax["SCHILY.acl.access"]
                val defaultAcl = pax["SCHILY.acl.default"]
                accessAcl?.let { safeAcl(it, admittedUsers, admittedGroups) }
                defaultAcl?.let { require(directory) { "Default ACL on non-directory" }; safeAcl(it, admittedUsers, admittedGroups) }
                val userXattrs = pax.filterKeys { it.startsWith("SCHILY.xattr.user.") }
                    .mapKeys { it.key.removePrefix("SCHILY.xattr.") }
                pax = emptyMap()
                val hash = MessageDigest.getInstance("SHA-256")
                var left = size; val buffer = ByteArray(65536)
                while (left > 0) {
                    val n = input.read(buffer, 0, minOf(left, buffer.size.toLong()).toInt())
                    require(n > 0) { "Truncated tar payload" }; hash.update(buffer, 0, n); left -= n
                }
                padding(size); total += size
                require(total <= RecoveryCapsule.MAX_TOTAL && entries.size < 100000) { "Tar expansion bound exceeded" }
                entries[name] = VolumeTarEntry(name, directory, mode.toInt(), uid.toInt(), gid.toInt(), size,
                    java.util.HexFormat.of().formatHex(hash.digest()), modified.seconds, modified.nanos, link,
                    when { hard -> "hard"; symbolic -> "symbolic"; else -> null },
                    accessAcl, defaultAcl, userXattrs)
            }
        }
        require(entries["."]?.directory == true) { "Explicit archive root required" }
        entries.values.filter { it.path != "." }.forEach { entry ->
            val parent = entry.path.substringBeforeLast('/', ".")
            require(entries[parent]?.directory == true) { "Tar parent is absent or not a directory" }
        }
        return entries.values.sortedBy { it.path }
    }
}
