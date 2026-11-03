package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import kotlinx.serialization.Serializable

@Serializable internal data class VolumeTarEntry(val path: String, val directory: Boolean, val mode: Int,
    val uid: Int, val gid: Int, val size: Long, val sha256: String, val modifiedSeconds: Long = 0,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val modifiedNanos: Int = 0)

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

/** Strict read-only USTAR/PAX inspection before native import. No links, devices, sparse files or privilege bits. */
internal object VolumeTar {
    /** Podman exports children, not the mount root. Prepend the observed root without rewriting source data. */
    const val MAX_ROOT_PREFIX = 1536L
    fun prependRoot(path: Path, uid: Int, gid: Int, mode: Int, modifiedSeconds: Long, modifiedNanos: Int = 0) {
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
        val prefix = if (modifiedNanos == 0 && modifiedSeconds >= 0) root else {
            val record = "mtime=${timestamp.decimal()}\n"
            var length = record.length + 3
            while (length != record.length + length.toString().length + 1) length = record.length + length.toString().length + 1
            val pax = "$length $record".toByteArray(Charsets.US_ASCII)
            header("PaxHeaders/root", 'x', pax.size, 384) + pax + ByteArray((512 - pax.size % 512) % 512) + root
        }
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
    fun inspect(path: Path, owner: Int): List<VolumeTarEntry> {
        require(owner in 1..65534)
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
                        val record = bytes.copyOfRange(space + 1, offset + length - 1).decodeToString(throwOnInvalidSequence = true)
                        val key = record.substringBefore('='); val value = record.substringAfter('=', "")
                        require('=' in record && key in setOf("path", "size", "uid", "gid", "mtime", "atime", "ctime", "uname", "gname") && key !in values) {
                            "Unsupported PAX attribute"
                        }
                        if (key in setOf("mtime", "atime", "ctime")) VolumeTimestamp.parse(value)
                        if (key in setOf("uname", "gname")) require(value.length <= 256 && value.none { it.code < 32 }) { "Invalid PAX owner name" }
                        values[key] = value; offset += length
                    }
                    pax = values
                    continue
                }
                require(kind in setOf('\u0000', '0', '5') && text(header, 157, 100).isEmpty()) { "Tar links or special files refused" }
                val directory = kind == '5'
                val prefix = text(header, 345, 155)
                val rawName = if (prefix.isEmpty()) text(header, 0, 100) else prefix + "/" + text(header, 0, 100)
                val name = normalized(pax["path"] ?: rawName, directory)
                val size = pax["size"]?.toLong() ?: rawSize
                val uid = pax["uid"]?.toLong() ?: number(header, 108, 8)
                val gid = pax["gid"]?.toLong() ?: number(header, 116, 8)
                val mode = number(header, 100, 8)
                require(uid == owner.toLong() && gid == owner.toLong() && mode in 0..511 && size in 0..RecoveryCapsule.MAX_TOTAL &&
                    (!directory || size == 0L) && name !in entries) { "Tar ownership, mode, size or duplicate path refused" }
                val modified = pax["mtime"]?.let(VolumeTimestamp::parse) ?: VolumeTimestamp(number(header, 136, 12))
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
                    java.util.HexFormat.of().formatHex(hash.digest()), modified.seconds, modified.nanos)
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
