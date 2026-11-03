package net.datamancy.platform

import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*

class VolumeTarTest {
    companion object {
        fun member(name: String, kind: Char = '0', data: ByteArray = "fixture".toByteArray(), uid: Int = 999,
            mode: Int = 384, link: String = ""): ByteArray {
            val header = ByteArray(512)
            fun text(offset: Int, value: String) { value.toByteArray().copyInto(header, offset) }
            fun octal(offset: Int, length: Int, value: Long) = text(offset, value.toString(8).padStart(length - 1, '0'))
            text(0, name); octal(100, 8, mode.toLong()); octal(108, 8, uid.toLong()); octal(116, 8, uid.toLong())
            octal(124, 12, data.size.toLong()); octal(136, 12, 0); header[156] = kind.code.toByte()
            text(157, link); text(257, "ustar"); text(263, "00")
            for (i in 148..155) header[i] = 32
            val sum = header.sumOf { it.toInt() and 255 }
            for (i in 148..155) header[i] = 0
            octal(148, 8, sum.toLong())
            return header + data + ByteArray((512 - data.size % 512) % 512)
        }
        fun tar(vararg entries: ByteArray): ByteArray = entries.fold(ByteArray(0)) { a, b -> a + b } + ByteArray(1024)
        fun root() = member("./", '5', ByteArray(0), mode = 448)
        fun pax(key: String, value: String): ByteArray {
            val body = "$key=$value\n"
            var size = body.toByteArray().size + 3
            while (true) { val next = body.toByteArray().size + size.toString().length + 1; if (next == size) break; size = next }
            return "$size $body".toByteArray()
        }
    }
    private fun inspect(bytes: ByteArray): List<VolumeTarEntry> {
        val file = Files.createTempFile("volume-tar-unit-", ".tar", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        try { Files.write(file, bytes); return VolumeTar.inspect(file, 999) } finally { Files.delete(file) }
    }
    @Test fun `preserve observed mount root around a native child-only archive without guessing missing metadata`() {
        val file = Files.createTempFile("volume-root-unit-", ".tar", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        try {
            val data = ByteArray(200000) { (it % 251).toByte() }
            Files.write(file, tar(member("data", data = data)))
            assertFailsWith<IllegalArgumentException> { VolumeTar.inspect(file, 999) }
            VolumeTar.prependRoot(file, 999, 999, 448, 123)
            val entries = VolumeTar.inspect(file, 999)
            assertEquals(listOf(".", "data"), entries.map { it.path })
            assertEquals(448, entries.first().mode)
            assertEquals(ReleaseLocks.sha256(data), entries.last().sha256)
            assertFailsWith<IllegalArgumentException> { VolumeTar.prependRoot(file, -1, 999, 448, 123) }
            assertFailsWith<IllegalArgumentException> { VolumeTar.prependRoot(file, 999, 999, 4096, 123) }
            Files.write(file, byteArrayOf(1))
            assertFailsWith<IllegalArgumentException> { VolumeTar.prependRoot(file, 999, 999, 448, 123) }
        } finally { Files.delete(file) }
    }
    @Test fun `inspect canonical data permissions and supported PAX without extracting anything`() {
        val data = "original bytes".toByteArray()
        val result = inspect(tar(root(), member("dir/", '5', ByteArray(0), mode = 448),
            member("meta", 'x', pax("path", "dir/value") + pax("uid", "999") + pax("gid", "999") + pax("size", data.size.toString()) + pax("mtime", "123.456") + pax("uname", "database") + pax("gname", "database")),
            member("ignored", data = data)))
        assertEquals(listOf(".", "dir", "dir/value"), result.map { it.path })
        assertEquals(ReleaseLocks.sha256(data), result.last().sha256)
        assertEquals(384, result.last().mode)
        assertEquals(123L, result.last().modifiedSeconds)
        assertEquals(456000000, result.last().modifiedNanos)
        assertTrue(result.first().directory)
        assertEquals(1, inspect(tar(root())).size)
        assertEquals(2, inspect(tar(root(), member("file", '\u0000'))).size)
    }
    @Test fun `nanosecond modification times are compared rather than rounded away`() {
        fun archive(time: String) = inspect(tar(root(), member("meta", 'x', pax("mtime", time)), member("file"))).last()
        val before = archive("123.000000001")
        val after = archive("123.000000002")
        assertEquals(before.sha256, after.sha256)
        assertNotEquals(before, after)
        assertEquals(VolumeTimestamp(-1, 500000000), VolumeTimestamp.parse("-0.5"))
        assertEquals(VolumeTimestamp(-2, 999999999), VolumeTimestamp.parse("-1.000000001"))
        assertEquals(VolumeTimestamp(-1, 500000000), archive("-0.5").let { VolumeTimestamp(it.modifiedSeconds, it.modifiedNanos) })
        for (value in listOf("0", "1.123456789", "-0.000000001", "-8589934591", "8589934591.999999999")) {
            val parsed = VolumeTimestamp.parse(value)
            assertEquals(parsed, VolumeTimestamp.parse(parsed.decimal()))
        }
        for (value in listOf("-8589934591.1", "8589934592", "1.0000000001", "NaN", "1e2", "+1", ".1"))
            assertFails { VolumeTimestamp.parse(value) }
        assertFails { VolumeTimestamp(0, -1) }; assertFails { VolumeTimestamp(0, 1000000000) }
    }

    @Test fun `root PAX preserves fractional and negative time while retaining child bytes`() {
        val file = Files.createTempFile("volume-time-unit-", ".tar", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        try {
            for (time in listOf(VolumeTimestamp(123, 1), VolumeTimestamp(-1, 500000000), VolumeTimestamp(-1), VolumeTimestamp(0))) {
                val body = ByteArray(200000) { (it % 251).toByte() }
                Files.write(file, tar(member("data", data = body)))
                val size = Files.size(file)
                VolumeTar.prependRoot(file, 999, 999, 448, time.seconds, time.nanos)
                val result = VolumeTar.inspect(file, 999)
                assertEquals(time, result.first().let { VolumeTimestamp(it.modifiedSeconds, it.modifiedNanos) })
                assertEquals(ReleaseLocks.sha256(body), result.last().sha256)
                assertEquals(if (time == VolumeTimestamp(0)) 512L else VolumeTar.MAX_ROOT_PREFIX, Files.size(file) - size)
            }
        } finally { Files.delete(file) }
    }

    @Test fun `zero nanoseconds do not change legacy entry encoding`() {
        val json = kotlinx.serialization.json.Json { encodeDefaults = true }
        val entry = inspect(tar(root())).single()
        val wire = json.encodeToString(VolumeTarEntry.serializer(), entry)
        assertFalse("modifiedNanos" in wire)
        assertEquals(entry, json.decodeFromString(VolumeTarEntry.serializer(), wire))
        val changed = entry.copy(modifiedNanos = 1)
        assertEquals(changed, json.decodeFromString(VolumeTarEntry.serializer(), json.encodeToString(VolumeTarEntry.serializer(), changed)))
    }

    @Test fun `reject traversal aliases links devices privileges foreign owners duplicates and missing parents`() {
        for (name in listOf("../escape", "/absolute", "a/../b", "a//b", "a\\b", "a\nb", "a/./b", "file/"))
            assertFailsWith<Exception>(name) { inspect(tar(root(), member(name))) }
        for (kind in listOf('1','2','3','4','6','7','g','L','S'))
            assertFailsWith<IllegalArgumentException> { inspect(tar(root(), member("bad", kind))) }
        for (entry in listOf(member("bad", uid = 0), member("bad", mode = 2048), member("bad", link = "outside"),
            member("missing/child"), member("dir", '5'), member(".", '0')))
            assertFailsWith<Exception> { inspect(tar(root(), entry)) }
        assertFailsWith<IllegalArgumentException> { inspect(tar(root(), member("value"), member("./value"))) }
        assertFailsWith<IllegalArgumentException> { inspect(tar(member("file"))) }
        assertFailsWith<IllegalArgumentException> { inspect(tar(root(), member("file"), member("file/child"))) }
    }
    @Test fun `reject corrupt truncated metadata and trailing data`() {
        val valid = tar(root(), member("file"))
        for (bytes in listOf(valid.copyOf(10), valid.copyOf(valid.size - 513), valid + byteArrayOf(1),
            valid.clone().apply { this[0] = 88 }, valid.clone().apply { this[1024 + 7] = 1 }))
            assertFailsWith<Exception> { inspect(bytes) }
        for (meta in listOf(pax("GNU.sparse.map", "0,1"), pax("path", "../escape"), pax("uid", "0"), pax("mtime", "not-a-time"), pax("ctime", "9999999999"), pax("gname", "bad\nname"),
            pax("path", "value") + pax("path", "other"), "999 path=x\n".toByteArray(), "bad\n".toByteArray()))
            assertFailsWith<Exception> { inspect(tar(root(), member("meta", 'x', meta), member("file"))) }
        assertFailsWith<IllegalArgumentException> { inspect(tar(root(), member("meta", 'x', pax("path", "value")))) }
        assertFailsWith<IllegalArgumentException> { inspect(tar(root(), member("meta", 'x', pax("path", "value")), member("meta", 'x', pax("path", "value")))) }
    }
}
