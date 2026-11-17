package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path

/** Immutable maintenance intents/completions. Every caller holds the schedule lock. No timeout,
 * deletion, fresh-operation escape or caller-controlled unpause can clear an incomplete intent. */
internal object RssMaintenance {
    private val operation = Regex("[a-z][a-z0-9-]{0,63}")
    private val record = Regex("maintenance-([a-z][a-z0-9-]{0,63})\\.(intent|complete)")
    private fun bytes(expected: String, id: String): ByteArray {
        require(expected.matches(Regex("[a-f0-9]{64}")) && operation.matches(id))
        return "p0v3-rss-maintenance-v1\n$expected\n$id\n".toByteArray()
    }
    fun requireClear(root: Path, expected: String) {
        ReleasePrivateFiles.directory(root)
        val names = Files.list(root).use { paths -> paths.filter { it.fileName.toString().startsWith("maintenance-") }
            .limit(20001).map { it.fileName.toString() }.toList() }
        require(names.size <= 20000) { "RSS maintenance history full" }
        val groups = names.map { requireNotNull(record.matchEntire(it)) { "Unknown RSS maintenance record" } }
            .groupBy { it.groupValues[1] }
        for ((id, records) in groups) {
            require(records.map { it.groupValues[2] }.toSet() == setOf("intent", "complete")) {
                "Incomplete RSS maintenance; publication and fresh operations refused"
            }
            val expectedBytes = bytes(expected, id)
            for (item in records) require(ReleasePrivateFiles.read(root.resolve(item.value)).contentEquals(expectedBytes)) {
                "Foreign RSS maintenance record"
            }
        }
    }
    fun claim(root: Path, expected: String, id: String) {
        val value = bytes(expected, id)
        requireClear(root, expected)
        require(!Files.exists(root.resolve("maintenance-$id.complete"), NOFOLLOW_LINKS)) { "RSS maintenance operation already completed" }
        ReleasePrivateFiles.save(root.resolve("maintenance-$id.intent"), value)
    }
    fun pending(root: Path, expected: String, id: String): String {
        val value = bytes(expected, id)
        require(ReleasePrivateFiles.read(root.resolve("maintenance-$id.intent")).contentEquals(value) &&
            !Files.exists(root.resolve("maintenance-$id.complete"), NOFOLLOW_LINKS)) {
            "Missing or completed RSS held-operation claim"
        }
        val other = Files.list(root).use { paths -> paths.filter {
            it.fileName.toString().startsWith("maintenance-") && it.fileName.toString() != "maintenance-$id.intent"
        }.limit(20001).toList() }
        require(other.size <= 20000 && other.none { it.fileName.toString().endsWith(".intent") &&
            !Files.exists(root.resolve(it.fileName.toString().removeSuffix(".intent") + ".complete"), NOFOLLOW_LINKS) }) {
            "Multiple incomplete RSS maintenance intents"
        }
        return ReleaseLocks.sha256(value)
    }
    fun complete(root: Path, expected: String, id: String) {
        val value = bytes(expected, id)
        require(ReleasePrivateFiles.read(root.resolve("maintenance-$id.intent")).contentEquals(value)) {
            "RSS maintenance claim changed"
        }
        ReleasePrivateFiles.save(root.resolve("maintenance-$id.complete"), value)
        requireClear(root, expected)
    }
}
