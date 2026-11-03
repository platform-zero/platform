package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** Transport binding, not another qualification evaluator. Pinned Acceptance independently validates
 * semantic history/evidence during FINISH and ASSESS. Caller holds the release dispatch lock. */
internal class ReleaseQualificationDispatch(private val root: Path, private val acceptance: ReleaseAcceptance) {
    private val json = Json { encodeDefaults = true }
    private val digest = Regex("[a-f0-9]{64}")
    private val maxJournalBytes = 16 * 1024 * 1024
    private data class History(val bytes: ByteArray, val entries: List<JsonObject>) {
        val last get() = entries.last()
        val head get() = last.getValue("sha256").jsonPrimitive.content
    }
    private fun history(path: Path): History = try {
        val bytes = ReleasePrivateFiles.read(path, maxJournalBytes)
        require(bytes.isNotEmpty() && bytes.last() == 10.toByte()) { "Incomplete qualification journal" }
        val lines = bytes.decodeToString(throwOnInvalidSequence = true).dropLast(1).split('\n')
        require(lines.size in 1..10000)
        var previous = "0".repeat(64)
        val entries = lines.mapIndexed { index, line ->
            val entry = json.parseToJsonElement(line).jsonObject
            require(entry.keys == setOf("sequence", "event", "trial", "correction", "previousSha256", "sha256") &&
                entry.getValue("sequence").jsonPrimitive.int == index + 1 &&
                entry.getValue("event").jsonPrimitive.content in setOf("BEGIN", "FINISH", "CORRECTION") &&
                entry.getValue("previousSha256").jsonPrimitive.content == previous) { "Qualification history binding mismatch" }
            require(entry.getValue("event") == JsonPrimitive("CORRECTION") || entry.getValue("trial") is JsonObject) {
                "Qualification trial object required"
            }
            val head = entry.getValue("sha256").jsonPrimitive.content
            val unstamped = JsonObject(entry.toMutableMap().also { it["sha256"] = JsonPrimitive("") })
            require(digest.matches(head) && ReleaseLocks.sha256(unstamped.toString().toByteArray()) == head) {
                "Qualification history digest mismatch"
            }
            previous = head
            entry
        }
        History(bytes, entries)
    } catch (_: IllegalArgumentException) {
        throw IllegalArgumentException("Invalid qualification transport history; private contents withheld")
    }
    fun finishAndAssess(finish: ReleaseAcceptanceInvocation, candidate: ActivationInput,
        legacyExpectedHead: String? = null): String {
        require(finish.artifacts == null && finish.contexts == null)
        val assessment = finish.copy(input = candidate)
        // All pinned distributions and inputs must exist before claiming or invoking FINISH.
        acceptance.preflight("finish-qualified", finish)
        acceptance.preflight("assess-qualified", assessment)
        val journal = Path.of(finish.journal)
        val before = history(journal)
        require(before.head == finish.expectedHead && before.last.getValue("event") == JsonPrimitive("BEGIN")) {
            "Qualification requires exact pending BEGIN"
        }
        val identity = before.last.getValue("trial").jsonObject
        val candidateBytes = ReleasePrivateFiles.read(Path.of(candidate.path))
        val candidateValue = try {
            json.parseToJsonElement(candidateBytes.decodeToString(throwOnInvalidSequence = true))
        } catch (_: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid assessment candidate; private contents withheld")
        }
        require(ReleaseLocks.sha256(candidateBytes) == candidate.sha256 && candidateValue == identity["candidate"]) {
            "Assessment candidate differs from pending trial"
        }
        // Identity is journal + BEGIN, not caller-chosen request/candidate paths. Changed requests
        // cannot evade an uncertain attempt. CREATE_NEW directory is itself a durable no-replay claim.
        val id = ReleaseLocks.sha256((journal.toRealPath().toString() + "\n" + before.head).toByteArray())
        val attempt = root.resolve("qualification-$id")
        Files.createDirectory(attempt, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.sync(root)
        ReleasePrivateFiles.save(attempt.resolve("intent.json"), buildJsonObject {
            put("schemaVersion", 1); put("finish", json.encodeToJsonElement(finish))
            put("candidate", json.encodeToJsonElement(candidate)); put("journalSha256", ReleaseLocks.sha256(before.bytes))
        }.toString().toByteArray())
        acceptance.run("finish-qualified", finish) // stdout is deliberately not authority for the new head.
        val after = history(journal)
        require(after.bytes.size > before.bytes.size && after.bytes.copyOfRange(0, before.bytes.size).contentEquals(before.bytes) &&
            after.entries.size == before.entries.size + 1 && after.last.getValue("event") == JsonPrimitive("FINISH")) {
            "FINISH did not append exactly one bound record"
        }
        val finished = after.last.getValue("trial").jsonObject
        require(listOf("id", "ordinal", "candidate", "installId", "restoreId").all {
            identity.containsKey(it) && finished[it] == identity[it]
        }) { "FINISH changed trial identity" }
        require(legacyExpectedHead == null || legacyExpectedHead == after.head) { "Legacy assessment head differs from actual FINISH" }
        val bound = assessment.copy(expectedHead = after.head)
        ReleasePrivateFiles.save(attempt.resolve("assessment.json"), json.encodeToString(bound).toByteArray())
        val result = acceptance.run("assess-qualified", bound)
        require(ReleasePrivateFiles.read(journal, maxJournalBytes).contentEquals(after.bytes)) { "Qualification changed during assessment" }
        ReleasePrivateFiles.save(attempt.resolve("result.json"), buildJsonObject {
            put("schemaVersion", 1); put("journalHead", after.head)
            put("journalSha256", ReleaseLocks.sha256(after.bytes)); put("assessmentOutputSha256", ReleaseLocks.sha256(result.toByteArray()))
        }.toString().toByteArray())
        return result
    }
}
