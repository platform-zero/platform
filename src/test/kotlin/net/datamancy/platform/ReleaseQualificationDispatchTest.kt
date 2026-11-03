package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import kotlin.test.*

class ReleaseQualificationDispatchTest {
    // Synthetic journal records exercise transport binding only, not semantic qualification.
    private class Fixture : AutoCloseable {
        val root = Files.createTempDirectory("qualification-head-unit-").also {
            Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
        }
        val journal = root.resolve("history.jsonl")
        val trial = buildJsonObject {
            put("id", "unit-trial"); put("ordinal", 1); put("candidate", buildJsonObject { put("unit", true) })
            put("installId", "q-111111111111"); put("restoreId", "q-222222222222"); put("outcome", "RUNNING")
        }
        fun entry(sequence: Int, event: String, previous: String, value: JsonObject = trial): JsonObject {
            val blank = buildJsonObject {
                put("sequence", sequence); put("event", event); put("trial", value); put("correction", JsonNull)
                put("previousSha256", previous); put("sha256", "")
            }
            return JsonObject(blank.toMutableMap().also { it["sha256"] = JsonPrimitive(ReleaseLocks.sha256(blank.toString().toByteArray())) })
        }
        val begin = entry(1, "BEGIN", "0".repeat(64))
        val head = begin.getValue("sha256").jsonPrimitive.content
        val tail = entry(2, "FINISH", head, JsonObject(trial.toMutableMap().also { it["outcome"] = JsonPrimitive("PASSED") }))
        fun pin(name: String, value: String = "{}"): ActivationInput {
            val p = root.resolve(name); ReleasePrivateFiles.save(p, value.toByteArray())
            return ActivationInput(p.toString(), ReleaseLocks.sha256(value.toByteArray()))
        }
        val candidate = pin("candidate.json", trial.getValue("candidate").toString())
        val request = ReleaseAcceptanceInvocation("a".repeat(64), pin("products.json"), pin("manifest.json"),
            pin("evidence.json"), journal.toString(), head)
        val calls = mutableListOf<List<String>>()
        var finishEffect: () -> Unit = { append(tail) }
        var assessEffect: () -> Unit = {}
        var exitCode = 0
        val acceptance = ReleaseAcceptance(root, AcceptanceControllerProcess { args, _ ->
            calls += args
            if (args[1] == "finish-qualified") finishEffect() else assessEffect()
            RuntimeCommandResult(exitCode, "untrusted stdout is not a journal head")
        }) { _, _ -> }
        val dispatch = ReleaseQualificationDispatch(root, acceptance)
        init { ReleasePrivateFiles.save(journal, (begin.toString() + "\n").toByteArray()) }
        fun append(value: JsonObject) { Files.writeString(journal, value.toString() + "\n", java.nio.file.StandardOpenOption.APPEND) }
        fun attempts() = Files.list(root).use { paths -> paths.filter { Files.isDirectory(it) }.toList() }
        override fun close() { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `actual appended head is durably bound without trusting stdout or predicting a hash`() = Fixture().use { f ->
        assertEquals("untrusted stdout is not a journal head", f.dispatch.finishAndAssess(f.request, f.candidate))
        assertEquals(listOf("finish-qualified", "assess-qualified"), f.calls.map { it[1] })
        assertEquals(f.tail.getValue("sha256").jsonPrimitive.content, f.calls.last().last())
        assertEquals(f.candidate.path, f.calls.last()[4])
        val attempt = f.attempts().single()
        val bound = Json.decodeFromString<ReleaseAcceptanceInvocation>(Files.readString(attempt.resolve("assessment.json")))
        assertEquals(f.calls.last().last(), bound.expectedHead)
        assertTrue(Files.exists(attempt.resolve("result.json")))
        assertFails { f.dispatch.finishAndAssess(f.request, f.candidate) }
        assertEquals(2, f.calls.size)
    }
    @Test fun `legacy expected head is checked against actual append and wire remains strict`() = Fixture().use { f ->
        assertFails { f.dispatch.finishAndAssess(f.request, f.candidate, "f".repeat(64)) }
        assertEquals(1, f.calls.size)
        assertFalse(Files.exists(f.attempts().single().resolve("assessment.json")))
        val request: ReleaseRequest = ReleaseRequest.QualifyBound(f.request, f.candidate)
        val file = f.root.resolve("request.json")
        ReleasePrivateFiles.save(file, Json { classDiscriminator = "operation" }.encodeToString(request).toByteArray())
        assertEquals(request, ReleaseDispatch.read(file))
    }
    @Test fun `invalid input or stale and corrupt history refuses before any attempt`() {
        Fixture().use { f ->
            assertFails { f.dispatch.finishAndAssess(f.request, f.candidate.copy(sha256 = "0".repeat(64))) }
            assertFails { f.dispatch.finishAndAssess(f.request, f.pin("foreign-candidate.json")) }
            val failure = assertFails { f.dispatch.finishAndAssess(f.request, f.pin("malformed-candidate.json", "{unit-private-secret")) }
            assertFalse(failure.message.orEmpty().contains("unit-private-secret"))
            assertFails { f.dispatch.finishAndAssess(f.request.copy(expectedHead = "f".repeat(64)), f.candidate) }
            assertFails { f.dispatch.finishAndAssess(f.request.copy(contexts = f.candidate), f.candidate) }
            Files.writeString(f.journal, f.begin.toString())
            assertFails { f.dispatch.finishAndAssess(f.request, f.candidate) }
            Files.writeString(f.journal, f.begin.toString().replace(f.head, "0".repeat(64)) + "\n")
            assertFails { f.dispatch.finishAndAssess(f.request, f.candidate) }
            assertTrue(f.calls.isEmpty()); assertTrue(f.attempts().isEmpty())
        }
    }
    @Test fun `uncertain finish is once only even when input paths change or request changes`() = Fixture().use { f ->
        f.finishEffect = { throw InterruptedException("synthetic lost acknowledgement") }
        try {
            assertFailsWith<InterruptedException> { f.dispatch.finishAndAssess(f.request, f.candidate) }
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
        assertFails { f.dispatch.finishAndAssess(f.request.copy(input = f.pin("other-evidence.json")), f.pin("other-candidate.json", f.trial.getValue("candidate").toString())) }
        assertEquals(1, f.calls.size)
        assertTrue(Files.exists(f.attempts().single().resolve("intent.json")))
    }
    @Test fun `missing extra foreign or rewritten finish cannot authorize assessment`() {
        for (mode in listOf("missing", "extra", "foreign", "rewrite", "wrong-event")) Fixture().use { f ->
            f.finishEffect = {
                when (mode) {
                    "missing" -> Unit
                    "extra" -> { f.append(f.tail); f.append(f.entry(3, "CORRECTION", f.tail.getValue("sha256").jsonPrimitive.content)) }
                    "foreign" -> f.append(f.entry(2, "FINISH", f.head, JsonObject(f.trial.toMutableMap().also { it["installId"] = JsonPrimitive("foreign") })))
                    "rewrite" -> Files.writeString(f.journal, f.tail.toString() + "\n")
                    else -> f.append(f.entry(2, "CORRECTION", f.head))
                }
            }
            assertFails(mode) { f.dispatch.finishAndAssess(f.request, f.candidate) }
            assertEquals(1, f.calls.size)
        }
    }
    @Test fun `assessment failure and concurrent journal change retain the claim without success`() {
        for (mode in listOf("refusal", "drift")) Fixture().use { f ->
            f.assessEffect = {
                if (mode == "refusal") f.exitCode = 1
                else f.append(f.entry(3, "CORRECTION", f.tail.getValue("sha256").jsonPrimitive.content))
            }
            assertFails { f.dispatch.finishAndAssess(f.request, f.candidate) }
            assertTrue(Files.exists(f.attempts().single().resolve("assessment.json")))
            assertFalse(Files.exists(f.attempts().single().resolve("result.json")))
        }
    }
}
