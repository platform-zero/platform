package net.datamancy.platform

import java.nio.file.Files
import java.time.Instant
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import kotlin.test.*

class WeeklyFunctionalVerifierTest {
    private val hash = "a".repeat(64)
    private val now = Instant.parse("2026-01-04T04:00:00Z")
    private val oracle = buildJsonObject { put("historicalObject", "original-independent-value") }
    private val case = WeeklyFunctionalCase("fixture", "forgejo", "native", "restore", "native", "/unit/adapter.py", hash,
        setOf("historical-readback"), buildJsonObject {}, oracle)
    private val plan = WeeklyFunctionalPlan(candidate = buildJsonObject {
        for (key in listOf("implementationSha256", "artifactsSha256", "configurationSha256", "acceptanceSha256", "sitePolicySha256")) put(key, hash)
    }, cases = listOf(case))
    private val snapshot = KopiaSnapshotReceipt(id = "cap-111111111111", generation = "q-abcdef123456", bundleSha256 = hash,
        snapshotId = "b".repeat(32), rootObjectId = "k" + "b".repeat(32), manifestSha256 = hash, files = 1,
        plaintextBytes = 10, image = "example.test/kopia@sha256:$hash", imageId = hash)
    private val request = WeeklyFunctionalRequest("cap-222222222222", snapshot, "q-222222222222", hash, setOf("fixture:historical-readback"))
    @Test fun `real protocol validates exact original oracle assertions artifacts and invocation`() {
        for (fault in listOf("none", "url", "oracle", "assertion", "artifact", "invocation", "timeout", "request",
            "schema", "extra-assertion", "reserved", "escape", "digest", "empty-artifacts", "symlink", "missing-artifact", "interrupted")) {
            val activePlan = if (fault == "url") plan.copy(cases = listOf(case.copy(context = buildJsonObject {
                put("url", "https://unit.invalid/readback"); put("generation", "foreign-context-generation")
            }))) else plan
            val root = Files.createTempDirectory("weekly-functional-unit-")
            var at = now
            val verifier = WeeklyFunctionalVerifier({ at }) { _, input, output, _ ->
                val inputValue = Json.parseToJsonElement(ReleasePrivateFiles.read(input).decodeToString()).jsonObject
                val invocation = inputValue.getValue("invocation").jsonObject
                assertEquals("RESTORE", invocation.getValue("binding").jsonObject.getValue("phase").jsonPrimitive.content)
                assertEquals(request.target, inputValue.getValue("context").jsonObject.getValue("generation").jsonPrimitive.content)
                assertEquals(if (fault == "url") JsonPrimitive("https://unit.invalid/readback") else JsonNull, inputValue["url"])
                val bytes = "actual unit native artifact".toByteArray()
                ReleasePrivateFiles.save(output.parent.resolve("readback.json"), bytes)
                val artifactName = when (fault) {
                    "reserved" -> "request.json"
                    "escape" -> "../escape.json"
                    "symlink" -> "linked.json"
                    "missing-artifact" -> "missing.json"
                    else -> "readback.json"
                }
                if (fault == "symlink") Files.createSymbolicLink(output.parent.resolve(artifactName), output.parent.resolve("readback.json"))
                val report = buildJsonObject {
                    put("schemaVersion", if (fault == "schema") 2 else 1)
                    put("invocationId", if (fault == "invocation") "other" else invocation.getValue("invocationId").jsonPrimitive.content)
                    put("assertions", buildJsonObject {
                        put("historical-readback", fault != "assertion")
                        if (fault == "extra-assertion") put("unrequested", true)
                    })
                    put("oracle", if (fault == "oracle") buildJsonObject { put("historicalObject", "new fixture") } else oracle)
                    put("artifacts", buildJsonObject {
                        if (fault != "empty-artifacts") put(artifactName,
                            if (fault == "digest") "invalid" else if (fault == "artifact") hash else ReleaseLocks.sha256(bytes))
                    })
                }
                ReleasePrivateFiles.save(output, Json.encodeToString(report).toByteArray())
                if (fault == "timeout") at = now.plusSeconds(28800)
                if (fault == "request") Files.writeString(input, "changed")
                if (fault == "interrupted") Thread.currentThread().interrupt()
            }
            try {
                if (fault in setOf("none", "url")) {
                    val result = verifier.verify(activePlan, request, root, now.plusSeconds(28800))
                    assertTrue(result.passed); assertEquals(request.requiredAssertions, result.assertions)
                    assertTrue(Files.exists(root.resolve("functional-fixture/verified.json")))
                    assertFails { verifier.verify(plan, request, root, now.plusSeconds(28800)) }
                } else {
                    assertFails { verifier.verify(activePlan, request, root, now.plusSeconds(28800)) }
                    assertFalse(Files.exists(root.resolve("functional-fixture/verified.json")))
                }
            } finally { Thread.interrupted(); Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
        }
    }
    @Test fun `program transport scrubs environment and retains timeout failure and interruption without retry`() {
        for (fault in listOf("none", "timeout", "exit", "interrupt", "expired", "pin")) {
            val root = Files.createTempDirectory("weekly-transport-unit-")
            var starts = 0
            var checked = false
            var destroyed = false
            val process = object : Process() {
                override fun getOutputStream() = java.io.ByteArrayOutputStream()
                override fun getInputStream() = java.io.InputStream.nullInputStream()
                override fun getErrorStream() = java.io.InputStream.nullInputStream()
                override fun waitFor(): Int = error("Unbounded wait forbidden")
                override fun waitFor(timeout: Long, unit: java.util.concurrent.TimeUnit): Boolean {
                    assertEquals(60L, timeout); assertEquals(java.util.concurrent.TimeUnit.SECONDS, unit)
                    if (fault == "interrupt") throw InterruptedException("unit interrupted wait")
                    return fault != "timeout"
                }
                override fun exitValue() = if (fault == "exit") 9 else 0
                override fun destroy() { destroyed = true }
                override fun descendants(): java.util.stream.Stream<ProcessHandle> = java.util.stream.Stream.empty()
            }
            try {
                val invoke = {
                    WeeklyFunctionalVerifier.executeProgram(case, root.resolve("request.json"), root.resolve("result.json"),
                        if (fault == "expired") now else now.plusSeconds(60), { now }, {
                            checked = true
                            if (fault == "pin") error("unit changed program pin")
                        }, { builder ->
                            assertTrue(checked); starts++
                            assertEquals(listOf("/usr/bin/python3", "-I", case.adapter, "--request", root.resolve("request.json").toString(),
                                "--result", root.resolve("result.json").toString()), builder.command())
                            assertEquals(setOf("PATH", "JAVA_HOME", "LANG"), builder.environment().keys)
                            assertEquals(root.resolve("adapter.stdout").toFile(), builder.redirectOutput().file())
                            assertEquals(root.resolve("adapter.stderr").toFile(), builder.redirectError().file())
                            assertEquals(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"),
                                Files.getPosixFilePermissions(root.resolve("adapter.stdout")))
                            process
                        })
                }
                if (fault == "none") invoke() else if (fault == "interrupt") assertFailsWith<InterruptedException> { invoke() } else assertFails { invoke() }
                assertTrue(checked)
                assertEquals(if (fault in setOf("expired", "pin")) 0 else 1, starts)
                assertEquals(fault in setOf("timeout", "exit", "interrupt"), destroyed)
                assertFalse(Files.exists(root.resolve("result.json")))
            } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
        }
    }
    @Test fun `deadline and interruption stop before allocating a functional invocation`() {
        for (interrupt in listOf(false, true)) {
            val root = Files.createTempDirectory("weekly-preflight-unit-")
            var calls = 0
            val verifier = WeeklyFunctionalVerifier({ now }) { _, _, _, _ -> calls++ }
            try {
                if (interrupt) Thread.currentThread().interrupt()
                assertFails { verifier.verify(plan, request, root, if (interrupt) now.plusSeconds(60) else now) }
                assertEquals(0, calls)
                assertEquals(0L, Files.list(root).use { it.count() })
            } finally { Thread.interrupted(); Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
        }
    }
    @Test fun `real verifier refuses mutable unit owned adapter before any process is started`() {
        val root = Files.createTempDirectory("weekly-untrusted-program-unit-")
        val attempt = Files.createTempDirectory(root, "attempt-")
        val adapter = Files.createTempFile(root, "adapter-", ".py")
        Files.writeString(adapter, "raise SystemExit('unit program must never execute')\n")
        val untrusted = plan.copy(cases = listOf(case.copy(adapter = adapter.toString(), adapterSha256 = RecoveryCapsule.fileHash(adapter))))
        try {
            assertFails { WeeklyFunctionalVerifier.validateInstalled(untrusted) }
            assertFails { WeeklyFunctionalVerifier.real().verify(untrusted, request, attempt, Instant.now().plusSeconds(60)) }
            assertFalse(Files.exists(attempt.resolve("functional-fixture/adapter.stdout")))
            assertFalse(Files.exists(attempt.resolve("functional-fixture/verified.json")))
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `missing duplicate unpinned or assertion incomplete plan fails before invocation`() {
        assertFails { WeeklyFunctionalVerifier.validate(plan.copy(cases = emptyList()), request.requiredAssertions) }
        assertFails { WeeklyFunctionalVerifier.validate(plan.copy(cases = listOf(case, case)), request.requiredAssertions) }
        assertFails { WeeklyFunctionalVerifier.validate(plan.copy(cases = listOf(case.copy(adapterSha256 = "bad"))), request.requiredAssertions) }
        assertFails { WeeklyFunctionalVerifier.validate(plan.copy(cases = listOf(case.copy(sourceOracle = buildJsonObject {}))), request.requiredAssertions) }
        assertFails { WeeklyFunctionalVerifier.validate(plan, emptySet()) }
        assertFails { WeeklyFunctionalVerifier.validate(plan.copy(schemaVersion = 2), request.requiredAssertions) }
        assertFails { WeeklyFunctionalVerifier.candidateHash(plan.copy(candidate = buildJsonObject {})) }
        assertFails { WeeklyFunctionalVerifier.candidateHash(plan.copy(candidate = JsonObject(plan.candidate + ("implementationSha256" to JsonPrimitive("invalid"))))) }
        for (invalid in listOf(case.copy(serviceId = "backup-restore"), case.copy(surface = "android"), case.copy(variant = "api34"),
            case.copy(adapter = "relative.py"), case.copy(adapter = "/unit/../adapter.py"), case.copy(adapter = "/unit/program.sh"),
            case.copy(assertions = emptySet()), case.copy(assertions = setOf("bad assertion")))) {
            assertFails { WeeklyFunctionalVerifier.validate(plan.copy(cases = listOf(invalid)), request.requiredAssertions) }
        }
    }
}
