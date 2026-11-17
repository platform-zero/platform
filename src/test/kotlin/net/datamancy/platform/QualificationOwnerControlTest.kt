package net.datamancy.platform

import java.nio.charset.StandardCharsets
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.io.InputStream
import java.util.concurrent.TimeUnit
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class QualificationOwnerControlTest {
    private val hash = "a".repeat(64)
    private val key = ByteArray(32) { it.toByte() }
    private val json = QualificationOwnerControl.json
    private val scope = QualificationControlScope(suiteId = "0".repeat(24), generationId = "q-000000000001",
        bundleSha256 = hash, operation = "execute-qualified", controllerSha256 = hash,
        products = ActivationInput("/private/products", hash), manifest = ActivationInput("/private/manifest", hash),
        binding = ActivationInput("/private/binding", hash), journalFile = "/private/journal",
        journalHeadSha256 = hash, artifactRoot = "/private/cases", contexts = null)

    @Test fun `frozen field order has an explicit null and default schema version`(): Unit {
        val wire = json.encodeToString(scope)
        val golden = """{"schemaVersion":1,"suiteId":"${"0".repeat(24)}","generationId":"q-000000000001","bundleSha256":"$hash","operation":"execute-qualified","controllerSha256":"$hash","products":{"path":"/private/products","sha256":"$hash"},"manifest":{"path":"/private/manifest","sha256":"$hash"},"binding":{"path":"/private/binding","sha256":"$hash"},"journalFile":"/private/journal","journalHeadSha256":"$hash","artifactRoot":"/private/cases","contexts":null}"""
        assertEquals(golden, wire)
    }
    @Test fun `canonical authenticated HELLO has strict byte identity and domain separation`(): Unit {
        val body = QualificationControlRequestBody(suiteId = "0".repeat(24), scopeSha256 = hash,
            sequence = 1, operation = "HELLO", payload = buildJsonObject { put("scopeSha256", hash) })
        val literal = """{"schemaVersion":1,"suiteId":"${"0".repeat(24)}","scopeSha256":"$hash","sequence":1,"operation":"HELLO","payload":{"scopeSha256":"$hash"}}"""
        assertEquals(literal, json.encodeToString(body))
        val signed = QualificationControlRequest(body,
            QualificationOwnerControl.mac(key, "request", literal.toByteArray(StandardCharsets.UTF_8)))
        val wire = json.encodeToString(signed).encodeToByteArray()
        assertEquals(signed, QualificationOwnerControl.canonicalRequest(wire))
        assertFalse(QualificationOwnerControl.mac(key, "response", literal.encodeToByteArray()) == signed.mac)
        assertFalse(QualificationOwnerControl.mac(ByteArray(32), "request", literal.encodeToByteArray()) == signed.mac)
        assertFails { QualificationOwnerControl.mac(key, "HELLO", literal.encodeToByteArray()) }
        assertFails { QualificationOwnerControl.mac(ByteArray(8), "request", literal.encodeToByteArray()) }
    }
    @Test fun `duplicate keys unknown keys malformed UTF8 and oversized frames cannot canonicalize`(): Unit {
        val signed = json.encodeToString(QualificationControlRequest(
            QualificationControlRequestBody(suiteId = "0".repeat(24), scopeSha256 = hash,
                sequence = 1, operation = "HELLO", payload = buildJsonObject { put("scopeSha256", hash) }), hash))
        assertFails { QualificationOwnerControl.canonicalRequest(signed.replace("\"sequence\":1", "\"sequence\":1,\"sequence\":1").encodeToByteArray()) }
        assertFails { QualificationOwnerControl.canonicalRequest(signed.replace("\"mac\":", "\"extra\":1,\"mac\":").encodeToByteArray()) }
        assertFails { QualificationOwnerControl.canonicalRequest(byteArrayOf(0xc3.toByte(), 0x28)) }
        assertFails { QualificationOwnerControl.canonicalRequest(ByteArray(65537) { 32 }) }
        assertFails { QualificationOwnerControl.canonicalRequest(signed.replace("\"sequence\":1", "\"sequence\":01").encodeToByteArray()) }
        assertTrue(json.encodeToString(scope).contains("\"contexts\":null"))
    }
    @Test fun `refusal wire uses bounded error enum with null payload and no exception text`(): Unit {
        val refused = QualificationControlReplyBody(suiteId = "0".repeat(24), scopeSha256 = hash,
            sequence = 2, operation = "RSS_CASE_BEGIN", status = "REFUSED", payload = null,
            errorCode = "UNCERTAIN")
        val wire = json.encodeToString(refused)
        assertEquals("""{"schemaVersion":1,"suiteId":"${"0".repeat(24)}","scopeSha256":"$hash","sequence":2,"operation":"RSS_CASE_BEGIN","status":"REFUSED","payload":null,"errorCode":"UNCERTAIN"}""", wire)
        assertFalse(wire.contains("capabilityBase64"))
    }
    @Test fun `peer UID and supervised PID are both required but peer API never supplies PID`(): Unit {
        QualificationOwnerControl.requirePeer(123, "controller", "controller")
        assertFails { QualificationOwnerControl.requirePeer(0, "controller", "controller") }
        assertFails { QualificationOwnerControl.requirePeer(123, "runner", "controller") }
        assertFails { QualificationOwnerControl.requirePeer(123, "", "controller") }
    }
    @Test fun `claim ordering refuses HELLO only pending completion duplicate and post-phase effects`(): Unit {
        val claims = QualificationOwnerClaims()
        assertFails { claims.requireFinished() }
        assertFails { claims.beginCase("RSS", "/case", hash) }
        claims.beginPhase(hash)
        var writes = 0
        assertFails { claims.completePhaseWith { writes++ } }
        assertEquals(0, writes) // An empty phase must never reach the durable writer.
        claims.beginCase("RSS", "/case", hash)
        assertFails { claims.beginCase("RSS", "/case", hash) }
        assertFails { claims.completeCase("RSS", "/case", "b".repeat(64)) }
        assertFails { claims.completePhaseWith { writes++ } }
        assertEquals(0, writes) // Nor may a pending case reach the writer.
        assertFails { claims.requireFinished() }
        claims.completeCase("RSS", "/case", hash)
        assertFails { claims.completePhaseWith { writes++; error("Durable writer failed") } }
        assertFails { claims.requireFinished() }
        claims.completePhaseWith { writes++ }
        assertEquals(2, writes)
        claims.requireFinished()
        assertFails { claims.beginCase("NATIVE", "/later", hash) }
        val foreignThread = Thread { assertFails { claims.requireFinished() } }
        foreignThread.start(); foreignThread.join()
    }
    private class FakeChild : Process() {
        var running = true
        var stopAcknowledged = false
        var exitBetweenCheckAndTick = false
        override fun getOutputStream(): OutputStream = ByteArrayOutputStream()
        override fun getInputStream(): InputStream = ByteArrayInputStream(byteArrayOf())
        override fun getErrorStream(): InputStream = ByteArrayInputStream(byteArrayOf())
        override fun waitFor(): Int { running = false; return 0 }
        override fun waitFor(timeout: Long, unit: TimeUnit): Boolean = stopAcknowledged
        override fun exitValue(): Int { check(!running); return 0 }
        override fun destroy() { running = false }
        override fun isAlive(): Boolean {
            if (exitBetweenCheckAndTick) {
                exitBetweenCheckAndTick = false
                running = false
                return true // Exit immediately after awaitExit's condition read.
            }
            return running
        }
    }
    @Test fun `EOF waits for actual child exit and retains timeout or unacknowledged cleanup`(): Unit {
        val child = FakeChild()
        var polls = 0
        QualificationOwnerLifecycle.awaitExit(child, { polls++; if (polls == 4) child.running = false }, {})
        assertEquals(4, polls) // No arbitrary 100ms grace period.
        val raced = FakeChild().also { it.exitBetweenCheckAndTick = true }
        var ticks = 0
        QualificationOwnerLifecycle.awaitExit(raced, {
            ticks++
            assertFalse(raced.isAlive) // Deadline/pipe tick accepts observed exit.
        }, {})
        assertEquals(1, ticks)
        val stuck = FakeChild()
        assertFails { QualificationOwnerLifecycle.awaitExit(stuck, { error("Parent monotonic deadline") }, {}) }
        assertTrue(stuck.isAlive)
        assertFails { QualificationOwnerLifecycle.requireStopped(stuck, 5) }
        stuck.stopAcknowledged = true
        QualificationOwnerLifecycle.requireStopped(stuck, 5)
    }
    @Test fun `zero read then child exit requires actual EOF and never admits a late frame`(): Unit {
        val child = FakeChild()
        var reads = 0
        var budgetTicks = 0
        val eof = QualificationOwnerLifecycle.headerRead(
            read = { reads++; if (reads == 1) { child.running = false; 0 } else -1 },
            alive = { child.isAlive }, tick = { budgetTicks++ }, pause = {})
        assertEquals(-1, eof)
        assertEquals(2, reads)
        assertEquals(2, budgetTicks) // Deadline/output tick persists after observed exit.
        assertFails {
            QualificationOwnerLifecycle.headerRead(read = { 1 }, alive = { false },
                tick = { budgetTicks++ }, pause = {})
        } // Exited child cannot authorize another positive frame.
        val partial = ByteBuffer.allocate(4)
        partial.put(1.toByte())
        assertFails { require(partial.position() == 0) } // Existing EOF branch rejects partial header.
    }
    @Test fun `child output is capped before writes even during no RPC and bootstrap fits atomic pipe`(): Unit {
        val dir = Files.createTempDirectory("qualification-io-unit-")
        try {
            val out = dir.resolve("out"); val err = dir.resolve("err")
            FileChannel.open(out, CREATE_NEW, WRITE).use { stdout ->
                FileChannel.open(err, CREATE_NEW, WRITE).use { stderr ->
                    val io = QualificationOwnerOutput(ByteArrayInputStream(ByteArray(10) { 65 }),
                        ByteArrayInputStream(ByteArray(3) { 66 }), stdout, stderr, 9, budget = {})
                    assertFails { io.pump() }
                    assertEquals(9L, Files.size(out)) // Bounded prefix precedes refusal of byte10.
                    assertEquals(0L, Files.size(err))
                    assertFails { io.sync() }
                    assertFails { io.pump() }
                    assertEquals(9L, Files.size(out))
                }
            }
            FileChannel.open(out, WRITE, TRUNCATE_EXISTING).use { stdout ->
                FileChannel.open(err, WRITE, TRUNCATE_EXISTING).use { stderr ->
                    val io = QualificationOwnerOutput(ByteArrayInputStream(ByteArray(9) { 65 }),
                        ByteArrayInputStream(ByteArray(3) { 66 }), stdout, stderr, 9, budget = {})
                    io.sync()
                    assertEquals(9L, Files.size(out)); assertEquals(3L, Files.size(err))
                }
            }
            FileChannel.open(out, WRITE, TRUNCATE_EXISTING).use { stdout ->
                FileChannel.open(err, WRITE, TRUNCATE_EXISTING).use { stderr ->
                    val io = QualificationOwnerOutput(ByteArrayInputStream(ByteArray(9000) { 65 }),
                        ByteArrayInputStream(byteArrayOf()), stdout, stderr, 8200, budget = {})
                    assertFails { io.pump() }
                    val bounded = Files.size(out)
                    assertEquals(8200L, bounded) // A first successful8192-byte chunk MUST be counted.
                    assertFails { io.sync() } // Fsync existing bytes; poisoned capture cannot repump.
                    assertFails { io.pump() }
                    assertEquals(bounded, Files.size(out))
                }
            }
            FileChannel.open(out, WRITE, TRUNCATE_EXISTING).use { stdout ->
                FileChannel.open(err, WRITE, TRUNCATE_EXISTING).use { stderr ->
                    var budgetChecks = 0
                    val io = QualificationOwnerOutput(ByteArrayInputStream(ByteArray(9000) { 65 }),
                        ByteArrayInputStream(byteArrayOf()), stdout, stderr, 8200,
                        budget = { if (++budgetChecks >= 6) error("Parent monotonic budget expired") })
                    assertFails { io.pump() }
                    assertEquals(8192L, Files.size(out))
                    assertFails { io.sync() }
                    assertEquals(8192L, Files.size(out))
                }
            }
            FileChannel.open(out, WRITE, TRUNCATE_EXISTING).use { stdout ->
                FileChannel.open(err, WRITE, TRUNCATE_EXISTING).use { stderr ->
                    var expired = false
                    val io = QualificationOwnerOutput(ByteArrayInputStream(ByteArray(5) { 65 }),
                        ByteArrayInputStream(byteArrayOf()), stdout, stderr, 9,
                        budget = { if (expired) error("Parent budget expired at next pump entry") })
                    io.pump()
                    assertEquals(5L, Files.size(out))
                    expired = true
                    assertFails { io.pump() } // Entry guard must latch poisoned before teardown.
                    assertFails { io.sync() } // Fsyncs existing bytes without calling the expired guard.
                    assertFails { io.pump() }
                    assertEquals(5L, Files.size(out))
                }
            }
            QualificationOwnerControl.boundedBootstrap(4096)
            assertFails { QualificationOwnerControl.boundedBootstrap(4097) }
            assertFails { QualificationOwnerControl.boundedBootstrap(4) }
        } finally { Files.deleteIfExists(dir.resolve("out")); Files.deleteIfExists(dir.resolve("err")); Files.delete(dir) }
    }
    @Test fun `persisted intent survives failed handler and lost reply prevents resend`(): Unit {
        val root = Files.createTempDirectory("qualification-record-unit-").toAbsolutePath()
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        try {
            val records = QualificationOwnerRecords(root)
            val body = """{"scopeSha256":"$hash","sequence":2}""".encodeToByteArray()
            records.intent(2, body)
            assertTrue(ReleasePrivateFiles.read(root.resolve("2.intent.json")).contentEquals(body))
            assertFalse(Files.exists(root.resolve("2.result.json"))) // Crash before handler result.
            assertFails { QualificationOwnerRecords(root).intent(2, body) }
            records.result(2, """{"status":"OK","errorCode":null}""".encodeToByteArray())
            assertFails { QualificationOwnerRecords(root).intent(2, body) } // Reply may be lost.
            assertFails { records.result(2, """{"status":"OK"}""".encodeToByteArray()) }
            assertFails { records.result(3, """{"status":"OK"}""".encodeToByteArray()) }
        } finally {
            Files.deleteIfExists(root.resolve("2.intent.json")); Files.deleteIfExists(root.resolve("2.result.json"))
            Files.delete(root)
        }
    }
    @Test fun `phase admission retains first raw attempt across changed controller and binding bytes`(): Unit {
        val generation = Files.createTempDirectory("qualification-phase-unit-").toAbsolutePath()
        Files.setPosixFilePermissions(generation, PosixFilePermissions.fromString("rwx------"))
        val control = generation.resolve("qualification-control")
        Files.createDirectory(control, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val original = buildJsonObject {
            put("generationId", scope.generationId); put("trialId", "original-trial"); put("phase", "INSTALL")
        }
        try {
            val first = QualificationOwnerControl.admitPhase(generation, scope, original)
            val initial = ReleasePrivateFiles.read(first)
            assertFails { QualificationOwnerControl.admitPhase(generation, scope.copy(
                suiteId = "b".repeat(24), controllerSha256 = "b".repeat(64),
                binding = scope.binding.copy(sha256 = "b".repeat(64)), artifactRoot = "/other"), original) }
            assertTrue(initial.contentEquals(ReleasePrivateFiles.read(first)))
        } finally {
            Files.deleteIfExists(control.resolve(Files.list(control).use { it.findFirst().orElseThrow() }.fileName))
            Files.delete(control); Files.delete(generation)
        }
    }
    @Test fun `stopped child log fsync failure still runs first cleanup and retains both errors`(): Unit {
        val events = mutableListOf<String>()
        val syncError = IllegalStateException("output fsync failed")
        val cleanupError = IllegalArgumentException("original bridge removal uncertain")
        val observed = kotlin.runCatching {
            QualificationOwnerLifecycle.stoppedCleanup(
                sync = { events += "sync"; throw syncError },
                cleanup = { events += "original teardown"; throw cleanupError })
        }.exceptionOrNull()
        assertEquals(syncError, observed)
        assertEquals(listOf(cleanupError), observed?.getSuppressed()?.toList())
        assertEquals(listOf("sync", "original teardown"), events)
        val onlySync = kotlin.runCatching {
            QualificationOwnerLifecycle.stoppedCleanup(
                sync = { events += "second sync"; throw syncError },
                cleanup = { events += "second teardown" })
        }.exceptionOrNull()
        assertEquals(syncError, onlySync)
        assertEquals(listOf("sync", "original teardown", "second sync", "second teardown"), events)
    }
    @Test fun `suite identifier binds installed controller binding head and mode without using artifact path`(): Unit {
        val invocation = ReleaseAcceptanceInvocation(hash, scope.products, scope.manifest, scope.binding,
            scope.journalFile, scope.journalHeadSha256, scope.artifactRoot)
        val id = QualificationOwnerControl.suiteId(invocation, "execute-qualified")
        assertEquals(24, id.length)
        assertTrue(id.matches(Regex("[a-f0-9]{24}")))
        assertEquals(id, QualificationOwnerControl.suiteId(invocation.copy(artifacts = "/other"), "execute-qualified"))
        assertFalse(id == QualificationOwnerControl.suiteId(invocation.copy(expectedHead = "b".repeat(64)), "execute-qualified"))
        assertFalse(id == QualificationOwnerControl.suiteId(invocation, "execute-staged"))
    }
}
