package net.datamancy.platform

import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions
import java.util.Comparator
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class QualificationCaseSpoolTest {
    private val invocation = "case-00000000-0000-0000-0000-000000000001"
    private val json = Json { encodeDefaults = true; explicitNulls = true; ignoreUnknownKeys = false }
    private val dmode = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
    private val fmode = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))
    private fun directory(parent: Path, name: String) = Files.createDirectory(parent.resolve(name), dmode)
    private fun ready(path: Path) {
        FileChannel.open(path, setOf(CREATE_NEW, WRITE), fmode).use { it.force(true) }
        ReleasePrivateFiles.sync(path.parent)
    }
    private fun offered(case: Path, sequence: Int, family: String = "OFFICE_CALLBACK"): ActivationInput {
        val stem = sequence.toString().padStart(8, '0')
        val file = case.resolve("control-requests/$stem.json")
        val request = QualificationSpoolRequest(1, invocation, sequence, family,
            buildJsonObject { put("action", "READ_LEDGER"); put("operationKey", "office-callback-v2:${"a".repeat(64)}") })
        val raw = json.encodeToString(request).encodeToByteArray()
        ReleasePrivateFiles.save(file, raw)
        ready(file.resolveSibling("$stem.ready"))
        return ActivationInput(file.toString(), ReleaseLocks.sha256(raw))
    }
    private fun fixture(test: (Path, Path, QualificationCaseSpool) -> Unit) {
        val base = Files.createTempDirectory("q-spool-unit-").toAbsolutePath()
        Files.setPosixFilePermissions(base, PosixFilePermissions.fromString("rwx------"))
        val case = directory(base, "case")
        directory(case, "control-requests"); directory(case, "control-results")
        val control = directory(base, "control")
        try { test(case, control, QualificationCaseSpool(case, control, invocation)) }
        finally { Files.walk(base).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) } } }
    }
    private fun actor(request: QualificationSpoolRequest, digest: String): OwnerCaseNativeReply =
        OwnerCaseNativeReply(invocation, request.family, digest,
            buildJsonObject { put("operationKey", request.request.getValue("operationKey")); put("observed", true) })
    private fun publishHost(case: Path, sequence: Int, reply: OwnerCaseNativeReply) {
        val stem = sequence.toString().padStart(8, '0')
        val request = case.resolve("control-requests/$stem.json")
        val path = case.resolve("control-results/$stem.json")
        ReleasePrivateFiles.save(path, json.encodeToString(QualificationSpoolResult(1, invocation,
            sequence, reply.family, ReleaseLocks.sha256(ReleasePrivateFiles.read(request)), reply.result)).encodeToByteArray())
        ready(path.resolveSibling("$stem.ready"))
    }
    @Test fun `empty census is valid only before a ready request or attempted native effect`(): Unit = fixture { case, _, spool ->
        spool.requireDrained()
        offered(case, 1)
        assertFails { spool.requireDrained() }
    }
    @Test fun `QClient owner dispatch persists original intent and reply before publishing exact result`(): Unit = fixture { case, control, spool ->
        val pin = offered(case, 1)
        val events = mutableListOf<String>()
        val response = spool.service(true, null, beforeEffect = { events += "running before" },
            afterEffect = { events += "running after" }, actor = { request, digest ->
                val stem = "00000001"
                val original = control.resolve("case-native/$invocation/$stem.intent.json")
                assertEquals(pin.sha256, ReleaseLocks.sha256(ReleasePrivateFiles.read(original)))
                assertFalse(Files.exists(original.resolveSibling("$stem.result.json")))
                events += "typed native"
                actor(request, digest)
            })
        assertEquals(pin.sha256, response?.requestSha256)
        assertEquals(listOf("running before", "typed native", "running after"), events)
        assertTrue(Files.exists(control.resolve("case-native/$invocation/00000001.result.json")))
        assertTrue(Files.exists(case.resolve("control-results/00000001.ready")))
        spool.requireDrained()
    }
    @Test fun `host C1 reply is protected before ACK while acceptance alone publishes outer result`(): Unit = fixture { case, control, spool ->
        val pin = offered(case, 1)
        val response = requireNotNull(spool.service(false, OwnerCaseNative(case.toString(), "OFFICE_CALLBACK", pin),
            beforeEffect = {}, afterEffect = {}, actor = ::actor))
        assertTrue(Files.exists(control.resolve("case-native/$invocation/00000001.result.json")))
        assertFalse(Files.exists(case.resolve("control-results/00000001.json")))
        assertFails { spool.requireDrained() }
        publishHost(case, 1, response)
        spool.requireDrained()
    }
    @Test fun `uncertain actor or absent host ACK poisons one-use sequence without next effect`(): Unit = fixture { case, control, spool ->
        offered(case, 1)
        var effects = 0
        assertFails { spool.service(true, null, beforeEffect = {}, afterEffect = {}, actor = { _, _ ->
            effects++; error("typed actor ACK lost")
        }) }
        assertEquals(1, effects)
        assertTrue(Files.exists(control.resolve("case-native/$invocation/00000001.intent.json")))
        assertFalse(Files.exists(control.resolve("case-native/$invocation/00000001.result.json")))
        assertFails { spool.service(true, null, beforeEffect = {}, afterEffect = {}, actor = { request, digest ->
            effects++; actor(request, digest)
        }) }
        assertEquals(1, effects)
    }
    @Test fun `missing host ACK publication poisons the next sequence without another native effect`(): Unit = fixture { case, control, spool ->
        val first = offered(case, 1)
        requireNotNull(spool.service(false, OwnerCaseNative(case.toString(), "OFFICE_CALLBACK", first),
            {}, {}, ::actor))
        val second = offered(case, 2)
        var effects = 0
        assertFails { spool.service(false, OwnerCaseNative(case.toString(), "OFFICE_CALLBACK", second),
            {}, {}, { request, digest -> effects++; actor(request, digest) }) }
        assertEquals(0, effects)
        assertFalse(Files.exists(control.resolve("case-native/$invocation/00000002.intent.json")))
        assertFails { spool.service(false, OwnerCaseNative(case.toString(), "OFFICE_CALLBACK", second),
            {}, {}, { request, digest -> effects++; actor(request, digest) }) }
        assertEquals(0, effects)
    }
    @Test fun `observed client exit before native effect never dispatches or publishes`(): Unit = fixture { case, control, spool ->
        offered(case, 1)
        var effects = 0
        assertFails { spool.service(true, null, beforeEffect = { error("tracked client exited") },
            afterEffect = {}, actor = { request, digest -> effects++; actor(request, digest) }) }
        assertEquals(0, effects)
        assertFalse(Files.exists(control.resolve("case-native/$invocation/00000001.intent.json")))
        assertFails { spool.requireDrained() }
    }
    @Test fun `extra ready request rejects the first effect not merely final completion`(): Unit = fixture { case, control, spool ->
        offered(case, 1)
        offered(case, 2)
        var effects = 0
        assertFails { spool.service(true, null, {}, {}, { request, digest -> effects++; actor(request, digest) }) }
        assertEquals(0, effects)
        assertFalse(Files.exists(control.resolve("case-native/$invocation/00000001.intent.json")))
        assertFails { spool.requireDrained() }
    }
    @Test fun `transport directory replacement cannot inherit the prelaunch directory identity`(): Unit = fixture { case, control, spool ->
        val original = case.resolve("control-requests")
        Files.move(original, case.resolve("retained-original-requests"))
        directory(case, "control-requests")
        offered(case, 1)
        var effects = 0
        assertFails { spool.service(true, null, {}, {}, { request, digest -> effects++; actor(request, digest) }) }
        assertEquals(0, effects)
        assertFalse(Files.exists(control.resolve("case-native/$invocation/00000001.intent.json")))
    }
    @Test fun `exact census rejects deleted exchanged extra and altered result or marker`(): Unit = fixture { case, control, spool ->
        val first = offered(case, 1)
        val firstReply = requireNotNull(spool.service(false, OwnerCaseNative(case.toString(), "OFFICE_CALLBACK", first),
            {}, {}, ::actor))
        publishHost(case, 1, firstReply)
        val second = offered(case, 2)
        val secondReply = requireNotNull(spool.service(false, OwnerCaseNative(case.toString(), "OFFICE_CALLBACK", second),
            {}, {}, ::actor))
        publishHost(case, 2, secondReply)
        spool.requireDrained()
        val firstResult = case.resolve("control-results/00000001.json")
        val secondResult = case.resolve("control-results/00000002.json")
        val original = Files.readAllBytes(firstResult)
        Files.write(firstResult, Files.readAllBytes(secondResult), TRUNCATE_EXISTING)
        assertFails { spool.requireDrained() }
        Files.write(firstResult, original, TRUNCATE_EXISTING)
        Files.delete(secondResult)
        assertFails { spool.requireDrained() }
        ReleasePrivateFiles.save(secondResult, json.encodeToString(QualificationSpoolResult(1, invocation,
            2, secondReply.family, secondReply.requestSha256, secondReply.result)).encodeToByteArray())
        Files.createFile(case.resolve("control-results/00000003.json"))
        assertFails { spool.requireDrained() }
        Files.delete(case.resolve("control-results/00000003.json"))
        Files.setPosixFilePermissions(case.resolve("control-requests/00000001.ready"),
            PosixFilePermissions.fromString("rw-r--r--"))
        assertFails { spool.requireDrained() }
    }
}
