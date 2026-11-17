package net.datamancy.platform

import java.security.MessageDigest
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.json.*
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull

class QualificationCaseControllerTest {
    private val suite = "0123456789abcdef01234567"
    private val first = "case-00000000-0000-0000-0000-000000000001"
    private val second = "case-00000000-0000-0000-0000-000000000002"
    private fun independentId(id: String, suffix: String = ""): String {
        val digest = MessageDigest.getInstance("SHA-256").digest((suite + id + suffix).encodeToByteArray())
        return "r-${digest.joinToString("") { "%02x".format(it) }.take(12)}"
    }

    @Test fun `distinct fixed bridge operation IDs bind each case and action`(): Unit {
        assertEquals(independentId(first), qualificationCaseBridgeOperation(suite, first, "install"))
        assertEquals(independentId(first, "\nremove"), qualificationCaseBridgeOperation(suite, first, "remove"))
        assertEquals(independentId(second), qualificationCaseBridgeOperation(suite, second, "install"))
        assertNotEquals(qualificationCaseBridgeOperation(suite, first, "remove"),
            qualificationCaseBridgeOperation(suite, first, "install"))
        assertNotEquals(qualificationCaseBridgeOperation(suite, first, "install"),
            qualificationCaseBridgeOperation(suite, second, "install"))
        for (invalid in listOf("Case-${first.removePrefix("case-")}", "case-NOT-A-UUID", first.uppercase()))
            assertFailsWith<IllegalArgumentException> { qualificationCaseBridgeOperation(suite, invalid, "install") }
        assertFailsWith<IllegalArgumentException> { qualificationCaseBridgeOperation("xyz", first, "install") }
        assertFailsWith<IllegalArgumentException> { qualificationCaseBridgeOperation(suite, first, "retry") }
    }

    @Test fun `Office restored browser bridge excludes files-native and binds both selected hosts`(): Unit {
        val isolation = "a".repeat(64)
        val office = buildJsonObject {
            put("originalHost", "office.datamancy.net"); put("port", 443)
            put("address", "10.9.0.2"); put("isolationProofSha256", isolation)
        }
        val files = buildJsonObject {
            put("originalHost", "files.datamancy.net"); put("port", 443)
            put("address", "10.9.0.2"); put("isolationProofSha256", isolation)
        }
        val pair: Map<String,JsonElement> = mapOf("bridge" to office,
            "bridges" to JsonObject(mapOf("files.datamancy.net" to files)))
        val leaves = setOf("office.datamancy.net", "files.datamancy.net",
            "files-native.datamancy.net").associateWith { "b".repeat(64) }
        assertEquals(pair, qualificationOfficeBrowserBridgeProjection(pair,isolation,leaves))
        assertEquals(setOf("files.datamancy.net"), pair.getValue("bridges").jsonObject.keys)
        val foreign = pair + ("bridges" to JsonObject(mapOf("files.datamancy.net" to files,
            "files-native.datamancy.net" to files)))
        assertFailsWith<IllegalArgumentException> {
            qualificationOfficeBrowserBridgeProjection(foreign,isolation,leaves)
        }
        assertFailsWith<IllegalArgumentException> {
            qualificationOfficeBrowserBridgeProjection(pair,"c".repeat(64),leaves)
        }
        assertFailsWith<IllegalArgumentException> {
            qualificationOfficeBrowserBridgeProjection(pair,isolation,leaves - "files-native.datamancy.net")
        }
    }

    @Test fun `Files native producer CA retains scoped client path and host native path without browser bridge`(): Unit {
        val dir = Files.createTempDirectory("office-native-projection-")
        val proofs = Files.createDirectory(dir.resolve("owner-proofs"),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val file = proofs.resolve("files-native-api-ca.pem")
        val bytes = "unit-only-singleton-native-ca".encodeToByteArray()
        ReleasePrivateFiles.save(file,bytes)
        try {
            val generation = "q-111111111111"
            val bundle = "a".repeat(64)
            val isolation = "b".repeat(64)
            val leaf = "c".repeat(64)
            val ca = ReleaseLocks.sha256(bytes)
            val api = buildJsonObject {
                put("originalHost","files-native.datamancy.net"); put("port",443)
                put("address","10.9.0.2"); put("caFile","/case/owner-proofs/files-native-api-ca.pem")
                put("caSha256",ca); put("leafSha256",leaf); put("generationId",generation)
                put("bundleSha256",bundle); put("isolationProofSha256",isolation)
            }
            val projection = QualificationOfficeInputs(mapOf("nativeApi" to api),
                listOf(ActivationInput(file.toString(),ca)))
            val client = qualificationFilesNativeCaseProjection(projection,dir,generation,bundle,
                isolation,leaf,QualificationExecutionMode.QCLIENT_RUNNER).getValue("nativeApi").jsonObject
            assertEquals("/case/owner-proofs/files-native-api-ca.pem",client.getValue("caFile").jsonPrimitive.content)
            val host = qualificationFilesNativeCaseProjection(projection,dir,generation,bundle,
                isolation,leaf,QualificationExecutionMode.HOST_NATIVE).getValue("nativeApi").jsonObject
            assertEquals(file.toString(),host.getValue("caFile").jsonPrimitive.content)
            assertEquals(client - "caFile",host - "caFile")
            assertFailsWith<IllegalArgumentException> {
                qualificationFilesNativeCaseProjection(projection,dir,generation,bundle,
                    isolation,"d".repeat(64),QualificationExecutionMode.QCLIENT_RUNNER)
            }
            assertFailsWith<IllegalArgumentException> {
                qualificationFilesNativeCaseProjection(projection,dir,generation,bundle,
                    "d".repeat(64),leaf,QualificationExecutionMode.QCLIENT_RUNNER)
            }
            assertFailsWith<IllegalArgumentException> {
                qualificationFilesNativeCaseProjection(QualificationOfficeInputs(mapOf("nativeApi" to api),
                    listOf(ActivationInput(file.toString(),"d".repeat(64)))),dir,generation,bundle,
                    isolation,leaf,QualificationExecutionMode.QCLIENT_RUNNER)
            }
        } finally {
            Files.deleteIfExists(file); Files.deleteIfExists(proofs); Files.deleteIfExists(dir)
        }
    }

    @Test fun `teardown cannot move from retained owner thread`(): Unit {
        val driver = QualificationCaseSafetyDriver()
        val failure = AtomicReference<Throwable?>()
        val outside = Thread {
            try { driver.close(false, false, stop = { error("no stop") }, remove = { error("no bridge") }) }
            catch (error: Throwable) { failure.set(error) }
        }
        outside.start(); outside.join()
        assertEquals(IllegalStateException::class, failure.get()?.let { it::class })
        assertEquals(null to null, driver.close(false, false,
            stop = { error("no stop") }, remove = { error("no bridge") }))
    }

    @Test fun `two cases close client before the original bridge with no duplicate teardown`(): Unit {
        val events = mutableListOf<String>()
        for (invocation in listOf(first, second)) {
            val driver = QualificationCaseSafetyDriver()
            val fence = ActivationInput("/protected/$invocation/fenced.json", "a".repeat(64))
            val removal = ActivationInput("/protected/$invocation/removed.json", "b".repeat(64))
            val closed = driver.close(true, true,
                stop = { events += "$invocation:stop"; fence to true },
                remove = { actual ->
                    assertEquals(fence, actual)
                    events += "$invocation:remove"
                    removal to true
                })
            assertEquals(fence to removal, closed)
            assertFailsWith<IllegalStateException> { driver.close(true, true,
                stop = { error("replayed stop") }, remove = { error("replayed bridge") }) }
        }
        assertEquals(listOf("$first:stop", "$first:remove", "$second:stop", "$second:remove"), events)
    }

    @Test fun `unknown client stop cannot issue bridge removal or authorize next source effect`(): Unit {
        val events = mutableListOf<String>()
        val driver = QualificationCaseSafetyDriver()
        assertFailsWith<IllegalArgumentException> {
            driver.close(true, true, stop = { events += "unknown stop"; null to false },
                remove = { events += "forbidden remove"; null to true })
        }
        assertEquals(listOf("unknown stop"), events)
        assertFailsWith<IllegalStateException> {
            driver.close(true, true, stop = { events += "replayed stop"; null to true },
                remove = { events += "replayed remove"; null to true })
        }
        assertEquals(listOf("unknown stop"), events)
    }

    @Test fun `lost start acknowledgement adopts original identity without a second start`(): Unit {
        val events = mutableListOf<String>()
        val identity = ActivationInput("/protected/original/fenced.json", "d".repeat(64))
        val removal = ActivationInput("/protected/original/removed.json", "e".repeat(64))
        val closed = QualificationCaseSafetyDriver().close(true, true,
            stop = { events += "observe original intent and CID, then stop"; identity to true },
            remove = { observed -> assertEquals(identity, observed); events += "remove original bridge"; removal to true })
        assertEquals(identity to removal, closed)
        assertEquals(listOf("observe original intent and CID, then stop", "remove original bridge"), events)
    }

    @Test fun `unknown original removal CAS cannot be retried with a new operation`(): Unit {
        val driver = QualificationCaseSafetyDriver()
        val fence = ActivationInput("/protected/original/fenced.json", "d".repeat(64))
        val events = mutableListOf<String>()
        assertFailsWith<IllegalArgumentException> {
            driver.close(true, true,
                stop = { events += "fence original client"; fence to true },
                remove = { assertEquals(fence, it); events += "observe uncertain removal"; null to false })
        }
        assertEquals(listOf("fence original client", "observe uncertain removal"), events)
        assertFailsWith<IllegalStateException> { driver.close(false, true,
            stop = { error("unexpected second stop") }, remove = { events += "second CAS"; null to true }) }
        assertEquals(listOf("fence original client", "observe uncertain removal"), events)
    }

    @Test fun `host RSS bridge has no synthetic client fence and still removes its own bridge`(): Unit {
        val driver = QualificationCaseSafetyDriver()
        val removal = ActivationInput("/protected/host/removal.json", "c".repeat(64))
        val (client, bridge) = driver.close(false, true,
            stop = { error("Host case has no QClient") }, remove = { observed ->
                assertNull(observed)
                removal to true
            })
        assertNull(client)
        assertEquals(removal, bridge)
    }
}
