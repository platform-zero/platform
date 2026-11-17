package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.json.*
import kotlin.test.*

class QualificationOpenSearchActorTest {
    private val invocation = "case-00000000-0000-0000-0000-000000000001"
    private fun request(action: String) = buildJsonObject { put("action", action) }

    @Test fun `only fixed actions derive stable original operation IDs and roles`() {
        val tags = mapOf("CREATE" to "original-create", "DOCUMENT" to "original-get",
            "HISTORY" to "original-history", "DENY" to "node-denial")
        val ids = tags.map { (action, tag) ->
            val operation = QualificationOpenSearchActor.operation(invocation, "INSTALL", request(action))
            assertEquals("nq-" + ReleaseLocks.sha256("$invocation\nopensearch\n$tag".encodeToByteArray()).take(12), operation.id)
            assertEquals(if (action == "DENY") "NODE" else "ADMIN", operation.role)
            assertEquals(operation, QualificationOpenSearchActor.operation(invocation, "INSTALL", request(action)))
            operation.id
        }
        assertEquals(4, ids.toSet().size)
        assertFails { QualificationOpenSearchActor.operation(invocation, "RESTORE", request("CREATE")) }
        for (action in tags.keys - "CREATE")
            assertEquals(QualificationOpenSearchActor.operation(invocation, "INSTALL", request(action)),
                QualificationOpenSearchActor.operation(invocation, "RESTORE", request(action)))
        for (bad in listOf(request("DELETE"), JsonObject(request("CREATE") + ("role" to JsonPrimitive("ADMIN"))),
            buildJsonObject { put("action", true) }, buildJsonObject { put("url", "https://example.invalid/") }))
            assertFails { QualificationOpenSearchActor.operation(invocation, "INSTALL", bad) }
        assertFails { QualificationOpenSearchActor.operation("../foreign", "INSTALL", request("CREATE")) }
    }

    @Test fun `projection preserves original bytes and empty denial without overwrite or generation mount`() {
        val mode = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
        val base = Files.createTempDirectory("opensearch-projection-unit-", mode)
        try {
            val home = Files.createDirectory(base.resolve("originals"), mode)
            val case = Files.createDirectory(base.resolve("case"), mode)
            val operation = QualificationOpenSearchActor.operation(invocation, "INSTALL", request("DENY")).id
            val rawRequest = "{\"unit\":\"request\"}".encodeToByteArray()
            val rawResult = "{\"unit\":\"result\"}".encodeToByteArray()
            ReleasePrivateFiles.save(home.resolve("$operation.request.json"), rawRequest)
            ReleasePrivateFiles.save(home.resolve("$operation.result.json"), rawResult)
            Files.createFile(home.resolve("$operation.response"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
            val reply = QualificationOpenSearchActor.project(case, home, operation, rawRequest, rawResult,
                ReleaseLocks.sha256(byteArrayOf()))
            assertEquals(setOf("schemaVersion", "nativeRequest", "nativeResult", "response"), reply.keys)
            for ((field, raw) in listOf("nativeRequest" to rawRequest, "nativeResult" to rawResult,
                "response" to byteArrayOf())) {
                val pin = reply.getValue(field).jsonObject
                val path = case.resolve(pin.getValue("relativePath").jsonPrimitive.content)
                assertContentEquals(raw, Files.readAllBytes(path))
                assertEquals(ReleaseLocks.sha256(raw), pin.getValue("sha256").jsonPrimitive.content)
                assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(path))
            }
            assertFails { QualificationOpenSearchActor.project(case, home, operation, rawRequest, rawResult,
                ReleaseLocks.sha256(byteArrayOf())) }
            assertContentEquals(rawRequest, Files.readAllBytes(home.resolve("$operation.request.json")))
        } finally { Files.walk(base).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}
