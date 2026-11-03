package net.datamancy.platform

import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.Flow
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import kotlin.test.*

class TransactionalCaddyTest {
    private val json = Json { encodeDefaults = true }
    private val binding = CaddySiteBinding("test", "https", "http://127.0.0.1:2019", setOf("board.datamancy.net"))
    private val generation = "q-abcdef123456"
    private val upstreams = listOf(CaddyUpstream("board.datamancy.net", "p0v3-live-$generation-core-planka:1337"))
    private val op = "r-000000000001"
    private val next = "r-000000000002"
    private val third = "r-000000000003"
    private val token = "a".repeat(64)
    private fun unrelated(host: String = "unrelated.example.org") = buildJsonObject {
        put("match", buildJsonArray { add(buildJsonObject { put("host", buildJsonArray { add(host) }) }) })
        put("handle", buildJsonArray { add(buildJsonObject { put("handler", "static_response"); put("body", "leave intact") }) })
    }
    private fun config(routes: List<JsonElement>) = buildJsonObject {
        put("admin", buildJsonObject { put("listen", "127.0.0.1:2019") })
        put("apps", buildJsonObject { put("http", buildJsonObject { put("servers", buildJsonObject {
            put("https", buildJsonObject { put("listen", buildJsonArray { add(":443") }); put("routes", JsonArray(routes)) })
        }) }) })
    }
    private inner class Fake : CaddyTransport {
        var configuration = config(listOf(unrelated()))
        val calls = mutableListOf<String>()
        var failure = ""
        var badRead = false
        var readCount = 0
        fun routes() = configuration.getValue("apps").jsonObject.getValue("http").jsonObject.getValue("servers").jsonObject
            .getValue("https").jsonObject.getValue("routes").jsonArray
        fun hash() = TransactionalCaddy.digest(configuration)
        fun etag() = "\"/config/ ${hash().take(16)}\""
        override fun exchange(method: String, path: String, etag: String?, body: ByteArray?): CaddyReply {
            calls += method
            if (method == "GET") {
                assertEquals("/config/", path); assertNull(etag); assertNull(body); readCount++
                if (badRead) return CaddyReply(302, byteArrayOf(), null)
                return CaddyReply(200, configuration.toString().toByteArray(), etag())
            }
            assertEquals("PATCH", method); assertEquals("/config/apps/http/servers/https/routes", path)
            assertEquals(etag(), etag)
            if (failure == "before") error("synthetic lost request")
            if (failure == "conflict") return CaddyReply(412, byteArrayOf(), null)
            if (failure != "ignored") configuration = config(Json.parseToJsonElement(requireNotNull(body).decodeToString()).jsonArray)
            if (failure == "after") error("synthetic lost acknowledgement")
            if (failure == "interrupt") throw InterruptedException("synthetic interruption")
            return CaddyReply(200, byteArrayOf(), null)
        }
    }
    private fun temporary(action: (Path, Fake, TransactionalCaddy) -> Unit) {
        val root = Files.createTempDirectory("caddy-unit-")
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        try { val fake = Fake(); action(root, fake, TransactionalCaddy(root, binding, fake)) }
        finally { Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    private fun intentHash(root: Path, operation: String = op) = ReleaseLocks.sha256(Files.readAllBytes(root.resolve("$operation.intent.json")))

    @Test fun `single CAS preserves unrelated settings and restricted routes do not leak control cookies`() = temporary { root, fake, control ->
        val initial = fake.configuration
        val result = control.replace(op, fake.hash(), null, generation, upstreams, token)
        assertEquals("applied", result.status); assertEquals(listOf("GET", "PATCH", "GET"), fake.calls)
        assertEquals(unrelated(), fake.routes().last()); assertEquals(initial["admin"], fake.configuration["admin"])
        val slot = fake.routes().first().jsonObject
        assertEquals(TransactionalCaddy.digest(slot), control.observeSlotSha256())
        assertEquals(fake.hash(), control.observeConfigurationSha256())
        assertEquals(result.observedSlotSha256, control.observeRestrictedSlotSha256(generation, upstreams))
        assertFails { control.observeRestrictedSlotSha256("q-111111111111", upstreams) }
        val children = slot.getValue("handle").jsonArray.single().jsonObject.getValue("routes").jsonArray
        val pattern = children.first().jsonObject.getValue("match").jsonArray.single().jsonObject.getValue("header_regexp")
            .jsonObject.getValue("Cookie").jsonObject.getValue("pattern").jsonPrimitive.content.toRegex()
        assertTrue(pattern.containsMatchIn("session=app; __Host-p0v3_acceptance=$token; other=x"))
        assertFalse(pattern.containsMatchIn("__Host-p0v3_acceptance=${token}0"))
        val proxy = children.first().jsonObject.getValue("handle").jsonArray.single().jsonObject
        val replacements = proxy.getValue("headers").jsonObject.getValue("request").jsonObject.getValue("replace").jsonObject.getValue("Cookie").jsonArray
        for (cookie in listOf("__Host-p0v3_acceptance=$token; session=app", "session=app; __Host-p0v3_acceptance=$token", "session=app; __Host-p0v3_acceptance=$token; other=x")) {
            var filtered = cookie
            for (replacement in replacements) filtered = filtered.replace(replacement.jsonObject.getValue("search_regexp").jsonPrimitive.content.toRegex(), "")
            assertFalse(token in filtered); assertTrue("session=app" in filtered)
        }
        assertTrue("503" in children.last().toString())
        assertFalse(Files.exists(root.resolve("pending.json")))
        assertFails { control.replace(op, fake.hash(), result.observedSlotSha256, generation, upstreams, token) }
        assertEquals(1, fake.calls.count { it == "PATCH" })
    }

    @Test fun `explicit public transition and rollback replace only the bound owned slot`() = temporary { root, fake, control ->
        val restricted = control.replace(op, fake.hash(), null, generation, upstreams, token)
        val previous = fake.routes().first()
        val opened = control.replace(next, fake.hash(), restricted.observedSlotSha256, generation, upstreams, null)
        assertFalse("header_regexp" in fake.routes().first().toString())
        assertFails { control.observeRestrictedSlotSha256(generation, upstreams) }
        assertFails { control.revert(third, next, "0".repeat(64), fake.hash()) }
        val reverted = control.revert(third, next, intentHash(root, next), fake.hash())
        assertEquals("applied", reverted.status); assertEquals(previous, fake.routes().first())
        assertNotEquals(opened.observedSlotSha256, reverted.observedSlotSha256)
    }

    @Test fun `fresh installation rollback removes only its owned route group`() = temporary { root, fake, control ->
        control.replace(op, fake.hash(), null, generation, upstreams, token)
        control.revert(next, op, intentHash(root), fake.hash())
        assertEquals(JsonArray(listOf(unrelated())), fake.routes())
    }

    @Test fun `lost acknowledgements and conflicts require explicit read only reconciliation`() {
        for (failure in listOf("after", "before", "conflict", "ignored", "interrupt")) temporary { root, fake, control ->
            fake.failure = failure
            assertFails { control.replace(op, fake.hash(), null, generation, upstreams, token) }
            assertTrue(Files.exists(root.resolve("pending.json")))
            assertFails { control.replace(next, fake.hash(), control.observeSlotSha256(), generation, upstreams, token) }
            val writes = fake.calls.count { it == "PATCH" }
            assertFails { control.reconcile(op, "0".repeat(64)) }
            val result = control.reconcile(op, intentHash(root))
            assertEquals(if (failure in setOf("after", "interrupt")) "applied" else "not-applied", result.status)
            assertEquals(writes, fake.calls.count { it == "PATCH" })
            assertFalse(Files.exists(root.resolve("pending.json")))
        }
    }

    @Test fun `reconciliation preserves unrelated concurrent changes and refuses divergent owned state`() = temporary { root, fake, control ->
        fake.failure = "after"
        assertFails { control.replace(op, fake.hash(), null, generation, upstreams, token) }
        val intended = fake.routes().first()
        fake.configuration = config(listOf(control.revision(next, generation, upstreams, token), unrelated("new.example.org")))
        assertFails { control.reconcile(op, intentHash(root)) }
        fake.configuration = config(listOf(intended, unrelated("new.example.org")))
        val result = control.reconcile(op, intentHash(root))
        assertEquals("applied", result.status); assertEquals(unrelated("new.example.org"), fake.routes().last())
        // Simulate loss of the final pending-claim removal acknowledgement. Existing result is never overwritten.
        val before = Files.readAllBytes(root.resolve("$op.result.json"))
        ReleasePrivateFiles.save(root.resolve("pending.json"), Files.readAllBytes(root.resolve("$op.intent.json")))
        control.reconcile(op, intentHash(root))
        assertContentEquals(before, Files.readAllBytes(root.resolve("$op.result.json")))
    }

    @Test fun `foreign sites stale bindings overlapping catchall and duplicate routes fail before PATCH`() = temporary { root, fake, control ->
        assertFails { control.replace(op, "0".repeat(64), null, generation, upstreams, token) }
        assertFails { control.replace(op, fake.hash(), "0".repeat(64), generation, upstreams, token) }
        assertFails { TransactionalCaddy(root, binding.copy(site = "other"), fake).replace(op, fake.hash(), null, generation, upstreams, token) }
        for (route in listOf(unrelated("board.datamancy.net"), unrelated("*.example.org"), buildJsonObject { put("handle", buildJsonArray { add(buildJsonObject { put("handler", "static_response") }) }) })) {
            fake.configuration = config(listOf(route))
            assertFails { control.replace(op, fake.hash(), null, generation, upstreams, token) }
        }
        val slot = control.revision(op, generation, upstreams, token)
        fake.configuration = config(listOf(slot, slot)); assertFails { control.observeSlotSha256() }
        fake.badRead = true; assertFails { control.observeSlotSha256() }
        assertFalse("PATCH" in fake.calls)
    }

    @Test fun `wrapped unrelated hosts remain unchanged and unsafe identity inputs are rejected`() = temporary { _, fake, control ->
        val wrapper = buildJsonObject { put("handle", buildJsonArray { add(buildJsonObject { put("handler", "subroute"); put("routes", buildJsonArray { add(unrelated()) }) }) }) }
        fake.configuration = config(listOf(wrapper))
        control.replace(op, fake.hash(), null, generation, upstreams, token)
        assertEquals(wrapper, fake.routes().last())
        for (bad in listOf("datamancy.net", "*.datamancy.net", "foreign.example.org")) assertFails { TransactionalCaddy(Path.of("/unused"), binding.copy(approvedHosts = setOf(bad)), fake) }
        for (url in listOf("https://127.0.0.1:2019", "http://localhost:2019", "http://127.0.0.1:2019/", "http://127.0.0.1:2019?x=y")) assertFails { LocalCaddyTransport(url) }
        assertFails { LocalCaddyTransport(binding.endpoint).exchange("DELETE", "/config/", null, null) }
        assertFails { TransactionalCaddy.real(Path.of("/unused/alternate-journal"), binding) }
        TransactionalCaddy(Path.of("/unused"), binding.copy(approvedHosts = setOf("client.matrix.datamancy.net")), fake)
        assertFails { control.revision("bad", generation, upstreams, token) }
        assertFails { control.revision(next, generation, emptyList(), token) }
        assertFails { control.revision(next, generation, listOf(upstreams.single().copy(dial = "other:1337")), token) }
        assertFails { control.revision(next, generation, upstreams, "short") }
        assertEquals(TransactionalCaddy.digest(Json.parseToJsonElement("{\"a\":1,\"b\":2}")), TransactionalCaddy.digest(Json.parseToJsonElement("{\"b\":2,\"a\":1}")))
    }

    @Test fun `response subscriber bounds streamed data and cancels excess subscriptions`() {
        var requested = 0L; var cancelled = 0
        val subscription = object : Flow.Subscription { override fun request(n: Long) { requested += n }; override fun cancel() { cancelled++ } }
        val body = BoundedCaddyBody(4)
        body.onSubscribe(subscription); body.onSubscribe(subscription)
        body.onNext(listOf(ByteBuffer.wrap(byteArrayOf(1, 2)))); body.onNext(listOf(ByteBuffer.wrap(byteArrayOf(3, 4))))
        body.onComplete(); assertContentEquals(byteArrayOf(1, 2, 3, 4), body.body.toCompletableFuture().get()); assertEquals(3, requested)
        val overflow = BoundedCaddyBody(1); overflow.onSubscribe(subscription); overflow.onNext(listOf(ByteBuffer.wrap(byteArrayOf(1, 2))))
        overflow.onNext(listOf(ByteBuffer.wrap(byteArrayOf(3))))
        assertTrue(overflow.body.toCompletableFuture().isCompletedExceptionally); assertEquals(2, cancelled)
        val failed = BoundedCaddyBody(1); failed.onError(IllegalStateException("unit")); assertTrue(failed.body.toCompletableFuture().isCompletedExceptionally)
    }

    @Test fun `private control files reject links unsafe modes replacement and excessive contents`() = temporary { root, _, _ ->
        val file = root.resolve("test")
        ReleasePrivateFiles.save(file, byteArrayOf(1, 2))
        assertFails { ReleasePrivateFiles.read(file, 1) }; assertFails { ReleasePrivateFiles.read(file, 0) }
        assertFails { ReleasePrivateFiles.removeExact(file, byteArrayOf(2)) }
        val link = root.resolve("link"); Files.createSymbolicLink(link, file); assertFails { ReleasePrivateFiles.read(link) }; Files.delete(link)
        Files.createLink(link, file); assertFails { ReleasePrivateFiles.read(file) }; Files.delete(link)
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-r--r--")); assertFails { ReleasePrivateFiles.read(file) }
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"))
        ReleasePrivateFiles.removeExact(file, byteArrayOf(1, 2)); assertFalse(Files.exists(file))
    }
}
