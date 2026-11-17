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

    @Test fun `restored native RSS original SNI bridge excludes foreign hosts and requires removal plus isolation before source resume`(): Unit {
        val root = Files.createTempDirectory("restored-bridge-unit-")
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        val cert = root.resolve("source-certificate.pem")
        val certificateBytes = "SYNTHETIC UNIT CERT, not service TLS".toByteArray()
        ReleasePrivateFiles.save(cert, certificateBytes)
        val originalKey = root.resolve("source-private-key.pem")
        val privateKeyBytes = "SYNTHETIC UNIT PRIVATE KEY, never a real service secret".toByteArray()
        ReleasePrivateFiles.save(originalKey, privateKeyBytes)
        val source = "q-000000000001"; val target = "q-000000000002"
        val host = "notify.datamancy.net"
        val network = "scoped-clients"
        val image = "registry.example.invalid/pinned@sha256:${"a".repeat(64)}"
        val caddy = RuntimeProcess("caddy", image, "a".repeat(64), 1000,
            entrypoint = "/usr/bin/caddy", command = listOf("run", "--config", "/run/secrets/caddy.json"),
            files = listOf(RuntimeFile("bridge-cert.pem", "/run/secrets/bridge-cert.pem"),
                RuntimeFile("bridge-key.pem", "/run/secrets/bridge-key.pem")), networks = listOf(network),
            networkAliases = listOf(RuntimeNetworkAlias(network, host)), readiness = listOf("true"),
            capabilities = listOf("NET_BIND_SERVICE"))
        val client = RuntimeProcess("official-client", image, "a".repeat(64), 1000,
            networks = listOf(network), readiness = listOf("true"))
        val spec = PrivateDeploymentSpec(name = "$target-bridge", volumes = emptyList(),
            processes = listOf(caddy, client), networks = listOf(network), store = RuntimeStore.CANONICAL_V2)
        val binding = RestoredBridgeBinding(op, "unit", source, target, "a".repeat(64), network,
            "10.89.0.5", setOf("official-client"), "bridge", "r-000000000007", "b".repeat(64), "d".repeat(64),
            setOf(host), listOf(CaddyUpstream(host, "p0v3-live-$target-app-ntfy:8080")),
            mapOf(host to ActivationInput(cert.toString(), ReleaseLocks.sha256(certificateBytes))),
            mapOf(host to ActivationInput(originalKey.toString(), ReleaseLocks.sha256(privateKeyBytes))),
            mapOf(host to "/run/secrets/bridge-cert.pem"), mapOf(host to "/run/secrets/bridge-key.pem"))
        assertFalse("nativeClientCapabilities" in json.encodeToString(binding) ||
            "qualifierClientInvocationId" in json.encodeToString(binding) ||
            "qualifierClientContainerId" in json.encodeToString(binding) ||
            "qualifierClientAddress" in json.encodeToString(binding)) // historical binding bytes
        val nativeOnly = binding.copy(allowedClients = emptySet(), nativeClientCapabilities = setOf("rss-mastodon"))
        assertFailsWith<IllegalArgumentException> {
            RestrictedRestoreBridge(root, binding.copy(qualifierClientInvocationId = "case-ui",
                qualifierClientContainerId = "f".repeat(64)), spec,
                CaddyTransport { _, _, _, _ -> error("unbound client must not send") },
                { true }, { null }, { "d".repeat(64) }, { "10.89.0.5" })
        }
        RestrictedRestoreBridge(root, nativeOnly, spec.copy(processes = listOf(caddy)),
            CaddyTransport { _, _, _, _ -> error("constructor cannot send network request") },
            { true }, { null }, { "d".repeat(64) }, { "10.89.0.5" }, { _, _, _ -> })
        var config = Json.parseToJsonElement("""{"apps":{"http":{"servers":{"p0v3-internal-unit-office":{"listen":["10.89.0.9:443"],"routes":[]}}},"tls":{"certificates":{"load_files":[{"certificate":"/run/secrets/bridge-cert.pem","key":"/run/secrets/bridge-key.pem"}]}}},"unrelated":{"keep":true}}""").jsonObject
        var writes = 0; var stopped = true; var isolated: String? = null
        val transport = CaddyTransport { method, path, etag, body ->
            assertEquals("/config/", path)
            val tag = "\"/config/ ${TransactionalCaddy.digest(config).take(16)}\""
            if (method == "GET") CaddyReply(200, config.toString().toByteArray(), tag)
            else {
                assertEquals("POST", method); assertEquals(tag, etag); writes++
                config = Json.parseToJsonElement(requireNotNull(body).decodeToString()).jsonObject
                CaddyReply(200, byteArrayOf(), null)
            }
        }
        try {
            val unready = RestrictedRestoreBridge(root, binding, spec, transport, { stopped }, { isolated },
                { null }, { "10.89.0.5" }, { _, _, _ -> error("unready must never read original certificate") }, { certificateBytes })
            assertFailsWith<IllegalArgumentException> { unready.install(TransactionalCaddy.digest(config)) }
            assertEquals(0, writes)
            val foreignInterface = RestrictedRestoreBridge(root, binding, spec, transport, { stopped }, { isolated },
                { "d".repeat(64) }, { "10.89.0.6" }, { _, _, _ -> error("wrong IP must never read cert") }, { certificateBytes })
            assertFailsWith<IllegalArgumentException> { foreignInterface.install(TransactionalCaddy.digest(config)) }
            assertEquals(0, writes)
            val mismatchedCrypto = RestrictedRestoreBridge(root, binding, spec, transport, { stopped }, { isolated },
                { "d".repeat(64) }, { "10.89.0.5" }, { _, _, _ -> }, { file -> if (file == "bridge-key.pem") "REGENERATED KEY".toByteArray() else certificateBytes })
            assertFailsWith<IllegalArgumentException> { mismatchedCrypto.install(TransactionalCaddy.digest(config)) }
            assertEquals(0, writes)
            val bridge = RestrictedRestoreBridge(root, nativeOnly, spec.copy(processes = listOf(caddy)), transport, { stopped }, { isolated },
                { "d".repeat(64) }, { "10.89.0.5" }, { bytes, name, hosts -> assertContentEquals(certificateBytes, bytes); assertEquals(host, name); assertEquals(setOf(host), hosts) },
                { file -> if (file == "bridge-cert.pem") certificateBytes else if (file == "bridge-key.pem") privateKeyBytes
                    else error("Foreign sealed input") })
            val before = TransactionalCaddy.digest(config)
            val installed = bridge.install(before)
            assertEquals("install", installed.action); assertEquals(1, writes)
            assertTrue("strict_sni_host" in config.toString() && "static_response" in config.toString())
            assertTrue("10.89.0.5:443" in config.toString())
            assertTrue("10.89.0.5/32" in config.toString() && "remote_ip" in config.toString())
            assertFalse("\"listen\":[\":443\"]" in config.toString())
            assertTrue("notify.datamancy.net" in config.toString())
            assertFalse("acceptanceToken" in config.toString() || "__Host-p0v3_acceptance" in config.toString())
            assertEquals(JsonPrimitive(true), config.getValue("unrelated").jsonObject["keep"])
            assertTrue("p0v3-internal-unit-office" in config.getValue("apps").jsonObject.getValue("http")
                .jsonObject.getValue("servers").jsonObject)
            assertFailsWith<Exception> { bridge.install(TransactionalCaddy.digest(config)) }
            ReleasePrivateFiles.save(root.resolve("client.pending"), "uncertain client request".encodeToByteArray())
            assertFailsWith<IllegalArgumentException> { bridge.remove(next, TransactionalCaddy.digest(config)) }
            assertEquals(1, writes)
            ReleasePrivateFiles.removeExact(root.resolve("client.pending"), "uncertain client request".encodeToByteArray())
            val removed = bridge.remove(next, TransactionalCaddy.digest(config))
            assertEquals("remove", removed.action); assertEquals(2, writes)
            assertTrue("p0v3-internal-unit-office" in config.getValue("apps").jsonObject.getValue("http")
                .jsonObject.getValue("servers").jsonObject)
            assertTrue("/run/secrets/bridge-cert.pem" in config.getValue("apps").jsonObject.getValue("tls")
                .jsonObject.getValue("certificates").jsonObject.getValue("load_files").toString())
            assertFailsWith<IllegalArgumentException> { bridge.sourceResumeProof(removed, "c".repeat(64)) }
            isolated = "c".repeat(64)
            val proof = bridge.sourceResumeProof(removed, requireNotNull(isolated))
            assertTrue(proof.matches(Regex("[a-f0-9]{64}")))
            assertTrue(Files.exists(root.resolve("${removed.operation}.resume-proof.json")))
            assertEquals(proof, bridge.sourceResumeProof(removed, requireNotNull(isolated)))
            stopped = false
            assertFailsWith<IllegalArgumentException> { bridge.sourceResumeProof(removed, requireNotNull(isolated)) }
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }

    @Test fun `approved start hostname serves only literal Keycloak sign in link without redirect or fake authentication`(): Unit {
        val site = CaddySiteBinding("test", "https", "http://127.0.0.1:2019", setOf("start.datamancy.net"))
        val fake = Fake()
        val root = Files.createTempDirectory("start-entry-unit-")
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        try {
            val route = TransactionalCaddy(root, site, fake).revision(op, generation, emptyList(), token)
            val routes = route.getValue("handle").jsonArray.single().jsonObject.getValue("routes").jsonArray
            val child = routes.first { it.jsonObject.getValue("match").jsonArray.single().jsonObject
                .getValue("path").jsonArray.single().jsonPrimitive.content == "/" }.jsonObject
            val callback = routes.first { it.jsonObject.getValue("match").jsonArray.single().jsonObject
                .getValue("path").jsonArray.single().jsonPrimitive.content == "/identity/operator/callback" }.jsonObject
            val callbackMatch = callback.getValue("match").jsonArray.single().jsonObject
            assertFalse("header_regexp" in callbackMatch)
            assertEquals("start.datamancy.net", callbackMatch.getValue("host").jsonArray.single().jsonPrimitive.content)
            val callbackResponse = callback.getValue("handle").jsonArray.single().jsonObject
            assertEquals("static_response", callbackResponse.getValue("handler").jsonPrimitive.content)
            assertFalse("code=" in callbackResponse.toString() || "state=" in callbackResponse.toString() ||
                "token=" in callbackResponse.toString() || "redirect" in callbackResponse.toString())
            assertEquals("no-referrer", callbackResponse.getValue("headers").jsonObject.getValue("Referrer-Policy")
                .jsonArray.single().jsonPrimitive.content)
            val match = child.getValue("match").jsonArray.single().jsonObject
            assertEquals("start.datamancy.net", match.getValue("host").jsonArray.single().jsonPrimitive.content)
            assertEquals("/", match.getValue("path").jsonArray.single().jsonPrimitive.content)
            assertFalse("header_regexp" in match) // Landing must be reachable without the private acceptance cookie.
            val response = child.getValue("handle").jsonArray.single().jsonObject
            assertEquals("static_response", response.getValue("handler").jsonPrimitive.content)
            val html = response.getValue("body").jsonPrimitive.content
            assertTrue("Sign in with Keycloak" in html)
            assertTrue("href=\"https://auth.datamancy.net/realms/p0v3/account/\"" in html)
            assertFalse("redirect_uri=" in html || "token=" in html || "logged in" in html)
            assertFailsWith<IllegalArgumentException> { TransactionalCaddy(root, site.copy(approvedHosts = setOf("*.datamancy.net")), fake) }
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }

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

    @Test fun `Hub private TLS upstream keeps original public forwarded hostname without foreign routes`(): Unit {
        assertFalse("tlsServerName" in json.encodeToString(upstreams.single()) ||
            "trustedCaFile" in json.encodeToString(upstreams.single()) ||
            "trustedCaSha256" in json.encodeToString(upstreams.single()) ||
            "forwardOriginalHost" in json.encodeToString(upstreams.single()))
        val hub = CaddyUpstream("notebooks.datamancy.net", "p0v3-live-$generation-app-hub:8443",
            "hub", "/run/secrets/hub-ca.pem", "a".repeat(64), true)
        val route = caddyOwnedUpstreamProxy(hub, true)
        val transport = route.getValue("transport").jsonObject.getValue("tls").jsonObject
        assertEquals("hub", transport.getValue("server_name").jsonPrimitive.content)
        assertEquals("file", transport.getValue("ca").jsonObject.getValue("provider").jsonPrimitive.content)
        assertEquals("/run/secrets/hub-ca.pem", transport.getValue("ca").jsonObject.getValue("pem_files")
            .jsonArray.single().jsonPrimitive.content)
        val request = route.getValue("headers").jsonObject.getValue("request").jsonObject
        val set = request.getValue("set").jsonObject
        assertEquals("hub", set.getValue("Host").jsonArray.single().jsonPrimitive.content)
        assertEquals("notebooks.datamancy.net", set.getValue("X-Forwarded-Host").jsonArray.single().jsonPrimitive.content)
        assertEquals("https", set.getValue("X-Forwarded-Proto").jsonArray.single().jsonPrimitive.content)
        assertTrue("__Host-p0v3_acceptance" in request.getValue("replace").toString())
        assertFailsWith<IllegalArgumentException> {
            caddyOwnedUpstreamProxy(CaddyUpstream("files.datamancy.net", "p0v3-live-$generation-seafile-files:8443"), false)
        }
        assertFailsWith<IllegalArgumentException> { caddyOwnedUpstreamProxy(hub.copy(trustedCaFile = null), false) }
        assertFailsWith<IllegalArgumentException> { caddyOwnedUpstreamProxy(hub.copy(trustedCaSha256 = "short"), false) }
        assertFailsWith<IllegalArgumentException> { caddyOwnedUpstreamProxy(hub.copy(forwardOriginalHost = false), false) }
        assertFailsWith<IllegalArgumentException> { caddyOwnedUpstreamProxy(hub.copy(host = "foreign.datamancy.net"), false) }
    }

    @Test fun `fresh qualification uses same Caddy ACME leaf on internal client IP only and removes after client fence`(): Unit {
        val root = Files.createTempDirectory("qualification-install-unit-")
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        try {
            val gen = "q-0123456789ab"
            val image = "registry.example.invalid/owned@sha256:${"a".repeat(64)}"
            val host = "rtc.datamancy.net"
            val net = "qualification-web"
            val spec = PrivateDeploymentSpec(name = "$gen-canonical-release-v2", volumes = emptyList(), store = RuntimeStore.CANONICAL_V2,
                networks = listOf("ingress-egress", net), ingress = RuntimeIngressPublication("unit", setOf(host), "192.0.2.10"),
                processes = listOf(RuntimeProcess("caddy", image, "a".repeat(64), 1000,
                    entrypoint = "/usr/bin/caddy", command = listOf("run", "--config", "/run/secrets/caddy.json"),
                    capabilities = listOf("NET_BIND_SERVICE"), networks = listOf("ingress-egress", net),
                    readiness = listOf("/usr/bin/caddy", "version")),
                    RuntimeProcess("livekit", image, "a".repeat(64), 1000,
                        networks = listOf(net), readiness = listOf("/usr/bin/livekit", "--version"))))
            val publicServer = buildJsonObject {
                put("listen", buildJsonArray { add("10.99.0.2:443") }); put("strict_sni_host", true)
                put("tls_connection_policies", buildJsonArray { add(buildJsonObject {
                    put("match", buildJsonObject { put("sni", buildJsonArray { add(host) }) })
                }) })
                put("routes", buildJsonArray { add(buildJsonObject {
                    put("@id", "p0v3-unit-owned"); put("terminal", true)
                    put("match", buildJsonArray { add(buildJsonObject {
                        put("host", buildJsonArray { add(host) })
                    }) })
                    put("handle", buildJsonArray { add(buildJsonObject {
                        put("handler", "subroute")
                        put("routes", buildJsonArray { add(buildJsonObject {
                            put("@id", "p0v3-unit-child"); put("terminal", true)
                            put("handle", buildJsonArray { add(buildJsonObject {
                                put("handler", "static_response"); put("status_code", 200)
                            }) })
                        }) })
                    }) })
                }) })
            }
            var active = buildJsonObject {
                put("apps", buildJsonObject {
                    put("http", buildJsonObject { put("servers", buildJsonObject { put("public", publicServer) }) })
                    put("tls", buildJsonObject { put("certificates", buildJsonObject {
                        put("automate", buildJsonArray { add(host) })
                    }) })
                })
            }
            val cid = "b".repeat(64)
            val request = QualificationInstallIngressBinding("r-123456789abc", "unit", gen,
                "a".repeat(64), "public", net, "10.99.0.3", "10.99.0.4", "rtc-browser", cid, setOf(host))
            val adapter = QualificationInstallIngress(root, request, spec,
                CaddyTransport { method, _, _, body ->
                    if (method == "GET") CaddyReply(200, active.toString().encodeToByteArray(),
                        "\"/config/ ${"a".repeat(16)}\"")
                    else { active = Json.parseToJsonElement(requireNotNull(body).decodeToString()).jsonObject
                        CaddyReply(200, byteArrayOf(1), null) }
                }, { "10.99.0.2" }, { "10.99.0.3" },
                { QualificationClientNative(cid, 1843, 12345, "10.99.0.4", "a".repeat(64)) },
                { 12345L }, { 12345L }, { it })
            val installed = adapter.install()
            val servers = active.getValue("apps").jsonObject.getValue("http").jsonObject.getValue("servers").jsonObject
            assertEquals(publicServer, servers.getValue("public"))
            val internal = servers.getValue("p0v3-unit-qualified-install").jsonObject
            assertEquals("10.99.0.3:443", internal.getValue("listen").jsonArray.single().jsonPrimitive.content)
            assertEquals("10.99.0.4/32", internal.getValue("routes").jsonArray.first().jsonObject
                .getValue("match").jsonArray.single().jsonObject.getValue("remote_ip").jsonObject
                .getValue("ranges").jsonArray.single().jsonPrimitive.content)
            assertFalse("p0v3-unit-child" in internal.toString())
            assertTrue(installed.nativeListenerInode > 1)
            adapter.remove(QualificationClientFence("rtc-browser", gen, cid, 12345,
                "c".repeat(64), "d".repeat(64)))
            assertEquals(setOf("public"), active.getValue("apps").jsonObject.getValue("http")
                .jsonObject.getValue("servers").jsonObject.keys)
        } finally { Files.deleteIfExists(root.resolve("control.lock")); Files.walk(root).use { paths ->
            paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        } }
    }

    @Test fun `BookStack PHP sees only native certs and token not Keykeeper introspect or logout`(): Unit {
        val identities = mapOf("keykeeper" to "10.89.0.7", "bookstack-php" to "10.89.0.8",
            "mas" to "10.89.0.9")
        val base = "/realms/p0v3/protocol/openid-connect/"
        val discovery = "/realms/p0v3/.well-known/openid-configuration"
        assertEquals(setOf("bookstack-php", "mas"), internalRouteConsumers("identity", "GET", discovery, identities))
        assertEquals(emptySet(), internalRouteConsumers("identity", "POST", discovery, identities))
        assertEquals(emptySet(), internalRouteConsumers("identity", "GET", discovery,
            mapOf("keykeeper" to "10.89.0.7")))
        assertEquals(identities.keys, internalRouteConsumers("identity", "GET", base + "certs", identities))
        assertEquals(identities.keys, internalRouteConsumers("identity", "POST", base + "token", identities))
        assertEquals(setOf("keykeeper"), internalRouteConsumers("identity", "POST", base + "token/introspect", identities))
        assertEquals(setOf("keykeeper"), internalRouteConsumers("identity", "POST", base + "logout", identities))
        assertEquals(setOf("mas"), internalRouteConsumers("identity", "GET", base + "userinfo", identities))
        assertEquals(emptySet(), internalRouteConsumers("identity", "POST", base + "userinfo", identities))
        assertEquals(emptySet(), internalRouteConsumers("identity", "GET", base + "authorize", identities))
        assertEquals(emptySet(), internalRouteConsumers("identity", "GET", base + "token/introspect", identities))
        val office = mapOf("onlyoffice-docservice" to "10.89.0.10", "onlyoffice-front" to "10.89.0.11")
        assertEquals(office.keys, internalRouteConsumers("office", "POST", "/onlyoffice/editor-callback/", office))
    }

    @Test fun `Office internal HTTPS permits only real Office member and exact Seafile native routes`(): Unit {
        val root = Files.createTempDirectory("internal-route-unit-")
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        try {
            val cert = "UNIT ORIGINAL CERT".encodeToByteArray()
            val key = "UNIT ORIGINAL KEY".encodeToByteArray()
            val ca = "-----BEGIN CERTIFICATE-----\nUNIT SEALED CA\n-----END CERTIFICATE-----".encodeToByteArray()
            fun source(name: String, bytes: ByteArray): ActivationInput {
                val file = root.resolve(name)
                ReleasePrivateFiles.save(file, bytes)
                return ActivationInput(file.toString(), ReleaseLocks.sha256(bytes))
            }
            val gen = "q-000000000002"
            val net = "onlyoffice-web"
            val image = "registry.example.invalid/owned@sha256:${"a".repeat(64)}"
            val caddy = RuntimeProcess("caddy", image, "a".repeat(64), 1000,
                files = listOf(RuntimeFile("cert.pem", "/run/secrets/cert.pem"),
                    RuntimeFile("key.pem", "/run/secrets/key.pem"), RuntimeFile("ca.pem", "/run/secrets/ca.pem")),
                networks = listOf(net, "seafile-web"),
                networkAliases = listOf(RuntimeNetworkAlias(net, "files.datamancy.net")), readiness = listOf("true"),
                capabilities = listOf("NET_BIND_SERVICE"))
            val consumer = RuntimeProcess("onlyoffice-docservice", image, "a".repeat(64), 1000,
                networks = listOf(net, "office-data"), readiness = listOf("true"))
            val front = RuntimeProcess("onlyoffice-front", image, "a".repeat(64), 1000,
                networks = listOf(net, "office-data"), readiness = listOf("true"))
            val backend = RuntimeProcess("seafile-files", image, "a".repeat(64), 1000,
                networks = listOf("seafile-web", "office-data"), readiness = listOf("true"))
            val spec = PrivateDeploymentSpec(name = "$gen-restored", volumes = emptyList(), processes = listOf(caddy, consumer, front, backend),
                networks = listOf(net, "seafile-web", "office-data"), store = RuntimeStore.CANONICAL_V2)
            val binding = InternalServiceBinding("r-000000000009", "office", gen, "a".repeat(64), net,
                "10.89.0.5", mapOf("onlyoffice-docservice" to "10.89.0.7",
                    "onlyoffice-front" to "10.89.0.8"),
                "p0v3-internal-office-onlyoffice-web", "files.datamancy.net",
                "p0v3-live-$gen-restored-seafile-files:8443", "seafile-files",
                source("source-cert", cert), source("source-key", key),
                "/run/secrets/cert.pem", "/run/secrets/key.pem", source("source-ca", ca), "/run/secrets/ca.pem")
            assertFalse("nativePublicCertificate" in json.encodeToString(binding))
            var current = Json.parseToJsonElement("""{"apps":{"http":{"servers":{"foreign":{"listen":["10.89.1.1:443"]}}}},"foreign":{"retained":true}}""").jsonObject
            var writes = 0; var lostAcknowledgement = true
            val transport = CaddyTransport { method, path, etag, body ->
                assertEquals("/config/", path)
                val expected = "\"/config/ ${TransactionalCaddy.digest(current).take(16)}\""
                if (method == "GET") CaddyReply(200, current.toString().encodeToByteArray(), expected)
                else {
                    assertEquals("POST", method); assertEquals(expected, etag); writes++
                    current = Json.parseToJsonElement(requireNotNull(body).decodeToString()).jsonObject
                    if (lostAcknowledgement) {
                        lostAcknowledgement = false
                        error("synthetic lost POST acknowledgement; source must read only")
                    }
                    CaddyReply(200, byteArrayOf(), null)
                }
            }
            val actor = InternalServiceRoutes(root, binding, spec, transport, { "10.89.0.5" },
                { id -> if (id == "onlyoffice-docservice") "10.89.0.7" else "10.89.0.8" },
                { bytes, host -> assertContentEquals(cert, bytes); assertEquals("files.datamancy.net", host) },
                { file -> when (file) { "cert.pem" -> cert; "key.pem" -> key; "ca.pem" -> ca; else -> error("foreign") } })
            val prior = TransactionalCaddy.digest(current)
            assertFailsWith<IllegalStateException> { actor.install(prior) }
            assertEquals(1, writes)
            val pending = ReleasePrivateFiles.read(root.resolve("internal.pending"))
            val done = actor.reconcile(ReleaseLocks.sha256(pending))
            assertEquals(1, writes); assertEquals(prior, done.beforeSha256)
            assertEquals(JsonPrimitive(true), current.getValue("foreign").jsonObject["retained"])
            val server = current.getValue("apps").jsonObject.getValue("http").jsonObject.getValue("servers").jsonObject
                .getValue(binding.server).jsonObject
            assertEquals("10.89.0.5:443", server.getValue("listen").jsonArray.single().jsonPrimitive.content)
            val routes = server.getValue("routes").jsonArray
            assertEquals(4, routes.size)
            assertEquals(setOf("GET", "HEAD", "POST"), routes.take(3).map {
                it.jsonObject.getValue("match").jsonArray.single().jsonObject.getValue("method").jsonArray.single().jsonPrimitive.content
            }.toSet())
            assertTrue(routes.take(3).all {
                it.jsonObject.getValue("match").jsonArray.single().jsonObject.getValue("remote_ip")
                    .jsonObject.getValue("ranges").jsonArray.map { ip -> ip.jsonPrimitive.content }.toSet() ==
                    setOf("10.89.0.7/32", "10.89.0.8/32")
            })
            assertTrue("\"server_name\":\"seafile-files\"" in current.toString() &&
                "\"ca\":{\"provider\":\"file\",\"pem_files\"" in current.toString())
            assertFalse("/api2/repos/" in current.toString() || "/admin/" in current.toString())
            assertFailsWith<IllegalArgumentException> { actor.install(TransactionalCaddy.digest(current)) }
            assertEquals(1, writes)
            assertFailsWith<IllegalArgumentException> {
                InternalServiceRoutes(root, binding.copy(consumerAddresses = mapOf("foreign" to "10.89.0.8")),
                    spec, transport, { "10.89.0.5" }, { "10.89.0.8" })
            }
            // Canonical source can use its already-owned PUBLIC ACME leaf on an exact primary
            // ingress IP. Internal listener does not mount a second conflicting cert/key or
            // alter the renewal policy; restored target above uses original sealed crypto.
            val canonicalRoot = root.resolve("canonical")
            Files.createDirectory(canonicalRoot)
            Files.setPosixFilePermissions(canonicalRoot, PosixFilePermissions.fromString("rwx------"))
            val publicCaddy = caddy.copy(networks = listOf("ingress-egress", net, "seafile-web"),
                files = listOf(RuntimeFile("ca.pem", "/run/secrets/ca.pem")),
                entrypoint = "/usr/bin/caddy", command = listOf("run", "--config", "/run/secrets/caddy.json"))
            val publicSpec = spec.copy(networks = listOf("ingress-egress") + spec.networks,
                processes = listOf(publicCaddy, consumer, front, backend),
                ingress = RuntimeIngressPublication("unit", setOf("files.datamancy.net"), "0.0.0.0"))
            val publicBinding = binding.copy(operation = "r-000000000010", certificateFile = "", privateKeyFile = "",
                nativePublicCertificate = true)
            val issuer = AcmeEnvironment.PRODUCTION.directory
            var published = Json.parseToJsonElement("""{"storage":{"module":"file_system","root":"/data/caddy"},"apps":{"http":{"servers":{"public":{"listen":["10.89.0.3:443"],"routes":[]}}},"tls":{"automation":{"policies":[{"subjects":["files.datamancy.net"],"issuers":[{"module":"acme","ca":"$issuer"}]}]},"certificates":{"automate":["files.datamancy.net"]}}}}""").jsonObject
            val publicTransport = CaddyTransport { method, _, etag, body ->
                val tag = "\"/config/ ${TransactionalCaddy.digest(published).take(16)}\""
                if (method == "GET") CaddyReply(200, published.toString().encodeToByteArray(), tag)
                else {
                    assertEquals(tag, etag)
                    published = Json.parseToJsonElement(requireNotNull(body).decodeToString()).jsonObject
                    CaddyReply(200, byteArrayOf(), null)
                }
            }
            val sourceActor = InternalServiceRoutes(canonicalRoot, publicBinding, publicSpec, publicTransport,
                { "10.89.0.5" }, { id -> if (id == "onlyoffice-docservice") "10.89.0.7" else "10.89.0.8" },
                { _, _ -> }, { file -> if (file == "ca.pem") ca else error("Source public cert must stay Caddy-owned") },
                { ReleaseLocks.sha256(it) }, { host -> assertEquals("files.datamancy.net", host); ReleaseLocks.sha256(cert) })
            sourceActor.install(TransactionalCaddy.digest(published))
            assertFalse("load_files" in published.getValue("apps").jsonObject.getValue("tls")
                .jsonObject.getValue("certificates").jsonObject)
            assertEquals("10.89.0.3:443", published.getValue("apps").jsonObject.getValue("http")
                .jsonObject.getValue("servers").jsonObject.getValue("public").jsonObject
                .getValue("listen").jsonArray.single().jsonPrimitive.content)
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
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
