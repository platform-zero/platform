package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.json.*
import kotlin.test.*

class GenerationReleaseEffectsTest {
    private val generation = "q-111111111111"
    private val site = CaddySiteBinding("unit", "https", "http://127.0.0.1:2019", setOf("boards.datamancy.net"))
    private val upstreams = listOf(CaddyUpstream("boards.datamancy.net", "p0v3-live-$generation-core-planka:1337"))
    private fun configuration(routes: JsonArray) = buildJsonObject {
        put("apps", buildJsonObject { put("http", buildJsonObject { put("servers", buildJsonObject {
            put("https", buildJsonObject { put("routes", routes) })
        }) }) })
    }
    private inner class Transport : CaddyTransport {
        var current = configuration(JsonArray(emptyList()))
        var failAfterWrite = false
        override fun exchange(method: String, path: String, etag: String?, body: ByteArray?): CaddyReply {
            if (method == "GET") return CaddyReply(200, current.toString().toByteArray(), "\"/config/ ${TransactionalCaddy.digest(current).take(16)}\"")
            current = configuration(Json.parseToJsonElement(requireNotNull(body).decodeToString()).jsonArray)
            if (failAfterWrite) error("synthetic lost acknowledgement")
            return CaddyReply(200, byteArrayOf(), null)
        }
    }
    private class Control : ReleaseGenerationControl {
        val calls = mutableListOf<String>(); var failure: String? = null
        private fun call(name: String) {
            calls += name
            if (failure == "interrupt-$name") Thread.currentThread().interrupt()
            if (failure == name) error("synthetic failure")
        }
        override fun preflight() = call("preflight")
        override fun stage() = call("stage")
        override fun readiness() = call("readiness")
        override fun freeze() = call("freeze")
        override fun verifyQuiesced() = call("quiesce")
        override fun capture(): String { call("capture"); return "cap-111111111111" }
        override fun restoreTest(snapshot: String) { assertEquals("cap-111111111111", snapshot); call("restore-test") }
        override fun migrate() = call("migrate")
        override fun resumeRestrictedCandidate() = call("resume-restricted")
        override fun isolateCandidate() = call("isolate")
        override fun restorePrevious(snapshot: String) = call("restore-previous")
        override fun verifyPrevious() = call("verify-previous")
        override fun qualificationSnapshot(): String { call("qualification-snapshot"); return "cap-222222222222" }
    }
    private fun fixture(action: (Path, Transport, Control, GenerationReleaseEffects, MutableList<String>) -> Unit) {
        val root = Files.createTempDirectory("release-effects-unit-")
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        fun dir(name: String) = Files.createDirectory(root.resolve(name), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val caddyRoot = dir("caddy"); val effectsRoot = dir("effects")
        try {
            val transport = Transport(); val caddy = TransactionalCaddy(caddyRoot, site, transport)
            val token = "a".repeat(64); val tokenPath = root.resolve("token"); ReleasePrivateFiles.save(tokenPath, token.toByteArray())
            val ingress = ReleaseIngress(site, caddyRoot.toString(), upstreams, ActivationInput(tokenPath.toString(), ReleaseLocks.sha256(token.toByteArray())),
                caddy.observeConfigurationSha256(), null, "r-111111111111", "r-222222222222", "r-333333333333", "r-444444444444")
            val deployment = ReleaseDeploymentBinding(generation, "b".repeat(64), "c".repeat(64),
                TransactionalCaddy.digest(caddy.revision(ingress.cutover, generation, upstreams, token)))
            val control = Control(); val publication = mutableListOf<String>()
            val effects = GenerationReleaseEffects(effectsRoot, "transaction", "d".repeat(64), deployment, ingress, control,
                object : ReleasePublicationControl {
                    override fun pause() { publication += "pause" }
                    override fun release() { publication += "release" }
                }, caddy)
            action(effectsRoot, transport, control, effects, publication)
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `typed production composition retains intents and uses real caddy CAS protocol`() = fixture { root, _, control, effects, publication ->
        effects.preflight(); effects.pauseOutbound(); effects.stageImmutableCandidate(); effects.checkPrivateReadinessAndIntegrations()
        effects.freezeNonTestWrites(); effects.quiesceQueues(); val cap = effects.snapshotCoordinated()
        effects.verifySnapshotAndIsolatedFunctionalRestore(cap); effects.migrateStaged()
        effects.restrictPublicWritesToAcceptance(); effects.loadAllApprovedHostsOnce()
        assertEquals("cap-222222222222", effects.verifyQualificationSnapshot())
        effects.openPublicWrites(); effects.releaseOutbound()
        effects.restrictPublicWritesToAcceptance(); effects.pauseOutbound(); effects.isolateCandidate()
        effects.restoreOldSnapshot(cap); effects.verifyOldStack()
        assertEquals(listOf("pause", "release", "pause"), publication)
        assertTrue("resume-restricted" in control.calls)
        for (name in listOf("stage", "readiness", "freeze", "capture", "restore-test", "migrate", "restrict", "cutover", "open-writes", "outbound", "isolate")) {
            assertTrue(Files.exists(root.resolve("$name.intent.json"))); assertTrue(Files.exists(root.resolve("$name.result.json")))
        }
        assertFails { effects.stageImmutableCandidate() }
        assertEquals(1, control.calls.count { it == "stage" })
    }
    @Test fun `lost cutover acknowledgement is observed before scoped rollback never resent`() = fixture { _, transport, _, effects, _ ->
        effects.preflight(); effects.restrictPublicWritesToAcceptance(); transport.failAfterWrite = true
        assertFails { effects.loadAllApprovedHostsOnce() }
        transport.failAfterWrite = false
        effects.reloadPreviousCaddyConfig()
        val routes = transport.current["apps"]!!.jsonObject["http"]!!.jsonObject["servers"]!!.jsonObject["https"]!!.jsonObject["routes"]!!.jsonArray
        assertTrue(routes.isEmpty())
    }
    @Test fun `effect failure keeps failed record and prohibits another attempt`() = fixture { root, _, control, effects, _ ->
        control.failure = "stage"
        assertFails { effects.stageImmutableCandidate() }
        assertTrue(Files.readString(root.resolve("stage.result.json")).contains("\"passed\":false"))
        control.failure = null
        assertFails { effects.stageImmutableCandidate() }
        assertEquals(listOf("stage"), control.calls)
    }
    @Test fun `interrupted effect does not invoke generation and retains uncertainty`() = fixture { root, _, control, effects, _ ->
        Thread.currentThread().interrupt()
        try {
            assertFailsWith<InterruptedException> { effects.stageImmutableCandidate() }
            assertTrue(Thread.currentThread().isInterrupted); assertTrue(control.calls.isEmpty())
            assertTrue(Files.exists(root.resolve("stage.result.json")))
        } finally { Thread.interrupted() }
    }
    @Test fun `cancellation after an effect returns is retained as uncertain not successful`() = fixture { root, _, control, effects, _ ->
        control.failure = "interrupt-stage"
        try {
            assertFailsWith<InterruptedException> { effects.stageImmutableCandidate() }
            assertTrue(Thread.currentThread().isInterrupted)
            assertEquals(listOf("stage"), control.calls)
        } finally { Thread.interrupted() }
        assertTrue(Files.readString(root.resolve("stage.result.json")).contains("\"passed\":false"))
        assertFails { effects.stageImmutableCandidate() }
        assertEquals(1, control.calls.size)
    }
    @Test fun `unknown public cutover cannot be overwritten by restricting stale configuration`() = fixture { _, transport, _, effects, _ ->
        effects.preflight(); effects.restrictPublicWritesToAcceptance(); effects.loadAllApprovedHostsOnce()
        transport.failAfterWrite = true
        assertFails { effects.openPublicWrites() }
        assertFails { effects.restrictPublicWritesToAcceptance() }
    }
}
