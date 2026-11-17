package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*

/** Mocked Podman answers only; no application initializer or installed unit runs here. */
class RuntimeQuadletInitializerTest {
    private val spec = FragmentAssemblyFixture.plan().specs.single()
    private val fingerprint = "f".repeat(64)
    private fun fixture(action: (java.nio.file.Path, RuntimeQuadletInitializer) -> Unit) {
        val root = Files.createTempDirectory("quadlet-original-init-",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try {
            Files.createDirectory(root.resolve(spec.name), PosixFilePermissions.asFileAttribute(
                PosixFilePermissions.fromString("rwx------")))
            action(root, RuntimeQuadletInitializer(root, spec, fingerprint, root))
        }
        finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    private fun answer(id: String, intent: String, fp: String = fingerprint,
        image: String = spec.processes.single { it.id == id }.imageId,
        exit: Int = 0, running: Boolean = false, cid: String = "b".repeat(64)): String {
        val p = spec.processes.single { it.id == id }
        return """[{"Id":"$cid","Name":"p0v3-live-${spec.name}-${p.id}","Image":"sha256:$image",
            "Config":{"Image":"${p.image}","Labels":{"io.p0v3.private-deployment":"${spec.name}",
            "io.p0v3.runtime-fingerprint":"$fp","io.p0v3.initializer-intent":"$intent"}},
            "State":{"Status":"${if (running) "running" else "exited"}","Running":$running,"ExitCode":$exit,
            "StartedAt":"2026-11-13T10:00:00Z","FinishedAt":"2026-11-13T10:00:02Z"}}]""".trimIndent()
    }
    private fun client(id: String, response: RuntimeCommandResult): RuntimeCommands = RuntimeCommands { args ->
        assertEquals(listOf("container", "inspect", "p0v3-live-${spec.name}-$id"), args)
        response
    }

    @Test fun `original one-shot intent precedes effect and lost ACK cannot replay`() = fixture { root, history ->
        assertFalse(history.completed("forgejo-owner-init"))
        val intent = history.begin("forgejo-owner-init")
        assertTrue(intent.matches(Regex("[a-f0-9]{64}")))
        assertTrue(Files.exists(root.resolve("quadlet-forgejo-owner-init.intent.json")))
        assertFalse(history.completed("forgejo-owner-init"))
        val env = history.prepareEnvironment("forgejo-owner-init")
        assertEquals("P0_RUNTIME_FINGERPRINT=$fingerprint\nP0_INITIALIZER_INTENT=$intent\n",
            Files.readString(env))
        assertEquals(env, history.prepareEnvironment("forgejo-owner-init"))
        assertFailsWith<IllegalArgumentException> { history.begin("forgejo-owner-init") }.also {
            assertContains(it.message.orEmpty(), "reconcile, do not replay")
        }
        assertFails { history.begin("forgejo") }
        assertFails { history.nativeComplete("forgejo-owner-init", client("forgejo-owner-init",
            RuntimeCommandResult(1, ""))) }
        assertFalse(Files.exists(root.resolve("quadlet-forgejo-owner-init.result.json")))
        history.nativeComplete("forgejo-owner-init", client("forgejo-owner-init",
            RuntimeCommandResult(0, answer("forgejo-owner-init", intent))))
        assertTrue(history.completed("forgejo-owner-init"))
        assertFails { history.begin("forgejo-owner-init") }
        // Lost completion ACK reads the original result; never rewrites it or inspects a new CID.
        assertFails { history.nativeComplete("forgejo-owner-init", RuntimeCommands {
            error("Native inspect must not run after original result")
        }) }
    }

    @Test fun `foreign identity partial output and corrupt completion fail closed`() = fixture { root, history ->
        val intent = history.begin("forgejo-db-init")
        val id = "forgejo-db-init"; val original = spec.processes.single { it.id == id }
        val env = history.prepareEnvironment(id)
        val originalEnv = Files.readAllBytes(env)
        Files.writeString(env, "P0_RUNTIME_FINGERPRINT=untrusted\n")
        assertFails { history.nativeComplete(id, RuntimeCommands { error("Changed env must precede inspect") }) }
        Files.write(env, originalEnv)
        for (output in listOf(answer(id, intent, fp = "0".repeat(64)),
            answer(id, intent, image = "0".repeat(64)), answer(id, intent, exit = 1),
            answer(id, intent, running = true), answer(id, intent, cid = "not-a-cid"),
            answer(id, "0".repeat(64)), "[]", "[{},{}]")) {
            assertFails { history.nativeComplete(id, client(id, RuntimeCommandResult(0, output))) }
        }
        assertFalse(Files.exists(root.resolve("quadlet-forgejo-db-init.result.json")))
        val changed = RuntimeQuadletInitializer(root, spec, "a".repeat(64), root)
        assertFails { changed.completed(id) }
        assertFails { changed.nativeComplete(id, RuntimeCommands { error("Foreign input must precede inspect") }) }
        history.nativeComplete(id, client(id, RuntimeCommandResult(0, answer(id, intent, image = original.imageId))))
        assertTrue(history.completed(id))
        Files.writeString(root.resolve("quadlet-forgejo-db-init.result.json"), "wrong")
        assertFails { history.completed(id) }
    }
}
