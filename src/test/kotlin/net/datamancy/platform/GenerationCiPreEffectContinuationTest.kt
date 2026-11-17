package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import kotlin.test.*

/** Artifact-backed read-only test of the exact failed original; no effect or fabricated ACK. */
class GenerationCiPreEffectContinuationTest {
    @Test fun `copied original footprint fences tampered managed output and uncertain CI effect`(@TempDir temp: Path) {
        val source = GenerationRuntime.BASE.resolve(GenerationCiPreEffectContinuation.GENERATION)
        val copy = temp.resolve("original")
        val dirs = listOf("", "managed", "managed/control", "managed/inputs", "rss", "rss/state", "rss/tokens")
        for (dir in dirs) {
            val path = if (dir.isEmpty()) copy else copy.resolve(dir)
            Files.createDirectory(path)
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
        }
        for (path in listOf("assembly.intent.json", "assembly.result.json", "ownership.intent.json",
            "managed/control/storage.conf", "managed/inputs/broker.json", "managed/inputs/target-lane.toml",
            "rss/state/rss-state.json", "rss/state/rss-state.lock")) {
            Files.copy(source.resolve(path),copy.resolve(path))
            Files.setPosixFilePermissions(copy.resolve(path),PosixFilePermissions.fromString("rw-------"))
        }
        GenerationCiPreEffectContinuation.verifyPreEffectFootprint(copy)
        Files.writeString(copy.resolve("managed/inputs/broker.json"), "tampered")
        assertFailsWith<IllegalArgumentException> { GenerationCiPreEffectContinuation.verifyPreEffectFootprint(copy) }
        Files.delete(copy.resolve("managed/inputs/broker.json"))
        Files.copy(source.resolve("managed/inputs/broker.json"),copy.resolve("managed/inputs/broker.json"))
        Files.setPosixFilePermissions(copy.resolve("managed/inputs/broker.json"),PosixFilePermissions.fromString("rw-------"))
        Files.createDirectory(copy.resolve("ci"))
        assertFailsWith<IllegalArgumentException> { GenerationCiPreEffectContinuation.verifyPreEffectFootprint(copy) }
        Files.delete(copy.resolve("ci"))
        GenerationCiPreEffectContinuation.verifyPreEffectFootprint(copy)
    }
    @Test fun `failed original is exact pre CI and cannot become passed`() {
        val root = GenerationRuntime.BASE.resolve(GenerationCiPreEffectContinuation.GENERATION)
        val failed = GenerationRuntime.privateInput(root.resolve("assembly.result.json")).decodeToString()
        assertContains(failed, "\"passed\":false")
        assertContains(failed, "java.lang.IllegalArgumentException")
        val dispositionFile = root.resolve(GenerationCiPreEffectContinuation.FILE)
        if (java.nio.file.Files.exists(dispositionFile)) {
            val pin = GenerationCiPreEffectContinuation.binding(root)
            val record = GenerationCiPreEffectContinuation.verify(root, pin)
            assertFalse(record.originalPassed)
            assertFailsWith<IllegalArgumentException> {
                GenerationCiPreEffectContinuation.verify(root, pin.copy(sha256 = "0".repeat(64)))
            }
            if (!java.nio.file.Files.exists(root.resolve(GenerationCiPreEffectContinuation.INTENT))) {
                GenerationCiPreEffectContinuation.verify(root,pin,beforeEffects=true)
            } else {
                assertFailsWith<IllegalArgumentException> {
                    GenerationCiPreEffectContinuation.verify(root,pin,beforeEffects=true)
                }
            }
        } else {
            val original = GenerationCiPreEffectContinuation.original(root)
            assertEquals("java.lang.IllegalArgumentException", kotlinx.serialization.json.Json
                .decodeFromString<AssemblyPreparationOutcome>(GenerationRuntime.privateInput(root.resolve("assembly.result.json")).decodeToString()).failureType)
            assertFalse(original.originalPassed)
            assertEquals(GenerationCiPreEffectContinuation.ORIGINAL_CONTROLLER,original.originalControllerSha256)
        }
    }
}
