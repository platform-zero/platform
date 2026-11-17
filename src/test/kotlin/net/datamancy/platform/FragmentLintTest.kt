package net.datamancy.platform

import java.nio.file.Files
import kotlinx.serialization.json.*
import kotlin.test.*

class FragmentLintTest {
    @Test fun `CLI lint accepts a copied declaration but grants no runtime authority`() {
        val root = Files.createTempDirectory("fragment-lint-")
        val path = root.resolve("fragment.yaml")
        try {
            val bytes = javaClass.getResourceAsStream("/fragments/v2/forgejo/r1/fragment.yaml")!!.use { it.readBytes() }
            Files.write(path, bytes)
            val output = mutableListOf<String>(); val errors = mutableListOf<String>()
            assertEquals(0, runCommand(arrayOf("release", "fragment-lint", path.toString()), output::add, errors::add))
            assertTrue(errors.isEmpty())
            val report = Json.parseToJsonElement(output.single()).jsonObject
            assertEquals(ReleaseLocks.sha256(bytes), report.getValue("sourceSha256").jsonPrimitive.content)
            assertTrue(report.getValue("localDeclarationValid").jsonPrimitive.boolean)
            for (field in listOf("runtimeAdmitted", "fullGraphValidated", "qualificationEvidence")) {
                assertFalse(report.getValue(field).jsonPrimitive.boolean)
            }
            assertFalse(output.single().contains("CREATE ROLE"))
            assertEquals(listOf(path), Files.list(root).use { it.toList() })
            assertContentEquals(bytes, Files.readAllBytes(path))
            assertTrue(GenerationAssembly.catalog.none { it.id == "forgejo-postgres" || it.id == "postgres-timescale" })
        } finally { Files.deleteIfExists(path); Files.delete(root) }
    }

    @Test fun `CLI refuses linked invalid and oversized inputs without exposing content`() {
        val root = Files.createTempDirectory("fragment-lint-negative-")
        val path = root.resolve("bad.yaml"); val link = root.resolve("link.yaml")
        try {
            Files.writeString(path, "secret: never-disclose-this-value")
            Files.createSymbolicLink(link, path)
            for (input in listOf(path, link, root)) {
                val output = mutableListOf<String>(); val errors = mutableListOf<String>()
                assertEquals(1, runCommand(arrayOf("release", "fragment-lint", input.toString()), output::add, errors::add))
                assertTrue(output.isEmpty())
                assertFalse(errors.single().contains("never-disclose-this-value"))
            }
            Files.write(path, ByteArray(FragmentYaml.MAX_BYTES + 1) { 32 })
            assertFails { FragmentLint.inspect(path) }
        } finally { Files.deleteIfExists(link); Files.deleteIfExists(path); Files.delete(root) }
    }
}
