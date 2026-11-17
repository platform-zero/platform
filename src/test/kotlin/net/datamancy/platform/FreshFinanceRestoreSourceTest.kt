package net.datamancy.platform

import kotlin.test.*
import kotlinx.serialization.json.*

class FreshFinanceRestoreSourceTest {
    @Test fun `r4 importer mounts actual reset implementation before first startup`() {
        val base = "/fragments/v3/firefly-iii/r4/"
        fun source(name: String) = checkNotNull(javaClass.getResource(base + name)).readText()
        val definition = Json.parseToJsonElement(source("fragment.yaml")).jsonObject
        assertEquals(4, definition.getValue("revision").jsonPrimitive.int)
        val process = definition.getValue("processes").jsonArray.map { it.jsonObject }
            .single { it.getValue("id").jsonPrimitive.content == "firefly-importer" }
        assertTrue(process.getValue("files").jsonArray.any { it.jsonObject.let { file ->
            file.getValue("file").jsonPrimitive.content == "finance-restore-access-reset.php" &&
                file.getValue("target").jsonPrimitive.content == "/opt/firefly-importer/RestoreAccessReset.php"
        } })
        assertTrue(definition.getValue("templates").jsonArray.any { it.jsonObject.let { template ->
            template.getValue("output").jsonPrimitive.content == "finance-restore-access-reset.php" &&
                template.getValue("resource").jsonPrimitive.content == "restore-access-reset.php"
        } })
        assertContains(source("restore-access-reset.php"), "getenv('P0V3_GENERATION')")
        assertContains(source("restore-access-reset.php"), "fsync(")
        assertContains(source("initialize-policy.php"), "require_once '/opt/firefly-importer/RestoreAccessReset.php'")
        val env = FreshFinanceImporterSource.inputs("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "a".repeat(64), "q-123456789abc")
        assertContains(env, "P0V3_GENERATION=q-123456789abc\n")
        assertFails { FreshFinanceImporterSource.inputs("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "a".repeat(64), "q-ffffffffffff/foreign") }
    }
}
