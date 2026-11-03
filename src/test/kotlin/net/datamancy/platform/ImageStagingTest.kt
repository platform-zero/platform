package net.datamancy.platform

import java.nio.file.Files
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ImageStagingTest {
    private val hash = "a".repeat(64)
    private val image = AcquiredImage("fixture", "https://example.org", "example.org/image:1.0",
        "example.org/image@sha256:$hash", "b".repeat(64), emptyList(), "sha256:$hash", "amd64", "linux")
    private val inventory = AcquiredInventory(1, "candidate", listOf(image))
    private fun info(root: String = PrivateRootfulCommands.ROOT) = RuntimeCommandResult(0,
        """{"store":{"graphRoot":"$root","runRoot":"${PrivateRootfulCommands.RUN}"}}""")
    private fun inspection(id: String = image.imageId) = RuntimeCommandResult(0,
        """[{"Id":"$id","Digest":"${image.selectedManifestDigest}","Architecture":"amd64","Os":"linux"}]""")

    @Test fun `cache verification never pulls mutable discovery tag`() {
        val calls = mutableListOf<List<String>>()
        val stage = ImageStaging { args -> calls += args; if (args.first() == "info") info() else inspection() }
        assertEquals(listOf("fixture"), stage.stage(inventory))
        assertEquals(2, calls.size)
        assertTrue(calls.none { it.contains(image.reference) })
        val path = Files.createTempFile("image-inventory", ".json")
        try {
            Files.writeString(path, Json.encodeToString(inventory))
            assertEquals(inventory, ImageStaging.inventory(path))
        } finally { Files.delete(path) }
    }
    @Test fun `missing image pulls only the exact digest then verifies content`() {
        var present = false
        val stage = ImageStaging { args ->
            when (args.first()) {
                "info" -> info()
                "pull" -> {
                    assertEquals(listOf("pull", "--platform=linux/amd64", image.pinnedImage), args)
                    present = true
                    RuntimeCommandResult(0, "pulled")
                }
                else -> if (present) inspection() else RuntimeCommandResult(125, "not present")
            }
        }
        assertEquals(listOf("fixture"), stage.stage(inventory))
    }
    @Test fun `shared store mutable image content mismatch and failed pulls reject`() {
        assertFailsWith<IllegalArgumentException> { ImageStaging { info("/var/lib/containers/storage") }.stage(inventory) }
        assertFailsWith<IllegalArgumentException> { ImageStaging { error("must not call") }
            .stage(inventory.copy(images = listOf(image.copy(pinnedImage = image.reference)))) }
        assertFailsWith<IllegalArgumentException> { ImageStaging { args ->
            if (args.first() == "info") info() else inspection("c".repeat(64))
        }.stage(inventory) }
        assertFailsWith<IllegalStateException> { ImageStaging { args ->
            if (args.first() == "info") info() else RuntimeCommandResult(125, "failed")
        }.stage(inventory) }
    }
}
