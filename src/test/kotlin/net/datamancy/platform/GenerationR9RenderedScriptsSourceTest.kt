package net.datamancy.platform

import org.junit.jupiter.api.Test
import kotlin.test.*
import java.nio.file.Path
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject

/** Pure selected OCI-to-script source; fake passwords below never enter release. */
class GenerationR9RenderedScriptsSourceTest {
    @Test fun `selected source binds thirteen rendered SHA1 and SHA256 pairs without Redis acceptance`() {
        val generation="q-5962a9fda75b"
        val root=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/$generation")
        val input=ReleasePrivateFiles.read(Path.of(
            "/mnt/media/p0-v3/release-bootstrap-anchors/mastodon/$generation/rendered-scripts.json"),65536)
        val source=Json.parseToJsonElement(input.decodeToString()).jsonObject
        assertEquals(13,source.getValue("renderedSha256").jsonObject.size)
        assertEquals("dafc870490ce3420c4c612d67a945d77c4bd15a098409779314673b51e09b9a4",
            ReleaseLocks.sha256(input))
        val inventory=Json.decodeFromString<AcquiredInventory>(ReleasePrivateFiles.read(root.resolve("inventory.json"),2097152)
            .decodeToString())
        val projected=MastodonRedisBridgeSource.inputs(generation,
            inventory.images.single { it.product=="mastodon" },"7.2.15",
            input.decodeToString(),"a".repeat(64),"b".repeat(64))
        assertEquals(input.decodeToString(),projected.getValue("mastodon-bridge-scripts.json"))
        assertFalse(source.keys.contains("nativeScriptLoadObserved"))
    }
}
