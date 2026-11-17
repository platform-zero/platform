package net.datamancy.platform

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

class Q273UncertainManagedImportTerminalTest {
    @Test fun typedCheckpointCannotClaimAnOriginalImportOrStart() {
        val receipt=Q273UncertainImportDisposition(generation=Q273UncertainManagedImportTerminal.generation,
            member="q-273337d6772c-v2",bundleSha256=Q273UncertainManagedImportTerminal.bundleSha,
            originalStageIntentSha256="s",originalManagedIntentSha256="m",
            originalWorklanePrepareIntentSha256="p",manifestSha256="manifest",
            sourceManifestSha256="source",sourceManifestPath="/private/inputs/target-lane.toml",
            rootlessImageId="native-image",rootlessImageBytes=674517341,
            rootlessLayersSha256="layers",graphRoot="/private/containers/storage",
            graphAllocatedBytes=4338245632,graphEntries=182993,
            preservedHomeDirectories=listOf("managed/home/workspace","managed/home/.pi/agent/sessions",
                "managed/manifests","managed/control/data/worklane"),nativeSystemdUnitsSha256="empty",
            nativeSystemdUnitFilesSha256="empty")
        val decoded=Json.decodeFromString<Q273UncertainImportDisposition>(Json.encodeToString(receipt))
        assertEquals(receipt,decoded)
        assertFalse(decoded.importedImageAcknowledged)
        assertFalse(decoded.applicationUnitStarted)
        assertEquals(0,decoded.qualificationCycles)
    }
}
