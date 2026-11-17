package net.datamancy.platform

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Schema only; native Pi/TUIOS windows, original attempt and isolated managed
 * start must be observed after actual startup, never by this fixture. */
class ManagedRestoreStartupReceiptSourceTest {
    @Test fun `receipt schema carries independently sourced Pi and uncertain tool bindings`() {
        val h="a".repeat(64)
        val receipt=ManagedRestoreStartupReceipt("q-111111111111","q-222222222222",
            "source-lane","target-lane",h,h,h,h,h,h,h,"b".repeat(64),
            "source-window","target-window",listOf("native-tool-id"),h,h,h)
        val encoded=Json { encodeDefaults=true }.encodeToString(receipt)
        val parsed=Json.parseToJsonElement(encoded).jsonObject
        assertEquals("source-window",parsed.getValue("sourcePiWindowId").toString().trim('"'))
        assertTrue(listOf("sourcePiOracleSha256","originalAttemptSha256","targetPiReadbackSha256",
            "uncertainToolCalls","targetPiWindowId").all { it in parsed })
    }
}
