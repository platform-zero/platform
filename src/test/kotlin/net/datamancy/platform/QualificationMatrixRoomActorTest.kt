package net.datamancy.platform

import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class QualificationMatrixRoomActorTest {
    private val generation = "q-123456789abc"
    private val source = "q-abcdef123456"
    private val room = "!OriginalRoom1234:matrix.datamancy.net"
    private val device = "DEVICE0001"
    private val original = buildJsonObject {
        put("generation", generation); put("room", room)
        put("sourceGeneration", source); put("ownerDeviceId", device)
    }
    @Test fun `only matching original local Android pre-effect intent is admitted`() {
        QualificationMatrixRoomActor.verifyLocalIntent(original, generation, room, source, device)
        for ((key, foreign) in mapOf("generation" to "q-000000000000", "room" to "!Different:matrix.datamancy.net",
            "sourceGeneration" to generation, "ownerDeviceId" to "DIFFERENT")) {
            val changed = JsonObject(original + (key to JsonPrimitive(foreign)))
            assertThrows(IllegalArgumentException::class.java) {
                QualificationMatrixRoomActor.verifyLocalIntent(changed, generation, room, source, device)
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            QualificationMatrixRoomActor.verifyLocalIntent(JsonObject(original + ("command" to JsonPrimitive("sh"))),
                generation, room, source, device)
        }
    }
}
