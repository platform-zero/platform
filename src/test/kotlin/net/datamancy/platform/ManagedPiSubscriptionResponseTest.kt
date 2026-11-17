package net.datamancy.platform

import kotlin.test.*
import org.junit.jupiter.api.Test

class ManagedPiSubscriptionResponseTest {
    @Test fun `completed text and tool items become bounded Responses events`() {
        val value="""{"object":"response","status":"completed","model":"gpt-6-sol","id":"resp_fixture","output":[{"type":"message","id":"msg_fixture","role":"assistant","status":"completed","content":[{"type":"output_text","text":"hello","annotations":[]}]},{"type":"function_call","id":"fc_fixture","call_id":"call_fixture","name":"read","arguments":"{}","status":"completed"}]}"""
        val frames=ManagedPiSubscriptionResponse.sse(value.toByteArray()).decodeToString()
        assertEquals(2,frames.split("\"type\":\"response.output_item.added\"").size-1)
        assertEquals(2,frames.split("\"type\":\"response.output_item.done\"").size-1)
        assertTrue(frames.endsWith("data: [DONE]\n\n"))
        assertTrue(frames.contains("\"call_id\":\"call_fixture\""))
        assertFails { ManagedPiSubscriptionResponse.sse(value.replace("gpt-6-sol","other").toByteArray()) }
    }
    @Test fun `old project key host cannot be declared for selected generation`() {
        val gen="q-5962a9fda75b"
        fun pin(name:String)=ActivationInput("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/$gen/$name","a".repeat(64))
        assertFails { ManagedBrokerHostBinding(pin("agent-secret"),pin("reader-secret"),pin("upstream-openai-key"),graphOwnedLatePublicTrust=true).validate(gen) }
    }
}
