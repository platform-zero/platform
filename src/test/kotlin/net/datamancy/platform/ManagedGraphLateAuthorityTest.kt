package net.datamancy.platform

import org.junit.jupiter.api.Test
import kotlin.test.*

class ManagedGraphLateAuthorityTest {
    @Test fun `fresh managed broker declares future graph issuer without pre-acknowledged CA or leaf`() {
        val gen="q-5962a9fda75b"
        fun pin(file:String)=ActivationInput(
            "/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/$gen/$file","d".repeat(64))
        val marker=ActivationInput("/home/gerald/.local/share/p0-v3-subscription/openai-only/script-v3.result.json","d".repeat(64))
        val late=ManagedBrokerHostBinding(pin("agent-secret"),pin("reader-secret"),
            marker,graphOwnedLatePublicTrust=true,authenticationMode="pi-openai-oauth-v2")
        late.validate(gen)
        assertFailsWith<IllegalArgumentException> {
            late.copy(publicCa=pin("unissued-ca.pem")).validate(gen)
        }
        assertFailsWith<IllegalArgumentException> {
            late.copy(publicLeafSha256="a".repeat(64)).validate(gen)
        }
        assertFailsWith<IllegalArgumentException> {
            late.copy(graphOwnedLatePublicTrust=false).validate(gen)
        }
        assertFailsWith<IllegalArgumentException> {
            late.copy(upstreamKey=pin("upstream-openai-key")).validate(gen)
        }
    }
    @Test fun `managed source cannot issue plan from a developer controller or personal OAuth`() {
        assertFailsWith<Exception> {
            GenerationR9ManagedPlan.issue("q-5962a9fda75b","0".repeat(64))
        }
    }
}
