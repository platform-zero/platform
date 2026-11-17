package net.datamancy.platform

import java.nio.file.Path
import org.junit.jupiter.api.Test
import kotlin.test.*

/** Read-only owner/native lock diagnostic. Never records a terminal ACK. */
class Q5962TerminalNativeReadOnlyDiagnosticTest {
    @Test fun `native terminal preflight remains read only and exposes exact refusal`() {
        val census=ActivationInput(Path.of("/home/gerald/p0_v3/.coord/rapid-completion/core-q5962-member-v3-postinput-observation-735.json").toString(),
            "54ab7b8617df9eef62081fc0d1d22a093383f980de79e4778297f19a945da7c4")
        try {
            val evidence=GenerationRuntime.real().observeFailedPreparation("q-5962a9fda75b",census)
            assertEquals(135,evidence.nativeUnitCount)
            assertEquals(4,evidence.nativeNamespaceSha256.size)
        } catch(e:Exception) {
            // These messages are bounded, typed native-absence refusals. No
            // token, file contents or generated credential may be printed.
            throw AssertionError("Read-only terminal source/native refusal: ${e.javaClass.simpleName}: ${e.message?.take(180)}")
        }
    }
}
