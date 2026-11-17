package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import org.junit.jupiter.api.Test
import kotlin.test.*

/** Invalid read-only source input must fail before creating any one-use record.
 * This cannot be mistaken for a terminal ACK or native reconciliation. */
class Q5962TerminalV2PreEffectGuardTest {
    @Test fun `wrong v2 refusal log pin is rejected before any member or journal operation`() {
        val root=GenerationRuntime.BASE.resolve("q-5962a9fda75b")
        val log=Path.of("/home/gerald/p0_v3/.coord/rapid-completion/core-q5962-terminal-v2-once-764.log")
        val target=root.resolve(GenerationPreparationTerminalDisposition.V2_PRE_EFFECT)
        val old=if(Files.exists(target)) ReleaseLocks.sha256(ReleasePrivateFiles.read(target,16384)) else null
        val bad=ActivationInput(log.toString(),"0".repeat(64))
        assertFailsWith<IllegalArgumentException> {
            GenerationPreparationTerminalDisposition.recordV2PreEffectRefusal(root,
                ActivationInput("/home/gerald/p0_v3/.coord/rapid-completion/core-q5962-member-v3-postinput-observation-735.json",
                    "54ab7b8617df9eef62081fc0d1d22a093383f980de79e4778297f19a945da7c4"),bad)
        }
        assertEquals(old,if(Files.exists(target)) ReleaseLocks.sha256(ReleasePrivateFiles.read(target,16384)) else null)
    }
}
