package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse

class WorklaneLateBrokerImportProofTest {
    @Test fun actualIsolatedImportWithoutSocketAndFailedStartAreNotGenerationAcks() {
        val binary=ActivationInput(WorklaneLateBrokerImportProof.binaryPath,WorklaneLateBrokerImportProof.binarySha)
        WorklaneLateBrokerImportProof.verifySelected(binary)
        assertFalse(Files.exists(Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/native-probes/"+
            "worklane-late-broker-import-r1/control/run/broker.sock")))
        assertFalse(Files.exists(GenerationRuntime.BASE.resolve(Q273UncertainManagedImportTerminal.generation)
            .resolve("managed/worklane/prepare-managed-initial.result.json")))
    }
}
