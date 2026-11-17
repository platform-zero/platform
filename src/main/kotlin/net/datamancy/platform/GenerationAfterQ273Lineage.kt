package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS

/** q273's imported manifest/image stay fenced; a NEW candidate can inherit
 * only this typed terminal, never its unacknowledged image load or lane. */
internal object GenerationAfterQ273Lineage {
    const val generation="q-58321c79fde9"
    const val predecessorSha="8fd743fb0313a2e6d1e59e36da56a36d8d8051fc0a3a217be2438575edf269f7"
    val predecessor=ActivationInput(
        "/mnt/media/p0-v3/release-generations/q-273337d6772c/uncertain-native-worklane-manifest-import-v1.disposition.json",
        predecessorSha)
    fun verify(pin:ActivationInput,qc3:ActivationInput,q4d:ActivationInput,probe:ActivationInput) {
        require(pin==predecessor && qc3==GenerationAfterCapacityRefusalLineage.qc3)
        GenerationAfterCapacityRefusalLineage.verify(qc3,q4d,probe)
        val seen=Q273UncertainManagedImportTerminal.verify(pin)
        require(seen.originalResultsAbsent && seen.rootfulNamespaceAbsent &&
            !seen.importedImageAcknowledged && !seen.applicationUnitStarted &&
            seen.graphAllocatedBytes>=4294967296L && seen.graphEntries>1 && seen.qualificationCycles==0)
        WorklaneLateBrokerImportProof.verifySelected(ActivationInput(
            WorklaneLateBrokerImportProof.binaryPath,WorklaneLateBrokerImportProof.binarySha))
    }
    fun beforeSourceIssue(value:String) {
        if(value==generation) {
            require(!Files.exists(GenerationRuntime.BASE.resolve(value),NOFOLLOW_LINKS))
            verify(predecessor,GenerationAfterCapacityRefusalLineage.qc3,
                GenerationAfterNativeImportLineage.terminal,GenerationAfterNativeImportLineage.probe)
        }
    }
}
