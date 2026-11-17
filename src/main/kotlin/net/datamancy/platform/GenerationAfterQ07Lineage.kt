package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS

/** q07 copied disabled units but its auditor result never completed. Preserve
 * original root-owned files and unacknowledged installation, never inherit them. */
internal object GenerationAfterQ07Lineage {
    const val generation="q-74ba90c9136d"
    const val predecessorSha="f6518e51abf67f5e705ec56b26eec6a7724242aa5ab10a9fbd6206e787ee5bd4"
    val predecessor=ActivationInput(
        "/mnt/media/p0-v3/release-generations/q-083e9b7d2a64/partial-disabled-quadlet-install-umask-v1.disposition.json",
        predecessorSha)
    fun verify(q07:ActivationInput,q9b:ActivationInput,q583:ActivationInput,full:ActivationInput,
        q273:ActivationInput,qc3:ActivationInput,q4d:ActivationInput,rootless:ActivationInput) {
        require(q07==predecessor)
        GenerationAfterQ9bLineage.verify(q9b,q583,full,q273,qc3,q4d,rootless)
        val original=Q07PartialInstalledUnitTerminal.verify(q07)
        require(original.originalInstallResultAbsent && original.stageIntentAbsent && original.managedPrepareAbsent &&
            original.sudoUmaskRestrictedDirectories==134 && original.copiedRootOwnedFiles.size==268 &&
            original.generatedUnitHashes.size==134 && original.observedUnitStates.size==134 &&
            !original.applicationStarted && original.qualificationCycles==0)
    }
    fun beforeSourceIssue(value:String) {
        if (value==generation) {
            require(!Files.exists(GenerationRuntime.BASE.resolve(value),NOFOLLOW_LINKS))
            verify(predecessor,GenerationAfterQ9bLineage.predecessor,GenerationAfterQ583Lineage.predecessor,
                GenerationAfterQ583Lineage.isolatedFullPrepare,GenerationAfterQ273Lineage.predecessor,
                GenerationAfterCapacityRefusalLineage.qc3,GenerationAfterNativeImportLineage.terminal,
                GenerationAfterNativeImportLineage.probe)
        }
    }
}
