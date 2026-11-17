package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS

/** q583's prepared-but-never-started inputs are immutable lineage ONLY;
 * the new candidate must pin the real full isolated Worklane PREPARE return. */
internal object GenerationAfterQ583Lineage {
    const val generation="q-9bfa8ec0eb64"
    const val predecessorSha="ed8954b21a9b30337cf7cc1eaf0cdb403064bfdf3b13d9fb277c51d2a02bc685"
    val predecessor=ActivationInput(
        "/mnt/media/p0-v3/release-generations/q-58321c79fde9/prepared-no-start-native-absent-import-semantic-v1.disposition.json",
        predecessorSha)
    val isolatedFullPrepare=ActivationInput(
        WorklaneFullPrepareReturnProbe.base.resolve("full-production-prepare.result.json").toString(),
        WorklaneLateBrokerImportProof.fullPrepareReturnSha)
    fun verify(pin:ActivationInput,full:ActivationInput,q273:ActivationInput,
        qc3:ActivationInput,q4d:ActivationInput,rootless:ActivationInput) {
        require(pin==predecessor && full==isolatedFullPrepare)
        GenerationAfterQ273Lineage.verify(q273,qc3,q4d,rootless)
        val record=Q583PreparedNoStartTerminal.verify(pin)
        val probe=WorklaneFullPrepareReturnProbe.verify(full)
        require(record.nativeStageIntentAbsent && record.nativeManagedIntentAbsent &&
            record.rootlessGraphAbsent && !record.originalServeAttempted &&
            !record.originalServeAcknowledged && record.qualificationCycles==0 &&
            probe.productionBackendAttested && probe.nativeContainers==0 && probe.brokerSocketAbsent &&
            !probe.originalGenerationImportAcknowledged && !probe.applicationStarted &&
            !probe.qualificationEvidence)
    }
    fun beforeSourceIssue(value:String) {
        if(value==generation) {
            require(!Files.exists(GenerationRuntime.BASE.resolve(value),NOFOLLOW_LINKS))
            verify(predecessor,isolatedFullPrepare,GenerationAfterQ273Lineage.predecessor,
                GenerationAfterCapacityRefusalLineage.qc3,GenerationAfterNativeImportLineage.terminal,
                GenerationAfterNativeImportLineage.probe)
        }
    }
}
