package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS

/** Fresh successor to qc3's PRE-NATIVE capacity refusal. No source credentials,
 * qc3 runtime state, q4d physical graph or missing native ACK can transfer. */
internal object GenerationAfterCapacityRefusalLineage {
    const val generation="q-273337d6772c"
    const val qc3Sha="1ede4412555dde8ac1593bd97a74e7108af739a563cc4a6454eaa7df96989da3"
    val qc3=ActivationInput(
        "/mnt/media/p0-v3/release-generations/q-c3a7a9e29391/qc3-pre-native-capacity-no-start-v1.disposition.json",qc3Sha)
    fun verify(predecessor:ActivationInput,q4d:ActivationInput,probe:ActivationInput) {
        require(predecessor==qc3)
        val record=Qc3PreparedNoStartTerminal.verify(predecessor)
        GenerationAfterNativeImportLineage.verify(q4d,probe)
        require(record.originalQ4dUncertainImportTerminalSha256==q4d.sha256 &&
            record.originalIsolatedProbeSha256==probe.sha256 && record.stageIntentAbsent &&
            record.nativePrepareIntentAbsent && record.rootlessGraphAbsent &&
            !record.originalServeAcknowledged && record.qualificationCycles==0)
    }
    fun beforeSourceIssue(value:String) {
        if(value==generation) {
            require(!Files.exists(GenerationRuntime.BASE.resolve(value),NOFOLLOW_LINKS))
            verify(qc3,GenerationAfterNativeImportLineage.terminal,GenerationAfterNativeImportLineage.probe)
        }
    }
}
