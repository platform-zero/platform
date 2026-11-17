package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS

/** Complete cold PREPARE ACKs from q9b remain only history. Its unfinished
 * stage and physical VFS image are not reusable installation state. */
internal object GenerationAfterQ9bLineage {
    const val generation="q-083e9b7d2a64"
    const val predecessorSha="93bfe6b18afd387709ed6eea7288a184894b93f4bff478198d30ef37afe53d4f"
    val predecessor=ActivationInput(
        "/mnt/media/p0-v3/release-generations/q-9bfa8ec0eb64/cold-three-lane-prepare-uninstalled-stage-v1.disposition.json",
        predecessorSha)
    fun verify(q9b:ActivationInput,q583:ActivationInput,full:ActivationInput,q273:ActivationInput,
        qc3:ActivationInput,q4d:ActivationInput,rootless:ActivationInput) {
        require(q9b==predecessor)
        GenerationAfterQ583Lineage.verify(q583,full,q273,qc3,q4d,rootless)
        val original=Q9bColdPreparedUninstalledTerminal.verify(q9b)
        require(original.originalStageResultAbsent && original.originalManagedPrepareAcknowledged &&
            original.installedUnitsAbsent && original.nativeContainersAbsent &&
            !original.applicationStarted && original.qualificationCycles==0 &&
            original.originalLaneEvidence.keys==ManagedLaneKind.entries.toSet())
    }
    fun beforeSourceIssue(value:String) {
        if(value==generation) {
            require(!Files.exists(GenerationRuntime.BASE.resolve(value),NOFOLLOW_LINKS))
            verify(predecessor,GenerationAfterQ583Lineage.predecessor,
                GenerationAfterQ583Lineage.isolatedFullPrepare,GenerationAfterQ273Lineage.predecessor,
                GenerationAfterCapacityRefusalLineage.qc3,GenerationAfterNativeImportLineage.terminal,
                GenerationAfterNativeImportLineage.probe)
        }
    }
}
