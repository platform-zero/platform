package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** A genuinely new INSTALL must explicitly inherit only the FAILED history,
 * never its INSTALL credentials, member spec, state or native ACK. */
@Serializable internal data class AbandonedPreparationLineage(
    val priorGeneration:String,val terminal:ActivationInput,val priorCensus:ActivationInput,
    val priorControllerSha256:String,val correctedOwnershipSourceSha256:String,
    val reason:String="old-controller-final-sealed-ownership-check-used-empty-kopia-inventory",
    val generationScopedCredentials:String="new-issuance-only-no-transplant")

internal object AbandonedPreparationLineages {
    private val id=Regex("q-[a-f0-9]{12}")
    private val hash=Regex("[a-f0-9]{64}")
    private val source=Path.of("/home/gerald/p0_v3/platform/src/main/kotlin/net/datamancy/platform/SiteOwnership.kt")
    private val json=Json { ignoreUnknownKeys=false }
    fun inspect(target:String,newController:String,lineage:AbandonedPreparationLineage):PreparationTerminalDisposition {
        require(id.matches(target) && id.matches(lineage.priorGeneration) && target!=lineage.priorGeneration &&
            hash.matches(newController) && hash.matches(lineage.priorControllerSha256) &&
            newController!=lineage.priorControllerSha256 &&
            lineage.reason=="old-controller-final-sealed-ownership-check-used-empty-kopia-inventory" &&
            lineage.generationScopedCredentials=="new-issuance-only-no-transplant" &&
            Files.isRegularFile(source,NOFOLLOW_LINKS) && !Files.isSymbolicLink(source) &&
            ReleaseLocks.sha256(Files.readAllBytes(source))==lineage.correctedOwnershipSourceSha256) {
            "A changed controller requires original terminal lineage, corrected source and genuine fresh inputs"
        }
        val root=GenerationRuntime.BASE.resolve(lineage.priorGeneration)
        val saved=GenerationPreparationTerminalDisposition.readStored(root,lineage.priorCensus,lineage.terminal)
        val prior=Path.of("/mnt/media/p0-v3/runtime-deployments/${saved.member}.json")
        val bytes=ReleasePrivateFiles.read(prior,4194304)
        require(ReleaseLocks.sha256(bytes)==saved.manifestSha256)
        val spec=json.decodeFromString<PrivateDeploymentSpec>(bytes.decodeToString(throwOnInvalidSequence=true))
        require(spec.fragmentBinding?.controllerSha256==lineage.priorControllerSha256 &&
            saved.member.startsWith("${lineage.priorGeneration}-") &&
            saved.failedOutcomes.size==3 && saved.memberFileSha256.size>1)
        return saved
    }
    /** For the first NEW native effect, not just a request/source review:
     * re-observe old generation under the global owner/RSS and native locks. */
    fun verifyLive(target:String,newController:String,lineage:AbandonedPreparationLineage) {
        inspect(target,newController,lineage)
        GenerationPreparationTerminalDisposition.verify(GenerationRuntime.BASE.resolve(lineage.priorGeneration),lineage.priorCensus,lineage.terminal)
    }
}
