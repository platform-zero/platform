package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Test
import kotlin.test.*

/** Forensic only: construct the would-be sealed bundle IN MEMORY from the
 * original v3 attempted result. Never re-run a producer or write an ACK. */
class Q5962PostMemberV3ReadOnlyDiagnosticTest {
    @Test fun `actual complete member inputs pass independently checked final ownership`() {
        val id="q-5962a9fda75b"
        val root=GenerationRuntime.BASE.resolve(id)
        val anchor=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/$id")
        val request=anchor.resolve("assembly-request.pi-subscription-v6.member-budgeted.json")
        val plan=GenerationAssembly().plan(GenerationAssembly.readRequest(request),
            GenerationAssembly.readInventory(anchor.resolve("inventory.json")))
        fun bytes(name:String)=ReleasePrivateFiles.read(root.resolve(name),4_194_304)
        for(name in listOf("assembly.result.json","assembly-ci-pre-effect-v2.result.json",
            GenerationCiMemberPreEffectContinuation.RESULT))
            assertFalse(Json.parseToJsonElement(bytes(name).decodeToString()).let {
                it.jsonObject.getValue("passed").jsonPrimitive.content.toBoolean() })
        assertFalse(Files.exists(root.resolve("bundle.json")))
        val pin=Json.decodeFromString<GenerationPin>(bytes("$id-v2.prepare-ci-member-v3.result.json")
            .decodeToString(throwOnInvalidSequence=true))
        assertEquals(plan.specs.single(),pin.spec)
        val memberRoot=PrivateDeployment.BASE.resolve(pin.member.name)
        assertEquals(pin.manifestSha256,ReleaseLocks.sha256(ReleasePrivateFiles.read(
            PrivateDeployment.BASE.resolve("${pin.member.name}.json"),4_194_304)))
        assertEquals(pin.inputHashes.keys,PrivateDeployment.inputNames(pin.spec).toSet())
        assertTrue(pin.inputHashes.all { (name,hash) ->
            ReleaseLocks.sha256(ReleasePrivateFiles.read(memberRoot.resolve(name),1_048_576))==hash })
        val ownership=Json.decodeFromString<BoundSiteOwnership>(bytes(GenerationCiMemberPreEffectContinuation.OWNERSHIP)
            .decodeToString(throwOnInvalidSequence=true))
        val capacity=GenerationCapacityPlanner.plan(plan.specs,plan.generation.diskReservationMiB,
            requireNotNull(plan.generation.workingBudget))
        val wouldBe=GenerationBundle(plan.generation,listOf(pin),capacity.install.memoryMiB +
            GenerationManagedComponents.memoryReservationMiB(plan.generation),
            ReleaseLocks.sha256(bytes(GenerationCiMemberPreEffectContinuation.INTENT)),ownership=ownership)
        SiteOwnerships.checkSealed(wouldBe)
    }
}
