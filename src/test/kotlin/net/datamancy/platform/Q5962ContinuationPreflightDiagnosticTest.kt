package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Test
import kotlin.test.*

class Q5962ContinuationPreflightDiagnosticTest {
    @Test fun `diagnose original and revised pre intent checks without any preparation effect`() {
        val anchor=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/q-5962a9fda75b")
        val plan=GenerationAssembly().plan(GenerationAssembly.readRequest(anchor.resolve("assembly-request.pi-subscription-v4.budgeted.json")),
            GenerationAssembly.readInventory(anchor.resolve("inventory.json")))
        val root=GenerationRuntime.BASE.resolve(plan.generation.id)
        val p=requireNotNull(plan.generation.predecessorDisposition)
        GenerationCiPreEffectContinuation.verify(root,p,
            beforeEffects=!java.nio.file.Files.exists(root.resolve(GenerationCiPreEffectContinuation.INTENT)))
        val original=Json.decodeFromString<AssemblySummary>(GenerationRuntime.privateInput(root.resolve("assembly.intent.json")).decodeToString())
        val updated=original.request.copy(candidateSha256=plan.summary.request.candidateSha256,
            releaseCandidateSha256=plan.summary.request.releaseCandidateSha256,
            quadletControllerSha256=plan.summary.request.quadletControllerSha256,
            rssPlan=plan.summary.request.rssPlan,managedLanes=plan.summary.request.managedLanes,
            predecessorDisposition=p,workingBudget=plan.summary.request.workingBudget)
        println("requestEqual=${updated==plan.summary.request} namesEqual=${original.members.map{it.name}==plan.summary.members.map{it.name}} ciEqual=${plan.generation.forgejoCi==original.request.forgejoCi} spec=${plan.specs.size} plan=${plan.recipes.size} members=${original.members.size}")
        assertEquals(updated,plan.summary.request)
        assertEquals(plan.generation.forgejoCi,original.request.forgejoCi)
        GenerationCiPreEffectContinuation.unchangedInputs(root,requireNotNull(plan.generation.managedLanes))
        // The historical v4 ownership was checked with its original controller. Later
        // source changes deliberately invalidate that candidate; never rebind it to
        // the current controller or use this forensic test as live admission.
    }
}
