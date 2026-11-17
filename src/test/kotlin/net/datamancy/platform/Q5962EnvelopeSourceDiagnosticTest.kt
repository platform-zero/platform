package net.datamancy.platform

import java.nio.file.Path
import org.junit.jupiter.api.Test
import kotlin.test.*

class Q5962EnvelopeSourceDiagnosticTest {
    @Test fun `bound complete source has exact r9 prospective model prerequisites`() {
        val root=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/q-5962a9fda75b")
        val request=GenerationAssembly.readRequest(root.resolve("assembly-request.pi-subscription.unbudgeted.json"))
        val plan=GenerationAssembly().plan(request,GenerationAssembly.readInventory(root.resolve("inventory.json")))
        val spec=plan.specs.single()
        println("source-envelope prerequisites: recipe=${spec.fragmentBinding?.recipe}, processCount=${spec.processes.size}, steady=${spec.processes.count { !it.oneShot }}, notebook=${NotebookSelectedGraph.selected(GenerationRuntime.BASE.resolve(request.id),spec)}, missing=${plan.summary.missingCapabilities}, store=${request.store}, release=${request.releaseCandidateSha256!=null}")
        assertEquals(133,spec.processes.size)
        assertTrue(NotebookSelectedGraph.selected(GenerationRuntime.BASE.resolve(request.id),spec))
        val low=spec.processes.filter { it.memoryMiB<64 }.map { it.id to it.memoryMiB }
        println("source-envelope low-cap-processes=$low")
        val rows=GenerationWorkingEnvelopeIssuer.forecastRows(spec)
        println("source-envelope forecast rows=${rows.size}, notebook=${rows.filter { it.process.endsWith("/alice") || it.process.endsWith("/bob") }}")
        val model=GenerationWorkingEnvelopeIssuer::class.java.getDeclaredMethod("model",AssemblyPlan::class.java).apply { isAccessible=true }
        try { println("source-envelope candidate model="+(model.invoke(GenerationWorkingEnvelopeIssuer,plan) as GenerationFirstStartEnvelope).observedMemAvailableMiB) }
        catch (failure: java.lang.reflect.InvocationTargetException) { throw requireNotNull(failure.targetException) }
        val compiled=CanonicalTopology.compile(plan)
        val manifest=PackagedGraphFragment.pendingV3R9().first
        val hosts=requireNotNull(manifest.integratedReference).modules.flatMap { it.privateRoutes.map(CanonicalIngressRoute::host) }.toSet()
        println("source-ownership hosts=${hosts.size}, routes=${request.portalRoutes?.size}")
        val budgeted=GenerationAssembly.readRequest(root.resolve("assembly-request.pi-subscription-v2.budgeted.json"))
        val bound=GenerationAssembly().plan(budgeted,GenerationAssembly.readInventory(root.resolve("inventory.json")))
        val ownership=CanonicalTopology.ownership(CanonicalTopology.compile(bound),"full-private-r9",
            requireNotNull(budgeted.portalRoutes),hosts)
        SiteOwnerships.bind(bound,ownership,hosts)
    }
}
