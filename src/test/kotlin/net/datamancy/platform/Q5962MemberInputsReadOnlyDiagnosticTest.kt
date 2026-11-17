package net.datamancy.platform

import java.nio.file.Path
import org.junit.jupiter.api.Test
import kotlin.test.*

class Q5962MemberInputsReadOnlyDiagnosticTest {
    @Test fun `issued original ingress grants produce full r9 source input map without runtime mutation`() {
        val root=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/q-5962a9fda75b")
        val plan=GenerationAssembly().plan(GenerationAssembly.readRequest(root.resolve("assembly-request.pi-subscription-v5.budgeted.json")),
            GenerationAssembly.readInventory(root.resolve("inventory.json")))
        val request=plan.summary.request
        val generation=request.id
        val binary=Path.of("/home/gerald/p0_v3/.coord/rapid-completion/caddy-config-check-bin-142")
        val ingressPath=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/ingress/fresh/$generation.json")
        val ntfyPath=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/identity/ntfy-fresh/$generation.json")
        assertTrue(java.nio.file.Files.isRegularFile(ingressPath))
        assertTrue(java.nio.file.Files.isRegularFile(ntfyPath))
        val ingress=FreshNativeIngressCustody.issueOnce(ingressPath,binary) { error("Read-only diagnosis cannot regenerate ingress grants") }
        val ntfy=FreshNtfyCustody.issueOnce(ntfyPath,binary) { error("Read-only diagnosis cannot regenerate ntfy grants") }
        val scripts=GenerationRuntime.privateInput(Path.of(requireNotNull(request.mastodonRedisScripts).path)).decodeToString()
        val outputs=CanonicalSharedYamlGraph.inputs(plan.inventory,plan.specs.single().name,
            freshIdentity=request.freshIdentity, mastodonRedisScripts=scripts,
            portalRoutes=request.portalRoutes,
            managedLanesSubject=requireNotNull(request.managedLanes).lanes.first().subject,
            managedReaderSubject=request.managedLanes.readerSubject,
            managedBrokerHost=request.managedLanes.native.brokerHost,
            freshIngressGrants=ingress.copy(ntfySsoToken=ntfy.ssoToken),freshIngressRecord=ingressPath,
            freshNtfy=ntfy,freshCaddyCli=binary,candidateRevision=9)
        assertEquals(PrivateDeployment.inputNames(plan.specs.single()).toSet(),outputs.keys)
    }
}
