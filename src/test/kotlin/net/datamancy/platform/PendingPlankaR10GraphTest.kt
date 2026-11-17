package net.datamancy.platform

import kotlin.test.*

class PendingPlankaR10GraphTest {
    @Test fun `opt-in r10 full graph compiles exactly one enrollment initializer on acquired source`() {
        if (System.getenv("P0V3_VERIFY_R10_GRAPH_ONLY") != "1") return
        val inventory = kotlinx.serialization.json.Json.decodeFromString<AcquiredInventory>(
            java.nio.file.Files.readString(java.nio.file.Path.of(
                "/mnt/media/p0-v3/release-bootstrap-anchors/assembly/q-5712d9335843/inventory.json")))
        val name = "q-5712d9335843-v2"
        val oldRequest = GenerationAssembly.readRequest(java.nio.file.Path.of(
            "/mnt/media/p0-v3/release-bootstrap-anchors/assembly/q-5712d9335843/assembly-request.nonvm-v1.unbudgeted.json"))
        assertFailsWith<IllegalArgumentException> { GenerationAssembly().plan(oldRequest,
            GenerationAssembly.readInventory(java.nio.file.Path.of(
                "/mnt/media/p0-v3/release-bootstrap-anchors/assembly/q-5712d9335843/inventory.json"))) }
        val dir = java.nio.file.Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/q-5712d9335843")
        val grant = java.nio.file.Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/planka/q-5712d9335843/grant.json")
        val closure = dir.resolve("rss-source-artifact-closure.r10-v2.json")
        val source = oldRequest.copy(
            selections = listOf(AssemblySelection(CanonicalSharedYamlGraph.R10_ASSEMBLY_RECIPE)),
            // Source-only provisional plan; the v1 controller is STALE and may not be sealed.
            abandonedPreparation = requireNotNull(oldRequest.abandonedPreparation).copy(
                correctedOwnershipSourceSha256 = ReleaseLocks.sha256(java.nio.file.Files.readAllBytes(
                    java.nio.file.Path.of("src/main/kotlin/net/datamancy/platform/SiteOwnership.kt")))),
            freshPlankaActorGrant = ActivationInput(grant.toString(), ReleaseLocks.sha256(
                ReleasePrivateFiles.read(grant, 8192))),
            portalRoutes = kotlinx.serialization.json.Json.decodeFromString<List<SiteRouteOwner>>(
                ReleasePrivateFiles.read(dir.resolve("graph-portal-routes.r10-v2.json"), 65536)
                    .decodeToString(throwOnInvalidSequence = true)),
            rssPlan = requireNotNull(oldRequest.rssPlan).copy(artifactClosure =
                ActivationInput(closure.toString(), ReleaseLocks.sha256(ReleasePrivateFiles.read(closure, 65536)))))
        val compiled = GenerationAssembly().plan(source, GenerationAssembly.readInventory(dir.resolve("inventory.json")))
        assertEquals(134, compiled.specs.single().processes.size)
        assertEquals(134, SiteOwnerships.inspect(compiled).processes.size)
        assertTrue(compiled.summary.missingCapabilities.isEmpty())
        val manifest = PackagedGraphFragment.pendingV3R10().first
        val hosts = requireNotNull(manifest.integratedReference).modules.flatMap {
            it.privateRoutes.map(CanonicalIngressRoute::host)
        }.toSet()
        val owned = CanonicalTopology.ownership(CanonicalTopology.compile(compiled, false),
            "full-private-r10", requireNotNull(source.portalRoutes), hosts)
        assertEquals(134, owned.processes.size)
        assertEquals(source.portalRoutes, owned.routes)
        assertFailsWith<IllegalArgumentException> {
            CanonicalTopology.ownership(CanonicalTopology.compile(compiled, false),
                "full-private-r10", requireNotNull(source.portalRoutes).dropLast(1), hosts)
        }
        val install = CanonicalSharedYamlGraph.pendingR10Spec(inventory, name)
        val restore = CanonicalSharedYamlGraph.pendingR10Spec(inventory, name, FragmentPhase.RESTORE)
        assertEquals(134, install.processes.size)
        assertTrue(install.processes.single { it.id == "planka-enroll" }.oneShot)
        assertTrue("planka" in install.processes.single { it.id == "planka-enroll" }.dependencies)
        assertTrue("planka-enroll" !in restore.processes.map { it.id })
        // Serving Planka keeps its private enrollment-side network attachment;
        // RESTORE excludes the one-shot caller, not a required daemon attachment.
        assertTrue("planka-enrollment" in restore.networks)
        assertEquals(PackagedGraphFragment.pendingV3R10().second.getValue("canonical/r10/index.yaml"),
            install.fragmentBinding!!.resources.getValue("fragments/v3/canonical/r10/index.yaml"))
    }
    @Test fun `new full graph pins planka r2 while sealed r9 remains unchanged`() {
        val (old, oldPins) = PackagedGraphFragment.pendingV3R9()
        val (next, pins) = PackagedGraphFragment.pendingV3R10()
        assertEquals(9, old.revision)
        assertEquals(10, next.revision)
        assertEquals(1, old.fragments.single { it.id == "planka-postgres" }.revision)
        assertEquals(2, next.fragments.single { it.id == "planka-postgres" }.revision)
        assertEquals("b68a989e8970358df41028c2ebfac9293bf6d23b70174d962e086f397cb9095f",
            oldPins.getValue("canonical/r9/index.yaml"))
        assertEquals("219b83a99f5c9c0da853c17f5b6f7559772efd19f9822db3a264dc60ca1d192f",
            pins.getValue("canonical/r10/index.yaml"))
        assertEquals("9b9c9fac25ee9037e0ef045f5bd9c024f0e021f65ff595ccfd34339b166117ca",
            pins.getValue("planka/r2/fragment.yaml"))
        assertFalse("planka/r2/fragment.yaml" in oldPins)
        val installed = PackagedGraphFragment.loadPendingV3("planka-postgres", 2, 10).definition
        assertEquals(listOf("planka-db-init", "planka-init", "planka-db-finalize", "planka", "planka-enroll"),
            installed.install.processes)
        assertEquals(listOf("planka"), installed.restore.processes)
        assertEquals(listOf("planka"), installed.install.dependencies.getValue("planka-enroll"))
        assertFalse(installed.processes.single { it.id == "planka" }.environmentFile == "planka-enrollment.env")
        val base = FragmentRecipes.fragments(5)
        val selected = next.fragments.drop(2).map { PackagedGraphFragment.loadPendingV3(it.id, it.revision, 10) }
        assertEquals(134, base.sumOf { it.definition.install.processes.size } +
            selected.sumOf { it.definition.install.processes.size })
        assertEquals(133, base.sumOf { it.definition.install.processes.size } +
            old.fragments.drop(2).sumOf { ref ->
                PackagedGraphFragment.loadPendingV3(ref.id, ref.revision, 9).definition.install.processes.size
            })
        assertEquals(setOf("postgres", "forgejo") + selected.map { it.definition.product }.toSet(),
            (base + selected).map { it.definition.product }.toSet())
        assertEquals(setOf("planka-enroll"), installed.install.processes.toSet() -
            PackagedGraphFragment.loadPendingV3("planka-postgres", 1, 9).definition.install.processes.toSet())
        assertEquals(setOf("planka-enrollment.env", "planka-enroll.js"),
            installed.inputs.map { it.name }.toSet() -
                PackagedGraphFragment.loadPendingV3("planka-postgres", 1, 9).definition.inputs.map { it.name }.toSet())
    }
}
