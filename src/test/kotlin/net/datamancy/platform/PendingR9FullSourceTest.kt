package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.*

/** Opt-in bounded artifact-backed *offline* spec/render checks: no application
 * startup, runtime preparation, credential generation or Podman load. */
class PendingR9FullSourceTest {
    @Test fun `r9 full graph projects exact acquired archive identities and renders quadlet source`() {
        val graphOnly=System.getenv("P0V3_VERIFY_R9_GRAPH_ONLY") == "1"
        if (!graphOnly && System.getenv("P0V3_VERIFY_R9_FULL_SOURCE") != "1") return
        val json = Json { ignoreUnknownKeys = false }
        val root = Path.of("/mnt/media/p0-v3/image-acquisition-receipts")
        val development = root.resolve("canonical-private-assembled-stack-images/combined-private-development-keycloak-optimized-inventory.json")
        val inventory = json.decodeFromString<AcquiredInventory>(Files.readString(development))
        val archiveRoot = root.resolve("full-private-adapted-oci-archives-r1")
        val added = listOf("huly-caddy-adapted", "huly-elasticsearch-adapted", "huly-kvs-adapted",
            "keykeeper-adapted", "mail-bootstrap-adapted", "mailserver-adapted").map { artifact ->
            val receipt = json.parseToJsonElement(Files.readString(archiveRoot.resolve("$artifact.export.result.json"))).jsonObject
            val manifest = receipt.getValue("ociManifestDigest").jsonPrimitive.content
            AcquiredImage(artifact, "authenticated-local-build-archive", "localhost/p0v3-$artifact:sealed",
                "localhost/p0v3-$artifact@$manifest", receipt.getValue("imageId").jsonPrimitive.content,
                listOf("localhost/p0v3-$artifact@$manifest"), manifest, "amd64", "linux")
        } + listOf("keycloak-auth-gateway" to root.resolve("full-private-auth-gateway-independent-archive-r1/archive-export.result.json"),
            "portal" to root.resolve("full-private-portal-image-r2/portal.pull.result.json")).map { (name, path) ->
            val result = json.parseToJsonElement(Files.readString(path)).jsonObject
            val manifest = result.getValue(if (name == "portal") "manifestDigest" else "ociManifestDigest").jsonPrimitive.content
            val pinned = if (name == "portal") result.getValue("image").jsonPrimitive.content
                else "localhost/p0v3-$name@$manifest"
            AcquiredImage(name, "pinned-support-observation", pinned, pinned,
                result.getValue("imageId").jsonPrimitive.content, listOf(pinned), manifest, "amd64", "linux")
        }
        val full = inventory.copy(images = inventory.images + added +
            listOf(FreshFinanceImporterArtifact.acquired(), FreshFinanceImporterArtifact.acquiredSso()))
        val name = "q-000000000099-canonical-shared-core-v3"
        val sourceSpec = CanonicalSharedYamlGraph.pendingR9Spec(full, name)
        // Existing historical controller identity is a test-only render input,
        // not a release authorization or fresh generation installation.
        val controller = Json.parseToJsonElement(Files.readString(Path.of(
            "/mnt/media/p0-v3/release-generations/q-d874eb36057e/bundle.json"))).jsonObject
            .getValue("members").jsonArray.single().jsonObject.getValue("spec").jsonObject
            .getValue("fragmentBinding").jsonObject
        val spec = CanonicalSharedYamlGraph.pendingR9Spec(full, name, FragmentPhase.INSTALL,
            controller.getValue("controllerSha256").jsonPrimitive.content,
            controller.getValue("controllerUid").jsonPrimitive.int,
            controller.getValue("controllerGid").jsonPrimitive.int)
        assertEquals(sourceSpec.processes, spec.processes)
        assertEquals(133, spec.processes.size)
        val enrollment = spec.processes.single { it.id == "donetick-actors-init" }
        assertTrue(enrollment.oneShot && enrollment.networks == listOf("donetick-enroll"))
        assertTrue("donetick-enroll" !in spec.processes.single { it.id == "donetick" }.networks)
        assertEquals(listOf("donetick-actors-init", "caddy"), spec.processes.single { it.id == "donetick" }.dependencies)
        assertEquals(79, spec.processes.count { !it.oneShot })
        assertTrue(NotebookSelectedGraph.selected(GenerationRuntime.BASE.resolve("q-000000000099"),spec))
        val bootstrapWorking=spec.processes.associate { "${spec.name}/${it.id}" to it.memoryMiB.toLong() }
        assertFails { GenerationCapacityPlanner.plan(listOf(spec),spec.volumes.size.toLong()*1024,
            GenerationWorkingBudget(ActivationInput("/tmp/r9-envelope-source","a".repeat(64)),
                bootstrapWorking + ("${spec.name}/alice" to 64L))) }
        assertEquals(4096L,bootstrapWorking.getValue("${spec.name}/alice") +
            bootstrapWorking.getValue("${spec.name}/bob"))
        assertEquals(FreshFinanceImporterArtifact.IMAGE,
            spec.processes.single { it.id == "firefly-importer" }.image)
        assertEquals(FreshFinanceImporterArtifact.SSO_IMAGE,
            spec.processes.single { it.id == "firefly-sso" }.image)
        assertEquals(spec.processes.single { it.id == "firefly-sso" }.image,
            spec.processes.single { it.id == "firefly-importer-sso" }.image)
        assertTrue(spec.processes.single { it.id == "firefly-importer" }.files.any {
            it.target == "/var/www/html/bootstrap/app.php" })
        val caddyPeer = spec.processes.single { it.id == "caddy" }
        assertEquals(RuntimeControlSocketMount(
            GenerationRuntime.BASE.resolve("q-000000000099").resolve("managed/control/run").toString(),
            "/run/p0-control"), caddyPeer.controlSocketMount)
        assertTrue("opensearch-web" in caddyPeer.networks && "opensearch-data" !in caddyPeer.networks)
        assertTrue(caddyPeer.files.map { it.file }.containsAll(listOf("opensearch-ca.pem",
            "opensearch-reader.pem", "opensearch-reader-key.pem")))
        assertTrue("opensearch-web" in spec.processes.single { it.id == "opensearch" }.networks)
        val r9Manifest = PackagedGraphFragment.pendingV3R9().first
        val trust=CanonicalPrivateIngressTrust.project(r9Manifest,spec)
        assertEquals("bookstack",trust.getValue("bookstack.datamancy.net").product)
        assertEquals("bookstack",trust.getValue("api.bookstack.datamancy.net").product)
        assertEquals("bookstack.datamancy.net",CanonicalPrivateIngressTrust.requireRoute(r9Manifest,spec,
            "bookstack","APP","bookstack.datamancy.net").hostname)
        assertFails { CanonicalPrivateIngressTrust.requireRoute(r9Manifest,spec,
            "bookstack","APP","api.bookstack.datamancy.net") }
        assertEquals("firefly-iii",trust.getValue("firefly.datamancy.net").product)
        assertEquals(PrivateIngressTrustMode.GRAPH_ISSUED_LEAF,trust.getValue("office.datamancy.net").mode)
        assertEquals("onlyoffice-office-ca.pem",trust.getValue("office.datamancy.net").caInput)
        assertEquals("seafile-ca.pem",trust.getValue("files.datamancy.net").caInput)
        assertEquals("huly-ca.pem",trust.getValue("work.datamancy.net").caInput)
        assertEquals("sogo-ca.pem",trust.getValue("groupware.datamancy.net").caInput)
        assertEquals(PrivateIngressTrustMode.POST_START_CADDY_CA,trust.getValue("bookstack.datamancy.net").mode)
        assertFalse("books.datamancy.net" in trust)
        assertFalse("finance.datamancy.net" in trust)
        assertEquals("office.datamancy.net",CanonicalPrivateIngressTrust.requirePrivateCaller(r9Manifest,spec,
            "onlyoffice","office.datamancy.net",spec.processes.single { it.id == "seafile-files" }).hostname)
        assertEquals("office.datamancy.net",CanonicalPrivateIngressTrust.requirePrivateCaller(r9Manifest,spec,
            "onlyoffice","office.datamancy.net",spec.processes.single { it.id == "seafile-backend" }).hostname)
        assertTrue("office-data" !in spec.processes.single { it.id == "caddy" }.networks)
        assertEquals("firefly.datamancy.net",CanonicalPrivateIngressTrust.requirePrivateCaller(r9Manifest,spec,
            "firefly-iii","firefly.datamancy.net",spec.processes.single { it.id == "firefly-importer" }).hostname)
        val siteRoutes = CanonicalGraphCaddyfile.siteRoutes(r9Manifest, spec)
        assertEquals(siteRoutes.size, siteRoutes.map { it.host }.distinct().size)
        assertTrue(siteRoutes.any { it.host == "datamancy.net" && it.process.endsWith("/portal") })
        assertTrue(siteRoutes.any { it.host == "api.bookstack.datamancy.net" })
        assertFalse(siteRoutes.any { it.host == "kopia.datamancy.net" })
        val fullCaddyfile = CanonicalGraphCaddyfile.render(r9Manifest, spec)
        assertContains(fullCaddyfile, "reverse_proxy unix//run/p0-control/http.sock")
        assertContains(fullCaddyfile, "@device_api path /v1/models /v1/chat/completions")
        assertContains(fullCaddyfile, "keycloak-auth.datamancy.net/oauth2/start?rd=")
        assertContains(fullCaddyfile, "requiredActions\":\"native-readback-pending")
        assertContains(fullCaddyfile, "header_regexp X-Webservices-SSO-Subject")
        // Explicit source-only graph scope; the original FULL test below still
        // requires exact native Caddy adaptation and all downstream assertions.
        if (graphOnly) {
            val source = Path.of("/home/gerald/p0_v3/.coord/rapid-completion/fresh-r9-full-caddyfile-control-v2")
            if (Files.exists(source)) assertEquals(fullCaddyfile,Files.readString(source))
            else Files.writeString(source,fullCaddyfile)
            return
        }
        val caddyfileOutput = Path.of("/home/gerald/p0_v3/.coord/rapid-completion/fresh-r9-full-caddyfile-control-v2-full")
        Files.writeString(caddyfileOutput, fullCaddyfile)
        val nativeFixture = CanonicalGraphCaddyfile.render(PackagedGraphFragment.pendingV3R9().first, spec,
            FreshNativeIngressGrants("e".repeat(64),
                "\$2a\$12\$0un/uJ8ntkji/FFOdcPUgeK4Zo/x0qsj.n6yfmRLORMk8mTKBCPu2",
                ntfySsoToken = "tk_" + "a".repeat(32),
                bookstackApiId = "p0v3-" + "b".repeat(32), bookstackApiSecret = "c".repeat(64)))
        Files.writeString(Path.of("/home/gerald/p0_v3/.coord/rapid-completion/fresh-r9-caddy-native-fixture-control-v2"), nativeFixture)
        assertTrue(nativeFixture.contains("android-test-runner") && nativeFixture.contains("X-Internal-Token"))
        val nativeAdapted = CanonicalGraphCaddyfile.adaptFresh(PackagedGraphFragment.pendingV3R9().first,
            spec, FreshNativeIngressGrants("e".repeat(64),
                "\$2a\$12\$0un/uJ8ntkji/FFOdcPUgeK4Zo/x0qsj.n6yfmRLORMk8mTKBCPu2",
                ntfySsoToken = "tk_" + "a".repeat(32),
                bookstackApiId = "p0v3-" + "b".repeat(32), bookstackApiSecret = "c".repeat(64)),
            Path.of("/home/gerald/p0_v3/.coord/rapid-completion/caddy-config-check-bin-142"))
        assertTrue(nativeAdapted.contains("http_basic") && nativeAdapted.contains("X-Internal-Token"))
        // This q000 fixture has only dummy grants, not q5962's original issuer
        // records. Typed source closure for q5962 is tested separately; never
        // grant a synthetic generation full feature closure.
        assertFailsWith<IllegalArgumentException> {
            CanonicalGraphCaddyfile.adaptFresh(r9Manifest, spec,
                FreshNativeIngressGrants("e".repeat(64),
                    "\$2a\$12\$0un/uJ8ntkji/FFOdcPUgeK4Zo/x0qsj.n6yfmRLORMk8mTKBCPu2",
                    ntfySsoToken = "tk_" + "a".repeat(32),
                    bookstackApiId = "p0v3-" + "b".repeat(32), bookstackApiSecret = "c".repeat(64)),
                Path.of("/home/gerald/p0_v3/.coord/rapid-completion/caddy-config-check-bin-142"),
                requireFeatureClosure = true)
        }
        assertFailsWith<IllegalArgumentException> {
            CanonicalGraphCaddyfile.adaptFresh(r9Manifest, spec,
                FreshNativeIngressGrants("e".repeat(64),
                    "\$2a\$12\$0un/uJ8ntkji/FFOdcPUgeK4Zo/x0qsj.n6yfmRLORMk8mTKBCPu2"),
                Path.of("/home/gerald/p0_v3/.coord/rapid-completion/caddy-config-check-bin-142"),
                requireFeatureClosure = true)
        }
        val selectedIngress = CanonicalSharedYamlGraph.pendingR9CaddyInputs(spec).getValue("caddy.json")
        assertTrue(selectedIngress.length > 5000 && selectedIngress.contains("auth-gateway:4180"))
        assertEquals(selectedIngress.toByteArray().toList(), PackagedGraphFragment.r9CaddyJson().toList())
        assertEquals(40, PackagedGraphFragment.pendingV3R9().first.integratedReference!!.routes.size)
        val rendered = RuntimeQuadlets.render(spec)
        assertEquals(spec.processes.size, rendered.files.keys.count { it.endsWith(".container") })
        assertTrue(NotebookSelectedGraph.selected(Path.of("/mnt/media/p0-v3/release-generations/q-000000000099"),spec))
        assertEquals(RuntimeControlSocketMount(
            GenerationRuntime.BASE.resolve("q-000000000099").resolve("notebooks/control.sock").toString(),
            "/run/p0-notebooks/control.sock"),
            spec.processes.single { it.id == "hub-controller" }.controlSocketMount)
        val output = Path.of("/home/gerald/p0_v3/.coord/rapid-completion/fresh-r9-r3-bao-late-quadlets-control-v2-source")
        if (!Files.exists(output)) Files.createDirectory(output)
        for ((relative, content) in rendered.files) {
            val target = output.resolve(relative)
            Files.createDirectories(target.parent)
            if (Files.exists(target)) assertEquals(content, Files.readString(target))
            else Files.writeString(target, content)
        }
        val restore = CanonicalSharedYamlGraph.pendingR9Spec(full, name, FragmentPhase.RESTORE,
            controller.getValue("controllerSha256").jsonPrimitive.content,
            controller.getValue("controllerUid").jsonPrimitive.int,
            controller.getValue("controllerGid").jsonPrimitive.int)
        assertTrue(restore.processes.size in 60..160)
        assertTrue(NotebookSelectedGraph.selected(Path.of("/mnt/media/p0-v3/release-generations/q-000000000099"),restore))
        assertEquals(restore.processes.size, RuntimeQuadlets.render(restore).files.keys.count { it.endsWith(".container") })
        runNotebookEpisodeSimulation(spec)
        val caddy = CaddyRuntime.inputs().getValue("caddy.json")
        val baseline = Path.of("/home/gerald/p0_v3/.coord/rapid-completion/fresh-r9-caddy-empty-source-135.json")
        if (Files.exists(baseline)) assertEquals(caddy, Files.readString(baseline))
        else Files.writeString(baseline, caddy)
        assertFalse(caddy.contains(":443")) // routes require separate ownership admission
        assertEquals(9, PackagedGraphFragment.pendingV3R9().first.revision)
    }
}
