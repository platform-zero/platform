package net.datamancy.platform

import java.nio.file.Files
import kotlin.test.*

class JupyterHubRuntimeTest {
    private val inventory = AcquiredInventory(1, "candidate", listOf("jupyterhub", "jupyter-notebook", "caddy").map {
        val pin = if (it == "caddy") HulyRuntime.CADDY_BASE else "example.org/$it@sha256:" + "a".repeat(64)
        AcquiredImage(it, "upstream", "example.org/$it:1", pin, "b".repeat(64), emptyList(), pin.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `native hub allocates isolated homes and restricts browser origins without runtime socket access`(): Unit {
        val spec = JupyterHubRuntime.spec(inventory)
        val inputs = JupyterHubRuntime.inputs { host -> mapOf("ca.pem" to "$host-ca\n", "web.pem" to "$host-web\n", "web-key.pem" to "$host-key\n") }
        assertEquals(SingleUserRestore.inputNames(spec), inputs.keys)
        assertEquals(setOf("alice", "bob", "controller", "hub"), spec.processes.map { it.id }.toSet())
        assertEquals(setOf("alice", "bob", "hub"), spec.volumes.map { it.id }.toSet())
        assertTrue(spec.processes.all { it.userId == 1000 && it.capabilities.isEmpty() && it.apparmorProfile == "p0v3-private-v1" })
        for (user in listOf("alice", "bob")) {
            val process = spec.processes.single { it.id == user }
            assertEquals(listOf(RuntimeMount(user, "/home/jovyan")), process.volumes)
            assertFalse(process.files.any { it.file == "hub-settings.json" })
            assertEquals(listOf("$user-control"), process.files.filter { it.file.endsWith("-control") }.map { it.file })
            assertContains(inputs.getValue("$user.env"), "JUPYTERHUB_OAUTH_CALLBACK_URL=https://$user.hub:8443/user/$user/oauth_callback")
            assertContains(inputs.getValue("caddyfile"), "not header Origin https://$user.hub:8443")
        }
        assertNotEquals(inputs.getValue("alice-control"), inputs.getValue("bob-control"))
        assertContains(inputs.getValue("hub-config.py"), "cookie_host_prefix_enabled = True")
        assertContains(inputs.getValue("caddyfile"), "respond @notebooks")
        assertEquals(2, Regex("route\\s*\\{\\s*respond @foreignOrigin").findAll(inputs.getValue("caddyfile")).count())
        assertContains(inputs.getValue("trust.pem"), "hub-ca")
        assertContains(inputs.getValue("notebook.py"), "allow_unauthenticated_access = False")
        assertFails { JupyterHubRuntime.spec(inventory, "../escape") }
        assertFails { JupyterHubRuntime.spec(inventory.copy(images = emptyList())) }
        assertFails { JupyterHubRuntime.spec(inventory.copy(images = inventory.images.map { it.copy(architecture = "arm64") })) }
    }
    @Test fun `canonical Hub and personal notebook retain separate original state and scoped inputs`(): Unit {
        val hub = JupyterHubRuntime.canonicalFragment(inventory, "canonical-files")
        assertEquals(setOf("hub-data", "hub-web"), hub.spec.networks.toSet())
        assertEquals(setOf("alice", "bob", "hub", "hub-controller"), hub.spec.processes.map { it.id }.toSet())
        assertEquals(setOf("hub-web"), hub.webNetworks)
        assertTrue(hub.providerNetworks.isEmpty())
        assertEquals(hub.spec.volumes, JupyterHubRuntime.coldRestoreFragment(hub).spec.volumes)
        val hubInputs = JupyterHubRuntime.canonicalInputs { host -> mapOf("ca.pem" to "$host-ca\n",
            "web.pem" to "$host-web\n", "web-key.pem" to "$host-key\n") }
        assertEquals(PrivateDeployment.inputNames(hub.spec).toSet(), hubInputs.keys)
        assertEquals("hub-ca\n", hubInputs.getValue("jupyterhub-ca.pem"))
        assertEquals(listOf(RuntimeFile("jupyterhub-ca.pem", "/run/secrets/hub-ca.pem")),
            hub.spec.processes.single { it.id == "hub" }.files.filter { it.file == "jupyterhub-ca.pem" })
        assertTrue(hub.spec.processes.filter { it.id != "hub" }.all { process ->
            process.files.none { it.file == "jupyterhub-ca.pem" } })
        assertFalse("jupyterhub-ca.pem" in JupyterHubRuntime.inputs { host -> mapOf(
            "ca.pem" to "$host-ca\n", "web.pem" to "$host-web\n", "web-key.pem" to "$host-key\n") })
        val ingress = hubInputs.getValue("jupyterhub-caddyfile")
        assertContains(ingress, "reverse_proxy hub-controller:8000")
        assertContains(ingress, "not header Origin https://notebooks.datamancy.net")
        assertFalse("respond @notebooks" in ingress)
        assertContains(hubInputs.getValue("jupyterhub-hub-config.py"), "c.JupyterHub.subdomain_host = ''")
        assertContains(hubInputs.getValue("jupyterhub-alice.env"),
            "JUPYTERHUB_OAUTH_CALLBACK_URL=https://notebooks.datamancy.net/user/alice/oauth_callback")
        val personal = NotebookRuntime.canonicalFragment(inventory, "canonical-files")
        assertEquals(setOf("notebook-data", "notebook-web"), personal.spec.networks.toSet())
        val personalInputs = NotebookRuntime.canonicalInputs { "1".repeat(64) }
        assertEquals(PrivateDeployment.inputNames(personal.spec).toSet(), personalInputs.keys)
        assertEquals(personal.spec.volumes, NotebookRuntime.coldRestoreFragment(personal).spec.volumes)
        assertFails { NotebookRuntime.canonicalInputs { "!untrusted" } }
    }
    @Test fun `private certificates admit only bounded explicit DNS names`(): Unit {
        var extension = ""
        PrivateWebPki.generate("hub", listOf("hub", "alice.hub", "bob.hub")) { root, args ->
            if (Files.exists(root.resolve("web.ext"))) extension = Files.readString(root.resolve("web.ext"))
            for (flag in listOf("-out", "-keyout")) if (flag in args) Files.writeString(root.resolve(args[args.indexOf(flag) + 1]), "unit-only")
        }
        assertContains(extension, "subjectAltName=DNS:hub,DNS:alice.hub,DNS:bob.hub")
        for (names in listOf(emptyList(), listOf("hub", "*.hub"), listOf("hub", "hub"), listOf("foreign"), listOf("hub", "a\nDNS:bad"), listOf("hub", "a..hub"))) {
            assertFails { PrivateWebPki.generate("hub", names) { _, _ -> error("must not execute") } }
        }
    }
}
