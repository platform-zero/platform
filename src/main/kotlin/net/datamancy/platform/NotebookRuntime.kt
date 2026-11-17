package net.datamancy.platform

import java.nio.file.Path

/** A token-authenticated personal notebook container, not a substitute for isolated multi-user Hub spawning. */
internal object NotebookRuntime {
    fun spec(inventory: AcquiredInventory, name: String = "notebook"): PrivateDeploymentSpec {
        val image = inventory.images.single { it.product == "jupyter-notebook" }
        require(image.os == "linux" && image.architecture == "amd64")
        val common = RuntimeProcess("notebook", image.pinnedImage, image.imageId, 1000,
            environmentFile = "notebook.env", volumes = listOf(RuntimeMount("home", "/home/jovyan")),
            apparmorProfile = "p0v3-private-v1", memoryMiB = 2048)
        return PrivateDeploymentSpec(name = name, volumes = listOf(RuntimeVolume("home", 1000)), processes = listOf(
            common.copy(id = "notebook-init", oneShot = true, entrypoint = "/opt/conda/bin/python",
                command = listOf("-c", "from pathlib import Path; Path('/home/jovyan/work').mkdir(exist_ok=True)")),
            common.copy(dependencies = listOf("notebook-init"), entrypoint = "/opt/conda/bin/jupyter-lab",
                command = listOf("--config=/etc/jupyter/p0.py"), files = listOf(RuntimeFile("server.py", "/etc/jupyter/p0.py")),
                readiness = listOf("/opt/conda/bin/python", "-c", "import os,urllib.request; r=urllib.request.Request('http://127.0.0.1:8888/api/status',headers={'Authorization':'token '+os.environ['P0V3_NOTEBOOK_TOKEN']}); assert urllib.request.build_opener(urllib.request.ProxyHandler({})).open(r,timeout=3).status==200"))
        )).also { PrivateDeployment.validate(it) }
    }
    fun coldRestoreSpec(compiled: PrivateDeploymentSpec): PrivateDeploymentSpec {
        require(compiled.processes.map { it.id }.toSet() == setOf("notebook-init", "notebook") &&
            compiled.processes.filter { it.oneShot }.map { it.id } == listOf("notebook-init"))
        val notebook = compiled.processes.single { it.id == "notebook" }
        require(notebook.entrypoint == "/opt/conda/bin/jupyter-lab" && notebook.dependencies == listOf("notebook-init"))
        return compiled.copy(processes = listOf(notebook.copy(dependencies = emptyList(), entrypoint = "/bin/sh",
            command = listOf("-ec", "test -d /home/jovyan/work; test ! -L /home/jovyan/work; exec /opt/conda/bin/jupyter-lab \"${'$'}@\"", "restored-notebook") + notebook.command)),
            databaseAccess = compiled.databaseAccess.filterNot { it.consumer == "notebook-init" }).also { PrivateDeployment.validate(it) }
    }

    fun canonicalFragment(inventory: AcquiredInventory, name: String): CanonicalProviderFragment {
        val source = spec(inventory, name)
        val partial = source.copy(store = RuntimeStore.CANONICAL_V2, networks = listOf("notebook-data", "notebook-web"),
            processes = source.processes.map { p -> p.copy(
                environmentFile = p.environmentFile?.let { "jupyter-notebook-$it" },
                files = p.files.map { it.copy(file = "jupyter-notebook-${it.file}") },
                networks = if (p.oneShot) listOf("notebook-data") else listOf("notebook-data", "notebook-web")) })
        PrivateDeployment.validate(partial)
        return CanonicalProviderFragment("jupyter-notebook", partial, webNetworks = setOf("notebook-web"))
    }

    fun coldRestoreFragment(fresh: CanonicalProviderFragment): CanonicalProviderFragment {
        require(fresh.product == "jupyter-notebook" && fresh.spec.processes.map { it.id }.toSet() ==
            setOf("notebook-init", "notebook") && fresh.spec.store == RuntimeStore.CANONICAL_V2)
        return fresh.copy(spec = coldRestoreSpec(fresh.spec))
    }

    fun canonicalInputs(token: () -> String = RuntimePreparation::password): Map<String, String> =
        inputs(token).mapKeys { (name, _) -> "jupyter-notebook-$name" }

    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "notebook", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }

    fun inputs(token: () -> String = RuntimePreparation::password): Map<String, String> {
        val secret = token(); require(secret.matches(Regex("[a-f0-9]{64}")))
        return mapOf("notebook.env" to "HOME=/home/jovyan\nP0V3_NOTEBOOK_TOKEN=$secret\n",
                "server.py" to """
                    import os
                    c = get_config()
                    c.ServerApp.ip = "0.0.0.0"
                    c.ServerApp.port = 8888
                    c.ServerApp.port_retries = 0
                    c.ServerApp.root_dir = "/home/jovyan/work"
                    c.ServerApp.open_browser = False
                    c.ServerApp.allow_remote_access = True
                    c.ServerApp.allow_unauthenticated_access = False
                    c.ServerApp.allow_origin = ""
                    c.ServerApp.disable_check_xsrf = False
                    c.ServerApp.trust_xheaders = False
                    c.ServerApp.terminals_enabled = False
                    c.ServerApp.log_level = "WARN"
                    c.IdentityProvider.token = os.environ["P0V3_NOTEBOOK_TOKEN"]
                    c.LabApp.extension_manager = "readonly"
                """.trimIndent() + "\n")
    }
}
