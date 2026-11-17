package net.datamancy.platform

import java.nio.file.Path

/** Provider-less Caddy recipe. Enrollment is separate: boot opens only a container-loopback admin
 * endpoint, never public listeners or automatic issuance. Host publication needs the ingress owner.
 * Certificate/account state and autosaved configuration are separate durable volumes.
 */
internal object CaddyRuntime {
    fun spec(inventory: AcquiredInventory, name: String = "caddy"): PrivateDeploymentSpec {
        val image = inventory.images.single { it.product == "caddy" }
        return PrivateDeploymentSpec(name = name,
            volumes = listOf(RuntimeVolume("caddy-data", 1000), RuntimeVolume("caddy-config", 1000)),
            processes = listOf(RuntimeProcess("caddy", image.pinnedImage, image.imageId, 1000,
                entrypoint = "/usr/bin/caddy", command = listOf("run", "--resume", "--config", "/run/secrets/caddy.json"),
                environmentFile = "caddy.env", files = listOf(RuntimeFile("caddy.json", "/run/secrets/caddy.json")),
                volumes = listOf(RuntimeMount("caddy-data", "/data"), RuntimeMount("caddy-config", "/config")),
                capabilities = listOf("NET_BIND_SERVICE"), networks = listOf("ingress-control"),
                readiness = listOf("/usr/bin/wget", "-q", "-O", "/dev/null", "http://127.0.0.1:2019/config/"))),
            networks = listOf("ingress-control")).also { PrivateDeployment.validate(it) }
    }
    /** Idempotent post-composition attachment to app-owned frontend networks only. Does not create
     * a host route or attach Caddy to SQL/admin, scheduler or unrelated networks. */
    fun withFrontendNetworks(spec: PrivateDeploymentSpec, webNetworks: Set<String>): PrivateDeploymentSpec {
        PrivateDeployment.validate(spec)
        require(webNetworks.size <= 64 && webNetworks.all { network ->
            network in spec.networks && network.endsWith("-web") && network != "ingress-egress" &&
                network != "ingress-control" && network.matches(Regex("[a-z][a-z0-9-]{0,39}")) &&
                spec.processes.any { it.id != "caddy" && network in it.networks }
        }) { "Caddy may join only explicit application frontend networks" }
        require(spec.processes.count { it.id == "caddy" } == 1)
        return spec.copy(processes = spec.processes.map { process ->
            if (process.id == "caddy") process.copy(networks = (process.networks + webNetworks.sorted()).distinct()) else process
        }).also { PrivateDeployment.validate(it) }
    }

    fun inputs(): Map<String, String> = mapOf(
        "caddy.env" to "XDG_DATA_HOME=/data\nXDG_CONFIG_HOME=/config\nHOME=/tmp\n",
        "caddy.json" to """{"admin":{"listen":"127.0.0.1:2019"},"storage":{"module":"file_system","root":"/data/caddy"},"apps":{"http":{"servers":{}}}}""" + "\n")
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "caddy",
        store: RuntimeStore = RuntimeStore.LEGACY): Path = RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base, ::inputs)

    /** Explicit fresh-source publication only, called before sealing the generation. ACME needs a
     * dedicated egress network; no application may join it and all other networks stay internal. */
    fun publish(spec: PrivateDeploymentSpec, ingress: RuntimeIngressPublication): PrivateDeploymentSpec {
        require(spec.ingress == null && spec.store == RuntimeStore.CANONICAL_V2)
        return spec.copy(ingress = ingress, networks = (listOf("ingress-egress") + spec.networks).distinct(),
            processes = spec.processes.map { if (it.id == "caddy") it.copy(networks = (listOf("ingress-egress") + it.networks).distinct()) else it })
            .also { PrivateDeployment.validate(it) }
    }

    /** Never resume the source's autosaved public routes when booting an isolated restore. Certificates
     * are retained unchanged; the restricted controller must explicitly enroll target listeners/routes.
     * No bootstrap process, CA generation or credential initializer is present in either projection. */
    fun restoreSpec(inventory: AcquiredInventory, name: String): PrivateDeploymentSpec {
        val fresh = spec(inventory, name)
        return fresh.copy(processes = fresh.processes.map { it.copy(command = it.command - "--resume") })
    }
}
