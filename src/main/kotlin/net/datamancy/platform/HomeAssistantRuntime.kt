package net.datamancy.platform

import java.nio.file.Path

/** Only virtual devices. No host networking, physical devices, discovery, cloud or unrelated home configuration. */
internal object HomeAssistantRuntime {
    fun spec(inventory: AcquiredInventory, name: String = "homeassistant"): PrivateDeploymentSpec {
        val image = inventory.images.single { it.product == "homeassistant" }
        require(image.os == "linux" && image.architecture == "amd64")
        val common = RuntimeProcess("homeassistant", image.pinnedImage, image.imageId, 1000,
            entrypoint = "/usr/local/bin/python3", environmentFile = "homeassistant.env",
            volumes = listOf(RuntimeMount("config", "/config")), apparmorProfile = "p0v3-private-v1", memoryMiB = 2048)
        return PrivateDeploymentSpec(name = name, volumes = listOf(RuntimeVolume("config", 1000)), processes = listOf(
            common.copy(id = "config-init", oneShot = true, files = listOf(RuntimeFile("configuration.yaml", "/run/secrets/configuration.yaml")),
                command = listOf("-c", "from pathlib import Path; p=Path('/config/configuration.yaml'); f=p.open('xb'); f.write(Path('/run/secrets/configuration.yaml').read_bytes()); f.close()")),
            common.copy(dependencies = listOf("config-init"), command = listOf("-m", "homeassistant", "--config", "/config"),
                readinessHttpPort = 8123, readinessHttpPath = "/manifest.json")
        )).also { PrivateDeployment.validate(it) }
    }
    /** Reviewed 2026.10.4 only. Original auth/onboarding and recorder schema must already exist. */
    fun coldRestoreSpec(compiled: PrivateDeploymentSpec): PrivateDeploymentSpec {
        PrivateDeployment.validate(compiled)
        require(compiled.processes.filter { it.oneShot }.map { it.id } == listOf("config-init"))
        val daemon = compiled.processes.single { !it.oneShot }
        require(daemon.id == "homeassistant" && daemon.entrypoint == "/usr/local/bin/python3" &&
            daemon.command == listOf("-m", "homeassistant", "--config", "/config") &&
            compiled.processes.all { it.image == "ghcr.io/home-assistant/home-assistant@sha256:21935614df6d9f24f680a1ef749f0570d2d6b7936c606c0a44253ae875865c04" }) {
            "Unreviewed Home Assistant cold-start image or entrypoint"
        }
        val guard = requireNotNull(javaClass.getResourceAsStream("/runtime/homeassistant-recovery-guard.py"))
            .bufferedReader().use { it.readText() }
        return compiled.copy(processes = listOf(daemon.copy(dependencies = emptyList(), environmentFile = null,
            command = listOf("-c", guard))))
            .also { PrivateDeployment.validate(it) }
    }

    /** Keep the historical recipe bytes and initializer unchanged; prefix only canonical input names. */
    fun canonicalFragment(inventory: AcquiredInventory, name: String): CanonicalProviderFragment {
        val original = spec(inventory, name)
        val fragment = original.copy(store = RuntimeStore.CANONICAL_V2,
            networks = listOf("home-data", "home-web"), processes = original.processes.map { process ->
                process.copy(id = if (process.id == "config-init") "homeassistant-config-init" else process.id,
                    dependencies = process.dependencies.map { if (it == "config-init") "homeassistant-config-init" else it },
                    files = process.files.map { it.copy(file = "homeassistant-${it.file}") },
                    environmentFile = process.environmentFile?.let { "homeassistant-$it" },
                    networks = if (process.oneShot) listOf("home-data") else listOf("home-data", "home-web"))
            })
        PrivateDeployment.validate(fragment)
        return CanonicalProviderFragment("homeassistant", fragment, webNetworks = setOf("home-web"))
    }
    fun canonicalInputs(): Map<String, String> = inputs().mapKeys { (key, _) -> "homeassistant-$key" }
        .mapValues { (key, value) -> if (key == "homeassistant-configuration.yaml") {
            require("frontend:\n" in value)
            value.replace("frontend:\n", "frontend:\npersistent_notification:\n")
        } else value }
    fun coldRestoreFragment(fresh: CanonicalProviderFragment): CanonicalProviderFragment {
        require(fresh.product == "homeassistant" && fresh.spec.store == RuntimeStore.CANONICAL_V2 &&
            fresh.spec.processes.filter { it.oneShot }.map { it.id } == listOf("homeassistant-config-init") &&
            fresh.spec.volumes.single().id == "config")
        val original = fresh.spec.processes.single { !it.oneShot }
        require(original.id == "homeassistant" && original.entrypoint == "/usr/local/bin/python3" &&
            original.command == listOf("-m", "homeassistant", "--config", "/config") &&
            original.image == "ghcr.io/home-assistant/home-assistant@sha256:21935614df6d9f24f680a1ef749f0570d2d6b7936c606c0a44253ae875865c04")
        val guard = requireNotNull(javaClass.getResourceAsStream("/runtime/homeassistant-recovery-guard.py"))
            .bufferedReader().use { it.readText() }
        val cold = fresh.spec.copy(processes = listOf(original.copy(dependencies = emptyList(),
            environmentFile = null, command = listOf("-c", guard))))
        PrivateDeployment.validate(cold)
        return fresh.copy(spec = cold)
    }

    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "homeassistant", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }

    fun inputs(): Map<String, String> =
            mapOf("homeassistant.env" to "HOME=/config\nP0V3_FIXTURE_PASSWORD=${RuntimePreparation.password()}\n",
                "configuration.yaml" to """
                    homeassistant:
                      name: Private virtual-device fixture
                      latitude: 0
                      longitude: 0
                      elevation: 0
                      unit_system: metric
                      time_zone: UTC
                      country: GB
                    frontend:
                    api:
                    config:
                    history:
                    recorder:
                    logger:
                      default: warning
                    input_boolean:
                      private_probe:
                        name: Private trigger
                      private_result:
                        name: Private automated result
                    automation:
                      - id: p0v3_private_mirror
                        alias: Private virtual switch automation
                        triggers:
                          - trigger: state
                            entity_id: input_boolean.private_probe
                            to: "on"
                        actions:
                          - action: input_boolean.turn_on
                            target:
                              entity_id: input_boolean.private_result
                """.trimIndent() + "\n")
}
