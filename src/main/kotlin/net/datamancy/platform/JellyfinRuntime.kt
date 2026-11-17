package net.datamancy.platform

import java.nio.file.Path

/** Isolated media fixture: no host media, devices, discovery network or public port is mounted. */
internal object JellyfinRuntime {
    fun spec(inventory: AcquiredInventory, name: String = "jellyfin"): PrivateDeploymentSpec {
        val image = inventory.images.single { it.product == "jellyfin" }
        require(image.os == "linux" && image.architecture == "amd64")
        return PrivateDeploymentSpec(name = name,
            volumes = listOf("config", "cache", "media").map { RuntimeVolume(it, 1000) }, processes = listOf(
                RuntimeProcess("media-init", image.pinnedImage, image.imageId, 1000, oneShot = true,
                    entrypoint = "/bin/sh", apparmorProfile = "p0v3-private-v1",
                    volumes = listOf(RuntimeMount("media", "/media"), RuntimeMount("config", "/config")),
                    files = listOf(RuntimeFile("system.xml", "/run/secrets/system.xml")), command = listOf("-ec", """
                        mkdir -p /config/config
                        test ! -e /config/config/system.xml
                        cp /run/secrets/system.xml /config/config/system.xml
                        chmod 600 /config/config/system.xml
                        exec /usr/lib/jellyfin-ffmpeg/ffmpeg -nostdin -n -f lavfi -i sine=frequency=440:duration=3 -metadata 'title=Platform Zero private tone' -metadata 'artist=Generated fixture' -c:a pcm_s16le /media/private-tone.wav
                    """.trimIndent())),
                RuntimeProcess("jellyfin", image.pinnedImage, image.imageId, 1000, dependencies = listOf("media-init"),
                    entrypoint = "/jellyfin/jellyfin", environmentFile = "jellyfin.env",
                    volumes = listOf(RuntimeMount("config", "/config"), RuntimeMount("cache", "/cache"), RuntimeMount("media", "/media")),
                    apparmorProfile = "p0v3-private-v1", memoryMiB = 2048, readinessHttpPort = 8096, readinessHttpPath = "/Users/Public")
            )).also { PrivateDeployment.validate(it) }
    }
    fun canonicalFragment(inventory: AcquiredInventory, name: String): CanonicalProviderFragment {
        val original = spec(inventory, name)
        val fragment = original.copy(store = RuntimeStore.CANONICAL_V2,
            networks = listOf("media-data", "media-web"), processes = original.processes.map { process ->
                process.copy(id = if (process.oneShot) "jellyfin-media-init" else process.id,
                    dependencies = process.dependencies.map { if (it == "media-init") "jellyfin-media-init" else it },
                    environmentFile = process.environmentFile?.let { "jellyfin-$it" },
                    files = process.files.map { it.copy(file = "jellyfin-${it.file}") },
                    networks = if (process.oneShot) listOf("media-data") else listOf("media-data", "media-web"))
            })
        PrivateDeployment.validate(fragment)
        return CanonicalProviderFragment("jellyfin", fragment, webNetworks = setOf("media-web"))
    }
    fun canonicalInputs(): Map<String, String> = inputs().mapKeys { (key, _) -> "jellyfin-$key" }
    fun coldRestoreFragment(fresh: CanonicalProviderFragment): CanonicalProviderFragment {
        require(fresh.product == "jellyfin" && fresh.spec.store == RuntimeStore.CANONICAL_V2 &&
            fresh.spec.processes.map { it.id }.toSet() == setOf("jellyfin-media-init", "jellyfin") &&
            fresh.spec.volumes.map { it.id }.toSet() == setOf("config", "cache", "media"))
        val server = fresh.spec.processes.single { it.id == "jellyfin" }
        require(server.dependencies == listOf("jellyfin-media-init") && server.entrypoint == "/jellyfin/jellyfin" &&
            server.volumes.any { it == RuntimeMount("media", "/media") })
        return fresh.copy(spec = fresh.spec.copy(processes = listOf(server.copy(dependencies = emptyList()))).also {
            PrivateDeployment.validate(it)
        })
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "jellyfin", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }

    fun inputs(): Map<String, String> =
            mapOf("system.xml" to "<?xml version=\"1.0\" encoding=\"utf-8\"?><ServerConfiguration><IsStartupWizardCompleted>false</IsStartupWizardCompleted><PluginRepositories><RepositoryInfo><Name>Jellyfin Stable</Name><Url>https://repo.jellyfin.org/files/plugin/manifest.json</Url><Enabled>false</Enabled></RepositoryInfo></PluginRepositories><EnableAutomaticRestart>false</EnableAutomaticRestart></ServerConfiguration>\n",
                "jellyfin.env" to "JELLYFIN_DATA_DIR=/config\nJELLYFIN_CONFIG_DIR=/config/config\nJELLYFIN_LOG_DIR=/config/log\nJELLYFIN_CACHE_DIR=/cache\nJELLYFIN_FFMPEG=/usr/lib/jellyfin-ffmpeg/ffmpeg\nP0V3_FIXTURE_PASSWORD=${RuntimePreparation.password()}\n")
}
