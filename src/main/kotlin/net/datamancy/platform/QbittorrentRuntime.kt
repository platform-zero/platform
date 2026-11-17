package net.datamancy.platform

import java.nio.file.Path
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/** Authenticated private transfer fixture. No trackers, DHT, peer discovery, UPnP or host media mounts. */
internal object QbittorrentRuntime {
    fun passwordSetting(password: String, salt: ByteArray): String {
        require(salt.size == 16 && password.length >= 12)
        val key = PBEKeySpec(password.toCharArray(), salt, 100000, 512)
        return try {
            val hash = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512").generateSecret(key).encoded
            "@ByteArray(${Base64.getEncoder().encodeToString(salt)}:${Base64.getEncoder().encodeToString(hash)})"
        } finally { key.clearPassword() }
    }
    fun spec(inventory: AcquiredInventory, name: String = "qbittorrent"): PrivateDeploymentSpec {
        val image = inventory.images.single { it.product == "qbittorrent" }
        require(image.os == "linux" && image.architecture == "amd64")
        val common = RuntimeProcess("qbittorrent", image.pinnedImage, image.imageId, 1000,
            environmentFile = "qbittorrent.env", volumes = listOf(RuntimeMount("config", "/config")),
            apparmorProfile = "p0v3-private-v1", memoryMiB = 512)
        return PrivateDeploymentSpec(name = name, volumes = listOf(RuntimeVolume("config", 1000), RuntimeVolume("downloads", 1000)), processes = listOf(
            common.copy(id = "config-init", oneShot = true, entrypoint = "/bin/sh",
                files = listOf(RuntimeFile("qbittorrent.conf", "/run/secrets/qbittorrent.conf")), command = listOf("-ec",
                    "mkdir -p /config/qBittorrent; test ! -e /config/qBittorrent/qBittorrent.conf; cp /run/secrets/qbittorrent.conf /config/qBittorrent/qBittorrent.conf; chmod 600 /config/qBittorrent/qBittorrent.conf")),
            common.copy(dependencies = listOf("config-init"), entrypoint = "/app/qbittorrent-nox", command = listOf("--webui-port=8080"),
                volumes = common.volumes + RuntimeMount("downloads", "/downloads"), readinessHttpPort = 8080)
        )).also { PrivateDeployment.validate(it) }
    }
    fun canonicalFragment(inventory: AcquiredInventory, name: String): CanonicalProviderFragment {
        val original = spec(inventory, name)
        val fragment = original.copy(store = RuntimeStore.CANONICAL_V2,
            networks = listOf("transfer-data", "transfer-web"), processes = original.processes.map { process ->
                process.copy(id = if (process.oneShot) "qbittorrent-config-init" else process.id,
                    dependencies = process.dependencies.map { if (it == "config-init") "qbittorrent-config-init" else it },
                    environmentFile = process.environmentFile?.let { "qbittorrent-$it" },
                    files = process.files.map { it.copy(file = "qbittorrent-${it.file}") },
                    networks = if (process.oneShot) listOf("transfer-data") else listOf("transfer-data", "transfer-web"))
            })
        PrivateDeployment.validate(fragment)
        return CanonicalProviderFragment("qbittorrent", fragment, webNetworks = setOf("transfer-web"))
    }
    fun canonicalInputs(): Map<String, String> = canonicalize(inputs(), fresh = false)

    /** Fresh r9: the application's own PBKDF2 WebUI account and Caddy's native
     * Basic gate MUST derive from the same issued password. Do not generate a
     * second random credential in the generic legacy config producer. */
    fun freshCanonicalInputs(nativePassword: String, salt: ByteArray = ByteArray(16).also {
        SecureRandom().nextBytes(it)
    }): Map<String, String> {
        require(nativePassword.matches(Regex("[a-f0-9]{64}")))
        val generated = inputs(nativePassword, salt)
        // The daemon reads only the hashed native config; never leak the raw
        // ingress password through its runtime environment file.
        return canonicalize(generated + ("qbittorrent.env" to "HOME=/config\nXDG_CONFIG_HOME=/config\nXDG_DATA_HOME=/config\n"), fresh = true)
    }
    private fun canonicalize(source: Map<String, String>, fresh: Boolean): Map<String, String> = source
        .mapKeys { (key, _) -> "qbittorrent-$key" }
        .mapValues { (key, value) -> if (key == "qbittorrent-qbittorrent.conf") {
            require("WebUI\\ServerDomains=qbittorrent\n" in value)
            value.replace("WebUI\\ServerDomains=qbittorrent\n",
                "WebUI\\ServerDomains=qbittorrent;torrents.datamancy.net${if (fresh) ";qbittorrent-native.datamancy.net" else ""}\n")
        } else value }
    fun coldRestoreFragment(fresh: CanonicalProviderFragment): CanonicalProviderFragment {
        require(fresh.product == "qbittorrent" && fresh.spec.store == RuntimeStore.CANONICAL_V2 &&
            fresh.spec.processes.map { it.id }.toSet() == setOf("qbittorrent-config-init", "qbittorrent") &&
            fresh.spec.volumes.map { it.id }.toSet() == setOf("config", "downloads"))
        val daemon = fresh.spec.processes.single { it.id == "qbittorrent" }
        require(daemon.entrypoint == "/app/qbittorrent-nox" && daemon.dependencies == listOf("qbittorrent-config-init") &&
            daemon.volumes == listOf(RuntimeMount("config", "/config"), RuntimeMount("downloads", "/downloads")))
        return fresh.copy(spec = fresh.spec.copy(processes = listOf(daemon.copy(dependencies = emptyList()))).also {
            PrivateDeployment.validate(it)
        })
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "qbittorrent", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }

    fun inputs(): Map<String, String> = inputs(RuntimePreparation.password(),
        ByteArray(16).also { SecureRandom().nextBytes(it) })

    private fun inputs(password: String, salt: ByteArray): Map<String, String> {
            require(password.matches(Regex("[a-f0-9]{64}")) && salt.size == 16)
            return mapOf("qbittorrent.env" to "HOME=/config\nXDG_CONFIG_HOME=/config\nXDG_DATA_HOME=/config\nP0V3_QBIT_PASSWORD=$password\n",
                "qbittorrent.conf" to """
                    [LegalNotice]
                    Accepted=true
                    [AutoRun]
                    enabled=false
                    program=
                    [BitTorrent]
                    Session\DefaultSavePath=/downloads/
                    Session\DHTEnabled=false
                    Session\PeXEnabled=false
                    Session\LSDEnabled=false
                    Session\Port=6881
                    [Preferences]
                    Connection\UPnP=false
                    Connection\PortRangeMin=6881
                    Downloads\SavePath=/downloads/
                    WebUI\Address=*
                    WebUI\Port=8080
                    WebUI\Username=p0v3-fixture
                    WebUI\Password_PBKDF2="${passwordSetting(password, salt)}"
                    WebUI\LocalHostAuth=true
                    WebUI\AuthSubnetWhitelistEnabled=false
                    WebUI\CSRFProtection=true
                    WebUI\ClickjackingProtection=true
                    WebUI\HostHeaderValidation=true
                    WebUI\ServerDomains=qbittorrent
                """.trimIndent() + "\n")
    }
}
