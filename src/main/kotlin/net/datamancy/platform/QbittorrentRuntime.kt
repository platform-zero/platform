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
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "qbittorrent", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) {
            val password = RuntimePreparation.password()
            val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
            mapOf("qbittorrent.env" to "HOME=/config\nXDG_CONFIG_HOME=/config\nXDG_DATA_HOME=/config\nP0V3_QBIT_PASSWORD=$password\n",
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
