package net.datamancy.platform

import java.nio.file.Path
import java.security.SecureRandom
import java.util.HexFormat

/** Private native repository server. Only an immutable synthetic source is mounted, never host data. */
internal object KopiaRuntime {
    fun spec(inventory: AcquiredInventory, name: String = "backup"): PrivateDeploymentSpec {
        val image = inventory.images.single { it.product == "kopia" }
        require(image.os == "linux" && image.architecture == "amd64")
        val mounts = listOf(RuntimeMount("repository", "/repository"), RuntimeMount("configuration", "/configuration"))
        return PrivateDeploymentSpec(name = name, volumes = listOf(RuntimeVolume("repository", 1000), RuntimeVolume("configuration", 1000)), processes = listOf(
            RuntimeProcess("repository-init", image.pinnedImage, image.imageId, 1000, oneShot = true,
                entrypoint = "/bin/sh", environmentFile = "repository.env", volumes = mounts,
                apparmorProfile = "p0v3-private-v1", memoryMiB = 512,
                command = listOf("-ec", "test -z \"${'$'}(ls -A /repository)\"; test -z \"${'$'}(ls -A /configuration)\"; umask 077; exec /usr/bin/kopia --disable-file-logging repository create filesystem --path=/repository --no-check-for-updates")),
            RuntimeProcess("backup", image.pinnedImage, image.imageId, 1000, dependencies = listOf("repository-init"),
                entrypoint = "/usr/bin/kopia", environmentFile = "server.env", volumes = mounts,
                files = listOf(RuntimeFile("ca.pem", "/run/secrets/ca.pem"), RuntimeFile("web.pem", "/run/secrets/web.pem"), RuntimeFile("web-key.pem", "/run/secrets/web-key.pem"), RuntimeFile("fixture.txt", "/source/fixture.txt")),
                apparmorProfile = "p0v3-private-v1", memoryMiB = 1024,
                command = listOf("--disable-file-logging", "server", "start", "--address=0.0.0.0:51515", "--tls-cert-file=/run/secrets/web.pem", "--tls-key-file=/run/secrets/web-key.pem", "--ui", "--control-api", "--no-grpc", "--no-enable-actions", "--no-check-for-updates", "--no-persistent-logs", "--ui-preferences-file=/configuration/ui-preferences.json"),
                readiness = listOf("/usr/bin/kopia", "--disable-file-logging", "repository", "status"))
        )).also { PrivateDeployment.validate(it) }
    }
    fun inputs(pki: () -> Map<String, String> = { PrivateWebPki.generate("backup") },
               secret: () -> String = { HexFormat.of().formatHex(ByteArray(32).also { SecureRandom().nextBytes(it) }) }): Map<String, String> {
        val password = secret(); val admin = secret(); val control = secret()
        require(listOf(password, admin, control).all { it.matches(Regex("[a-f0-9]{64}")) } && setOf(password, admin, control).size == 3)
        val environment = "HOME=/tmp\nKOPIA_CONFIG_PATH=/configuration/repository.config\nKOPIA_PASSWORD=$password\nKOPIA_CACHE_DIRECTORY=/tmp/cache\nKOPIA_CHECK_FOR_UPDATES=false\n"
        val certificates = pki(); require(certificates.keys == setOf("ca.pem", "web.pem", "web-key.pem"))
        // ca.pem is retained as an input as well as mounted for the native operator TLS client.
        return certificates + mapOf("repository.env" to environment,
            "server.env" to environment + "KOPIA_SERVER_USERNAME=fixture-admin\nKOPIA_SERVER_PASSWORD=$admin\nKOPIA_SERVER_CONTROL_USER=fixture-control\nKOPIA_SERVER_CONTROL_PASSWORD=$control\n",
            "fixture.txt" to "Platform Zero synthetic backup fixture. No host files or owner content.\n")
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "backup", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }
}
