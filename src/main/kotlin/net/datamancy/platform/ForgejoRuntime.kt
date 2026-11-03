package net.datamancy.platform

import java.nio.file.Path

/** Private Git hosting with a persistent SQLite database and no registration, mail, federation or runners. */
internal object ForgejoRuntime {
    fun spec(inventory: AcquiredInventory, name: String = "forgejo"): PrivateDeploymentSpec {
        val image = inventory.images.single { it.product == "forgejo" }
        require(image.architecture == "amd64" && image.os == "linux")
        val common = RuntimeProcess("forgejo", image.pinnedImage, image.imageId, 1000,
            entrypoint = "/usr/local/bin/forgejo", environmentFile = "forgejo.env",
            volumes = listOf(RuntimeMount("forgejo", "/data")), files = listOf(RuntimeFile("app.ini", "/etc/forgejo/app.ini")),
            memoryMiB = 1024, apparmorProfile = "p0v3-private-v1", readinessHttpPort = 3000, readinessHttpPath = "/api/healthz")
        return PrivateDeploymentSpec(name = name, volumes = listOf(RuntimeVolume("forgejo", 1000)), processes = listOf(
            common.copy(id = "forgejo-init", entrypoint = "/bin/sh", oneShot = true, readinessHttpPort = null,
                command = listOf("-ec", """
                    /usr/local/bin/forgejo --work-path /data --config /etc/forgejo/app.ini migrate
                    /usr/local/bin/forgejo --work-path /data --config /etc/forgejo/app.ini admin user create --username p0v3-bootstrap --password "${'$'}BOOTSTRAP_PASSWORD" --email bootstrap@localhost.invalid --admin --must-change-password=false
                """.trimIndent())),
            common.copy(dependencies = listOf("forgejo-init"), command = listOf("--work-path", "/data", "--config", "/etc/forgejo/app.ini", "web"))
        )).also { PrivateDeployment.validate(it) }
    }
    /** Staging restore: no database/admin initialization is allowed against recovered state. */
    fun restoreSpec(inventory: AcquiredInventory, name: String): PrivateDeploymentSpec {
        val source = spec(inventory, name)
        return source.copy(processes = listOf(
            source.processes.first().copy(id = "restore-check", command = listOf("-ec",
                "test -s /data/forgejo.db && test -d /data/repositories && test ! -e /data/.restore-in-progress")),
            source.processes.last().copy(dependencies = listOf("restore-check"))
        )).also { PrivateDeployment.validate(it) }
    }
    fun prepareRestore(inventory: AcquiredInventory, recoveredInputs: Path, base: Path = PrivateDeployment.BASE, name: String): Path {
        val inputs = listOf("app.ini", "forgejo.env").associateWith { ReleaseLocks.privateBytes(recoveredInputs.resolve(it)).decodeToString() }
        val path = RuntimePreparation.prepare(restoreSpec(inventory, name), base) { inputs }
        inputs.forEach { (file, value) -> require(ReleaseLocks.privateBytes(base.resolve(name).resolve(file)).decodeToString() == value) {
            "Restored runtime inputs differ; refusing replacement"
        } }
        return path
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "forgejo", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) {
            mapOf("forgejo.env" to "HOME=/data\nUSER=git\nBOOTSTRAP_PASSWORD=${RuntimePreparation.password()}\n",
                "app.ini" to """
                    APP_NAME = Platform Zero private Forgejo
                    RUN_USER = git
                    RUN_MODE = prod
                    WORK_PATH = /data
                    [database]
                    DB_TYPE = sqlite3
                    PATH = /data/forgejo.db
                    [repository]
                    ROOT = /data/repositories
                    DEFAULT_PRIVATE = private
                    [server]
                    APP_DATA_PATH = /data/app
                    HTTP_ADDR = 0.0.0.0
                    HTTP_PORT = 3000
                    ROOT_URL = http://forgejo:3000/
                    DISABLE_SSH = true
                    LFS_START_SERVER = false
                    [security]
                    INSTALL_LOCK = true
                    SECRET_KEY = ${RuntimePreparation.password()}
                    INTERNAL_TOKEN = ${RuntimePreparation.password()}
                    [oauth2]
                    JWT_SIGNING_ALGORITHM = HS256
                    JWT_SECRET = ${java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(java.util.HexFormat.of().parseHex(RuntimePreparation.password()))}
                    [service]
                    DISABLE_REGISTRATION = true
                    REQUIRE_SIGNIN_VIEW = true
                    ENABLE_NOTIFY_MAIL = false
                    [mailer]
                    ENABLED = false
                    [federation]
                    ENABLED = false
                    [actions]
                    ENABLED = false
                    [cron.update_checker]
                    ENABLED = false
                    [session]
                    PROVIDER = file
                    PROVIDER_CONFIG = /data/sessions
                    [log]
                    MODE = console
                    LEVEL = Warn
                """.trimIndent() + "\n")
        }
}
