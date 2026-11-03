package net.datamancy.platform

import java.nio.file.Path

/** Private chore-management fixture. Signup is local to this isolated network, not public onboarding. */
internal object DonetickRuntime {
    fun spec(inventory: AcquiredInventory, name: String = "donetick"): PrivateDeploymentSpec {
        val image = inventory.images.single { it.product == "donetick" }
        require(image.os == "linux" && image.architecture == "amd64")
        return PrivateDeploymentSpec(name = name, volumes = listOf(RuntimeVolume("data", 1000)), processes = listOf(
            RuntimeProcess("donetick", image.pinnedImage, image.imageId, 1000, entrypoint = "/donetick",
                environmentFile = "donetick.env", files = listOf(RuntimeFile("selfhosted.yaml", "/config/selfhosted.yaml")),
                volumes = listOf(RuntimeMount("data", "/donetick-data")), apparmorProfile = "p0v3-private-v1",
                readinessHttpPort = 2021, memoryMiB = 512)
        )).also { PrivateDeployment.validate(it) }
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "donetick", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) {
            mapOf("donetick.env" to "DT_ENV=selfhosted\nDT_SQLITE_PATH=/donetick-data/donetick.db\nP0V3_FIXTURE_PASSWORD=${RuntimePreparation.password()}\n",
                "selfhosted.yaml" to """
                    name: selfhosted
                    is_done_tick_dot_com: false
                    is_user_creation_disabled: false
                    database:
                      type: sqlite
                      migration: true
                    jwt:
                      secret: ${RuntimePreparation.password()}
                      session_time: 24h
                      max_refresh: 168h
                    server:
                      port: 2021
                      read_timeout: 10s
                      write_timeout: 10s
                      rate_period: 60s
                      rate_limit: 300
                      cors_allow_origins: ['http://donetick:2021']
                      serve_frontend: true
                      serve_swagger: true
                      public_host: http://donetick:2021
                    logging:
                      level: info
                      encoding: json
                      development: false
                    email:
                      log_raw_url: false
                    storage:
                      storage_type: local
                      base_path: /donetick-data/uploads
                    bridge:
                      enabled: false
                    realtime:
                      enabled: true
                      sse_enabled: true
                      allowed_origins: ['http://donetick:2021']
                """.trimIndent() + "\n")
        }
}
