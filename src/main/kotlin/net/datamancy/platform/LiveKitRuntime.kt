package net.datamancy.platform

import java.nio.file.Path
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS

/** Private authenticated SFU; ephemeral rooms, no public TURN, Matrix authorizer or recording. */
internal object LiveKitRuntime {
    fun spec(inventory: AcquiredInventory, name: String = "livekit"): PrivateDeploymentSpec {
        fun image(product: String) = inventory.images.single { it.product == product }.also {
            require(it.os == "linux" && it.architecture == "amd64")
        }
        val sfu = image("livekit"); val web = image("element")
        return PrivateDeploymentSpec(name = name, volumes = emptyList(), processes = listOf(
            RuntimeProcess("livekit", sfu.pinnedImage, sfu.imageId, 1000, entrypoint = "/livekit-server",
                command = listOf("--config", "/run/secrets/livekit.yaml"),
                files = listOf(RuntimeFile("livekit.yaml", "/run/secrets/livekit.yaml")),
                apparmorProfile = "p0v3-private-v1", memoryMiB = 1024, readinessHttpPort = 7880),
            RuntimeProcess("rtc", web.pinnedImage, web.imageId, 101, dependencies = listOf("livekit"),
                entrypoint = "/usr/sbin/nginx", command = listOf("-c", "/run/secrets/nginx.conf", "-g", "daemon off;"),
                files = listOf("nginx.conf", "web.pem", "web-key.pem", "ca.pem").map { RuntimeFile(it, "/run/secrets/$it") },
                apparmorProfile = "p0v3-private-v1", memoryMiB = 256, readinessHttpPort = 8080, readinessHttpPath = "/healthz")
        )).also { PrivateDeployment.validate(it) }
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "livekit", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }

    /** Source equality is checked by the generation compiler; no ephemeral call is claimed restored. */
    fun coldRestoreSpec(compiled: PrivateDeploymentSpec): PrivateDeploymentSpec {
        require(compiled.volumes.isEmpty() && compiled.processes.map { it.id }.toSet() == setOf("livekit", "rtc"))
        require(compiled.processes.none { it.oneShot })
        require(compiled.processes.single { it.id == "livekit" }.command == listOf("--config", "/run/secrets/livekit.yaml"))
        PrivateDeployment.validate(compiled)
        return compiled
    }

    /** Restore only this exact stateless recipe; rooms/participants are deliberately not backed up. */
    fun prepareRestore(inventory: AcquiredInventory, recovered: Path, name: String, base: Path = PrivateDeployment.BASE): Path {
        require(recovered.isAbsolute && recovered.normalize() == recovered && recovered.toRealPath() == recovered)
        val sourcePath = recovered.resolve("source-spec.json")
        ReleaseLocks.privateBytes(sourcePath)
        val source = PrivateDeployment.read(sourcePath)
        require(source == spec(inventory, source.name) && source.name != name) { "Unsupported SFU recovery recipe" }
        val inputs = SingleUserRestore.inputNames(source).associateWith {
            ReleaseLocks.privateBytes(recovered.resolve(it)).decodeToString(throwOnInvalidSequence = true)
        }
        if (Files.exists(base.resolve("$name.json"), NOFOLLOW_LINKS)) inputs.forEach { (file, content) ->
            require(ReleaseLocks.privateBytes(base.resolve(name).resolve(file)).contentEquals(content.toByteArray())) {
                "Recovered inputs changed; refusing replacement"
            }
        }
        return RuntimePreparation.prepare(source.copy(name = name), base) { inputs }
    }

    fun inputs(pki: () -> Map<String, String> = { PrivateWebPki.generate("rtc") }): Map<String, String> {
        val key = RuntimePreparation.password(); val secret = RuntimePreparation.password()
        return pki() + mapOf("livekit.yaml" to """
            port: 7880
            bind_addresses: [0.0.0.0]
            development: false
            keys:
              "$key": "$secret"
            rtc:
              tcp_port: 7881
              port_range_start: 50000
              port_range_end: 50020
              use_external_ip: false
              use_ice_lite: true
              stun_servers: []
              turn_servers: []
            turn:
              enabled: false
            room:
              auto_create: false
              empty_timeout: 60
              departure_timeout: 10
              max_participants: 8
              enable_remote_unmute: false
            logging:
              level: warn
              pion_level: error
        """.trimIndent() + "\n", "nginx.conf" to """
            worker_processes 1;
            pid /tmp/nginx.pid;
            error_log /tmp/nginx-error.log warn;
            events { worker_connections 512; }
            http {
                access_log off;
                client_body_temp_path /tmp/client_body;
                proxy_temp_path /tmp/proxy;
                fastcgi_temp_path /tmp/fastcgi;
                uwsgi_temp_path /tmp/uwsgi;
                scgi_temp_path /tmp/scgi;
                map ${'$'}http_upgrade ${'$'}connection_upgrade { default upgrade; '' close; }
                server { listen 8080; location = /healthz { return 200 'ready'; } location / { return 404; } }
                server {
                    listen 8443 ssl;
                    server_name rtc;
                    ssl_certificate /run/secrets/web.pem;
                    ssl_certificate_key /run/secrets/web-key.pem;
                    ssl_protocols TLSv1.2 TLSv1.3;
                    client_max_body_size 1m;
                    location = /fixture { default_type text/html; return 200 '<!doctype html><title>Private synthetic RTC fixture</title><body>Private synthetic RTC fixture</body>'; }
                    location / {
                        proxy_pass http://livekit:7880;
                        proxy_http_version 1.1;
                        proxy_set_header Host ${'$'}http_host;
                        proxy_set_header Upgrade ${'$'}http_upgrade;
                        proxy_set_header Connection ${'$'}connection_upgrade;
                        proxy_read_timeout 120s;
                        proxy_buffering off;
                    }
                }
            }
        """.trimIndent() + "\n")
    }
}
