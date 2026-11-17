package net.datamancy.platform

import java.nio.file.Path

/** Private HTTPS Element/Synapse integration. Internal PKI, not public ACME, MAS or RTC acceptance. */
internal object MatrixRuntime {
    fun spec(inventory: AcquiredInventory, name: String = "matrix"): PrivateDeploymentSpec {
        val source = SynapseRuntime.spec(inventory, name)
        fun image(product: String) = inventory.images.single { it.product == product }.also {
            require(it.os == "linux" && it.architecture == "amd64")
        }
        val element = image("element"); val caddy = image("caddy")
        return source.copy(volumes = source.volumes + listOf(RuntimeVolume("caddy-data", 65532), RuntimeVolume("caddy-config", 65532)),
            processes = source.processes + listOf(
                RuntimeProcess("element-web", element.pinnedImage, element.imageId, 101, dependencies = listOf("synapse"),
                    entrypoint = "/usr/sbin/nginx", command = listOf("-c", "/run/secrets/nginx.conf", "-g", "daemon off;"),
                    files = listOf(RuntimeFile("nginx.conf", "/run/secrets/nginx.conf"), RuntimeFile("element.json", "/run/secrets/element.json")),
                    apparmorProfile = "p0v3-private-v1", readinessHttpPort = 8080, readinessHttpPath = "/config.json"),
                RuntimeProcess("caddy", caddy.pinnedImage, caddy.imageId, 65532, dependencies = listOf("element-web"),
                    entrypoint = "/usr/bin/caddy", command = listOf("run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"),
                    files = listOf(RuntimeFile("caddyfile", "/etc/caddy/Caddyfile")),
                    volumes = listOf(RuntimeMount("caddy-data", "/data"), RuntimeMount("caddy-config", "/config")),
                    capabilities = listOf("NET_BIND_SERVICE"), apparmorProfile = "p0v3-private-v1", memoryMiB = 256,
                    readinessHttpPort = 8081, readinessHttpPath = "/healthz")
            )).also { PrivateDeployment.validate(it) }
    }
    /** Browser-only partial graph: the public Caddy is canonical, never copied into Element. */
    fun canonicalFragment(inventory: AcquiredInventory, base: PrivateDeploymentSpec): CanonicalProviderFragment {
        require(base.store == RuntimeStore.CANONICAL_V2 && base.processes.any { it.id == "caddy" && !it.oneShot })
        val image = inventory.images.single { it.product == "element" }.also {
            require(it.os == "linux" && it.architecture == "amd64")
        }
        val web = RuntimeProcess("element-web", image.pinnedImage, image.imageId, 101,
            dependencies = listOf("synapse", "mas"), entrypoint = "/usr/sbin/nginx",
            command = listOf("-c", "/run/secrets/element-nginx.conf", "-g", "daemon off;"),
            files = listOf(RuntimeFile("element-nginx.conf", "/run/secrets/element-nginx.conf"),
                RuntimeFile("element.json", "/run/secrets/element.json")),
            networks = listOf("element-web", "synapse-web"), memoryMiB = 256,
            apparmorProfile = "p0v3-private-v1", readinessHttpPort = 8080, readinessHttpPath = "/config.json")
        return CanonicalProviderFragment("element", PrivateDeploymentSpec(name = base.name, store = base.store,
            volumes = emptyList(), processes = listOf(web), networks = listOf("element-web", "synapse-web")),
            webNetworks = setOf("element-web"))
    }

    fun canonicalColdFragment(inventory: AcquiredInventory, base: PrivateDeploymentSpec,
        original: CanonicalProviderFragment): CanonicalProviderFragment {
        val fresh = canonicalFragment(inventory, base)
        require(original == fresh && fresh.spec.processes.none { it.oneShot }) {
            "Element cannot be reinitialized or replace original web inputs on recovery"
        }
        return fresh
    }

    fun canonicalInputs(): Map<String, String> = mapOf(
        "element-nginx.conf" to """
            worker_processes 1;
            pid /tmp/nginx.pid;
            error_log /tmp/nginx-error.log warn;
            events { worker_connections 512; }
            http {
              include /etc/nginx/mime.types;
              access_log off;
              server {
                listen 8080;
                root /app;
                client_max_body_size 10m;
                location = /config.element.json { return 404; }
                location = /config.json {
                  alias /run/secrets/element.json;
                  default_type application/json;
                  add_header Cache-Control no-store;
                }
                location /_matrix/ {
                  proxy_pass http://synapse:8008;
                  proxy_http_version 1.1;
                  proxy_buffering off;
                  proxy_set_header Host ${'$'}http_host;
                  proxy_set_header X-Forwarded-Proto https;
                }
                location / { try_files ${'$'}uri ${'$'}uri/ /index.html; }
              }
            }
        """.trimIndent() + "\n",
        "element.json" to """
            {"default_server_config":{"m.homeserver":{"base_url":"https://matrix.datamancy.net","server_name":"matrix.datamancy.net"},"org.matrix.msc2965.authentication":{"issuer":"https://matrix-auth.datamancy.net/","account":"https://matrix-auth.datamancy.net/account/"},"org.matrix.msc4143.rtc_foci":[{"type":"livekit","livekit_service_url":"https://matrix-rtc.datamancy.net/livekit/jwt"}]},"oidc_static_clients":{"https://matrix-auth.datamancy.net/":{"client_id":"${MatrixIdentityRuntime.ELEMENT_CLIENT}"}},"enable_client_well_known_lookups":true,"disable_custom_urls":true,"disable_guests":true,"disable_3pid_login":true,"brand":"Platform Zero chat.datamancy.net","features":{"feature_group_calls":true,"feature_element_call_video_rooms":true},"integrations_ui_url":"","integrations_rest_url":"","integrations_widgets_urls":[],"bug_report_endpoint_url":null,"default_federate":false}
        """.trimIndent() + "\n")

    /** Same-version cold restore only; Caddy certificate state and Synapse signing keys are retained. */
    fun coldRestoreSpec(compiled: PrivateDeploymentSpec): PrivateDeploymentSpec {
        val web = compiled.processes.filter { it.id in setOf("element-web", "caddy") }
        require(web.size == 2 && web.none { it.oneShot })
        val synapse = SynapseRuntime.coldRestoreSpec(compiled.copy(
            processes = compiled.processes.filterNot { it in web },
            volumes = compiled.volumes.filter { it.id in setOf("postgres", "synapse") }))
        return compiled.copy(processes = synapse.processes + web,
            databaseAccess = synapse.databaseAccess).also { PrivateDeployment.validate(it) }
    }

    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "matrix", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) {
            SynapseRuntime.inputs("https://element:8443/") + mapOf(
                "caddyfile" to """
                    {
                        admin off
                        auto_https disable_redirects
                        skip_install_trust
                    }
                    https://element:8443 {
                        tls internal
                        reverse_proxy element-web:8080
                    }
                    http://:8081 {
                        respond /healthz "ready" 200
                    }
                """.trimIndent() + "\n",
                "nginx.conf" to """
                    worker_processes 1;
                    pid /tmp/nginx.pid;
                    error_log /tmp/nginx-error.log warn;
                    events { worker_connections 512; }
                    http {
                        include /etc/nginx/mime.types;
                        default_type application/octet-stream;
                        access_log off;
                        client_body_temp_path /tmp/client_body;
                        proxy_temp_path /tmp/proxy;
                        fastcgi_temp_path /tmp/fastcgi;
                        uwsgi_temp_path /tmp/uwsgi;
                        scgi_temp_path /tmp/scgi;
                        server {
                            listen 8080;
                            root /app;
                            client_max_body_size 10m;
                            location = /config.element.json { return 404; }
                            location = /config.json {
                                alias /run/secrets/element.json;
                                default_type application/json;
                                add_header Cache-Control no-store;
                            }
                            location /_matrix/ {
                                proxy_pass http://synapse:8008;
                                proxy_http_version 1.1;
                                proxy_buffering off;
                                proxy_read_timeout 65s;
                                proxy_set_header Host ${'$'}http_host;
                            }
                            location / { try_files ${'$'}uri ${'$'}uri/ /index.html; }
                        }
                    }
                """.trimIndent() + "\n",
                "element.json" to """
                    {
                      "default_server_config": {"m.homeserver": {"base_url": "https://element:8443", "server_name": "matrix.private.invalid"}},
                      "disable_custom_urls": true,
                      "disable_guests": true,
                      "disable_3pid_login": true,
                      "brand": "Platform Zero private Matrix fixture",
                      "integrations_ui_url": "",
                      "integrations_rest_url": "",
                      "integrations_widgets_urls": [],
                      "bug_report_endpoint_url": null,
                      "show_labs_settings": false,
                      "default_federate": false
                    }
                """.trimIndent() + "\n")
        }
}
