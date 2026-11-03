package net.datamancy.platform

import java.nio.file.Path

/** Five wired, private observability products. No host log mounts, public routes or outward alert receivers. */
internal object ObservabilityRuntime {
    fun spec(inventory: AcquiredInventory, name: String = "observability"): PrivateDeploymentSpec {
        fun process(id: String, uid: Int, port: Int, path: String, arguments: List<String>,
                    config: String, target: String, data: String, dependencies: List<String> = emptyList(),
                    extraFiles: List<RuntimeFile> = emptyList(), environment: String? = null, memory: Int = 512): RuntimeProcess {
            val image = inventory.images.single { it.product == id }
            require(image.architecture == "amd64" && image.os == "linux")
            return RuntimeProcess(id, image.pinnedImage, image.imageId, uid, dependencies = dependencies,
                command = arguments, files = listOf(RuntimeFile(config, target)) + extraFiles,
                volumes = listOf(RuntimeMount(id, data)), environmentFile = environment, memoryMiB = memory,
                apparmorProfile = "p0v3-private-v1", readinessHttpPort = port, readinessHttpPath = path)
        }
        return PrivateDeploymentSpec(name = name, volumes = listOf(RuntimeVolume("alertmanager", 65534), RuntimeVolume("loki", 10001),
            RuntimeVolume("prometheus", 65534), RuntimeVolume("alloy", 65532), RuntimeVolume("grafana", 472)), processes = listOf(
            process("alertmanager", 65534, 9093, "/-/ready", listOf("--config.file=/etc/alertmanager/platform.yaml",
                "--storage.path=/alertmanager", "--cluster.listen-address="), "alertmanager.yaml", "/etc/alertmanager/platform.yaml", "/alertmanager"),
            process("loki", 10001, 3100, "/ready", listOf("-config.file=/etc/loki/platform.yaml"), "loki.yaml", "/etc/loki/platform.yaml", "/loki", memory = 1024),
            process("prometheus", 65534, 9090, "/-/ready", listOf("--config.file=/etc/prometheus/platform.yaml",
                "--storage.tsdb.path=/prometheus", "--storage.tsdb.retention.time=15d"), "prometheus.yaml", "/etc/prometheus/platform.yaml", "/prometheus",
                dependencies = listOf("alertmanager")),
            process("alloy", 65532, 12345, "/-/ready", listOf("run", "--storage.path=/var/lib/alloy", "--server.http.listen-addr=0.0.0.0:12345",
                "--disable-reporting", "/etc/alloy/platform.alloy"), "config.alloy", "/etc/alloy/platform.alloy", "/var/lib/alloy", dependencies = listOf("loki")),
            process("grafana", 472, 3000, "/api/health", emptyList(), "datasources.yaml", "/etc/grafana/provisioning/datasources/platform.yaml", "/var/lib/grafana",
                dependencies = listOf("prometheus", "loki"), environment = "grafana.env", memory = 1024)
        )).also { PrivateDeployment.validate(it) }
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "observability", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) {
            mapOf(
                "alertmanager.yaml" to """
                    global:
                      resolve_timeout: 5m
                    route:
                      receiver: private-no-outbound
                    receivers:
                      - name: private-no-outbound
                """.trimIndent() + "\n",
                "loki.yaml" to """
                    auth_enabled: false
                    server:
                      http_listen_port: 3100
                    common:
                      instance_addr: 127.0.0.1
                      path_prefix: /loki
                      replication_factor: 1
                      ring:
                        kvstore:
                          store: inmemory
                      storage:
                        filesystem:
                          chunks_directory: /loki/chunks
                          rules_directory: /loki/rules
                    schema_config:
                      configs:
                        - from: 2024-01-01
                          store: tsdb
                          object_store: filesystem
                          schema: v13
                          index:
                            prefix: index_
                            period: 24h
                    analytics:
                      reporting_enabled: false
                """.trimIndent() + "\n",
                "prometheus.yaml" to """
                    global:
                      scrape_interval: 15s
                      evaluation_interval: 15s
                    alerting:
                      alertmanagers:
                        - static_configs:
                            - targets: ['alertmanager:9093']
                    scrape_configs:
                      - job_name: prometheus
                        static_configs:
                          - targets: ['prometheus:9090']
                      - job_name: loki
                        static_configs:
                          - targets: ['loki:3100']
                      - job_name: alloy
                        static_configs:
                          - targets: ['alloy:12345']
                      - job_name: grafana
                        static_configs:
                          - targets: ['grafana:3000']
                      - job_name: alertmanager
                        static_configs:
                          - targets: ['alertmanager:9093']
                """.trimIndent() + "\n",
                "config.alloy" to """
                    logging {
                      level = "info"
                      format = "logfmt"
                    }
                    loki.write "local" {
                      endpoint {
                        url = "http://loki:3100/loki/api/v1/push"
                      }
                    }
                    loki.source.api "ingest" {
                      http {
                        listen_address = "0.0.0.0"
                        listen_port = 3500
                      }
                      use_incoming_timestamp = true
                      forward_to = [loki.write.local.receiver]
                    }
                """.trimIndent() + "\n",
                "datasources.yaml" to """
                    apiVersion: 1
                    datasources:
                      - name: Prometheus
                        uid: p0-prometheus
                        type: prometheus
                        access: proxy
                        url: http://prometheus:9090
                        isDefault: true
                        editable: false
                      - name: Loki
                        uid: p0-loki
                        type: loki
                        access: proxy
                        url: http://loki:3100
                        editable: false
                """.trimIndent() + "\n",
                "grafana.env" to "GF_SECURITY_ADMIN_USER=p0v3-admin\nGF_SECURITY_ADMIN_PASSWORD=${RuntimePreparation.password()}\nGF_USERS_ALLOW_SIGN_UP=false\nGF_AUTH_ANONYMOUS_ENABLED=false\nGF_ANALYTICS_REPORTING_ENABLED=false\nGF_ANALYTICS_CHECK_FOR_UPDATES=false\nGF_PLUGINS_CHECK_FOR_UPDATES=false\nGF_METRICS_ENABLED=true\n")
        }
}
