package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
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
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { legacyInputs() }

    private fun legacyInputs(): Map<String, String> = mapOf(
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

    /** Provider-less, six-product composition. The standalone V1 node-metrics and five-product
     * observability specs above are intentionally unchanged for historical serialized bytes.
     * No second Prometheus, host collector, host log mount, public listener or alert receiver. */
    fun canonicalSpec(inventory: AcquiredInventory, name: String = "observability"): PrivateDeploymentSpec {
        val legacy = spec(inventory, name)
        val (metricVolume, exporter) = NodeMetricsRuntime.canonicalExporter(inventory)
        require(metricVolume.id !in legacy.volumes.map { it.id } &&
            exporter.none { it.id in legacy.processes.map { process -> process.id } })
        // The full canonical recipe's generic `net` is SHARED with unrelated products.
        // Node, Alloy and Loki must have NO path from Caddy/qualification-web or other
        // applications. Only these six original products join this fixed internal network;
        // three public browser frontends ALSO join their distinct Caddy-only web network.
        val local = "observability-net"
        val web = "observability-web"
        val result = legacy.copy(volumes = legacy.volumes + metricVolume,
            networks = listOf(local, web),
            processes = exporter.map { it.copy(networks = listOf(local)) } + legacy.processes.map { process -> when (process.id) {
                "prometheus" -> process.copy(dependencies = (process.dependencies + "node").distinct(),
                    files = process.files + listOf("ca.pem", "admin.pem", "admin-key.pem", "rules.yaml")
                        .map { RuntimeFile(it, "/run/secrets/$it") },
                    networks = listOf(local, web))
                "grafana" -> process.copy(networks = listOf(local, web),
                    files = process.files + RuntimeFile("grafana-viewer.json", "/run/secrets/grafana-viewer.json"))
                "alertmanager" -> process.copy(networks = listOf(local, web))
                else -> process.copy(networks = listOf(local))
            } })
        require(result.processes.count { it.id == "prometheus" } == 1 &&
            result.processes.map { it.id }.toSet() == setOf("metrics-init", "node", "alertmanager",
                "alloy", "grafana", "loki", "prometheus") &&
            result.volumes.map { it.id }.toSet() == setOf("metrics", "alertmanager", "alloy", "grafana", "loki", "prometheus"))
        PrivateDeployment.validate(result)
        return result
    }

    /** Six fixed selected product capabilities in ONE provider-less contribution. The
     * historical catalog spec remains separate; COORD's full recipe owns assembly. */
    fun canonicalFragment(inventory: AcquiredInventory, name: String): CanonicalProviderFragment =
        CanonicalProviderFragment("prometheus", canonicalSpec(inventory, name).copy(store = RuntimeStore.CANONICAL_V2),
            webNetworks = setOf("observability-web"))

    /** Feature-owned projection of an already authenticated original fragment; no fresh
     * credentials, new provider, generic initializer stripping, or public promotion. */
    fun canonicalColdFragment(fresh: CanonicalProviderFragment, inventory: AcquiredInventory,
        targetName: String, originalSpecSha256: String): CanonicalProviderFragment {
        require(fresh.product == "prometheus" && fresh.webNetworks == setOf("observability-web") &&
            fresh.spec.store == RuntimeStore.CANONICAL_V2 &&
            fresh.spec == canonicalSpec(inventory, fresh.spec.name).copy(store = RuntimeStore.CANONICAL_V2))
        return fresh.copy(spec = recoveredSpec(fresh.spec, inventory, targetName, originalSpecSha256))
    }

    /** Create PKI and Grafana credentials only AFTER the complete canonical graph validates.
     * The 47 RSS principals, external mail receivers and old producer logs are never generated. */
    fun canonicalInputs(certificates: Map<String, String>, legacy: Map<String, String>,
        viewerPassword: String = RuntimePreparation.password()): Map<String, String> {
        val node = NodeMetricsRuntime.inputs(certificates)
        require(legacy.keys == setOf("alertmanager.yaml", "loki.yaml", "prometheus.yaml", "config.alloy",
            "datasources.yaml", "grafana.env") && viewerPassword.matches(Regex("[a-f0-9]{64}")))
        val scrape = """
            rule_files: ['/run/secrets/rules.yaml']
        """.trimIndent() + "\n"
        val nodeJob = """
              - job_name: private-node
                scheme: https
                tls_config:
                  ca_file: /run/secrets/ca.pem
                  cert_file: /run/secrets/admin.pem
                  key_file: /run/secrets/admin-key.pem
                  server_name: node
                  insecure_skip_verify: false
                  min_version: TLS12
                static_configs:
                  - targets: ['node:9100']
        """.trimIndent().prependIndent("  ") + "\n"
        val prometheus = legacy.getValue("prometheus.yaml").replaceFirst("scrape_configs:\n",
            scrape + "scrape_configs:\n") + nodeJob
        require(prometheus.contains("alertmanagers:") && prometheus.contains("job_name: private-node") &&
            legacy.getValue("alertmanager.yaml").contains("private-no-outbound") &&
            !legacy.getValue("alertmanager.yaml").contains("smtp_"))
        return legacy + node.filterKeys { it != "prometheus.yaml" && it != "rules.yaml" } + mapOf(
            "prometheus.yaml" to prometheus,
            "rules.yaml" to """
                groups:
                  - name: p0v3-private-telemetry
                    rules:
                      - alert: P0SyntheticMetricObserved
                        expr: p0v3_synthetic_probe{fixture="node-exporter"} == 42
                        for: 0s
                        labels:
                          scope: synthetic-only
                        annotations:
                          summary: Private original synthetic exporter data was read
            """.trimIndent() + "\n",
            "grafana.env" to legacy.getValue("grafana.env") +
                "GF_AUTH_BASIC_ENABLED=true\nGF_USERS_ALLOW_ORG_CREATE=false\nGF_SECURITY_DISABLE_GRAVATAR=true\n" +
                "GF_USERS_AUTO_ASSIGN_ORG=true\nGF_USERS_AUTO_ASSIGN_ORG_ROLE=Viewer\n" +
                "GF_USERS_VIEWERS_CAN_EDIT=false\n" +
                "GF_SERVER_DOMAIN=grafana.datamancy.net\nGF_SERVER_ROOT_URL=https://grafana.datamancy.net/\n" +
                "GF_SECURITY_COOKIE_SECURE=true\nGF_SECURITY_COOKIE_SAMESITE=strict\n",
            "grafana-viewer.json" to "{\"username\":\"p0-observer\",\"email\":\"p0-observer@localhost.invalid\",\"password\":\"$viewerPassword\"}\n")
    }

    fun prepareCanonical(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE,
        name: String = "observability", store: RuntimeStore = RuntimeStore.CANONICAL_V2): Path {
        val graph = canonicalSpec(inventory, name).copy(store = store)
        return RuntimePreparation.prepare(graph, base) {
            canonicalInputs(PrivateSearchPki.generate("node"), legacyInputs())
        }
    }

    /** Exact feature-owned cold projection: the canonical import backend REQUIRES no one-shot
     * process. Omit ONLY the known original metrics-init and its node dependency; unlike a
     * generic initializer-stripper, reject any other one-shot or foreign source graph. Import
     * retains all six original storage volumes and the original daemon PKI/role-input bytes. */
    fun recoveredSpec(source: PrivateDeploymentSpec, inventory: AcquiredInventory, name: String,
        sourceSha256: String): PrivateDeploymentSpec {
        require(source == canonicalSpec(inventory, source.name).copy(store = source.store) &&
            source.store == RuntimeStore.CANONICAL_V2 && source.name != name &&
            sourceSha256.matches(Regex("[a-f0-9]{64}"))) { "Foreign canonical observability source" }
        require(source.processes.filter { it.oneShot }.map { it.id } == listOf("metrics-init") &&
            source.processes.single { it.id == "node" }.dependencies == listOf("metrics-init"))
        val target = source.copy(name = name, processes = source.processes.filterNot { it.id == "metrics-init" }
            .map { process -> if (process.id == "node") process.copy(dependencies = emptyList()) else process })
        require(target.processes.none { it.oneShot } && target.volumes == source.volumes)
        PrivateDeployment.validate(target)
        return target
    }

    fun prepareRecovered(inventory: AcquiredInventory, recovered: Path, name: String,
        base: Path = PrivateDeployment.BASE): Path {
        require(recovered.isAbsolute && recovered.normalize() == recovered && recovered.toRealPath() == recovered)
        val originalPath = recovered.resolve("source-spec.json")
        val sourceBytes = ReleaseLocks.privateBytes(originalPath)
        val original = PrivateDeployment.read(originalPath)
        val target = recoveredSpec(original, inventory, name, ReleaseLocks.sha256(sourceBytes))
        val originalInputs = SingleUserRestore.inputNames(original).associateWith { file ->
            ReleaseLocks.privateBytes(recovered.resolve(file)).decodeToString(throwOnInvalidSequence = true)
        }
        val inputs = originalInputs.filterKeys { it in PrivateDeployment.inputNames(target).toSet() }
        require(originalInputs.keys - inputs.keys == setOf("fixture.prom") &&
            inputs.keys == PrivateDeployment.inputNames(target).toSet()) {
            "Recovered observability cannot generate fresh credential, dashboard or alert inputs"
        }
        if (Files.exists(base.resolve("$name.json"), NOFOLLOW_LINKS)) inputs.forEach { (file, contents) ->
            require(ReleaseLocks.privateBytes(base.resolve(name).resolve(file)).contentEquals(contents.toByteArray())) {
                "Original observability identity/configuration changed after import"
            }
        }
        return RuntimePreparation.prepare(target, base) { inputs }
    }
}
