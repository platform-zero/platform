package net.datamancy.platform

import java.nio.file.Path

/** Native node-exporter textfile/self metrics and authenticated Prometheus scraping; no host telemetry mounts. */
internal object NodeMetricsRuntime {
    const val BASE_IMAGE = "quay.io/prometheus/node-exporter@sha256:da83fae85603c4e47e6c68369a7d746e2dda683dc35ea2e234b4f171e0d92798"
    const val IMAGE = "localhost/p0v3-node-exporter@sha256:daf70dc167702888cd9d949edab429eda1d3abb92a81d788f8bb427711b28a96"
    const val IMAGE_ID = "7f5929fc3744930debe8888b0e726585e4526ea866fc8a94f0f32aeea0827d76"
    fun spec(inventory: AcquiredInventory, name: String = "node-metrics"): PrivateDeploymentSpec {
        fun image(product: String) = inventory.images.single { it.product == product }.also {
            require(it.os == "linux" && it.architecture == "amd64")
        }
        require(image("node-exporter").pinnedImage == BASE_IMAGE)
        val prometheus = image("prometheus")
        return PrivateDeploymentSpec(name = name, volumes = listOf(RuntimeVolume("prometheus", 65534), RuntimeVolume("metrics", 65534)), processes = listOf(
            RuntimeProcess("metrics-init", IMAGE, IMAGE_ID, 65534, oneShot = true, entrypoint = "/bin/sh",
                files = listOf(RuntimeFile("fixture.prom", "/run/secrets/fixture.prom")), volumes = listOf(RuntimeMount("metrics", "/synthetic")),
                apparmorProfile = "p0v3-private-v1", memoryMiB = 128,
                command = listOf("-ec", "test -z \"${'$'}(ls -A /synthetic)\"; umask 077; cp /run/secrets/fixture.prom /synthetic/fixture.prom; sync")),
            RuntimeProcess("node", IMAGE, IMAGE_ID, 65534, dependencies = listOf("metrics-init"),
                command = listOf("--web.listen-address=:9100", "--web.config.file=/run/secrets/web.yaml", "--collector.disable-defaults", "--collector.textfile", "--collector.textfile.directory=/synthetic"),
                files = listOf("ca.pem", "node.pem", "node-key.pem", "web.yaml").map { RuntimeFile(it, "/run/secrets/$it") },
                volumes = listOf(RuntimeMount("metrics", "/synthetic")),
                apparmorProfile = "p0v3-private-v1", memoryMiB = 128, readiness = listOf("/bin/nc", "-z", "-w", "2", "127.0.0.1", "9100")),
            RuntimeProcess("prometheus", prometheus.pinnedImage, prometheus.imageId, 65534, dependencies = listOf("node"),
                command = listOf("--config.file=/run/secrets/prometheus.yaml", "--storage.tsdb.path=/prometheus", "--storage.tsdb.retention.time=15d"),
                files = listOf("ca.pem", "admin.pem", "admin-key.pem", "prometheus.yaml", "rules.yaml").map { RuntimeFile(it, "/run/secrets/$it") },
                volumes = listOf(RuntimeMount("prometheus", "/prometheus")), apparmorProfile = "p0v3-private-v1", memoryMiB = 512,
                readinessHttpPort = 9090, readinessHttpPath = "/-/ready")
        )).also { PrivateDeployment.validate(it) }
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "node-metrics", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs(PrivateSearchPki.generate("node")) }
    fun inputs(certificates: Map<String, String>): Map<String, String> {
        require(certificates.keys == setOf("ca.pem", "node.pem", "node-key.pem", "admin.pem", "admin-key.pem"))
        return certificates + mapOf(
            "fixture.prom" to "# HELP p0v3_synthetic_probe Synthetic fixture, not host telemetry.\n# TYPE p0v3_synthetic_probe gauge\np0v3_synthetic_probe{fixture=\"node-exporter\"} 42\n",
            "web.yaml" to """
                tls_server_config:
                  cert_file: /run/secrets/node.pem
                  key_file: /run/secrets/node-key.pem
                  client_auth_type: RequireAndVerifyClientCert
                  client_ca_file: /run/secrets/ca.pem
                  min_version: TLS12
            """.trimIndent() + "\n",
            "rules.yaml" to """
                groups:
                  - name: private-exporter
                    rules:
                      - alert: PrivateTextfileInvalid
                        expr: node_textfile_scrape_error{job="private-node"} == 1
                        labels:
                          scope: synthetic-only
            """.trimIndent() + "\n",
            "prometheus.yaml" to """
                global:
                  scrape_interval: 2s
                  evaluation_interval: 2s
                rule_files: ['/run/secrets/rules.yaml']
                scrape_configs:
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
            """.trimIndent() + "\n")
    }
}
