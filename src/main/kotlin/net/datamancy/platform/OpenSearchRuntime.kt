package net.datamancy.platform

import java.nio.file.Path

/** Single-node private search with real TLS/client-certificate authorization; no demo security installation. */
internal object OpenSearchRuntime {
    fun spec(inventory: AcquiredInventory, name: String = "opensearch"): PrivateDeploymentSpec {
        val image = inventory.images.single { it.product == "opensearch" }
        require(image.os == "linux" && image.architecture == "amd64")
        val common = RuntimeProcess("opensearch", image.pinnedImage, image.imageId, 1000,
            apparmorProfile = "p0v3-private-v1", environmentFile = "search.env",
            volumes = listOf(RuntimeMount("config", "/config"), RuntimeMount("data", "/data")))
        val tls = listOf("ca.pem", "node.pem", "node-key.pem").map { RuntimeFile(it, "/config/$it") }
        return PrivateDeploymentSpec(name = name,
            volumes = listOf(RuntimeVolume("config", 1000), RuntimeVolume("data", 1000)), processes = listOf(
                common.copy(id = "search-config-init", oneShot = true, entrypoint = "/bin/sh", command = listOf("-ec",
                    "cp -a /usr/share/opensearch/config/. /config/; rm -f /config/*.pem; sed -i 's|file=logs/gc.log|file=/tmp/logs/gc.log|g' /config/jvm.options; mkdir -p /data/index")),
                common.copy(dependencies = listOf("search-config-init"), memoryMiB = 2048, entrypoint = "/bin/sh",
                    command = listOf("-ec", "mkdir -p /tmp/logs; exec /usr/share/opensearch/bin/opensearch"),
                    files = tls + RuntimeFile("opensearch.yml", "/config/opensearch.yml"),
                    readiness = listOf("/bin/sh", "-ec", """
                        set -- --silent --show-error --max-time 5 --cacert /config/ca.pem --cert /config/node.pem --key /config/node-key.pem
                        if test -f /data/.p0-security-ready; then
                          curl "${'$'}@" --fail --output /dev/null 'https://opensearch:9200/_cluster/health'
                        else
                          code=${'$'}(curl "${'$'}@" --output /tmp/bootstrap-response --write-out '%{http_code}' https://opensearch:9200/)
                          test "${'$'}code" = 503 && grep -q 'Security not initialized' /tmp/bootstrap-response
                        fi
                    """.trimIndent())),
                common.copy(id = "search-security-init", dependencies = listOf("opensearch"), oneShot = true,
                    environmentFile = "admin.env", entrypoint = "/bin/sh", memoryMiB = 512,
                    files = tls + listOf("admin.pem", "admin-key.pem").map { RuntimeFile(it, "/config/$it") } + listOf(
                        RuntimeFile("security.yml", "/config/opensearch-security/config.yml"),
                        RuntimeFile("roles.yml", "/config/opensearch-security/roles.yml"),
                        RuntimeFile("roles-mapping.yml", "/config/opensearch-security/roles_mapping.yml"),
                        RuntimeFile("internal-users.yml", "/config/opensearch-security/internal_users.yml")),
                    command = listOf("-ec", """
                        /usr/share/opensearch/plugins/opensearch-security/tools/securityadmin.sh -h opensearch -p 9200 -icl -cd /config/opensearch-security -cacert /config/ca.pem -cert /config/admin.pem -key /config/admin-key.pem
                        curl --silent --show-error --fail --max-time 30 --cacert /config/ca.pem --cert /config/node.pem --key /config/node-key.pem 'https://opensearch:9200/_cluster/health?wait_for_status=yellow&timeout=20s'
                        printf 'ready\n' > /data/.p0-security-ready
                    """.trimIndent()))
            )).also { PrivateDeployment.validate(it) }
    }
    /** Specialized native mTLS search engine, not the Huly Elasticsearch provider. */
    fun canonicalFragment(inventory: AcquiredInventory, name: String): CanonicalProviderFragment {
        val original = spec(inventory, name)
        val fragment = original.copy(store = RuntimeStore.CANONICAL_V2,
            networks = listOf("opensearch-data"), processes = original.processes.map { process ->
                process.copy(id = if (process.id == "search-config-init") "opensearch-config-init" else
                    if (process.id == "search-security-init") "opensearch-security-init" else process.id,
                    dependencies = process.dependencies.map { when (it) {
                        "search-config-init" -> "opensearch-config-init"
                        "search-security-init" -> "opensearch-security-init"
                        else -> it
                    } }, environmentFile = process.environmentFile?.let { "opensearch-$it" },
                    files = process.files.map { it.copy(file = "opensearch-${it.file}") },
                    networks = listOf("opensearch-data"))
            })
        PrivateDeployment.validate(fragment)
        return CanonicalProviderFragment("opensearch", fragment)
    }
    fun canonicalInputs(certificates: Map<String, String> = PrivateSearchPki.generate()): Map<String, String> =
        inputs(certificates).mapKeys { (key, _) -> "opensearch-$key" }

    /** r9-only browser read role: Caddy receives a distinct client certificate,
     * never the provider admin/node key. The exact generation CA signs all peers.
     * Historical r7/r8 issuance and cold receipts are not changed. */
    fun canonicalFreshInputs(): Map<String, String> {
        val generated = PrivateSearchPki.generate(freshReader = true)
        require(generated.keys == setOf("ca.pem", "node.pem", "node-key.pem", "admin.pem",
            "admin-key.pem", "reader.pem", "reader-key.pem"))
        val baseline = canonicalInputs(generated.filterKeys { it !in setOf("reader.pem", "reader-key.pem") })
        return baseline + mapOf(
            "opensearch-reader.pem" to generated.getValue("reader.pem"),
            "opensearch-reader-key.pem" to generated.getValue("reader-key.pem"),
            "opensearch-roles.yml" to (baseline.getValue("opensearch-roles.yml") +
                "caddy_reader:\n  cluster_permissions: ['cluster:monitor/main', 'cluster:monitor/health']\n" +
                "  index_permissions:\n    - index_patterns: ['*']\n      allowed_actions: ['read']\n  tenant_permissions: []\n"),
            "opensearch-roles-mapping.yml" to (baseline.getValue("opensearch-roles-mapping.yml") +
                "caddy_reader:\n  users: ['p0v3-caddy-reader']\n"))
    }
    fun coldRestoreFragment(fresh: CanonicalProviderFragment): CanonicalProviderFragment {
        require(fresh.product == "opensearch" && fresh.spec.store == RuntimeStore.CANONICAL_V2 &&
            fresh.spec.processes.map { it.id }.toSet() ==
                setOf("opensearch-config-init", "opensearch", "opensearch-security-init") &&
            fresh.spec.volumes.map { it.id }.toSet() == setOf("config", "data"))
        val original = fresh.spec.processes.single { it.id == "opensearch" }
        require(original.dependencies == listOf("opensearch-config-init") &&
            original.files.map { it.file }.toSet().containsAll(setOf("opensearch-ca.pem", "opensearch-node.pem",
                "opensearch-node-key.pem", "opensearch-opensearch.yml")))
        val cold = fresh.spec.copy(processes = listOf(original.copy(dependencies = emptyList())))
        PrivateDeployment.validate(cold)
        return fresh.copy(spec = cold)
    }
    fun inputs(certificates: Map<String, String>): Map<String, String> {
        require(certificates.keys == setOf("ca.pem", "node.pem", "node-key.pem", "admin.pem", "admin-key.pem"))
        return certificates + mapOf(
            "search.env" to "OPENSEARCH_PATH_CONF=/config\nOPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m\nDISABLE_INSTALL_DEMO_CONFIG=true\n",
            "admin.env" to "OPENSEARCH_JAVA_HOME=/usr/share/opensearch/jdk\nJAVA_OPTS=-Xms64m -Xmx256m\n",
            "opensearch.yml" to """
                cluster.name: p0v3-private-search
                node.name: opensearch
                network.host: 0.0.0.0
                discovery.type: single-node
                path.data: /data/index
                path.logs: /tmp/logs
                node.store.allow_mmap: false
                plugins.security.ssl.transport.pemcert_filepath: node.pem
                plugins.security.ssl.transport.pemkey_filepath: node-key.pem
                plugins.security.ssl.transport.pemtrustedcas_filepath: ca.pem
                plugins.security.ssl.transport.enforce_hostname_verification: true
                plugins.security.ssl.http.enabled: true
                plugins.security.ssl.http.pemcert_filepath: node.pem
                plugins.security.ssl.http.pemkey_filepath: node-key.pem
                plugins.security.ssl.http.pemtrustedcas_filepath: ca.pem
                plugins.security.ssl.http.clientauth_mode: REQUIRE
                plugins.security.authcz.admin_dn: ['CN=p0v3-admin']
                plugins.security.nodes_dn: ['CN=opensearch']
                plugins.security.allow_default_init_securityindex: false
                plugins.security.audit.type: internal_opensearch
            """.trimIndent() + "\n",
            "security.yml" to """
                _meta:
                  type: config
                  config_version: 2
                config:
                  dynamic:
                    http:
                      anonymous_auth_enabled: false
                    authc:
                      certificate_auth_domain:
                        http_enabled: true
                        transport_enabled: false
                        order: 0
                        http_authenticator:
                          type: clientcert
                          challenge: false
                          config:
                            username_attribute: cn
                        authentication_backend:
                          type: noop
            """.trimIndent() + "\n",
            "roles.yml" to "_meta:\n  type: roles\n  config_version: 2\nnode_health:\n  cluster_permissions: ['cluster:monitor/health']\n  index_permissions: []\n  tenant_permissions: []\n",
            "roles-mapping.yml" to "_meta:\n  type: rolesmapping\n  config_version: 2\nnode_health:\n  users: ['opensearch']\n",
            "internal-users.yml" to "_meta:\n  type: internalusers\n  config_version: 2\n")
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "opensearch", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs(PrivateSearchPki.generate()) }
}
