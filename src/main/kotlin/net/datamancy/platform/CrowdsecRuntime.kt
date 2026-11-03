package net.datamancy.platform

import java.nio.file.Path

/** Isolated native detection fixture. No host logs, CAPI sharing, firewall or public-route enforcement. */
internal object CrowdsecRuntime {
    fun spec(inventory: AcquiredInventory, name: String = "crowdsec"): PrivateDeploymentSpec {
        val image = inventory.images.single { it.product == "crowdsec" }
        require(image.os == "linux" && image.architecture == "amd64")
        val shared = listOf("crowdsec.yaml", "profiles.yaml", "acquis.yaml", "ca.pem", "web.pem", "web-key.pem").map { RuntimeFile(it, "/run/secrets/$it") }
        val volumes = listOf(RuntimeMount("data", "/data"), RuntimeMount("config", "/configuration"), RuntimeMount("logs", "/synthetic-logs"))
        val daemon = RuntimeProcess("guard", image.pinnedImage, image.imageId, 1000,
            environmentFile = "crowdsec.env", volumes = volumes, files = shared, apparmorProfile = "p0v3-private-v1", memoryMiB = 512)
        return PrivateDeploymentSpec(name = name, volumes = listOf("data", "config", "logs", "bootstrap").map { RuntimeVolume(it, 1000) }, processes = listOf(
            daemon.copy(id = "guard-init", entrypoint = "/bin/sh", oneShot = true,
                volumes = volumes + RuntimeMount("bootstrap", "/bootstrap"),
                files = shared + listOf("parser.yaml", "scenario.yaml").map { RuntimeFile(it, "/run/secrets/$it") },
                command = listOf("-ec", """
                    umask 077
                    test -z "${'$'}(ls -A /data)"
                    test -z "${'$'}(ls -A /configuration)"
                    test -z "${'$'}(ls -A /bootstrap)"
                    mkdir -p /configuration/parsers/s01-parse /configuration/scenarios /configuration/postoverflows /configuration/hub /configuration/collections
                    cp -R /staging/etc/crowdsec/patterns /configuration/patterns
                    cp /run/secrets/parser.yaml /configuration/parsers/s01-parse/private-http.yaml
                    cp /run/secrets/scenario.yaml /configuration/scenarios/private-http.yaml
                    printf '{}\n' > /configuration/hub/.index.json
                    printf 'simulation: false\n' > /configuration/simulation.yaml
                    touch /synthetic-logs/http.log
                    cscli -c /run/secrets/crowdsec.yaml machines add private-fixture --auto --url https://guard:8443/ --file /data/local-api.yaml > /bootstrap/enrollment.log
                    printf 'ca_cert_path: /run/secrets/ca.pem\n' >> /data/local-api.yaml
                    cscli -c /run/secrets/crowdsec.yaml bouncers add private-probe -o raw > /bootstrap/bouncer-key
                    test -s /bootstrap/bouncer-key
                    chmod 600 /data/local-api.yaml /bootstrap/bouncer-key
                    sync
                """.trimIndent())),
            daemon.copy(dependencies = listOf("guard-init"), entrypoint = "/usr/local/bin/crowdsec", command = listOf("-c", "/run/secrets/crowdsec.yaml"),
                readiness = listOf("/usr/local/bin/cscli", "-c", "/run/secrets/crowdsec.yaml", "lapi", "status"))
        )).also { PrivateDeployment.validate(it) }
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "crowdsec", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }
    fun inputs(pki: () -> Map<String, String> = { PrivateWebPki.generate("guard") }): Map<String, String> = pki() + mapOf(
        "crowdsec.env" to "SSL_CERT_FILE=/run/secrets/ca.pem\n",
        "crowdsec.yaml" to """
            common:
              daemonize: false
              log_media: stdout
              log_level: warning
              log_dir: /tmp
            config_paths:
              config_dir: /configuration
              data_dir: /data
              simulation_path: /configuration/simulation.yaml
              hub_dir: /configuration/hub
              index_path: /configuration/hub/.index.json
              notification_dir: /configuration/notifications
              plugin_dir: /usr/local/lib/crowdsec/plugins
            crowdsec_service:
              acquisition_path: /run/secrets/acquis.yaml
              parser_routines: 1
            cscli:
              output: human
              color: 'no'
            db_config:
              log_level: warning
              type: sqlite
              db_path: /data/crowdsec.db
              flush:
                max_items: 5000
                max_age: 7d
            api:
              client:
                insecure_skip_verify: false
                credentials_path: /data/local-api.yaml
              server:
                enable: true
                log_level: warning
                listen_uri: '0.0.0.0:8443'
                profiles_path: /run/secrets/profiles.yaml
                trusted_ips: [127.0.0.1, '::1']
                tls:
                  cert_file: /run/secrets/web.pem
                  key_file: /run/secrets/web-key.pem
            prometheus:
              enabled: true
              level: full
              listen_addr: 0.0.0.0
              listen_port: 6060
        """.trimIndent() + "\n",
        "profiles.yaml" to """
            name: private-fixture
            filters:
              - Alert.Remediation == true && Alert.GetScope() == 'Ip'
            decisions:
              - type: ban
                duration: 30m
            on_success: break
        """.trimIndent() + "\n",
        "acquis.yaml" to """
            source: file
            filenames: [/synthetic-logs/http.log]
            labels:
              type: p0v3-http
        """.trimIndent() + "\n",
        "parser.yaml" to """
            name: p0v3/private-http
            description: Synthetic private fixture access logs only
            filter: "evt.Line.Labels.type == 'p0v3-http'"
            onsuccess: next_stage
            nodes:
              - grok:
                  pattern: '%{TIMESTAMP_ISO8601:timestamp} %{IP:source_ip} %{INT:status} %{WORD:method} %{NOTSPACE:path}'
                  apply_on: Line.Raw
            statics:
              - target: evt.StrTime
                expression: evt.Parsed.timestamp
              - meta: source_ip
                expression: evt.Parsed.source_ip
              - meta: log_type
                value: p0v3_http
              - meta: http_status
                expression: evt.Parsed.status
              - meta: service
                value: private-http
        """.trimIndent() + "\n",
        "scenario.yaml" to """
            type: leaky
            name: p0v3/private-http-abuse
            description: Repeated unauthorized synthetic requests
            filter: "evt.Meta.log_type == 'p0v3_http' && evt.Meta.http_status == '401'"
            leakspeed: 1m
            capacity: 2
            groupby: evt.Meta.source_ip
            blackhole: 5m
            labels:
              service: private-http
              type: bruteforce
              remediation: true
        """.trimIndent() + "\n"
    )
}
