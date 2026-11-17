package net.datamancy.platform

/** Fixed dedicated-user Quadlets + systemd guard. The private sidecar is the
 * ONLY egress peer. Jobs join just the internal bridge through the audited
 * Docker API guard; runner sees only the guarded socket, not rootless Podman.
 * Unit publication and native daemon ACKs are separate one-use owner effects.
 */
internal object ForgejoCiNativeUnits {
    fun render(plan: ForgejoCiSourcePlan): Map<String, String> {
        plan.validate(plan.generation)
        val generation = plan.generation
        val name = "p0v3-ci-$generation"
        val base = "/home/webservices-lab-ci-runner/.local/share/p0v3-ci/$generation"
        val internal = "$name-internal"
        val egress = "$name-egress"
        val runner = requireNotNull(plan.runnerImage)
        val transport = requireNotNull(plan.transportImage)
        return linkedMapOf(
            "$internal.network" to """
                [Network]
                NetworkName=$internal
                Driver=bridge
                Internal=true
            """.trimIndent() + "\n",
            "$egress.network" to """
                [Network]
                NetworkName=$egress
                Driver=bridge
                Internal=false
            """.trimIndent() + "\n",
            "$name-transport.container" to """
                [Unit]
                Description=Owned private Forgejo-only CI network transport $generation
                After=$internal-network.service $egress-network.service
                Requires=$internal-network.service $egress-network.service
                [Container]
                Image=${transport.expectedImageId}
                ContainerName=$name-transport
                User=0:0
                Network=$internal.network
                Network=$egress.network
                NetworkAlias=forgejo.datamancy.net
                Volume=$base/transport-Caddyfile:/etc/caddy/Caddyfile:ro
                Volume=$base/transport-leaf.pem:/etc/ci/forgejo-leaf.pem:ro
                Volume=$base/transport-leaf-key.pem:/etc/ci/forgejo-leaf-key.pem:ro
                Volume=$base/transport-upstream-ca.pem:/etc/ci/forgejo-ca.pem:ro
                PodmanArgs=--pull=never --memory=128m --memory-swap=128m --pids-limit=64 --cap-drop=ALL --cap-add=NET_BIND_SERVICE --security-opt=no-new-privileges
                [Service]
                Restart=no
                TimeoutStartSec=180
                TimeoutStopSec=90
            """.trimIndent() + "\n",
            "$name-runner.container" to """
                [Unit]
                Description=Owned rootless Forgejo CI poller $generation
                After=$internal-network.service $name-transport.service $name-guard.service
                Requires=$internal-network.service $name-transport.service $name-guard.service
                [Container]
                Image=${runner.expectedImageId}
                ContainerName=$name-runner
                User=0:0
                Network=$internal.network
                Volume=$base/.runner:$base/.runner:ro
                Volume=$base/runner-config.yaml:$base/runner-config.yaml:ro
                Volume=$base/guard.sock:/run/p0v3-ci/guard.sock:ro
                Volume=$base/transport-ca.pem:/etc/ssl/certs/p0v3-ci-forgejo-ca.pem:ro
                Environment=DOCKER_HOST=unix:///run/p0v3-ci/guard.sock
                Environment=SSL_CERT_FILE=/etc/ssl/certs/p0v3-ci-forgejo-ca.pem
                Environment=GIT_SSL_CAINFO=/etc/ssl/certs/p0v3-ci-forgejo-ca.pem
                Environment=NODE_EXTRA_CA_CERTS=/etc/ssl/certs/p0v3-ci-forgejo-ca.pem
                Environment=CURL_CA_BUNDLE=/etc/ssl/certs/p0v3-ci-forgejo-ca.pem
                Exec=/usr/local/bin/forgejo-runner --config $base/runner-config.yaml daemon
                PodmanArgs=--pull=never --memory=256m --memory-swap=256m --pids-limit=128 --cap-drop=ALL --security-opt=no-new-privileges
                [Service]
                Restart=no
                TimeoutStartSec=180
                TimeoutStopSec=90
            """.trimIndent() + "\n",
            "$name-guard.service" to """
                [Unit]
                Description=Owned rootless Forgejo CI Docker API guard $generation
                After=$internal-network.service podman.socket
                Requires=$internal-network.service podman.socket
                [Service]
                Type=simple
                ExecStart=/usr/bin/python3 $base/guard.py $base/guard-config.json
                Environment=PYTHONDONTWRITEBYTECODE=1
                UMask=0077
                NoNewPrivileges=true
                PrivateTmp=true
                ProtectSystem=strict
                ProtectHome=read-only
                ReadWritePaths=$base
                RestrictAddressFamilies=AF_UNIX
                MemoryMax=256M
                MemorySwapMax=256M
                TasksMax=128
                KillMode=control-group
                Restart=no
                TimeoutStartSec=60
                TimeoutStopSec=60
            """.trimIndent() + "\n"
        )
    }
}
