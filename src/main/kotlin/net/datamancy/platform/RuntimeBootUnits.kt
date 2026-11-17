package net.datamancy.platform

import java.nio.file.Path
import java.security.MessageDigest
import kotlinx.serialization.json.Json

/** Boot/shutdown supervision only: never a timer, updater, restore runner or acceptance gate. */
internal object RuntimeBootUnits {
    private val slug = Regex("[a-z][a-z0-9-]{0,39}")
    private val digest = Regex("[a-f0-9]{64}")
    fun hash(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    fun manifest(name: String, base: Path = PrivateDeployment.BASE): Path {
        require(slug.matches(name)) { "Invalid supervised deployment" }
        return base.resolve("$name.json")
    }
    fun boundSpec(name: String, expectedHash: String, base: Path = PrivateDeployment.BASE): PrivateDeploymentSpec {
        require(digest.matches(expectedHash)) { "Invalid pinned manifest hash" }
        val bytes = ReleaseLocks.privateBytes(manifest(name, base))
        require(hash(bytes) == expectedHash) { "Supervised manifest changed; explicit review required" }
        return Json.decodeFromString<PrivateDeploymentSpec>(bytes.decodeToString()).also {
            require(it.name == name) { "Supervised deployment identity mismatch" }
            PrivateDeployment.validate(it)
        }
    }
    fun render(spec: PrivateDeploymentSpec, manifestHash: String, controllerHash: String, userId: Int): String {
        PrivateDeployment.validate(spec)
        require(spec.executionBackend == RuntimeExecutionBackend.DIRECT_PODMAN_V1) {
            "Quadlet generations require their own controller-owned boot installer; direct-Podman fallback refused"
        }
        require(digest.matches(manifestHash) && digest.matches(controllerHash) && userId in 1..65534)
        val controller = "/mnt/media/p0-v3/runtime-supervision/releases/$controllerHash/bin/p0-v3-platform"
        // ExecStop must have enough time for each daemon's audited graceful shutdown.
        val stopSeconds = 120 + spec.processes.count { !it.oneShot } * 60
        return """
            # Managed by p0v3-private-boot-v1; changes require explicit replacement review.
            [Unit]
            Description=Platform Zero private deployment ${spec.name} (not a public release)
            RequiresMountsFor=/mnt/media/p0-v3 /run/p0-v3-release-runtime
            Wants=network-online.target
            After=network-online.target apparmor.service
            [Service]
            Type=oneshot
            RemainAfterExit=yes
            User=$userId
            UMask=0077
            Environment=JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
            ExecStart=$controller runtime boot-apply ${spec.name} $manifestHash
            ExecStop=$controller runtime boot-stop ${spec.name} $manifestHash
            TimeoutStartSec=${120 + spec.processes.size * 720}
            TimeoutStopSec=$stopSeconds
            KillMode=process
            Restart=no
            StandardOutput=journal
            StandardError=journal
            [Install]
            WantedBy=multi-user.target
        """.trimIndent() + "\n"
    }
}
