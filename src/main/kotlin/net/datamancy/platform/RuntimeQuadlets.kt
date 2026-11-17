package net.datamancy.platform

import kotlinx.serialization.Serializable

@Serializable internal data class RuntimeQuadletBundle(val schemaVersion: Int = 1,
    val member: String, val specSha256: String, val files: Map<String, String>,
    val controllerEnforced: Set<String>, val runtimeAdmitted: Boolean = false)

/** Deterministic source units plus mandatory lifecycle drop-ins, never an independent launcher.
 * Prepared input fingerprints live in a controller-owned environment file; they are not known to
 * offline export. The installer/admission helper must verify that file against original input hashes.
 */
internal object RuntimeQuadlets {
    fun unit(spec: PrivateDeploymentSpec, process: RuntimeProcess) = "p0v3-${spec.name}-${process.id}"
    private fun name(spec: PrivateDeploymentSpec, id: String) = "p0v3-live-${spec.name}-$id"

    /** Quadlet -> generated systemd ExecStart: retain literal application dollars/specifiers. */
    private fun word(value: String): String {
        require('\u0000' !in value && '\r' !in value)
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"")
            .replace("\n", "\\n").replace("\t", "\\t").replace("$", "$$").replace("%", "%%") + "\""
    }

    fun render(spec: PrivateDeploymentSpec): RuntimeQuadletBundle {
        PrivateDeployment.validate(spec)
        require(spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2 && spec.store == RuntimeStore.CANONICAL_V2)
        require(spec.ingress == null && spec.nativeIngress == null) { "Quadlet publication mapping is not admitted yet" }
        require(spec.volumes.all { it.mappedOwners.isEmpty() }) { "Quadlet mixed-owner volume mapping is not admitted yet" }
        val binding = requireNotNull(spec.fragmentBinding)
        val controller = requireNotNull(binding.controllerSha256)
        val uid = requireNotNull(binding.controllerUid); val gid = requireNotNull(binding.controllerGid)
        val executable = "/mnt/media/p0-v3/runtime-supervision/releases/$controller/bin/p0-v3-platform"
        val helper = "/usr/bin/setpriv --reuid=$uid --regid=$gid --init-groups $executable runtime"
        val root = PrivateDeployment.BASE.resolve(spec.name)
        val files = sortedMapOf<String, String>()
        for (p in spec.processes) {
            val unit = unit(spec, p)
            val globals = listOf("--remote=false", "--module=${spec.store.module}", "--root=${spec.store.graph}",
                "--runroot=${spec.store.run}", "--network-config-dir=${spec.store.network}")
            val extra = mutableListOf("--replace=false", "--rm=false", "--memory=${p.memoryMiB}m",
                "--pids-limit=512", "--stop-timeout=30", "--image-volume=ignore")
            p.apparmorProfile?.let { extra += "--security-opt=apparmor=$it" }
            files["$unit.container"] = buildString {
                append("[Unit]\nDescription=Platform Zero owned process ${spec.name}/${p.id}\n")
                // Always false: copying a standalone .container must not bypass the mandatory
                // lifecycle drop-in. Only the complete installed bundle clears this condition.
                append("ConditionPathExists=!/\n")
                // No Requires=/After= application edges: the controller waits for actual readiness.
                append("[Container]\nImage=${p.image}\nContainerName=${name(spec, p.id)}\n")
                append("GlobalArgs=${globals.joinToString(" ")}\n")
                for (network in p.networks) {
                    val aliases = p.networkAliases.filter { it.network == network }.map { "alias=${it.host}" }
                    append("Network=${name(spec, network)}${if (aliases.isEmpty()) "" else ":" + aliases.joinToString(",")}\n")
                }
                append("NetworkAlias=${p.id}\nPull=never\nReadOnly=true\nNoNewPrivileges=true\nDropCapability=all\n")
                append("User=${p.userId}:${p.groupId}\n")
                p.capabilities.forEach { append("AddCapability=$it\n") }
                append("Label=io.p0v3.private-deployment=${spec.name}\n")
                append("Label=io.p0v3.runtime-fingerprint=${'$'}{P0_RUNTIME_FINGERPRINT}\n")
                if (p.oneShot) append("Label=io.p0v3.initializer-intent=${'$'}{P0_INITIALIZER_INTENT}\n")
                p.environmentFile?.let { append("EnvironmentFile=${root.resolve(it)}\n") }
                p.lateEnvironmentFile?.let { append("EnvironmentFile=${root.resolve(it)}\n") }
                p.files.forEach { append("Secret=${name(spec, "file-${it.file}")},type=mount,target=${it.target},uid=${p.userId},gid=${p.groupId},mode=0400\n") }
                p.volumes.forEach { append("Volume=${name(spec, "volume-${it.volume}")}:${it.target}:U\n") }
                p.controlSocketMount?.let { append("Volume=${it.source}:${it.target}:ro\n") }
                p.tmpfs.forEach { append("Tmpfs=$it:rw,nosuid,nodev,mode=1777,size=128m\n") }
                p.entrypoint?.let { append("Entrypoint=${word(it)}\n") }
                if (p.command.isNotEmpty()) append("Exec=${p.command.joinToString(" ", transform = ::word)}\n")
                append("PodmanArgs=${extra.joinToString(" ")}\n")
                append("[Service]\nRestart=no\nTimeoutStartSec=720\nTimeoutStopSec=120\nUMask=0077\n")
                append("Environment=JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64\n")
                append("EnvironmentFile=${root.resolve(if (p.oneShot) "runtime.quadlet-${p.id}.env" else "runtime.quadlet.env")}\n")
                append("UnsetEnvironment=CONTAINER_HOST CONTAINER_CONNECTION DOCKER_HOST PODMAN_HOST CONTAINERS_CONF CONTAINERS_CONF_OVERRIDE CONTAINERS_STORAGE_CONF\n")
                if (p.oneShot) append("Type=oneshot\nRemainAfterExit=yes\n")
            }
            // The generated default Stop/Post remove containers. Installation without these exact
            // drop-ins is forbidden; they must also be audited in effective systemd configuration.
            files["$unit.service.d/50-p0-lifecycle.conf"] = "[Unit]\nConditionPathExists=\n[Service]\n" +
                "ExecStartPre=\nExecStartPre=$helper unit-admit ${spec.name} ${p.id}\n" +
                // The direct generated Podman ExecStart has a post-admission owner-death
                // gap. Keep the systemd unit as sole supervisor, but run its exact pinned
                // generator argv through an owner-checked unit-run helper at execution time.
                // Keep the supervising JVM out of the delegated parent cgroup before
                // Podman enables memory/pids for its child. Without this, enabling
                // domain controllers requires moving a live supervisor mid-launch.
                "Delegate=yes\nDelegateSubgroup=p0v3-supervisor\n" +
                "ExecStart=\nExecStart=$helper unit-run ${spec.name} ${p.id}\n" +
                "ExecStop=\nExecStop=$helper unit-stop ${spec.name} ${p.id}\n" +
                // Post-stop runs even after a lost native stop ACK. The first helper
                // reconciles an original stop; the second fences and contains an
                // owner-dead foreground launch if the JVM was killed by systemd.
                "ExecStopPost=\nExecStopPost=-$helper unit-stop ${spec.name} ${p.id}\n" +
                "ExecStopPost=$helper unit-guard ${spec.name} ${p.id}\n"
        }
        return RuntimeQuadletBundle(member = spec.name, specSha256 = ReleaseLocks.sha256(
            kotlinx.serialization.json.Json.encodeToString(PrivateDeploymentSpec.serializer(), spec).toByteArray()),
            files = files, controllerEnforced = setOf("dependencyReadiness", "readiness", "imageId",
                "initializationHistory", "databaseAccess", "inputOwnership", "volumeOwnership",
                "unmountedRecoveryVolumes", "resourceProvisioning", "capacity", "locksAndFences", "unitAdmission"))
    }
}
