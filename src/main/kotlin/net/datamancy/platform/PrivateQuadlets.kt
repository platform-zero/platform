package net.datamancy.platform

import java.nio.file.Path

/** Files only. No generator invocation, image pull, unit install, Podman command or live-host write. */
data class QuadletBundle(val files: Map<String, String>, val graphRoot: String, val runRoot: String)

object PrivateQuadlets {
    private val safePath = Regex("/(?:[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+")
    private val unitName = Regex("p0v3-[a-z0-9-]+\\.(container|network|volume|timer)")

    fun render(lock: ReleaseLock, approvedHosts: Set<String>, ownedRoot: Path): QuadletBundle {
        ReleaseLocks.check(lock, approvedHosts)
        require(ownedRoot.isAbsolute && ownedRoot == ownedRoot.normalize() &&
            safePath.matches(ownedRoot.toString()) && ownedRoot.nameCount >= 3 &&
            !ownedRoot.startsWith(Path.of("/var/lib/containers")) &&
            !ownedRoot.startsWith(Path.of("/run/containers"))) { "Explicit v3-owned absolute store root required" }
        val graph = ownedRoot.resolve("store/graph").toString()
        val run = ownedRoot.resolve("store/run").toString()
        val globalArgs = "GlobalArgs=--root=$graph --runroot=$run\n"
        val files = sortedMapOf<String, String>()
        for (role in NetworkRole.entries) {
            val networkName = "p0v3-${role.name.lowercase()}"
            files["$networkName.network"] = "[Network]\nNetworkName=$networkName\nInternal=${role != NetworkRole.INGRESS}\n$globalArgs"
        }
        for (product in lock.products.sortedBy { it.id }) {
            for (state in product.state.sortedBy { it.id }) {
                val volumeName = "p0v3-${product.id}-${state.id}"
                require(volumeName.length < 240 && files.put("$volumeName.volume",
                    "[Volume]\nVolumeName=$volumeName\n$globalArgs") == null) { "Duplicate or long volume name" }
            }
            for (process in product.processes.sortedBy { it.id }) {
                val unit = "p0v3-${process.id}"
                val text = buildString {
                    append("[Unit]\nDescription=Platform Zero v3 ${process.id}\n")
                    process.dependencies.sorted().forEach {
                        append("Requires=p0v3-$it.service\nAfter=p0v3-$it.service\n")
                    }
                    append("[Container]\nImage=${process.image}\n")
                    process.networks.sortedBy { it.name }.forEach { append("Network=p0v3-${it.name.lowercase()}.network\n") }
                    append("NetworkAlias=p0v3-${process.id}\n")
                    process.stateIds.sorted().forEach { id ->
                        val state = product.state.single { it.id == id }
                        append("Volume=p0v3-${product.id}-${state.id}.volume:${state.containerPath}\n")
                    }
                    process.secretKeys.sorted().forEach { key ->
                        append("Secret=p0v3-${process.id}-${key.lowercase()},type=mount\n")
                    }
                    append("Pull=never\nReadOnly=true\nNoNewPrivileges=true\nDropCapability=all\n")
                    process.capabilities.sorted().forEach { append("AddCapability=$it\n") }
                    append("User=${process.userId}\n$globalArgs")
                    if (process.role != ProcessRole.DAEMON) append("[Service]\nType=oneshot\n")
                }
                require(unit.length < 240 && files.put("$unit.container", text) == null) { "Duplicate or long process unit" }
                if (process.role == ProcessRole.TIMER) {
                    files["$unit.timer"] = "[Unit]\nDescription=Platform Zero v3 scheduled ${process.id}\n" +
                        "[Timer]\nUnit=$unit.service\nOnCalendar=${process.schedule}\nPersistent=false\n"
                }
            }
        }
        require(files.keys.all(unitName::matches) && files.values.none { it.contains("AutoUpdate=registry") }) {
            "Unsafe generated Quadlet"
        }
        return QuadletBundle(files, graph, run)
    }

    /** Audit the actual Podman 5.4.2 generator dry-run output for EVERY generated Podman Exec*. */
    fun verifyGeneratorOutput(bundle: QuadletBundle, output: String) {
        require(!output.contains("error", ignoreCase = true) && !output.contains("warning", ignoreCase = true)) {
            "Quadlet generator rejected input"
        }
        val starts = output.lines().filter { it.startsWith("ExecStart=/usr/bin/podman ") }
        val expected = bundle.files.keys.count { it.endsWith(".container") || it.endsWith(".network") || it.endsWith(".volume") }
        require(starts.size == expected && expected > 0) { "Generator omitted a unit" }
        val podmanLines = output.lines().filter { it.matches(Regex("Exec(Start|Stop|StopPost|Reload)=.*?/podman .*")) }
        require(podmanLines.size >= expected && podmanLines.all {
            it.contains(" --root=${bundle.graphRoot} ") && it.contains(" --runroot=${bundle.runRoot} ")
        }) { "Quadlet uses a shared rootful store" }
        require(output.lines().filter { it.startsWith("ExecStart=/usr/bin/podman ") }
            .none { it.contains(" --pull always ") || it.contains(" --pull newer ") }) { "Mutable image update" }
    }
}
