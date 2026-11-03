package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.Serializable

/** Closed store identities, never caller-supplied paths or a default-store fallback. */
@Serializable enum class RuntimeStore {
    LEGACY, CANONICAL_V2;
    val graph: String get() = if (this == LEGACY) PrivateRootfulCommands.ROOT else "/mnt/media/p0-v3/runtime-stores/canonical-v2/graph"
    val run: String get() = if (this == LEGACY) PrivateRootfulCommands.RUN else "/run/p0-v3-canonical-v2/store"
    val network: String get() = if (this == LEGACY) PrivateRootfulCommands.NETWORK else "/mnt/media/p0-v3/runtime-stores/canonical-v2/networks"
    val module: Path get() = Path.of("/mnt/media/p0-v3/runtime-stores/canonical-v2/containers.conf")
    val configuration: String get() = """[engine]
lock_type = "file"
tmp_dir = "/run/p0-v3-canonical-v2/libpod"
static_dir = "/mnt/media/p0-v3/runtime-stores/canonical-v2/graph/libpod"
volume_path = "/mnt/media/p0-v3/runtime-stores/canonical-v2/graph/volumes"
[network]
default_subnet = "10.204.0.0/24"
default_subnet_pools = [{base = "10.203.0.0/16", size = 24}]
"""
    internal fun verifyConfiguration() {
        if (this == LEGACY) return
        require(module.toRealPath() == module && Files.isRegularFile(module, NOFOLLOW_LINKS) &&
            Files.getAttribute(module, "unix:uid", NOFOLLOW_LINKS) == 0 &&
            Files.getAttribute(module, "unix:nlink", NOFOLLOW_LINKS) == 1 &&
            (Files.getAttribute(module, "unix:mode", NOFOLLOW_LINKS) as Int) and 511 == 420 &&
            Files.size(module) == configuration.toByteArray().size.toLong() && Files.readString(module) == configuration) {
            "Pinned isolated runtime-store configuration required"
        }
        val ready = module.resolveSibling("ready")
        require(ready.toRealPath() == ready && Files.isRegularFile(ready, NOFOLLOW_LINKS) &&
            Files.getAttribute(ready, "unix:uid", NOFOLLOW_LINKS) == 0 &&
            Files.getAttribute(ready, "unix:nlink", NOFOLLOW_LINKS) == 1 &&
            (Files.getAttribute(ready, "unix:mode", NOFOLLOW_LINKS) as Int) and 511 == 420 &&
            Files.size(ready) == 65L && Files.readString(ready) == ReleaseLocks.sha256(configuration.toByteArray()) + "\n") {
            "Incomplete isolated runtime-store initialization"
        }
        for (path in listOf(module.parent, module.parent.parent)) require(path.toRealPath() == path &&
            Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) == 0 &&
            (Files.getAttribute(path, "unix:mode", NOFOLLOW_LINKS) as Int) and 511 == 493) { "Root-owned store boundary required" }
    }
    internal fun prefix(): List<String> = listOf("sudo", "-n", "podman", "--remote=false") +
        (if (this == LEGACY) emptyList() else listOf("--module=$module")) +
        listOf("--root=$graph", "--runroot=$run", "--network-config-dir=$network")
}
