package net.datamancy.platform

import java.io.ByteArrayInputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions
import java.security.cert.CertificateFactory
import java.time.Instant
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import kotlinx.serialization.Serializable
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

@Serializable data class RuntimeVolumeOwner(val userId: Int, val groupId: Int)
@Serializable data class RuntimeVolume(val id: String, val userId: Int,
    @OptIn(ExperimentalSerializationApi::class)
    @EncodeDefault(EncodeDefault.Mode.NEVER)
    val mappedOwners: List<RuntimeVolumeOwner> = emptyList())
@Serializable data class RuntimeMount(val volume: String, val target: String)
/** Only fixed, generation-bound control endpoints may be mounted; Caddy mounts the
 * private directory before the broker creates its socket, never an engine socket. */
@Serializable data class RuntimeControlSocketMount(val source: String, val target: String)
@Serializable data class RuntimeFile(val file: String, val target: String)
@Serializable data class RuntimeNetworkAlias(val network: String, val host: String)
@OptIn(ExperimentalSerializationApi::class)
@Serializable data class RuntimeProcess(val id: String, val image: String, val imageId: String,
    val userId: Int, val groupId: Int = userId, val dependencies: List<String> = emptyList(),
    val entrypoint: String? = null, val command: List<String> = emptyList(), val environmentFile: String? = null,
    val volumes: List<RuntimeMount> = emptyList(), val files: List<RuntimeFile> = emptyList(),
    val tmpfs: List<String> = listOf("/tmp"), val readiness: List<String> = emptyList(), val oneShot: Boolean = false,
    val memoryMiB: Int = 512, val capabilities: List<String> = emptyList(), val apparmorProfile: String? = null,
    val readinessHttpPort: Int? = null, val readinessHttpPath: String = "/",
    @EncodeDefault(EncodeDefault.Mode.NEVER) val networks: List<String> = listOf("net"),
    @EncodeDefault(EncodeDefault.Mode.NEVER) val networkAliases: List<RuntimeNetworkAlias> = emptyList(),
    @EncodeDefault(EncodeDefault.Mode.NEVER) val controlSocketMount: RuntimeControlSocketMount? = null,
    /** Result-bound per-process host env created after a declared native issuer, never
     * included in sealed preparation hashes. Unit admission rechecks its result. */
    @EncodeDefault(EncodeDefault.Mode.NEVER) val lateEnvironmentFile: String? = null)
/** Logical network writer; provider storage ownership is not application schema ownership. */
@Serializable data class RuntimeDatabaseAccess(val consumer: String, val provider: String, val volume: String,
    val database: String, val principal: String, val credentialFile: String, val network: String)
/** Explicit owned public ingress, never generic arbitrary host-port publication. */
@Serializable data class RuntimeIngressPublication(val site: String, val approvedHosts: Set<String>, val listenAddress: String)
@Serializable enum class RuntimeExecutionBackend { DIRECT_PODMAN_V1, QUADLET_V2 }
@Serializable data class RuntimeFragmentBinding(val recipe: String, val phase: String, val resources: Map<String, String>,
    val controllerSha256: String? = null, val controllerUid: Int? = null, val controllerGid: Int? = null)
@OptIn(ExperimentalSerializationApi::class)
@Serializable data class PrivateDeploymentSpec(val schemaVersion: Int = 1, val name: String,
    val volumes: List<RuntimeVolume>, val processes: List<RuntimeProcess>,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val networks: List<String> = listOf("net"),
    @EncodeDefault(EncodeDefault.Mode.NEVER) val databaseAccess: List<RuntimeDatabaseAccess> = emptyList(),
    @EncodeDefault(EncodeDefault.Mode.NEVER) val store: RuntimeStore = RuntimeStore.LEGACY,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val ingress: RuntimeIngressPublication? = null,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val nativeIngress: RuntimeNativeIngressPublication? = null,
    /** Cold V2 custody only: retain original initializer state without mounting it into any daemon. */
    @EncodeDefault(EncodeDefault.Mode.NEVER) val unmountedRecoveryVolumes: Set<String> = emptySet(),
    @EncodeDefault(EncodeDefault.Mode.NEVER) val executionBackend: RuntimeExecutionBackend = RuntimeExecutionBackend.DIRECT_PODMAN_V1,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val fragmentBinding: RuntimeFragmentBinding? = null)
@Serializable data class RuntimeStatus(val id: String, val state: String, val exitCode: Int?)
@Serializable internal data class RuntimeAudit(val name: String, val fingerprint: String,
    val existingResources: Int, val maintenanceId: String?, val statuses: List<RuntimeStatus>)
@Serializable internal data class FrozenRuntimeObservation(val name: String, val fingerprint: String,
    val fenceId: String, val jobsSha256: String, val completedInitializers: Set<String>, val statuses: List<RuntimeStatus>)
@Serializable internal data class RuntimeJobs(val fingerprint: String, val started: Set<String> = emptySet(),
    val completed: Set<String> = emptySet(), val checksum: String = "")

/** Persistent runtime. Host ports are denied except explicit canonical owned Caddy 80/443 publication.
 * No arbitrary host mounts, volume deletion or automatic image changes. Restores remain unpublished. */
internal class PrivateDeployment(private val base: Path, private val commands: RuntimeCommands,
    private val httpReady: (String, Int, String) -> Boolean = ::probeHttp,
    private val boundFingerprints: Map<String, String> = emptyMap(),
    private val backupAccess: RuntimeBackupAccess? = null,
    private val runtimeStore: RuntimeStore = RuntimeStore.LEGACY,
    private val ingressPortOwner: (Int) -> PortOwner = ::hostIngressPortOwner,
    private val pause: () -> Unit = { Thread.sleep(500) }) {
    companion object {
        val BASE: Path = Path.of("/mnt/media/p0-v3/runtime-deployments")
        private val json = Json { ignoreUnknownKeys = false }
        private val slug = Regex("[a-z][a-z0-9-]{0,39}")
        private val fileName = Regex("[a-z][a-z0-9.-]{0,79}")
        private val absolute = Regex("/(?:[a-zA-Z0-9_-]+(?:\\.[a-zA-Z0-9_-]+)*/)*[a-zA-Z0-9_.-]+")
        private const val OWNER = "io.p0v3.private-deployment"
        private const val HASH = "io.p0v3.runtime-fingerprint"
        private data class NativeLockIdentity(val inode: Long, val device: Long)
        private val orderedNativeLocks = ThreadLocal.withInitial { mutableMapOf<Path, NativeLockIdentity>() }
        private fun boundedNativeLock(channel: FileChannel, mustBeBound: Boolean): java.nio.channels.FileLock {
            if (!mustBeBound && RecoveryDeadline.remainingSecondsIfBound() == null) return channel.lock()
            var acquired: java.nio.channels.FileLock? = null
            while (acquired == null) {
                val left = RecoveryDeadline.remainingMillis()
                if (Thread.currentThread().isInterrupted) throw InterruptedException("Native runtime lock interrupted")
                acquired = try { channel.tryLock() }
                    catch (_: java.nio.channels.OverlappingFileLockException) { null }
                if (acquired == null) Thread.sleep(minOf(100L, left))
            }
            return requireNotNull(acquired)
        }
        private fun lockIdentity(path: Path): NativeLockIdentity {
            require(path.isAbsolute && path.normalize() == path && path.toRealPath() == path &&
                Files.isRegularFile(path, NOFOLLOW_LINKS) &&
                Files.getPosixFilePermissions(path) == PosixFilePermissions.fromString("rw-------") &&
                (Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() ==
                    com.sun.security.auth.module.UnixSystem().uid &&
                (Files.getAttribute(path, "unix:nlink", NOFOLLOW_LINKS) as Number).toLong() == 1L) {
                "Runtime member lock must be owned, regular and single-link"
            }
            return NativeLockIdentity((Files.getAttribute(path, "unix:ino", NOFOLLOW_LINKS) as Number).toLong(),
                (Files.getAttribute(path, "unix:dev", NOFOLLOW_LINKS) as Number).toLong())
        }
        /** Parent namespace gate precedes root creation as well as native member locking.
         * Without it a preparation can see an absent root, generate secrets, and populate
         * the lock-only directory after no-target source resume. Gate files are permanent. */
        private fun <T> withNamespaceGates(members: List<String>, runtimeRoot: Path,
            mustBeBound: Boolean, action: () -> T): T {
            fun acquire(index: Int): T {
                if (index == members.size) return action()
                val gate = runtimeRoot.resolve(".namespace-${members[index]}.lock")
                val initial = if (Files.exists(gate, NOFOLLOW_LINKS)) lockIdentity(gate) else null
                return JvmNativeLockGate.with(gate, JvmNativeLockGate.boundedAdmissionMillis(mustBeBound)) {
                    FileChannel.open(gate, setOf(CREATE, WRITE, NOFOLLOW_LINKS),
                        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))).use { channel ->
                        val opened = lockIdentity(gate)
                        require(initial == null || opened == initial) { "Native namespace gate changed during open" }
                        boundedNativeLock(channel, mustBeBound = mustBeBound).use {
                            require(lockIdentity(gate) == opened) { "Native namespace gate replaced while acquiring" }
                            val result = acquire(index + 1)
                            require(lockIdentity(gate) == opened) { "Native namespace gate replaced while held" }
                            result
                        }
                    }
                }
            }
            return acquire(0)
        }
        private fun <T> withMemberLock(name: String, runtimeRoot: Path,
            mustBeBound: Boolean, action: () -> T): T {
            val root = runtimeRoot.resolve(name)
            if (!Files.exists(root, NOFOLLOW_LINKS)) {
                Files.createDirectory(root, PosixFilePermissions.asFileAttribute(
                    PosixFilePermissions.fromString("rwx------")))
                FileChannel.open(runtimeRoot, READ).use { it.force(true) }
            }
            ReleasePrivateFiles.directory(root)
            val lock = root.resolve("runtime.lock")
            val initial = if (Files.exists(lock, NOFOLLOW_LINKS)) lockIdentity(lock) else null
            return JvmNativeLockGate.with(lock, JvmNativeLockGate.boundedAdmissionMillis(mustBeBound)) {
                FileChannel.open(lock, setOf(CREATE, WRITE, NOFOLLOW_LINKS),
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))).use { channel ->
                    val opened = lockIdentity(lock)
                    require(initial == null || opened == initial) { "Runtime member lock changed during open" }
                    boundedNativeLock(channel, mustBeBound = mustBeBound).use {
                        require(lockIdentity(lock) == opened) { "Runtime member lock replaced while acquiring" }
                        val held = orderedNativeLocks.get()
                        require(held.putIfAbsent(lock, opened) == null)
                        try { action() }
                        finally {
                            val unchanged = runCatching { lockIdentity(lock) == opened }.getOrDefault(false)
                            held.remove(lock)
                            if (held.isEmpty()) orderedNativeLocks.remove()
                            require(unchanged) { "Runtime member lock replaced while held; retain native isolation" }
                        }
                    }
                }
            }
        }
        /** Preparation holds the SAME namespace gate and member runtime.lock as a no-target
         * census from before its first absent-root test through input and manifest fsync. */
        fun <T> withPreparationNamespace(name: String, runtimeRoot: Path, action: (Boolean) -> T): T {
            require(slug.matches(name) && orderedNativeLocks.get().isEmpty())
            ReleasePrivateFiles.directory(runtimeRoot)
            return withNamespaceGates(listOf(name), runtimeRoot, mustBeBound = false) {
                val fresh = !Files.exists(runtimeRoot.resolve(name), NOFOLLOW_LINKS)
                withMemberLock(name, runtimeRoot, mustBeBound = false) { action(fresh) }
            }
        }
        /** Acquire source AND target namespace gates first, then all identical native member
         * runtime.lock files in global name order. Existing operations reenter held locks. */
        fun <T> withOrderedNativeLocks(members: Collection<String>, runtimeRoot: Path = BASE,
            action: () -> T): T {
            require(members.isNotEmpty() && members.size == members.toSet().size &&
                members.all { it.matches(Regex("q-[a-f0-9]{12}-[a-z][a-z0-9-]{0,39}")) })
            ReleasePrivateFiles.directory(runtimeRoot)
            val held = orderedNativeLocks.get()
            if (held.isNotEmpty()) {
                // Only a strict subset of the SAME already-held native member paths may
                // reenter; never acquire a later namespace gate/member out of order.
                require(members.all { member ->
                    val path = runtimeRoot.resolve(member).resolve("runtime.lock")
                    held[path] != null && lockIdentity(path) == held[path]
                }) { "Nested native cohort cannot extend ordered isolation locks" }
                return action()
            }
            val sorted = members.sorted()
            return withNamespaceGates(sorted, runtimeRoot, mustBeBound = true) {
                fun acquire(index: Int): T = if (index == sorted.size) action()
                    else withMemberLock(sorted[index], runtimeRoot, mustBeBound = true) { acquire(index + 1) }
                acquire(0)
            }
        }
        private val healthClient = java.net.http.HttpClient.newBuilder().version(java.net.http.HttpClient.Version.HTTP_1_1)
            .connectTimeout(java.time.Duration.ofSeconds(3))
            .followRedirects(java.net.http.HttpClient.Redirect.NEVER).build()
        private fun probeHttp(address: String, port: Int, path: String): Boolean {
            require(address.matches(Regex("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) && java.net.InetAddress.getByName(address).isSiteLocalAddress)
            return try {
                val uri = java.net.URI("http", null, address, port, path, null, null)
                healthClient.send(java.net.http.HttpRequest.newBuilder(uri).timeout(java.time.Duration.ofSeconds(3)).GET().build(),
                    java.net.http.HttpResponse.BodyHandlers.discarding()).statusCode() == 200
            } catch (e: java.io.IOException) { false }
        }
        fun real(boundFingerprints: Map<String, String> = emptyMap(), backupAccess: RuntimeBackupAccess? = null) =
            PrivateDeployment(BASE, PrivateRootfulCommands(120), boundFingerprints = boundFingerprints, backupAccess = backupAccess)
        /** Native read-only namespace census when an owned target has NO sealed bundle.
         * Do not infer isolation from missing files, a Podman callback or a stale target name. */
        fun observeAbsentOwnedTarget(source: GenerationBundle, sourceSha256: String, target: String,
            commands: RuntimeCommands = PrivateRootfulCommands(120, RuntimeStore.CANONICAL_V2),
            runtimeRoot: Path = BASE): NativeOwnedTargetAbsence {
            require(source.request.store == RuntimeStore.CANONICAL_V2 &&
                sourceSha256.matches(Regex("[a-f0-9]{64}")) &&
                target.matches(Regex("q-[a-f0-9]{12}")) && source.request.id != target &&
                source.members.isNotEmpty())
            val names = source.members.map { pin ->
                require(pin.spec.name.startsWith("${source.request.id}-"))
                target + pin.spec.name.removePrefix(source.request.id)
            }.sorted()
            require(names.distinct().size == names.size)
            val inventories = linkedMapOf<String, String>()
            for ((kind, args) in listOf(
                "container" to listOf("container", "ls", "--all", "--format", "{{.Names}}"),
                "network" to listOf("network", "ls", "--format", "{{.Name}}"),
                "volume" to listOf("volume", "ls", "--format", "{{.Name}}"),
                "secret" to listOf("secret", "ls", "--format", "{{.Name}}"))) {
                val result = commands.run(args)
                require(result.exitCode == 0 && result.output.toByteArray().size <= 2_000_000) {
                    "Native $kind namespace absence could not be audited"
                }
                require(result.output.lineSequence().map(String::trim).filter(String::isNotEmpty).all { value ->
                    value.length <= 255 && names.none { member -> value.startsWith("p0v3-live-$member-") }
                }) { "Native owned target $kind resource exists; no source resume" }
                inventories[kind] = ReleaseLocks.sha256(result.output.toByteArray())
            }
            names.forEach { member ->
                val dir = runtimeRoot.resolve(member)
                if (Files.exists(dir, NOFOLLOW_LINKS)) {
                    ReleasePrivateFiles.directory(dir)
                    Files.list(dir).use { entries -> require(entries.allMatch { entry ->
                        entry.fileName.toString() == "runtime.lock" && Files.isRegularFile(entry, NOFOLLOW_LINKS) &&
                            Files.getPosixFilePermissions(entry) == PosixFilePermissions.fromString("rw-------")
                    }) { "Native owned target runtime preparation exists; no source resume" } }
                }
            }
            return NativeOwnedTargetAbsence(source = ReleaseGeneration(source.request.id, sourceSha256),
                targetGeneration = target, targetMembers = names,
                podmanInventorySha256 = inventories, runtimeMemberDirectoriesEmpty = true)
        }
        fun inputNames(spec: PrivateDeploymentSpec): List<String> =
            (spec.processes.mapNotNull { it.environmentFile } + spec.processes.flatMap { p -> p.files.map { it.file } }).distinct().sorted()
        fun expectedFingerprint(spec: PrivateDeploymentSpec, inputHashes: Map<String, String>): String {
            validate(spec)
            require(inputHashes.keys == inputNames(spec).toSet() && inputHashes.values.all { it.matches(Regex("[a-f0-9]{64}")) }) {
                "Exact immutable runtime input hashes required"
            }
            val hashes = inputNames(spec).map { "$it:${inputHashes.getValue(it)}" }
            return ReleaseLocks.sha256((json.encodeToString(spec) + "\n" + hashes.joinToString("\n")).toByteArray())
        }
        fun read(path: Path): PrivateDeploymentSpec = json.decodeFromString(ReleaseLocks.privateBytes(path).decodeToString())
        fun validate(spec: PrivateDeploymentSpec): List<RuntimeProcess> {
            if (spec.executionBackend == RuntimeExecutionBackend.DIRECT_PODMAN_V1) {
                require(spec.fragmentBinding == null) { "YAML recipes cannot fall back to direct Podman" }
            } else {
                val binding = requireNotNull(spec.fragmentBinding) { "Quadlet requires a bound packaged recipe" }
                require(spec.store == RuntimeStore.CANONICAL_V2 && binding.recipe.matches(Regex("[a-z][a-z0-9-]{0,23}")) &&
                    binding.phase in setOf("INSTALL", "RESTORE") &&
                    (binding.controllerSha256 == null || binding.controllerSha256.matches(Regex("[a-f0-9]{64}"))) &&
                    (binding.controllerUid == null || binding.controllerUid in 1..65534) &&
                    (binding.controllerGid == null || binding.controllerGid in 1..65534) &&
                    binding.resources.isNotEmpty() &&
                    binding.resources.size <= 256 && binding.resources.all { (path, hash) ->
                        path.matches(Regex("[a-zA-Z0-9_./-]{1,240}")) && !path.startsWith('/') &&
                            path.split('/').none { it in setOf("", ".", "..") } && hash.matches(Regex("[a-f0-9]{64}"))
                    }) { "Invalid Quadlet fragment binding" }
            }
            require(spec.schemaVersion == 1 && slug.matches(spec.name) && spec.processes.size in 1..160 && spec.volumes.size <= 128)
            require(spec.processes.map { it.id }.distinct().size == spec.processes.size &&
                spec.volumes.map { it.id }.distinct().size == spec.volumes.size) { "Duplicate runtime resource" }
            val volumes = spec.volumes.associateBy { it.id }
            require(volumes.values.all { volume ->
                slug.matches(volume.id) && volume.userId in 1..65534 && volume.mappedOwners.size <= 64 &&
                    volume.mappedOwners.distinct() == volume.mappedOwners && volume.mappedOwners.all { owner ->
                        owner.userId in 0..65534 && owner.groupId in 0..65534 &&
                            owner != RuntimeVolumeOwner(volume.userId, volume.userId)
                    }
            }) { "Invalid or duplicate explicit volume owner mapping" }
            val byId = spec.processes.associateBy { it.id }
            spec.ingress?.let { ingress ->
                val caddy = requireNotNull(byId["caddy"]) { "Only the Caddy daemon may publish ingress" }
                require(spec.store == RuntimeStore.CANONICAL_V2 && slug.matches(ingress.site) &&
                    ingress.approvedHosts.size in 1..64 && ingress.approvedHosts.all { host ->
                        AcmePreflight.hostPattern.matches(host) && host.length <= 253 && host.split('.').all { it.length <= 63 }
                    } && ingress.listenAddress.split('.').let { parts -> parts.size == 4 && parts.all {
                        it.toIntOrNull()?.let { value -> value in 0..255 && value.toString() == it } == true
                    } } && "ingress-egress" in caddy.networks && spec.processes.filter { it.id != "caddy" }.none { "ingress-egress" in it.networks } &&
                    !caddy.oneShot && caddy.entrypoint == "/usr/bin/caddy" && caddy.command.firstOrNull() == "run") {
                    "Explicit exact-host canonical Caddy publication required"
                }
            }
            spec.nativeIngress?.let { native ->
                val public = requireNotNull(spec.ingress) { "Fixed LiveKit TURN requires the approved owned Caddy site" }
                val live = requireNotNull(byId[native.processId])
                require(spec.store == RuntimeStore.CANONICAL_V2 && native.site == public.site &&
                    native.approvedHost == "rtc.datamancy.net" && native.approvedHost in public.approvedHosts &&
                    native.listenAddress == public.listenAddress && native.processId == "livekit" &&
                    native.udpPort == 3478 && native.tlsPort == 5349 && !live.oneShot &&
                    live.networks.contains("qualification-web") && "ingress-egress" !in live.networks &&
                    spec.processes.single { it.id == "caddy" }.networks.contains("qualification-web")) {
                    "Only fixed approved LiveKit TURN may request an explicit native ingress lease"
                }
            }
            // A single 39-product generation owns more than 32 independently named
            // private networks. Keep exact ownership/slug/uniqueness checks;
            // bound the complete cohort rather than silently drop families.
            require(spec.networks.size in 1..128 && spec.networks.distinct() == spec.networks && spec.networks.all(slug::matches)) {
                "Distinct owned internal networks required"
            }
            for (p in spec.processes) {
                require(p.networks.isNotEmpty() && p.networks.distinct() == p.networks && spec.networks.containsAll(p.networks)) {
                    "Process uses an undeclared or duplicate network"
                }
                require(p.networkAliases.size <= 64 && p.networkAliases.distinct() == p.networkAliases &&
                    p.networkAliases.all { alias -> alias.network in p.networks &&
                        AcmePreflight.hostPattern.matches(alias.host) && alias.host.length <= 253 &&
                        alias.host.split('.').all { it.length <= 63 } }) {
                    "Exact generation-local network alias required"
                }
                require(slug.matches(p.id) && p.userId in 1..65534 && p.groupId in 0..65534 && p.memoryMiB in 64..16384 &&
                    p.image.matches(Regex("[a-z0-9.-]+/[a-zA-Z0-9/_.-]+@sha256:[a-f0-9]{64}")) &&
                    p.imageId.matches(Regex("[a-f0-9]{64}"))) { "Invalid or mutable runtime image/identity" }
                require(p.dependencies.distinct().size == p.dependencies.size && p.dependencies.all { it in byId && it != p.id })
                require(p.apparmorProfile == null || p.apparmorProfile == "p0v3-private-v1") { "Unapproved AppArmor profile" }
                require(p.environmentFile == null || (fileName.matches(p.environmentFile) && !p.environmentFile.startsWith("runtime.")))
                require(p.lateEnvironmentFile == null || (p.id == "keeper" &&
                    p.lateEnvironmentFile == "keeper-bao-late.env" && p.environmentFile == "keeper.env" &&
                    p.dependencies.contains("bao") && p.memoryMiB == 512 &&
                    spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2))
                require(p.entrypoint == null || absolute.matches(p.entrypoint))
                require(p.command.size <= 128 && p.command.all { it.length <= 32768 && '\u0000' !in it })
                require(p.oneShot || (p.readiness.isNotEmpty() xor (p.readinessHttpPort != null))) { "Exactly one daemon readiness probe required" }
                require(p.readinessHttpPort == null || p.readinessHttpPort in 1..65535)
                require(p.readinessHttpPath.matches(Regex("/[a-zA-Z0-9/_.-]*")) &&
                    p.readinessHttpPath.split('/').none { it == "." || it == ".." }) { "Unsafe readiness path" }
                require(p.readiness.size <= 64 && p.readiness.all { it.isNotEmpty() && it.length <= 2048 && '\u0000' !in it })
                require(p.controlSocketMount?.let { mount ->
                    p.userId == 1000 && spec.store == RuntimeStore.CANONICAL_V2 &&
                        spec.name.matches(Regex("q-[a-f0-9]{12}-[a-z][a-z0-9-]{0,23}")) &&
                        spec.fragmentBinding?.recipe == CanonicalSharedYamlGraph.RECIPE &&
                        (if (p.id == "caddy") mount.source == GenerationRuntime.BASE
                            .resolve(spec.name.substring(0, 14)).resolve("managed/control/run").toString() &&
                            mount.target == "/run/p0-control"
                        else p.id == "hub-controller" && p.files.any { it.file == "jupyterhub-hub-settings.json" &&
                            it.target == "/run/secrets/hub-settings.json" } &&
                            mount.source == GenerationRuntime.BASE.resolve(spec.name.substring(0, 14))
                                .resolve("notebooks/control.sock").toString() &&
                            mount.target == "/run/p0-notebooks/control.sock")
                } != false) { "Only exact generation-bound control sockets may be mounted" }
                require(p.volumes.all { volumes[it.volume]?.userId == p.userId && absolute.matches(it.target) && it.target != "/" } &&
                    p.files.all { fileName.matches(it.file) && !it.file.startsWith("runtime.") && absolute.matches(it.target) } &&
                    p.tmpfs.all { absolute.matches(it) } && p.capabilities.distinct().size == p.capabilities.size &&
                    p.capabilities.all { it == "NET_BIND_SERVICE" && p.id == "caddy" }) { "Unsafe runtime mount or capability" }
                val targets = p.volumes.map { it.target } + p.files.map { it.target } + p.tmpfs +
                    listOfNotNull(p.controlSocketMount?.target)
                require(targets.distinct().size == targets.size && targets.none { "/../" in it || it.endsWith("/..") || it.endsWith("/.") })
            }
            require(spec.networks.all { network -> spec.processes.any { network in it.networks } }) { "Orphan network" }
            val aliases = spec.processes.flatMap { it.networkAliases }
            require(aliases.distinct().size == aliases.size) { "Competing owners for one network-local host alias" }
            require(spec.databaseAccess.size <= 128 && spec.databaseAccess.map { it.consumer to it.database }.distinct().size == spec.databaseAccess.size) {
                "Duplicate or excessive database access"
            }
            for (access in spec.databaseAccess) {
                val consumer = requireNotNull(byId[access.consumer]) { "Unknown database consumer" }
                val provider = requireNotNull(byId[access.provider]) { "Unknown database provider" }
                require(consumer.id != provider.id && !provider.oneShot && provider.volumes.any { it.volume == access.volume } &&
                    access.database.matches(Regex("[a-z][a-z0-9_]{0,62}")) && access.principal.matches(Regex("[a-z][a-z0-9_]{0,62}")) &&
                    access.credentialFile == consumer.environmentFile && access.network in consumer.networks && access.network in provider.networks) {
                    "Database access lacks owned storage, credential consumer or shared network"
                }
            }
            val mountedVolumes = spec.processes.flatMap { process -> process.volumes.map { it.volume } }.toSet()
            require(volumes.keys - mountedVolumes == spec.unmountedRecoveryVolumes &&
                (spec.unmountedRecoveryVolumes.isEmpty() || spec.store == RuntimeStore.CANONICAL_V2 &&
                    spec.processes.none { it.oneShot })) { "Orphan volume or invalid cold-only custody" }
            val result = mutableListOf<RuntimeProcess>()
            val visiting = mutableSetOf<String>()
            val visited = mutableSetOf<String>()
            fun visit(id: String) {
                if (id in visited) return
                require(visiting.add(id)) { "Runtime dependency cycle" }
                byId.getValue(id).dependencies.forEach(::visit)
                visiting.remove(id); visited.add(id); result += byId.getValue(id)
            }
            spec.processes.forEach { visit(it.id) }
            return result
        }
    }
    private fun name(spec: PrivateDeploymentSpec, id: String) = "p0v3-live-${spec.name}-$id"
    private fun call(vararg args: String): String {
        val r = commands.run(args.toList())
        check(r.exitCode == 0) { "Private runtime ${args.first()} failed; inspect the owned resource privately" }
        return r.output.trim()
    }
    private fun exists(kind: String, name: String): Boolean {
        val result = commands.run(listOf(kind, "exists", name))
        check(result.exitCode in 0..1) { "Private runtime resource lookup failed" }
        return result.exitCode == 0
    }
    private fun inspect(kind: String, name: String): JsonObject =
        Json.parseToJsonElement(call(kind, "inspect", name)).jsonArray.single().jsonObject
    private fun labels(kind: String, obj: JsonObject): JsonObject =
        (when (kind) {
            "container" -> obj.getValue("Config").jsonObject.getValue("Labels")
            "secret" -> obj.getValue("Spec").jsonObject.getValue("Labels")
            else -> obj["Labels"] ?: obj["labels"]
        })
            ?.jsonObject ?: error("Resource ownership labels missing")
    private fun owned(spec: PrivateDeploymentSpec, kind: String, id: String, hash: String): JsonObject? {
        val resource = name(spec, id)
        if (!exists(kind, resource)) return null
        val data = inspect(kind, resource)
        val labels = labels(kind, data)
        require(labels[OWNER]?.jsonPrimitive?.content == spec.name && labels[HASH]?.jsonPrimitive?.content == hash) {
            "Foreign or changed private runtime resource: $resource"
        }
        if (kind == "network") require(data.getValue("internal").jsonPrimitive.boolean ==
            !(spec.ingress != null && id == "ingress-egress")) { "Runtime network isolation drift" }
        if (kind == "container") {
            val process = spec.processes.single { it.id == id }
            val config = data.getValue("Config").jsonObject
            val host = data.getValue("HostConfig").jsonObject
            val security = host.getValue("SecurityOpt").jsonArray.map { it.jsonPrimitive.content }
            val mounts = data.getValue("Mounts").jsonArray.map { it.jsonObject }
            val expectedCaps = process.capabilities.map { "CAP_$it" }.toSet()
            fun capabilities(field: String): Set<String> = data.getValue(field).let {
                if (it == JsonNull) emptySet() else it.jsonArray.map { value -> value.jsonPrimitive.content }.toSet()
            }
            val actualNetworks = data.getValue("NetworkSettings").jsonObject.getValue("Networks").jsonObject
            val aliasNetworks = process.networkAliases.map { it.network }.toSet()
            require(aliasNetworks.all { network ->
                val observed = actualNetworks[name(spec, network)]?.jsonObject?.get("Aliases")
                observed is JsonArray && observed.map { it.jsonPrimitive.content }.filter { '.' in it }.toSet() ==
                    process.networkAliases.filter { it.network == network }.map { it.host }.toSet()
            }) { "Generation-local DNS alias drift: $resource" }
            require(data.getValue("Image").jsonPrimitive.content.removePrefix("sha256:") == process.imageId &&
                config.getValue("User").jsonPrimitive.content == "${process.userId}:${process.groupId}" &&
                !host.getValue("Privileged").jsonPrimitive.boolean && host.getValue("ReadonlyRootfs").jsonPrimitive.boolean &&
                host.getValue("PortBindings").jsonObject == ingressBindings(spec, process.id) &&
                host["PublishAllPorts"] != JsonPrimitive(true) &&
                host.getValue("PidMode").jsonPrimitive.content == "private" &&
                host.getValue("IpcMode").jsonPrimitive.content in setOf("private", "shareable") &&
                host.getValue("UTSMode").jsonPrimitive.content == "private" &&
                host.getValue("CgroupMode").jsonPrimitive.content == "private" &&
                host.getValue("UsernsMode").jsonPrimitive.content == "" &&
                host.getValue("NetworkMode").jsonPrimitive.content == "bridge" &&
                host.getValue("Memory").jsonPrimitive.long == process.memoryMiB.toLong() * 1024 * 1024 &&
                host.getValue("PidsLimit").jsonPrimitive.int == 512 &&
                host.getValue("Devices").jsonArray.isEmpty() && host.getValue("GroupAdd").jsonArray.isEmpty() &&
                (host.getValue("VolumesFrom") == JsonNull || host.getValue("VolumesFrom").jsonArray.isEmpty()) &&
                security.toSet() == (setOf("no-new-privileges") + listOfNotNull(process.apparmorProfile?.let { "apparmor=$it" })) &&
                // Podman reports CapAdd relative to its default set, not the final OCI capability set.
                host.getValue("CapAdd").jsonArray.all { it.jsonPrimitive.content in expectedCaps } &&
                capabilities("EffectiveCaps") == expectedCaps && capabilities("BoundingCaps") == expectedCaps &&
                data.getValue("NetworkSettings").jsonObject.getValue("Networks").jsonObject.keys == process.networks.map { name(spec, it) }.toSet() &&
                (process.apparmorProfile == null || data.getValue("AppArmorProfile").jsonPrimitive.content == process.apparmorProfile) &&
                mounts.all { it.getValue("Type").jsonPrimitive.content == "volume" } &&
                mounts.map { it.getValue("Name").jsonPrimitive.content to it.getValue("Destination").jsonPrimitive.content }.toSet() ==
                    process.volumes.map { name(spec, "volume-${it.volume}") to it.target }.toSet()) { "Runtime container configuration drift: $resource" }
        }
        return data
    }
    private fun guardDirectory(path: Path) {
        require(path.isAbsolute && path.normalize() == path && Files.isDirectory(path, NOFOLLOW_LINKS) && path.toRealPath() == path &&
            Files.getPosixFilePermissions(path) == PosixFilePermissions.fromString("rwx------") &&
            Files.getAttribute(path, "unix:uid") == com.sun.security.auth.module.UnixSystem().uid.toInt()) { "Private owned runtime directory required" }
    }
    private fun fingerprint(spec: PrivateDeploymentSpec, root: Path): String {
        val inputs = inputNames(spec)
        val approved = inputs + setOf("runtime.owner", "runtime.lock", "runtime.jobs", "runtime.import.intent",
            "runtime.import.complete", RuntimeMaintenance.FILE, RuntimeMaintenance.TEMP, RuntimeBackupLeases.FILE)
        val turnOverlay = spec.store == RuntimeStore.CANONICAL_V2 &&
            spec.processes.count { it.id == "livekit" && !it.oneShot } == 1
        Files.list(root).use { paths -> require(paths.allMatch { entry ->
            entry.fileName.toString() in approved || turnOverlay && entry.fileName.toString() == "turn-revisions" &&
                Files.isDirectory(entry, NOFOLLOW_LINKS) && Files.getPosixFilePermissions(entry) ==
                    PosixFilePermissions.fromString("rwx------")
        }) { "Unexpected runtime directory entry" } }
        val hashes = inputs.associateWith { input ->
            val path = root.resolve(input)
            require(path.toRealPath() == path && Files.getAttribute(path, "unix:uid") == com.sun.security.auth.module.UnixSystem().uid.toInt())
            ReleaseLocks.sha256(ReleaseLocks.privateBytes(path))
        }
        return expectedFingerprint(spec, hashes)
    }
    private fun jobBytes(jobs: RuntimeJobs): ByteArray {
        val hash = ReleaseLocks.sha256(json.encodeToString(jobs.copy(checksum = "")).toByteArray())
        return json.encodeToString(jobs.copy(checksum = hash)).toByteArray()
    }
    private fun readJobs(spec: PrivateDeploymentSpec, root: Path, hash: String): RuntimeJobs {
        val path = root.resolve("runtime.jobs")
        if (!Files.exists(path, NOFOLLOW_LINKS)) return RuntimeJobs(hash)
        val bytes = ReleaseLocks.privateBytes(path)
        val jobs = json.decodeFromString<RuntimeJobs>(bytes.decodeToString())
        require(jobs.fingerprint == hash && jobs.started.containsAll(jobs.completed) &&
            jobs.started.all { id -> spec.processes.any { it.id == id && it.oneShot } } && jobBytes(jobs).contentEquals(bytes)) {
            "Corrupt or foreign initialization journal"
        }
        return jobs
    }
    private fun saveJobs(root: Path, jobs: RuntimeJobs) {
        val temp = root.resolve("runtime.jobs.tmp")
        FileChannel.open(temp, setOf(CREATE_NEW, WRITE), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))).use {
            val bytes = ByteBuffer.wrap(jobBytes(jobs)); while (bytes.hasRemaining()) it.write(bytes); it.force(true)
        }
        Files.move(temp, root.resolve("runtime.jobs"), java.nio.file.StandardCopyOption.ATOMIC_MOVE, java.nio.file.StandardCopyOption.REPLACE_EXISTING)
        FileChannel.open(root, READ).use { it.force(true) }
    }
    private fun verifyStore() {
        val info = Json.parseToJsonElement(call("info", "--format", "json")).jsonObject
        val store = info.getValue("store").jsonObject
        val security = info.getValue("host").jsonObject.getValue("security").jsonObject
        require(runtimeStore == RuntimeStore.LEGACY || info.getValue("host").jsonObject["freeLocks"] in listOf(null, JsonNull)) {
            "Isolated file-lock backend required"
        }
        require(!security.getValue("rootless").jsonPrimitive.boolean && security.getValue("apparmorEnabled").jsonPrimitive.boolean &&
            security.getValue("seccompEnabled").jsonPrimitive.boolean) { "Required rootful runtime confinement unavailable" }
        require(store.getValue("graphRoot").jsonPrimitive.content == runtimeStore.graph &&
            store.getValue("runRoot").jsonPrimitive.content == runtimeStore.run) { "Private runtime store mismatch" }
    }
    private fun <T> locked(spec: PrivateDeploymentSpec, observation: Boolean = false, allowMissingBackup: Boolean = false,
        action: PrivateDeployment.(Path, String, List<RuntimeProcess>) -> T): T {
        require(spec.executionBackend == RuntimeExecutionBackend.DIRECT_PODMAN_V1) {
            "Quadlet lifecycle admission is not installed; direct-Podman fallback refused"
        }
        if (runtimeStore != spec.store) return PrivateDeployment(base,
            if (commands is PrivateRootfulCommands) commands.scoped(spec.store) else commands,
            httpReady, boundFingerprints, backupAccess, spec.store, ingressPortOwner, pause).locked(spec, observation, allowMissingBackup, action)
        val ordered = validate(spec)
        guardDirectory(base)
        val root = base.resolve(spec.name)
        guardDirectory(root)
        val lock = root.resolve("runtime.lock")
        val checked: () -> T = {
            require(Files.getPosixFilePermissions(lock) == PosixFilePermissions.fromString("rw-------"))
            val hash = fingerprint(spec, root)
            if (boundFingerprints.isNotEmpty()) require(boundFingerprints[spec.name] == hash) {
                "Generation binding mismatch; no runtime effects authorized"
            }
            val lease = RuntimeBackupLeases.read(root, spec.name, hash)
            if (!observation) {
                require(lease == null || lease.access == backupAccess) { "Backup lease blocks ordinary runtime effects" }
                require(backupAccess == null || lease != null || allowMissingBackup) { "Missing backup lease; no effects authorized" }
            }
            val marker = root.resolve("runtime.owner")
            val expected = "p0v3-private-runtime-v1\n${spec.name}\n$hash\n"
            if (Files.exists(marker, NOFOLLOW_LINKS)) require(ReleaseLocks.privateBytes(marker).decodeToString() == expected) { "Runtime inputs changed; transactional update required" }
            verifyStore()
            // Audit EVERY existing resource before any Podman mutation.
            spec.networks.forEach { owned(spec, "network", it, hash) }
            spec.volumes.forEach { owned(spec, "volume", "volume-${it.id}", hash) }
            ordered.flatMap { it.files }.map { it.file }.distinct().forEach { owned(spec, "secret", "file-$it", hash) }
            ordered.forEach { owned(spec, "container", it.id, hash) }
            if (!observation && spec.ingress != null) {
                val caddy = owned(spec, "container", "caddy", hash)
                if (caddy?.getValue("State")?.jsonObject?.getValue("Running")?.jsonPrimitive?.boolean != true) {
                    require(listOf(80, 443).all { ingressPortOwner(it) == PortOwner.FREE }) {
                        "Public ingress ports occupied or ownership unknown; unrelated listeners remain untouched"
                    }
                }
            }
            action(root, hash, ordered)
        }
        val held = orderedNativeLocks.get()
        require(held.isEmpty() || lock in held) {
            "Unordered native member lock cannot join an existing source/target isolation cohort"
        }
        return if (lock in held) {
            val identity = held.getValue(lock)
            require(lockIdentity(lock) == identity) { "Reentered member lock identity changed" }
            checked().also { require(lockIdentity(lock) == identity) { "Reentered member lock replaced during native effect" } }
        }
        else JvmNativeLockGate.with(lock) {
            FileChannel.open(lock, setOf(CREATE, WRITE, NOFOLLOW_LINKS),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))).use { channel ->
                val original = lockIdentity(lock)
                boundedNativeLock(channel, mustBeBound = false).use {
                    require(lockIdentity(lock) == original) { "Native member lock replaced during admission" }
                    checked().also { require(lockIdentity(lock) == original) { "Native member lock replaced during effect" } }
                }
            }
        }
    }
    /** Every namespaced admin request is bound to a freshly audited live container and held runtime lock. */
    fun <T> withCaddyAdmin(spec: PrivateDeploymentSpec, expectedFingerprint: String, mutation: Boolean,
        action: (CaddyAdminTarget) -> T): T = locked(spec, observation = !mutation) { root, hash, _ ->
        require(hash == expectedFingerprint && expectedFingerprint.matches(Regex("[a-f0-9]{64}")))
        val process = spec.processes.single { it.id == "caddy" }
        require(!process.oneShot && process.entrypoint == "/usr/bin/caddy" && process.command.firstOrNull() == "run")
        if (mutation) {
            requireImportComplete(root, hash)
            val fence = RuntimeMaintenance.read(root, hash)
            require(fence == null || fence.stageTarget == "caddy") { "Maintenance fence blocks Caddy mutation" }
        }
        val data = requireNotNull(owned(spec, "container", "caddy", hash))
        val state = data.getValue("State").jsonObject
        val id = data.getValue("Id").jsonPrimitive.content
        val pid = state.getValue("Pid").jsonPrimitive.long
        require(state.getValue("Running").jsonPrimitive.boolean && pid in 2..Int.MAX_VALUE && id.matches(Regex("[a-f0-9]{64}")))
        action(CaddyAdminTarget(pid.toInt(), id))
    }
    /** Port ownership for ACME admission comes from a full live-container audit, not socket reachability. */
    fun ingressPortOwner(spec: PrivateDeploymentSpec, expectedFingerprint: String, port: Int): PortOwner =
        locked(spec, observation = true) { _, hash, _ ->
            require(port in setOf(80, 443) && hash == expectedFingerprint)
            val live = owned(spec, "container", "caddy", hash)
            if (spec.ingress != null && live?.getValue("State")?.jsonObject?.getValue("Running")?.jsonPrimitive?.boolean == true)
                PortOwner.OWNED_V3 else ingressPortOwner(port)
        }
    private fun ingressBindings(spec: PrivateDeploymentSpec, process: String): JsonObject = buildJsonObject {
        val ingress = spec.ingress
        if (process == "caddy" && ingress != null) for (port in listOf(80, 443)) {
            put("$port/tcp", buildJsonArray { add(buildJsonObject {
                put("HostIp", ingress.listenAddress); put("HostPort", port.toString())
            }) })
        }
    }
    private fun resourceCount(spec: PrivateDeploymentSpec, hash: String, ordered: List<RuntimeProcess>): Int {
        var count = spec.networks.count { owned(spec, "network", it, hash) != null }
        count += spec.volumes.count { owned(spec, "volume", "volume-${it.id}", hash) != null }
        count += ordered.flatMap { it.files }.map { it.file }.distinct().count { owned(spec, "secret", "file-$it", hash) != null }
        return count + ordered.count { owned(spec, "container", it.id, hash) != null }
    }
    private fun requirePristine(spec: PrivateDeploymentSpec, root: Path, hash: String, ordered: List<RuntimeProcess>) {
        require(!Files.exists(root.resolve("runtime.owner"), NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("runtime.jobs"), NOFOLLOW_LINKS) && RuntimeMaintenance.read(root, hash) == null &&
            RuntimeBackupLeases.read(root, spec.name, hash) == null &&
            resourceCount(spec, hash, ordered) == 0) { "Fresh generation requires empty resources and no previous initialization or fence" }
    }

    /** Audit all resources and pinned images before a generation may mutate any member. */
    fun audit(spec: PrivateDeploymentSpec, pristine: Boolean = false): RuntimeAudit = locked(spec, observation = true) { root, hash, ordered ->
        val jobs = readJobs(spec, root, hash)
        val fence = RuntimeMaintenance.read(root, hash)
        val resources = resourceCount(spec, hash, ordered)
        ordered.forEach { process ->
            val image = inspect("image", process.image)
            require(image.getValue("Id").jsonPrimitive.content.removePrefix("sha256:") == process.imageId &&
                image.getValue("Digest").jsonPrimitive.content == process.image.substringAfter('@')) { "Runtime image content mismatch" }
        }
        if (pristine) requirePristine(spec, root, hash, ordered)
        RuntimeAudit(spec.name, hash, resources, fence?.id, statuses(spec, jobs.completed))
    }

    /** One fixed native LiveKit TLS-adoption actor. This does not publish :5349; A15's
     * independent WebPKI handshake and A13's functional packet-return remain separate.
     * Immutable secret revisions and a one-use intent precede stopping the one old SFU.
     * A lost native acknowledgement leaves isolation and never triggers auto-restart. */
    fun adoptEffectiveTurn(bundle: GenerationBundle, pin: GenerationPin, operation: String,
        inputs: Map<String, String>): PublicTurnNativeObservation = locked(pin.spec) { root, fingerprint, _ ->
        require(base == BASE && pin.spec.store == RuntimeStore.CANONICAL_V2 &&
            pin.member.name == pin.spec.name && pin.runtimeFingerprint == fingerprint &&
            pin in bundle.members && bundle.request.id.matches(Regex("q-[a-f0-9]{12}")) &&
            operation.matches(Regex("[a-z0-9-]{1,64}")) &&
            inputs.keys == setOf("rtc-turn.pem", "rtc-turn-key.pem", "livekit.yaml"))
        RecoveryDeadline.remainingMillis() // No standalone native revision without inherited bounded controller lock.
        val proc = pin.spec.processes.single { it.id == "livekit" && !it.oneShot }
        require(proc.command == listOf("--config", "/run/secrets/livekit.yaml") &&
            setOf("livekit.yaml", "livekit-turn-template.yaml", "rtc-turn.pem", "rtc-turn-key.pem")
                .all { file -> proc.files.any { it.file == file } } &&
            proc.entrypoint == "/livekit-server")
        val generationRoot = GenerationRuntime.BASE.resolve(bundle.request.id)
        val public = requireNotNull(NativeCredentialRevision.readHead(generationRoot))
        val binding = public.revisions.getValue("rtc.datamancy.net")
        val recordBytes = ReleasePrivateFiles.read(Path.of(binding.path), 65536)
        require(ReleaseLocks.sha256(recordBytes) == binding.sha256)
        val certificate = Json { ignoreUnknownKeys = false }.decodeFromString<PublicCertificateRevision>(
            recordBytes.decodeToString(throwOnInvalidSequence = true))
        val revision = certificate.revisionId
        require(revision.matches(Regex("cert-[a-f0-9]{24}")) && certificate.generation == bundle.request.id &&
            certificate.bundleSha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(generationRoot.resolve("bundle.json"))) &&
            certificate.host == "rtc.datamancy.net" &&
            ReleaseLocks.sha256(inputs.getValue("rtc-turn.pem").toByteArray()) == certificate.chainPemSha256 &&
            ReleaseLocks.sha256(inputs.getValue("rtc-turn-key.pem").toByteArray()) == certificate.privateKeyPemSha256)
        val bootstrap = ReleasePrivateFiles.read(root.resolve("livekit.yaml"), 1048576)
        val template = ReleasePrivateFiles.read(root.resolve("livekit-turn-template.yaml"), 1048576)
        require(pin.inputHashes["livekit.yaml"] == ReleaseLocks.sha256(bootstrap) &&
            pin.inputHashes["livekit-turn-template.yaml"] == ReleaseLocks.sha256(template) &&
            inputs.getValue("livekit.yaml") == LiveKitRuntime.effectivePublicTurnConfig(bundle.request.id,
                certificate, bootstrap.decodeToString(throwOnInvalidSequence = true),
                template.decodeToString(throwOnInvalidSequence = true)))
        val turnRoot = root.resolve("turn-revisions")
        val operations = turnRoot.resolve("operations")
        val revisionRoot = turnRoot.resolve(revision)
        val parentIntent = generationRoot.resolve("credential-revisions/public/turn/$operation.intent.json")
        require(!Files.exists(revisionRoot, NOFOLLOW_LINKS) &&
            !Files.exists(operations.resolve("$operation.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(operations.resolve("$operation.result.json"), NOFOLLOW_LINKS) &&
            Files.exists(parentIntent, NOFOLLOW_LINKS) &&
            !Files.exists(generationRoot.resolve("credential-revisions/public/turn/$operation.result.json"), NOFOLLOW_LINKS))
        val admitted = Json { ignoreUnknownKeys = false }.decodeFromString<PublicTurnAdoptionIntent>(
            ReleasePrivateFiles.read(parentIntent, 65536).decodeToString(throwOnInvalidSequence = true))
        require(admitted.generation == bundle.request.id && admitted.bundleSha256 == certificate.bundleSha256 &&
            admitted.operationId == operation && admitted.publicRevisionSha256 == binding.sha256 &&
            admitted.leafDerSha256 == certificate.leafDerSha256 &&
            admitted.chainPemSha256 == certificate.chainPemSha256 &&
            admitted.privateKeyPemSha256 == certificate.privateKeyPemSha256 &&
            admitted.effectiveConfigSha256 == ReleaseLocks.sha256(inputs.getValue("livekit.yaml").toByteArray()) &&
            admitted.livekitFingerprint == fingerprint)
        // Earlier native attempts must have BOTH the native result and independent
        // A15 result before an unrelated new revision may replace the live process.
        if (Files.exists(operations, NOFOLLOW_LINKS)) {
            ReleasePrivateFiles.directory(operations)
            Files.list(operations).use { paths -> paths.forEach { entry ->
                val name = entry.fileName.toString()
                require(name.matches(Regex("[a-z0-9-]{1,64}\\.(intent|result)\\.json")) &&
                    Files.exists(operations.resolve(name.substringBefore('.') + ".intent.json"), NOFOLLOW_LINKS) &&
                    Files.exists(operations.resolve(name.substringBefore('.') + ".result.json"), NOFOLLOW_LINKS) &&
                    Files.exists(generationRoot.resolve("credential-revisions/public/turn/" +
                        name.substringBefore('.') + ".result.json"), NOFOLLOW_LINKS)) {
                    "Prior effective TURN native write remains uncertain"
                }
            } }
        }
        val container = name(pin.spec, "livekit")
        val prior = requireNotNull(owned(pin.spec, "container", "livekit", fingerprint))
        require(prior.getValue("State").jsonObject.getValue("Running").jsonPrimitive.boolean &&
            RuntimeMaintenance.read(root, fingerprint) == null)
        val intentBytes = Json.encodeToString(mapOf("operation" to operation,
            "generation" to bundle.request.id, "bundleSha256" to certificate.bundleSha256,
            "revision" to revision, "recordSha256" to binding.sha256,
            "runtimeFingerprint" to fingerprint,
            "chainSha256" to certificate.chainPemSha256, "keySha256" to certificate.privateKeyPemSha256,
            "configSha256" to ReleaseLocks.sha256(inputs.getValue("livekit.yaml").toByteArray()))).toByteArray()
        for (path in listOf(turnRoot, operations, revisionRoot)) {
            if (!Files.exists(path, NOFOLLOW_LINKS)) {
                Files.createDirectory(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
                FileChannel.open(path.parent, READ).use { it.force(true) }
            }
            ReleasePrivateFiles.directory(path)
        }
        ReleasePrivateFiles.save(operations.resolve("$operation.intent.json"), intentBytes)
        val files = listOf("rtc-turn.pem", "rtc-turn-key.pem", "livekit.yaml")
        files.forEach { file -> ReleasePrivateFiles.save(revisionRoot.resolve(file),
            inputs.getValue(file).toByteArray()) }
        val resourceLabels = listOf("--label=$OWNER=${pin.spec.name}", "--label=$HASH=$fingerprint",
            "--label=io.p0v3.effective-turn=$revision")
        files.forEach { file ->
            val secret = name(pin.spec, "turn-$revision-$file")
            require(!exists("secret", secret)) { "An uncertain effective TURN secret already exists" }
            call(*(listOf("secret", "create") + resourceLabels + listOf(secret, revisionRoot.resolve(file).toString())).toTypedArray())
            val observed = requireNotNull(owned(pin.spec, "secret", "turn-$revision-$file", fingerprint))
            require(labels("secret", observed)["io.p0v3.effective-turn"]?.jsonPrimitive?.content == revision)
        }
        // Only after every revision input is independently pinned may the old SFU stop.
        // Never force-remove a running process or fabricate success from a command return.
        call("stop", "--time=30", container)
        val stopped = requireNotNull(owned(pin.spec, "container", "livekit", fingerprint))
        require(!stopped.getValue("State").jsonObject.getValue("Running").jsonPrimitive.boolean)
        call("rm", container)
        require(!exists("container", container))
        val command = listOf("--config", "/run/turn-revisions/$revision/livekit.yaml")
        val args = mutableListOf("create", "--name=$container", "--pull=never", *proc.networks.map { network ->
            "--network=${name(pin.spec, network)}" + proc.networkAliases.filter { it.network == network }
                .joinToString(separator = ",", prefix = if (proc.networkAliases.any { it.network == network }) ":" else "") { "alias=${it.host}" }
        }.toTypedArray(), "--network-alias=livekit", "--read-only", "--cap-drop=all", "--security-opt=no-new-privileges",
            "--user=${proc.userId}:${proc.groupId}", "--memory=${proc.memoryMiB}m", "--pids-limit=512", "--stop-timeout=30",
            "--image-volume=ignore")
        args += resourceLabels
        proc.apparmorProfile?.let { args += "--security-opt=apparmor=$it" }
        proc.capabilities.forEach { args += "--cap-add=$it" }
        proc.tmpfs.forEach { args += "--tmpfs=$it:rw,nosuid,nodev,mode=1777,size=128m" }
        proc.volumes.forEach { args += "--volume=${name(pin.spec, "volume-${it.volume}")}:${it.target}:U" }
        proc.files.forEach { args += "--secret=${name(pin.spec, "file-${it.file}")},type=mount,target=${it.target},uid=${proc.userId},gid=${proc.groupId},mode=0400" }
        files.forEach { file -> args += "--secret=${name(pin.spec, "turn-$revision-$file")},type=mount,target=/run/turn-revisions/$revision/$file,uid=${proc.userId},gid=${proc.groupId},mode=0400" }
        proc.environmentFile?.let { args += "--env-file=${root.resolve(it)}" }
        proc.lateEnvironmentFile?.let { args += "--env-file=${root.resolve(it)}" }
        args += "--entrypoint=${requireNotNull(proc.entrypoint)}"
        args += proc.image
        args += command
        call(*args.toTypedArray())
        call("start", container)
        val current = requireNotNull(owned(pin.spec, "container", "livekit", fingerprint))
        val state = current.getValue("State").jsonObject
        val id = current.getValue("Id").jsonPrimitive.content.removePrefix("sha256:")
        require(state.getValue("Running").jsonPrimitive.boolean && id.matches(Regex("[a-f0-9]{64}")) &&
            labels("container", current)["io.p0v3.effective-turn"]?.jsonPrimitive?.content == revision &&
            current.getValue("Config").jsonObject.getValue("Cmd").jsonArray.map { it.jsonPrimitive.content } == command)
        val installed = files.associateWith { file ->
            val output = call("exec", "--user=${proc.userId}:${proc.groupId}", container, "sha256sum",
                "/run/turn-revisions/$revision/$file")
            val sha = output.substringBefore(' ')
            require(sha.matches(Regex("[a-f0-9]{64}")) &&
                sha == ReleaseLocks.sha256(inputs.getValue(file).toByteArray())) {
                "LiveKit effective secret was not mounted with its original bytes"
            }
            sha
        }
        val address = NamespaceCaddyTransport.ownedProcessAddress(pin.spec, fingerprint, "livekit", "rtc-turn")
        val factory = CertificateFactory.getInstance("X.509")
        val chain = factory.generateCertificates(ByteArrayInputStream(inputs.getValue("rtc-turn.pem").toByteArray()))
        val keys = java.security.KeyStore.getInstance("PKCS12").apply { load(null, null) }
        chain.forEachIndexed { index, value -> keys.setCertificateEntry("public-$index", value) }
        val managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(keys) }
        val tls = SSLContext.getInstance("TLS").apply { init(null, managers.trustManagers, null) }
        val tlsDeadline = System.nanoTime() + java.time.Duration.ofSeconds(90).toNanos()
        var observedLeaf: ByteArray? = null
        while (observedLeaf == null) {
            RecoveryDeadline.remainingMillis()
            val socket = Socket()
            try {
                socket.connect(InetSocketAddress(address, 5349), 2500)
                observedLeaf = (tls.socketFactory.createSocket(socket, "rtc.datamancy.net", 5349, true) as SSLSocket).use {
                    it.soTimeout = 2500
                    it.sslParameters = it.sslParameters.apply {
                        serverNames = listOf(javax.net.ssl.SNIHostName("rtc.datamancy.net"))
                        endpointIdentificationAlgorithm = "HTTPS"
                    }
                    it.startHandshake()
                    it.session.peerCertificates.first().encoded
                }
            } catch (failure: java.io.IOException) {
                if (System.nanoTime() >= tlsDeadline) throw failure
                Thread.sleep(500) // Read-only readiness observation, never a second native START.
            } finally { socket.close() }
        }
        val proof = PublicTurnNativeObservation(bundle.request.id, certificate.bundleSha256,
            operation, id, fingerprint, installed.getValue("rtc-turn.pem"),
            installed.getValue("rtc-turn-key.pem"), installed.getValue("livekit.yaml"), command,
            ReleaseLocks.sha256(requireNotNull(observedLeaf)), Instant.now().epochSecond)
        require(proof.tlsObservedLeafDerSha256 == certificate.leafDerSha256)
        ReleasePrivateFiles.save(operations.resolve("$operation.result.json"), Json.encodeToString(proof).toByteArray())
        proof
    }
    /** Allocate audited, empty staging resources without creating or starting any process. */
    fun provision(spec: PrivateDeploymentSpec): List<RuntimeStatus> = locked(spec) { root, hash, ordered ->
        require(RuntimeMaintenance.read(root, hash) == null) { "Maintenance fence blocks provisioning" }
        val jobs = readJobs(spec, root, hash)
        provisionResources(spec, root, hash, ordered)
        statuses(spec, jobs.completed)
    }
    private fun provisionResources(spec: PrivateDeploymentSpec, root: Path, hash: String, ordered: List<RuntimeProcess>) {
        // Fail before creating any resources if even one immutable image is missing or changed.
        ordered.forEach { p ->
            val image = inspect("image", p.image)
            require(image.getValue("Id").jsonPrimitive.content.removePrefix("sha256:") == p.imageId &&
                image.getValue("Digest").jsonPrimitive.content == p.image.substringAfter('@')) { "Runtime image content mismatch" }
        }
        val marker = root.resolve("runtime.owner")
        if (!Files.exists(marker, NOFOLLOW_LINKS)) {
            FileChannel.open(marker, setOf(CREATE_NEW, WRITE), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))).use {
                val data = ByteBuffer.wrap("p0v3-private-runtime-v1\n${spec.name}\n$hash\n".toByteArray())
                while (data.hasRemaining()) it.write(data)
                it.force(true)
            }
            FileChannel.open(root, READ).use { it.force(true) }
        }
        val labels = listOf("--label=$OWNER=${spec.name}", "--label=$HASH=$hash")
        spec.networks.forEach { network ->
            if (!exists("network", name(spec, network))) call(*(listOf("network", "create") +
                (if (spec.ingress != null && network == "ingress-egress") emptyList() else listOf("--internal")) +
                labels + name(spec, network)).toTypedArray())
        }
        spec.volumes.forEach { volume ->
            if (!exists("volume", name(spec, "volume-${volume.id}")))
                call(*(listOf("volume", "create") + labels + name(spec, "volume-${volume.id}")).toTypedArray())
        }
        ordered.flatMap { it.files }.map { it.file }.distinct().forEach { file ->
            val secret = name(spec, "file-$file")
            if (!exists("secret", secret)) call(*(listOf("secret", "create") + labels + listOf(secret, root.resolve(file).toString())).toTypedArray())
        }
    }
    /** Fresh, initializer-free targets only. Import never starts a process and retains its fence on every failure. */
    fun importCold(spec: PrivateDeploymentSpec, archives: Map<String, Path>, sourceArchiveSha256: String, verificationRoot: Path, expectedHashes: Map<String, String>,
        restoreMetadata: (PrivateDeploymentSpec, RuntimeVolume, List<VolumeTarEntry>) -> Unit = ColdVolumeImport::restoreTree,
        export: (PrivateDeploymentSpec, RuntimeVolume, Path) -> Unit = { member, volume, output ->
            ColdVolumeExport.export(member, volume, output, maximumBytes = minOf(RecoveryCapsule.MAX_TOTAL,
                Math.addExact(Files.size(archives.getValue(volume.id)), VolumeTar.MAX_METADATA_PREFIX)))
        }): MaintenanceFence = locked(spec) { root, hash, ordered ->
        require(spec.ingress == null && spec.name.matches(Regex("q-[a-f0-9]{12}-[a-z][a-z0-9-]{0,23}")) && ordered.none { it.oneShot } &&
            sourceArchiveSha256.matches(Regex("[a-f0-9]{64}")) && archives.keys == spec.volumes.map { it.id }.toSet() &&
            expectedHashes.keys == archives.keys && expectedHashes.values.all { it.matches(Regex("[a-f0-9]{64}")) }) { "Fresh retired-initializer restore definition required" }
        guardDirectory(verificationRoot)
        requirePristine(spec, root, hash, ordered)
        require(!Files.exists(root.resolve("runtime.import.intent"), NOFOLLOW_LINKS) && !Files.exists(root.resolve("runtime.import.complete"), NOFOLLOW_LINKS))
        val trees = spec.volumes.associate { volume -> volume.id to VolumeTar.inspect(archives.getValue(volume.id),
            volume.userId, volume.mappedOwners.map { it.userId to it.groupId }.toSet()) }
        val hashes = archives.mapValues { RecoveryCapsule.fileHash(it.value) }
        require(hashes == expectedHashes) { "Import payload differs from authenticated capsule declaration" }
        val marker = "p0v3-native-volume-import-v1\n$hash\n$sourceArchiveSha256\n"
        fun mark(file: String) {
            FileChannel.open(root.resolve(file), setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))).use { channel ->
                val buffer = ByteBuffer.wrap(marker.toByteArray()); while (buffer.hasRemaining()) channel.write(buffer); channel.force(true)
            }
            FileChannel.open(root, READ).use { it.force(true) }
        }
        mark("runtime.import.intent")
        val fence = RuntimeMaintenance.create(root, hash, "restore", null)
        provisionResources(spec, root, hash, ordered)
        for (volume in spec.volumes) {
            val archive = archives.getValue(volume.id)
            RecoveryCapsule.guard(archive, RecoveryCapsule.MAX_TOTAL)
            require(RecoveryCapsule.fileHash(archive) == hashes.getValue(volume.id)) { "Import archive changed after preflight" }
            call("volume", "import", name(spec, "volume-${volume.id}"), archive.toString())
            restoreMetadata(spec, volume, trees.getValue(volume.id))
            val observed = verificationRoot.resolve("${volume.id}.tar")
            export(spec, volume, observed)
            ColdVolumeImport.verifyImported(archive, observed, volume.userId,
                volume.mappedOwners.map { it.userId to it.groupId }.toSet())
            require(RecoveryCapsule.fileHash(archive) == hashes.getValue(volume.id)) {
                "Imported source archive changed during native readback"
            }
        }
        mark("runtime.import.complete")
        fence
    }
    private fun requireImportComplete(root: Path, hash: String) {
        val intent = root.resolve("runtime.import.intent"); val complete = root.resolve("runtime.import.complete")
        if (!Files.exists(intent, NOFOLLOW_LINKS) && !Files.exists(complete, NOFOLLOW_LINKS)) return
        val bytes = ReleaseLocks.privateBytes(intent)
        val text = bytes.decodeToString()
        require(text.matches(Regex("p0v3-native-volume-import-v1\\n$hash\\n[a-f0-9]{64}\\n")) &&
            bytes.contentEquals(ReleaseLocks.privateBytes(complete))) { "Incomplete or foreign import; startup and fence release refused" }
    }
    fun apply(spec: PrivateDeploymentSpec, pristine: Boolean = false): List<RuntimeStatus> = applySelected(spec, null, pristine)

    /** Start only a named process and its dependency closure, with the full immutable manifest/audits.
     * Other processes must already be stopped or absent. During maintenance, only the recorded target
     * is permitted and initializers must already be completed. External recovery still needs the lock. */
    fun stage(spec: PrivateDeploymentSpec, target: String): List<RuntimeStatus> {
        require(validate(spec).any { it.id == target }) { "Unknown staging target" }
        return applySelected(spec, target)
    }
    /** A controller-admitted fresh cold import may start daemons once, under the SAME runtime lock
     * as its final import/resource check and fence release. Never recreate missing imported state. */
    fun startImported(spec: PrivateDeploymentSpec, expectedFence: String): List<RuntimeStatus> = locked(spec) { root, hash, all ->
        require(spec.ingress == null && all.none { it.oneShot }) { "Imported startup cannot publish or initialize" }
        require(Files.exists(root.resolve("runtime.import.intent"), NOFOLLOW_LINKS) &&
            Files.exists(root.resolve("runtime.import.complete"), NOFOLLOW_LINKS)) { "Native import records required" }
        requireImportComplete(root, hash)
        val fence = requireNotNull(RuntimeMaintenance.read(root, hash)) { "Imported startup requires its retained fence" }
        require(fence.id == expectedFence && fence.reason == "restore" && fence.stageTarget == null)
        val jobs = readJobs(spec, root, hash)
        require(jobs.started.isEmpty() && jobs.completed.isEmpty()) { "Imported startup cannot inherit initializer history" }
        require(all.all { owned(spec, "container", it.id, hash) == null }) { "Imported startup already attempted; no replay" }
        val resources = spec.networks.size + spec.volumes.size + all.flatMap { it.files }.map { it.file }.distinct().size
        require(resourceCount(spec, hash, all) == resources) { "Imported startup cannot recreate missing runtime resources" }
        try {
            RuntimeMaintenance.remove(root, hash, expectedFence)
            applyLocked(spec, null, false, root, hash, all)
        } catch (error: Exception) {
            val interrupted = Thread.interrupted() || error is InterruptedException
            try {
                // Fence BEFORE stop. Failure of either must not hide the original uncertainty.
                try { RuntimeMaintenance.create(root, hash, "restore", null) } catch (failure: Exception) { error.addSuppressed(failure) }
                try { stopProcesses(spec, all) } catch (failure: Exception) { error.addSuppressed(failure) }
            } finally { if (interrupted || error.suppressed.any { it is InterruptedException }) Thread.currentThread().interrupt() }
            throw error
        }
    }

    /** Only the imported Planka database is allowed to run under the retained restore fence;
     * the application/other providers remain absent until native role-retired migration proof. */
    fun startImportedMigrationDatabase(spec: PrivateDeploymentSpec, expectedFence: String): List<RuntimeStatus> =
        locked(spec) { root, hash, all ->
            require(spec.ingress == null && all.none { it.oneShot } &&
                all.single { it.id == "planka" }.environmentFile == "planka.env")
            requireImportComplete(root, hash)
            val fence = requireNotNull(RuntimeMaintenance.read(root, hash))
            require(fence.reason == "restore" && fence.stageTarget == null && fence.id == expectedFence &&
                Files.exists(root.resolve("runtime.import.complete"), NOFOLLOW_LINKS))
            val jobs = readJobs(spec, root, hash)
            require(jobs.started.isEmpty() && jobs.completed.isEmpty() &&
                all.all { owned(spec, "container", it.id, hash) == null }) { "Migration database start already attempted" }
            val resources = spec.networks.size + spec.volumes.size + all.flatMap { it.files }.map { it.file }.distinct().size
            require(resourceCount(spec, hash, all) == resources)
            applyLocked(spec, "postgres", false, root, hash, all, ownedMigration = true)
        }

    /** Completes the same imported cohort, without restarting or reimporting the database.
     * The caller has already checked the immutable Knex migration and native NOLOGIN readback. */
    fun startImportedOwned(spec: PrivateDeploymentSpec, expectedFence: String): List<RuntimeStatus> =
        locked(spec) { root, hash, all ->
            require(spec.ingress == null && all.none { it.oneShot })
            requireImportComplete(root, hash)
            val fence = requireNotNull(RuntimeMaintenance.read(root, hash))
            require(fence.reason == "restore" && fence.stageTarget == null && fence.id == expectedFence &&
                all.single { it.id == "postgres" }.id == "postgres" && all.any { it.id == "planka" })
            val db = owned(spec, "container", "postgres", hash)?.getValue("State")?.jsonObject
            require(db?.getValue("Running")?.jsonPrimitive?.boolean == true &&
                all.filter { it.id != "postgres" }.all { owned(spec, "container", it.id, hash) == null }) {
                "Only the isolated migration database may precede Planka owned startup"
            }
            try {
                RuntimeMaintenance.remove(root, hash, expectedFence)
                applyLocked(spec, null, false, root, hash, all)
            } catch (error: Exception) {
                val interrupted = Thread.interrupted() || error is InterruptedException
                try {
                    try { RuntimeMaintenance.create(root, hash, "restore", null) }
                    catch (failure: Exception) { error.addSuppressed(failure) }
                    try { stopProcesses(spec, all) }
                    catch (failure: Exception) { error.addSuppressed(failure) }
                } finally { if (interrupted || error.suppressed.any { it is InterruptedException }) Thread.currentThread().interrupt() }
                throw error
            }
        }

    private fun applySelected(spec: PrivateDeploymentSpec, target: String?, pristine: Boolean = false): List<RuntimeStatus> = locked(spec) { root, hash, all ->
        applyLocked(spec, target, pristine, root, hash, all)
    }
    private fun applyLocked(spec: PrivateDeploymentSpec, target: String?, pristine: Boolean,
        root: Path, hash: String, all: List<RuntimeProcess>, ownedMigration: Boolean = false): List<RuntimeStatus> {
        requireImportComplete(root, hash)
        // Close the gap between a group preflight and this member's first allocation.
        if (pristine) requirePristine(spec, root, hash, all)
        val fence = RuntimeMaintenance.read(root, hash)
        require(fence == null || (target != null && target == fence.stageTarget) ||
            (ownedMigration && target == "postgres" && fence?.reason == "restore" && fence.stageTarget == null)) {
            "Maintenance fence blocks startup"
        }
        val selected = mutableSetOf<String>()
        fun include(id: String) {
            if (selected.add(id)) all.single { it.id == id }.dependencies.forEach(::include)
        }
        if (target == null) all.forEach { selected += it.id } else include(target)
        all.filter { it.id !in selected }.forEach { p ->
            val state = owned(spec, "container", p.id, hash)?.getValue("State")?.jsonObject
            require(state == null || !state.getValue("Running").jsonPrimitive.boolean) { "Non-staged process is running: ${p.id}" }
        }
        val ordered = all.filter { it.id in selected }
        var jobs = readJobs(spec, root, hash)
        if (backupAccess != null) {
            require(jobs.started == jobs.completed && jobs.completed == all.filter { it.oneShot }.map { it.id }.toSet()) {
                "Backup resume cannot replay initialization"
            }
            val expectedResources = spec.networks.size + spec.volumes.size + all.flatMap { it.files }.map { it.file }.distinct().size + all.size
            require(resourceCount(spec, hash, all) == expectedResources) { "Backup resume cannot recreate missing runtime resources" }
        }
        require(fence == null || ordered.filter { it.oneShot }.all { it.id in jobs.completed }) {
            "Maintenance staging cannot run unfinished initialization"
        }
        provisionResources(spec, root, hash, all)
        val labels = listOf("--label=$OWNER=${spec.name}", "--label=$HASH=$hash")
        ordered.forEach { p ->
            val container = name(spec, p.id)
            val present = exists("container", container)
            if (p.id == "livekit" && spec.store == RuntimeStore.CANONICAL_V2 &&
                Files.exists(root.resolve("turn-revisions"), NOFOLLOW_LINKS)) {
                // Never silently rebuild an effective public TURN process from sealed
                // disabled-bootstrap argv after an uncertain native revision write.
                require(present && Files.exists(root.resolve("turn-revisions/operations"), NOFOLLOW_LINKS)) {
                    "Effective TURN container lost; explicit native reconciliation required"
                }
                val sourceGeneration = spec.name.take(14)
                require(sourceGeneration.matches(Regex("q-[a-f0-9]{12}")))
                Files.list(root.resolve("turn-revisions/operations")).use { entries -> entries.forEach { entry ->
                    val match = Regex("([a-z0-9-]{1,64})\\.(intent|result)\\.json")
                        .matchEntire(entry.fileName.toString())
                    requireNotNull(match)
                    val attempt = match.groupValues[1]
                    require(Files.exists(root.resolve("turn-revisions/operations/$attempt.intent.json"), NOFOLLOW_LINKS) &&
                        Files.exists(root.resolve("turn-revisions/operations/$attempt.result.json"), NOFOLLOW_LINKS) &&
                        Files.exists(GenerationRuntime.BASE.resolve(sourceGeneration).resolve(
                            "credential-revisions/public/turn/$attempt.result.json"), NOFOLLOW_LINKS)) {
                        "Effective TURN attempt still lacks exact independent native receipt"
                    }
                } }
            }
            if (p.oneShot && p.id in jobs.completed) {
                if (present) {
                    val state = inspect("container", container).getValue("State").jsonObject
                    require(state.getValue("Status").jsonPrimitive.content == "exited" && state.getValue("ExitCode").jsonPrimitive.int == 0) {
                        "Completed initialization container changed: ${p.id}"
                    }
                }
                return@forEach
            }
            require(!p.oneShot || p.id !in jobs.started || present) { "Missing in-flight initialization; manual reconciliation required: ${p.id}" }
            if (!present) {
                val args = mutableListOf("create", "--name=$container", "--pull=never", *p.networks.map { network ->
                    "--network=${name(spec, network)}" + p.networkAliases.filter { it.network == network }
                        .joinToString(separator = ",", prefix = if (p.networkAliases.any { it.network == network }) ":" else "") { "alias=${it.host}" }
                }.toTypedArray(),
                    "--network-alias=${p.id}", "--read-only", "--cap-drop=all", "--security-opt=no-new-privileges",
                    "--user=${p.userId}:${p.groupId}", "--memory=${p.memoryMiB}m", "--pids-limit=512", "--stop-timeout=30", "--image-volume=ignore")
                args += labels
                p.apparmorProfile?.let { args += "--security-opt=apparmor=$it" }
                p.capabilities.forEach { args += "--cap-add=$it" }
                if (p.id == "caddy") spec.ingress?.let { ingress ->
                    listOf(80, 443).forEach { port -> args += "--publish=${ingress.listenAddress}:$port:$port/tcp" }
                }
                p.tmpfs.forEach { args += "--tmpfs=$it:rw,nosuid,nodev,mode=1777,size=128m" }
                p.volumes.forEach { args += "--volume=${name(spec, "volume-${it.volume}")}:${it.target}:U" }
                p.files.forEach { args += "--secret=${name(spec, "file-${it.file}")},type=mount,target=${it.target},uid=${p.userId},gid=${p.groupId},mode=0400" }
                p.environmentFile?.let { args += "--env-file=${root.resolve(it)}" }
                p.lateEnvironmentFile?.let { args += "--env-file=${root.resolve(it)}" }
                p.entrypoint?.let { args += "--entrypoint=$it" }
                args += p.image
                args += p.command
                call(*args.toTypedArray())
            }
            var state = requireNotNull(owned(spec, "container", p.id, hash)).getValue("State").jsonObject
            val status = state.getValue("Status").jsonPrimitive.content
            if (p.oneShot && status == "exited") {
                require(state.getValue("ExitCode").jsonPrimitive.int == 0) { "Failed initialization requires reconciliation: ${p.id}" }
            } else {
                if (p.oneShot && p.id !in jobs.started) {
                    jobs = jobs.copy(started = jobs.started + p.id)
                    saveJobs(root, jobs)
                }
                if (!state.getValue("Running").jsonPrimitive.boolean) call("start", container)
                if (p.oneShot) {
                    var completed = false
                    // Only retry the read-only wait observer, never start/replay the initialization job.
                    // Each real transport wait is bounded to 120 seconds; retain state after five timeouts.
                    repeat(5) {
                        if (!completed) try {
                            require(call("wait", container) == "0") { "Initialization failed: ${p.id}; state retained" }
                            completed = true
                        } catch (_: PrivateCommandTimeout) { /* The container may still be making progress. */ }
                    }
                    check(completed) { "Initialization wait budget exhausted: ${p.id}; state retained" }
                } else {
                    var ready = false
                    val deadline = System.nanoTime() + java.time.Duration.ofMinutes(10).toNanos()
                    for (attempt in 0 until 1200) {
                        if (System.nanoTime() >= deadline) break
                        val current = inspect("container", container)
                        state = current.getValue("State").jsonObject
                        check(state.getValue("Running").jsonPrimitive.boolean) { "Runtime daemon exited: ${p.id}" }
                        val healthy = if (p.readinessHttpPort != null) {
                            val network = current.getValue("NetworkSettings").jsonObject.getValue("Networks").jsonObject.getValue(name(spec, p.networks.first())).jsonObject
                            httpReady(network.getValue("IPAddress").jsonPrimitive.content, p.readinessHttpPort, p.readinessHttpPath)
                        } else commands.run(listOf("exec", container) + p.readiness).exitCode == 0
                        if (healthy) { ready = true; break }
                        pause()
                    }
                    check(ready) { "Runtime readiness failed: ${p.id}; state retained" }
                }
            }
            if (p.oneShot) {
                jobs = jobs.copy(started = jobs.started + p.id, completed = jobs.completed + p.id)
                saveJobs(root, jobs)
            }
        }
        return statuses(spec, jobs.completed)
    }
    /** Holds the actual runtime lock throughout a cold read; fencing alone is insufficient. */
    fun <T> withFrozen(spec: PrivateDeploymentSpec, expectedFence: String, action: (FrozenRuntimeObservation) -> T): T = locked(spec) { root, hash, _ ->
        fun observe(): FrozenRuntimeObservation {
            val fence = requireNotNull(RuntimeMaintenance.read(root, hash)) { "Cold capture requires maintenance" }
            require(fence.id == expectedFence) { "Cold capture fence changed" }
            val jobs = readJobs(spec, root, hash)
            require(jobs.completed == spec.processes.filter { it.oneShot }.map { it.id }.toSet() && jobs.started == jobs.completed) {
                "Cold capture requires completed initialization, not uncertain jobs"
            }
            val states = statuses(spec, jobs.completed)
            require(spec.processes.all { process -> states.single { it.id == process.id }.let {
                if (process.oneShot) it.state in setOf("completed", "exited") && it.exitCode == 0
                else it.state == "exited" && it.exitCode in setOf(0, 143)
            } }) { "Cold capture requires every daemon to be present and cleanly stopped" }
            val ledger = root.resolve("runtime.jobs")
            val ledgerHash = if (Files.exists(ledger, NOFOLLOW_LINKS)) ReleaseLocks.sha256(ReleaseLocks.privateBytes(ledger))
                else ReleaseLocks.sha256("no-initializers\n$hash\n".toByteArray())
            return FrozenRuntimeObservation(spec.name, hash, fence.id, ledgerHash, jobs.completed, states)
        }
        val before = observe()
        val result = action(before)
        require(fingerprint(spec, root) == hash && observe() == before) { "Runtime changed during cold capture" }
        result
    }

    private fun requireBackupReady(spec: PrivateDeploymentSpec, root: Path, hash: String) {
        requireImportComplete(root, hash)
        val jobs = readJobs(spec, root, hash)
        require(jobs.started == jobs.completed && jobs.completed == spec.processes.filter { it.oneShot }.map { it.id }.toSet()) {
            "Routine backup cannot complete or replay initialization"
        }
        val states = statuses(spec, jobs.completed)
        require(spec.processes.all { p -> states.single { it.id == p.id }.let {
            if (p.oneShot) it.state in setOf("completed", "exited") && it.exitCode == 0 else it.state == "running"
        } }) { "Backup lease requires a fully running initialized member" }
    }
    fun claimBackup(spec: PrivateDeploymentSpec) = locked(spec, allowMissingBackup = true) { root, hash, _ ->
        val access = requireNotNull(backupAccess)
        require(RuntimeMaintenance.read(root, hash) == null) { "Existing maintenance fence cannot become a backup lease" }
        requireBackupReady(spec, root, hash)
        RuntimeBackupLeases.create(root, spec.name, hash, access)
    }
    fun finishBackup(spec: PrivateDeploymentSpec) = locked(spec) { root, hash, _ ->
        require(RuntimeMaintenance.read(root, hash) == null) { "Backup cannot release a stopped-state fence implicitly" }
        requireBackupReady(spec, root, hash)
        RuntimeBackupLeases.remove(root, spec.name, hash, requireNotNull(backupAccess))
    }
    /** Stop-only authority also covers members not yet leased or already released by this attempt. */
    fun isolateBackup(spec: PrivateDeploymentSpec): String = locked(spec, allowMissingBackup = true) { root, hash, ordered ->
        val access = requireNotNull(backupAccess); access.validate()
        require(spec.name.startsWith(access.generation + "-"))
        val prior = RuntimeMaintenance.read(root, hash)
        val fence = RuntimeMaintenance.create(root, hash, prior?.reason ?: "backup", prior?.stageTarget)
        stopProcesses(spec, ordered)
        fence.id
    }
    fun stop(spec: PrivateDeploymentSpec): List<RuntimeStatus> = locked(spec) { root, hash, ordered ->
        val jobs = readJobs(spec, root, hash)
        stopProcesses(spec, ordered)
        statuses(spec, jobs.completed)
    }
    private fun stopProcesses(spec: PrivateDeploymentSpec, ordered: List<RuntimeProcess>) {
        var failure: Exception? = null
        ordered.asReversed().forEach { p ->
            try {
                val container = name(spec, p.id)
                if (exists("container", container) && inspect("container", container).getValue("State").jsonObject.getValue("Running").jsonPrimitive.boolean) {
                    call("stop", "--time=30", container)
                    val state = inspect("container", container).getValue("State").jsonObject
                    check(!state.getValue("Running").jsonPrimitive.boolean && state.getValue("ExitCode").jsonPrimitive.int in setOf(0, 143)) {
                        "Unclean runtime shutdown: ${p.id}; retained state needs recovery checks"
                    }
                }
            } catch (interrupted: InterruptedException) {
                Thread.currentThread().interrupt()
                throw interrupted
            } catch (error: Exception) {
                // A failed/unclean stop must not leave unrelated earlier members running. No retries.
                if (failure == null) failure = error else failure!!.addSuppressed(error)
            }
        }
        failure?.let { throw it }
    }
    fun enterMaintenance(spec: PrivateDeploymentSpec, reason: String, target: String? = null): MaintenanceFence {
        RuntimeMaintenance.validate(reason)
        require(target == null || validate(spec).any { it.id == target && !it.oneShot }) { "Unknown or one-shot maintenance target" }
        return locked(spec) { root, hash, ordered ->
            readJobs(spec, root, hash)
            val fence = RuntimeMaintenance.create(root, hash, reason, target) // Persist before any stop; failures retain it.
            stopProcesses(spec, ordered)
            fence
        }
    }
    fun maintenanceStatus(spec: PrivateDeploymentSpec): MaintenanceFence? = locked(spec, observation = true) { root, hash, _ -> RuntimeMaintenance.read(root, hash) }
    fun leaveMaintenance(spec: PrivateDeploymentSpec, id: String) = locked(spec) { root, hash, ordered ->
        requireImportComplete(root, hash)
        require(ordered.all { p -> owned(spec, "container", p.id, hash)?.getValue("State")?.jsonObject?.getValue("Running")?.jsonPrimitive?.boolean != true }) {
            "Stop all staged processes before releasing maintenance"
        }
        RuntimeMaintenance.remove(root, hash, id)
    }
    fun status(spec: PrivateDeploymentSpec): List<RuntimeStatus> = locked(spec, observation = true) { root, hash, _ -> statuses(spec, readJobs(spec, root, hash).completed) }
    private fun statuses(spec: PrivateDeploymentSpec, completed: Set<String>): List<RuntimeStatus> = spec.processes.map { p ->
        val resource = name(spec, p.id)
        if (!exists("container", resource)) RuntimeStatus(p.id, if (p.id in completed) "completed" else "absent", if (p.id in completed) 0 else null)
        else inspect("container", resource).getValue("State").jsonObject.let {
            RuntimeStatus(p.id, it.getValue("Status").jsonPrimitive.content, it.getValue("ExitCode").jsonPrimitive.int)
        }
    }
}

/** Fixed production native credential actor: no caller-selected command or alternate store. */
internal class NativePrivateTurnCredentialActuator : NativeTurnCredentialActuator {
    override fun adopt(bundle: GenerationBundle, process: GenerationPin, operationId: String,
        inputs: Map<String, String>): PublicTurnNativeObservation =
        PrivateDeployment.real(bundle.members.associate { it.member.name to it.runtimeFingerprint })
            .adoptEffectiveTurn(bundle, process, operationId, inputs)
}
