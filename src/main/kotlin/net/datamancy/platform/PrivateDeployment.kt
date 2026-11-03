package net.datamancy.platform

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

@Serializable data class RuntimeVolume(val id: String, val userId: Int)
@Serializable data class RuntimeMount(val volume: String, val target: String)
@Serializable data class RuntimeFile(val file: String, val target: String)
@OptIn(ExperimentalSerializationApi::class)
@Serializable data class RuntimeProcess(val id: String, val image: String, val imageId: String,
    val userId: Int, val groupId: Int = userId, val dependencies: List<String> = emptyList(),
    val entrypoint: String? = null, val command: List<String> = emptyList(), val environmentFile: String? = null,
    val volumes: List<RuntimeMount> = emptyList(), val files: List<RuntimeFile> = emptyList(),
    val tmpfs: List<String> = listOf("/tmp"), val readiness: List<String> = emptyList(), val oneShot: Boolean = false,
    val memoryMiB: Int = 512, val capabilities: List<String> = emptyList(), val apparmorProfile: String? = null,
    val readinessHttpPort: Int? = null, val readinessHttpPath: String = "/",
    @EncodeDefault(EncodeDefault.Mode.NEVER) val networks: List<String> = listOf("net"))
/** Logical network writer; provider storage ownership is not application schema ownership. */
@Serializable data class RuntimeDatabaseAccess(val consumer: String, val provider: String, val volume: String,
    val database: String, val principal: String, val credentialFile: String, val network: String)
/** Explicit owned public ingress, never generic arbitrary host-port publication. */
@Serializable data class RuntimeIngressPublication(val site: String, val approvedHosts: Set<String>, val listenAddress: String)
@OptIn(ExperimentalSerializationApi::class)
@Serializable data class PrivateDeploymentSpec(val schemaVersion: Int = 1, val name: String,
    val volumes: List<RuntimeVolume>, val processes: List<RuntimeProcess>,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val networks: List<String> = listOf("net"),
    @EncodeDefault(EncodeDefault.Mode.NEVER) val databaseAccess: List<RuntimeDatabaseAccess> = emptyList(),
    @EncodeDefault(EncodeDefault.Mode.NEVER) val store: RuntimeStore = RuntimeStore.LEGACY,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val ingress: RuntimeIngressPublication? = null)
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
        private val absolute = Regex("/(?:[a-zA-Z0-9_-]+/)*[a-zA-Z0-9_.-]+")
        private const val OWNER = "io.p0v3.private-deployment"
        private const val HASH = "io.p0v3.runtime-fingerprint"
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
            require(spec.schemaVersion == 1 && slug.matches(spec.name) && spec.processes.size in 1..128 && spec.volumes.size <= 128)
            require(spec.processes.map { it.id }.distinct().size == spec.processes.size &&
                spec.volumes.map { it.id }.distinct().size == spec.volumes.size) { "Duplicate runtime resource" }
            val volumes = spec.volumes.associateBy { it.id }
            require(volumes.values.all { slug.matches(it.id) && it.userId in 1..65534 })
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
            require(spec.networks.size in 1..32 && spec.networks.distinct() == spec.networks && spec.networks.all(slug::matches)) {
                "Distinct owned internal networks required"
            }
            for (p in spec.processes) {
                require(p.networks.isNotEmpty() && p.networks.distinct() == p.networks && spec.networks.containsAll(p.networks)) {
                    "Process uses an undeclared or duplicate network"
                }
                require(slug.matches(p.id) && p.userId in 1..65534 && p.groupId in 0..65534 && p.memoryMiB in 64..16384 &&
                    p.image.matches(Regex("[a-z0-9.-]+/[a-zA-Z0-9/_.-]+@sha256:[a-f0-9]{64}")) &&
                    p.imageId.matches(Regex("[a-f0-9]{64}"))) { "Invalid or mutable runtime image/identity" }
                require(p.dependencies.distinct().size == p.dependencies.size && p.dependencies.all { it in byId && it != p.id })
                require(p.apparmorProfile == null || p.apparmorProfile == "p0v3-private-v1") { "Unapproved AppArmor profile" }
                require(p.environmentFile == null || (fileName.matches(p.environmentFile) && !p.environmentFile.startsWith("runtime.")))
                require(p.entrypoint == null || absolute.matches(p.entrypoint))
                require(p.command.size <= 128 && p.command.all { it.length <= 32768 && '\u0000' !in it })
                require(p.oneShot || (p.readiness.isNotEmpty() xor (p.readinessHttpPort != null))) { "Exactly one daemon readiness probe required" }
                require(p.readinessHttpPort == null || p.readinessHttpPort in 1..65535)
                require(p.readinessHttpPath.matches(Regex("/[a-zA-Z0-9/_.-]*")) &&
                    p.readinessHttpPath.split('/').none { it == "." || it == ".." }) { "Unsafe readiness path" }
                require(p.readiness.size <= 64 && p.readiness.all { it.isNotEmpty() && it.length <= 2048 && '\u0000' !in it })
                require(p.volumes.all { volumes[it.volume]?.userId == p.userId && absolute.matches(it.target) && it.target != "/" } &&
                    p.files.all { fileName.matches(it.file) && !it.file.startsWith("runtime.") && absolute.matches(it.target) } &&
                    p.tmpfs.all { absolute.matches(it) } && p.capabilities.distinct().size == p.capabilities.size &&
                    p.capabilities.all { it == "NET_BIND_SERVICE" && p.id == "caddy" }) { "Unsafe runtime mount or capability" }
                val targets = p.volumes.map { it.target } + p.files.map { it.target } + p.tmpfs
                require(targets.distinct().size == targets.size && targets.none { "/../" in it || it.endsWith("/..") || it.endsWith("/.") })
            }
            require(spec.networks.all { network -> spec.processes.any { network in it.networks } }) { "Orphan network" }
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
            require(volumes.keys.all { id -> spec.processes.any { p -> p.volumes.any { it.volume == id } } }) { "Orphan volume" }
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
        Files.list(root).use { paths -> require(paths.allMatch { it.fileName.toString() in inputs + setOf("runtime.owner", "runtime.lock", "runtime.jobs", "runtime.import.intent", "runtime.import.complete", RuntimeMaintenance.FILE, RuntimeMaintenance.TEMP, RuntimeBackupLeases.FILE) }) { "Unexpected runtime directory entry" } }
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
        if (runtimeStore != spec.store) return PrivateDeployment(base,
            if (commands is PrivateRootfulCommands) commands.scoped(spec.store) else commands,
            httpReady, boundFingerprints, backupAccess, spec.store, ingressPortOwner, pause).locked(spec, observation, allowMissingBackup, action)
        val ordered = validate(spec)
        guardDirectory(base)
        val root = base.resolve(spec.name)
        guardDirectory(root)
        val lock = root.resolve("runtime.lock")
        return FileChannel.open(lock, setOf(CREATE, WRITE, NOFOLLOW_LINKS),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))).use { channel -> channel.lock().use {
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
        } }
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
        restoreRoot: (PrivateDeploymentSpec, RuntimeVolume, VolumeTarEntry) -> Unit = ColdVolumeImport::restoreRoot,
        export: (PrivateDeploymentSpec, RuntimeVolume, Path) -> Unit = ColdVolumeExport::export): MaintenanceFence = locked(spec) { root, hash, ordered ->
        require(spec.ingress == null && spec.name.matches(Regex("q-[a-f0-9]{12}-[a-z][a-z0-9-]{0,23}")) && ordered.none { it.oneShot } &&
            sourceArchiveSha256.matches(Regex("[a-f0-9]{64}")) && archives.keys == spec.volumes.map { it.id }.toSet() &&
            expectedHashes.keys == archives.keys && expectedHashes.values.all { it.matches(Regex("[a-f0-9]{64}")) }) { "Fresh retired-initializer restore definition required" }
        guardDirectory(verificationRoot)
        requirePristine(spec, root, hash, ordered)
        require(!Files.exists(root.resolve("runtime.import.intent"), NOFOLLOW_LINKS) && !Files.exists(root.resolve("runtime.import.complete"), NOFOLLOW_LINKS))
        val trees = spec.volumes.associate { it.id to VolumeTar.inspect(archives.getValue(it.id), it.userId) }
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
            restoreRoot(spec, volume, trees.getValue(volume.id).single { it.path == "." })
            val observed = verificationRoot.resolve("${volume.id}.tar")
            export(spec, volume, observed)
            require(VolumeTar.inspect(observed, volume.userId) == trees.getValue(volume.id) &&
                RecoveryCapsule.fileHash(archive) == hashes.getValue(volume.id)) { "Imported state differs from authenticated source" }
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

    private fun applySelected(spec: PrivateDeploymentSpec, target: String?, pristine: Boolean = false): List<RuntimeStatus> = locked(spec) { root, hash, all ->
        applyLocked(spec, target, pristine, root, hash, all)
    }
    private fun applyLocked(spec: PrivateDeploymentSpec, target: String?, pristine: Boolean,
        root: Path, hash: String, all: List<RuntimeProcess>): List<RuntimeStatus> {
        requireImportComplete(root, hash)
        // Close the gap between a group preflight and this member's first allocation.
        if (pristine) requirePristine(spec, root, hash, all)
        val fence = RuntimeMaintenance.read(root, hash)
        require(fence == null || (target != null && target == fence.stageTarget)) { "Maintenance fence blocks startup" }
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
                val args = mutableListOf("create", "--name=$container", "--pull=never", *p.networks.map { "--network=${name(spec, it)}" }.toTypedArray(),
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
