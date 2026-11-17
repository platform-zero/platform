package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import com.sun.security.auth.module.UnixSystem
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** Parse actual kernel user-namespace mappings, never a Podman inspect field or
 * launch-text assertion. Reject ambiguous, overflowing or overlapping UID/GID ranges. */
internal object QualificationClientUidMapping {
    private const val MAX_UID = 4294967295L
    fun hostId(mapping: String, containerId: Long = 1000): Long {
        require(containerId in 1..MAX_UID && mapping.length in 1..4096)
        val lines = mapping.trimEnd('\n').lines()
        require(lines.size in 1..16)
        val entries = lines.map { line ->
            val fields = line.trim().split(Regex("\\s+"))
            require(fields.size == 3 && fields.all { it.matches(Regex("[0-9]{1,10}")) })
            val (inside, outside, count) = fields.map(String::toLong)
            require(count in 1..MAX_UID && inside in 0..MAX_UID && outside in 0..MAX_UID &&
                inside <= MAX_UID - count + 1 && outside <= MAX_UID - count + 1)
            Triple(inside, outside, count)
        }
        for (i in entries.indices) for (j in 0 until i) {
            val a = entries[i]; val b = entries[j]
            require(a.first + a.third <= b.first || b.first + b.third <= a.first)
            require(a.second + a.third <= b.second || b.second + b.third <= a.second)
        }
        val matched = entries.filter { containerId >= it.first && containerId - it.first < it.third }
        require(matched.size == 1)
        return matched.single().let { it.second + containerId - it.first }
    }
    fun credentials(status: String, hostUid: Long, hostGid: Long) {
        require(status.length in 1..65536 && hostUid in 1..MAX_UID && hostGid in 1..MAX_UID)
        for ((field, expected) in listOf("Uid" to hostUid, "Gid" to hostGid)) {
            val lines = status.lineSequence().filter { it.startsWith("$field:") }.toList()
            require(lines.size == 1)
            val ids = lines.single().substringAfter(':').trim().split(Regex("\\s+"))
            require(ids.size == 4 && ids.all { it.matches(Regex("[0-9]{1,10}")) && it.toLong() == expected })
        }
    }
    fun observe(pid: Int) {
        require(pid > 1)
        val host = UnixSystem()
        require(host.uid > 0 && host.gid > 0)
        val root = Path.of("/proc/$pid")
        val before = Files.readAttributes(root, "unix:dev,ino", NOFOLLOW_LINKS)
        fun bounded(name: String, maximum: Int): String {
            val path = root.resolve(name)
            require(Files.isRegularFile(path, NOFOLLOW_LINKS))
            return Files.newBufferedReader(path).use { reader ->
                val buffer = CharArray(maximum + 1)
                var count = 0
                while (count <= maximum) {
                    val read = reader.read(buffer, count, buffer.size - count)
                    if (read < 0) break
                    require(read > 0)
                    count += read
                    require(count <= maximum)
                }
                require(count in 1..maximum)
                String(buffer, 0, count)
            }
        }
        require(hostId(bounded("uid_map", 4096), host.uid) == host.uid &&
            hostId(bounded("gid_map", 4096), host.gid) == host.gid)
        credentials(bounded("status", 65536), host.uid, host.gid)
        require(Files.readAttributes(root, "unix:dev,ino", NOFOLLOW_LINKS) == before)
    }
}

/** One native, image-pinned browser or Android client, not a Caddy namespace HTTP surrogate.
 * The caller retains its qualification/generation/source isolation locks until fenced(). A
 * lost run, nft, gate or stop acknowledgement is UNCERTAIN; no second client is started.
 */
@Serializable internal data class NativeSeafileToolPins(val seafCliSha256: String,
    val seafDaemonSha256: String, val seafileInitSha256: String,
    val seafileRpcSha256: String, val pysearpcInitSha256: String,
    val signedClosureSha256: String, val producerPublicKeySha256: String,
    val producerSignatureSha256: String, val opensslSha256: String)

@OptIn(ExperimentalSerializationApi::class)
@Serializable internal data class QualificationClientRequest(val operation: String, val generationId: String,
    val fingerprint: String, val invocationId: String, val caseDirectory: String, val caseIntentSha256: String,
    val suiteDirectory: String, val runnerSha256: String, val adapterSha256: String,
    val serviceId: String, val surface: String, val variant: String, val phase: String,
    val certificate: ActivationInput, val certificateLeafSha256: String,
    val imageId: String, val pinnedImage: String, val imageManifestSha256: String,
    val maximumMemoryMiB: Int, val maximumDiskMiB: Int, val maximumPids: Int,
    val officialApk: ActivationInput? = null,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val secondaryOfficialApk: ActivationInput? = null,
    val sourceObservationSha256: String? = null,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val seafileToolPins: NativeSeafileToolPins? = null,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val clientMode: String = "NORMAL",
    @EncodeDefault(EncodeDefault.Mode.NEVER) val grafanaNativeOracle: ActivationInput? = null,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val grafanaNativeObservation: ActivationInput? = null,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val predecessorFiles: List<ActivationInput> = emptyList(),
    @EncodeDefault(EncodeDefault.Mode.NEVER) val credentialFiles: List<ActivationInput> = emptyList(),
    @EncodeDefault(EncodeDefault.Mode.NEVER) val identityPrivateFiles: List<ActivationInput> = emptyList(),
    @EncodeDefault(EncodeDefault.Mode.NEVER) val hubPrivateFiles: List<ActivationInput> = emptyList(),
    @EncodeDefault(EncodeDefault.Mode.NEVER) val ntfyPrivateFiles: List<ActivationInput> = emptyList(),
    @EncodeDefault(EncodeDefault.Mode.NEVER) val filesNativeCa: ActivationInput? = null,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val hubHomeReadOnlyPaths: List<String> = emptyList(),
    @EncodeDefault(EncodeDefault.Mode.NEVER) val officePrivateFiles: List<ActivationInput> = emptyList(),
    @EncodeDefault(EncodeDefault.Mode.NEVER) val seafilePrivateFiles: List<ActivationInput> = emptyList(),
    @EncodeDefault(EncodeDefault.Mode.NEVER) val publicCertificateRevisions: Map<String, ActivationInput> = emptyMap(),
    @EncodeDefault(EncodeDefault.Mode.NEVER) val nativeCaseClaimSha256: String? = null,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val suiteClosure: QualificationClientSuite? = null)

/** This record is a durable POLICY, not proof that guest TURN/media returned. A07 independently
 * supplies native conntrack, guest packet and LiveKit packet/return readback. */
@Serializable internal data class QualificationTurnPolicy(val operation: String, val invocationId: String,
    val generationId: String, val clientNetwork: String = "qualification-web",
    val rtcHost: String = "matrix-rtc.datamancy.net", val caddyClientIp: String, val livekitClientIp: String,
    val containerId: String, val containerPid: Int, val containerNetnsInode: Long,
    val nftTable: String, val udpPort: Int = 3478, val tlsPort: Int = 5349,
    val deniedTcpPort: Int = 7880, val deniedUdpStart: Int = 50000, val deniedUdpEnd: Int = 50020,
    val rulesSha256: String, val nativeRulesReadbackSha256: String)

@Serializable internal data class QualificationClientIntent(val requestSha256: String,
    val containerName: String, val generationFingerprint: String, val network: String,
    val caddyIp: String, val livekitIp: String)
@Serializable internal data class QualificationClientNative(val containerId: String, val pid: Int,
    val netnsInode: Long, val clientIp: String, val imageId: String)
@Serializable internal data class QualificationClientFence(val invocationId: String, val generationId: String,
    val containerId: String, val clientNetnsInode: Long, val stoppedContainerStateSha256: String,
    val nativeClientReceiptSha256: String,
    val caAdoptionSha256: String? = null)
/** Host-side QEMU parentage only. Never substitutes for Android-guest kernel/iptables proof. */
@Serializable internal data class QualificationGuestBridge(val invocationId: String, val generationId: String,
    val containerId: String, val containerPid: Int, val containerNetnsInode: Long,
    val emulatorHostPid: Int, val emulatorHostNetnsInode: Long, val role: String,
    val serial: String, val avd: String, val guestPolicyFile: String)

/** Durable fence PLUS live Podman identity and vanished namespace; never a caller Boolean. */
internal fun nativeQualificationClientFence(generationId: String, spec: PrivateDeploymentSpec,
    fence: QualificationClientFence): QualificationClientFence {
    require(generationId.matches(Regex("q-[a-f0-9]{12}")) && spec.name.startsWith("$generationId-") &&
        fence.generationId == generationId && fence.invocationId.matches(Regex("[a-z][a-z0-9-]{0,95}")) &&
        fence.containerId.matches(Regex("[a-f0-9]{64}")) && fence.clientNetnsInode > 1)
    val root = GenerationRuntime.BASE.resolve(generationId).resolve("qualification-client").resolve(fence.invocationId)
    val json = Json { ignoreUnknownKeys = false }
    val saved = json.decodeFromString<QualificationClientFence>(ReleasePrivateFiles.read(root.resolve("fenced.json")).decodeToString())
    val native = json.decodeFromString<QualificationClientNative>(ReleasePrivateFiles.read(root.resolve("native.json")).decodeToString())
    require(saved == fence && native.containerId == fence.containerId &&
        native.netnsInode == fence.clientNetnsInode &&
        !Files.exists(Path.of("/proc/${native.pid}/ns/net"), NOFOLLOW_LINKS))
    val result = PrivateRootfulCommands(30, spec.store).run(listOf("inspect", "--type", "container",
        "p0v3-qc-$generationId-${fence.invocationId}"))
    require(result.exitCode == 0 && result.output.length in 1..262144 &&
        json.parseToJsonElement(result.output).jsonArray.single().jsonObject.let { container ->
            container.getValue("Id").jsonPrimitive.content == fence.containerId &&
                !container.getValue("State").jsonObject.getValue("Running").jsonPrimitive.boolean
        }) { "An unfenced or restarted official client blocks bridge removal" }
    return saved
}

internal fun admittedSeafileTools(request: QualificationClientRequest, approvedHosts: Set<String>,
    reviewedProducerKeySha256: String?): Boolean {
    val pins = request.seafileToolPins
    if (request.serviceId != "seafile" || request.surface != "HEADLESS" || request.variant != "NATIVE")
        return pins == null
    val hash = Regex("[a-f0-9]{64}")
    return pins != null && "files.datamancy.net" in approvedHosts &&
        reviewedProducerKeySha256?.matches(hash) == true &&
        pins.producerPublicKeySha256 == reviewedProducerKeySha256 &&
        listOf(pins.seafCliSha256, pins.seafDaemonSha256, pins.seafileInitSha256,
            pins.seafileRpcSha256, pins.pysearpcInitSha256, pins.signedClosureSha256,
            pins.producerPublicKeySha256, pins.producerSignatureSha256, pins.opensslSha256)
            .all(hash::matches)
}

/** Fixed rootful Podman store and fixed host nsenter + nft binary. No shell, caller command,
 * public port, global DNS/trust, registry pull, installation or host firewall change. */
internal class QualificationClientRuntime(private val root: Path, private val spec: PrivateDeploymentSpec,
    private val generationId: String, private val fingerprint: String, private val inventory: AcquiredInventory,
    private val approvedHosts: Set<String>, private val podman: RuntimeCommands,
    private val address: (String) -> String,
    private val namespace: (Int, List<String>, ByteArray?) -> RuntimeCommandResult,
    private val generationBase: Path = GenerationRuntime.BASE,
    private val capacity: () -> GenerationCapacity = {
        val mem = Files.readAllLines(Path.of("/proc/meminfo")).first { it.startsWith("MemAvailable:") }
            .split(Regex("\\s+")).filter { it.isNotEmpty() }[1].toLong() / 1024L
        GenerationCapacity(mem, Files.getFileStore(root.parent).usableSpace / 1048576L)
    }, private val reviewedSeafileProducerPublicKeySha256: String? = null) {
    companion object {
        private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
        private val hash = Regex("[a-f0-9]{64}")
        private val id = Regex("[a-z][a-z0-9-]{0,95}")
        private val ip = Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")
        private const val NETWORK = "qualification-web"
        private val ownerMode = PosixFilePermissions.fromString("rwx------")
        private const val MAX_READBACK = 262144
        fun real(generation: Path, spec: PrivateDeploymentSpec, fingerprint: String,
            inventory: AcquiredInventory, approvedHosts: Set<String>,
            reviewedSeafileProducerPublicKeySha256: String? = null): QualificationClientRuntime {
            require(generation.parent == GenerationRuntime.BASE &&
                generation.fileName.toString().matches(Regex("q-[a-f0-9]{12}")) &&
                spec.name.startsWith("${generation.fileName}-") &&
                spec.store == RuntimeStore.CANONICAL_V2 && hash.matches(fingerprint))
            require(spec.ingress == null || spec.ingress!!.approvedHosts == approvedHosts)
            return QualificationClientRuntime(generation.resolve("qualification-client"), spec,
                generation.fileName.toString(), fingerprint, inventory,
                approvedHosts, PrivateRootfulCommands(120, spec.store),
                { process -> NamespaceCaddyTransport.ownedProcessAddress(spec, fingerprint, process, NETWORK) },
                ::nativeNamespace, reviewedSeafileProducerPublicKeySha256 = reviewedSeafileProducerPublicKeySha256)
        }
        private fun nativeNamespace(pid: Int, argv: List<String>, input: ByteArray?): RuntimeCommandResult {
            require(pid > 1 && argv.isNotEmpty() && argv[0] == "/usr/sbin/nft" &&
                (argv == listOf("/usr/sbin/nft", "-f", "-") ||
                    argv == listOf("/usr/sbin/nft", "-j", "list", "tables") ||
                    argv.size == 6 && argv.take(5) == listOf("/usr/sbin/nft", "-j", "list", "table", "inet") &&
                    argv.last().matches(Regex("p0v3_qc_[a-f0-9]{12}")) ||
                    argv.size == 5 && argv.take(4) == listOf("/usr/sbin/nft", "delete", "table", "inet") &&
                    argv.last().matches(Regex("p0v3_qc_[a-f0-9]{12}"))))
            val process = ProcessBuilder(listOf("sudo", "-n", "nsenter", "--target", pid.toString(), "--net", "--") + argv)
                .redirectErrorStream(false).start()
            if (input == null) process.outputStream.close() else process.outputStream.use { it.write(input) }
            if (!process.waitFor(15, TimeUnit.SECONDS)) {
                process.destroyForcibly().waitFor(); throw PrivateCommandTimeout()
            }
            val stdout = process.inputStream.readNBytes(MAX_READBACK + 1)
            require(stdout.size <= MAX_READBACK) { "Oversized native nft readback" }
            // Never return untrusted stderr or certificate/credential data to a caller/log.
            return RuntimeCommandResult(process.exitValue(), stdout.decodeToString(throwOnInvalidSequence = true))
        }
        /** Pure exact namespace policy; default DROP applies to IPv4 and IPv6 output/input.
         * TURN nat is scoped to original audited Caddy IP; conntrack reverses return translation.
         * Loopback is only for local Chrome/Android control, never another host network. */
        internal fun nftRules(table: String, caddy: String, livekit: String): ByteArray {
            require(table.matches(Regex("p0v3_qc_[a-f0-9]{12}")) && ip.matches(caddy) && ip.matches(livekit) && caddy != livekit &&
                java.net.InetAddress.getByName(caddy).isSiteLocalAddress &&
                java.net.InetAddress.getByName(livekit).isSiteLocalAddress)
            return """table inet $table {
                chain dst { type nat hook output priority dstnat; policy accept;
                    ip daddr $caddy udp dport 3478 counter dnat ip to $livekit:3478
                    ip daddr $caddy tcp dport 5349 counter dnat ip to $livekit:5349
                }
                chain out { type filter hook output priority filter; policy drop;
                    oifname "lo" accept
                    ip daddr $livekit tcp dport 7880 counter drop
                    ip daddr $livekit udp dport 50000-50020 counter drop
                    ip daddr $caddy tcp dport 443 counter accept
                    ip daddr $livekit udp dport 3478 counter accept
                    ip daddr $livekit tcp dport 5349 counter accept
                    counter drop
                }
                chain in { type filter hook input priority filter; policy drop;
                    iifname "lo" accept
                    ct state established,related counter accept
                }
            }
            """.trimIndent().encodeToByteArray()
        }
    }
    private fun dir() {
        ReleasePrivateFiles.directory(root.parent)
        require(root == root.parent.resolve("qualification-client") &&
            root.parent == generationBase.resolve(generationId))
        if (!Files.exists(root, NOFOLLOW_LINKS)) {
            Files.createDirectory(root, PosixFilePermissions.asFileAttribute(ownerMode))
            ReleasePrivateFiles.sync(root.parent)
        }
        ReleasePrivateFiles.directory(root)
    }
    private fun caseRoot(request: QualificationClientRequest): Path = root.resolve(request.invocationId)
    private fun record(path: Path): JsonObject = json.parseToJsonElement(ReleasePrivateFiles.read(path).decodeToString()).jsonObject

    /** The root-only post-intent claim authorizes ONE exact native case, not arbitrary
     * container control or access to the generation-private claim directory from QClient. */
    private fun nativeCaseGate(request: QualificationClientRequest) {
        val required = request.surface == "HEADLESS" && request.variant == "NATIVE" &&
            request.serviceId in setOf("alloy", "loki", "node-exporter", "onlyoffice",
                "opensearch", "crowdsec", "qbittorrent")
        if (!required) {
            require(request.nativeCaseClaimSha256 == null)
            return
        }
        val claimSha = requireNotNull(request.nativeCaseClaimSha256)
        require(claimSha.matches(hash))
        val claimBytes = ReleasePrivateFiles.read(generationBase.resolve(request.generationId)
            .resolve("native-qualification-claims/${request.invocationId}.json"), 8192)
        require(ReleaseLocks.sha256(claimBytes) == claimSha)
        val claim = json.parseToJsonElement(claimBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        NativeQualificationClaims.read(NativeQualificationCaseBinding(request.generationId,
            request.invocationId, request.caseDirectory, request.caseIntentSha256, claimSha,
            request.serviceId, request.phase, claim.getValue("targetMemberName").jsonPrimitive.content,
            claim.getValue("targetFingerprint").jsonPrimitive.content))
    }

    /** Current selected graph ingress is authenticated against the actual generation
     * CA and live Caddy SNI leaf, never a Mozilla fixture or fabricated ACME head.
     * Denial-only clients make no original-host HTTPS request. */
    private fun privateIngressGate(request: QualificationClientRequest, intent: JsonObject, suite: Path) {
        if (request.clientMode == "NATIVE_NETWORK_DENIAL") {
            require(request.publicCertificateRevisions.isEmpty())
            return
        }
        val primary = if (request.surface == "HEADLESS") {
            mapOf("grafana" to "grafana.datamancy.net", "prometheus" to "metrics.datamancy.net",
                "alertmanager" to "alerts.datamancy.net", "mastodon" to "social.datamancy.net",
                "sogo" to "groupware.datamancy.net", "seafile" to "files.datamancy.net",
                "onlyoffice" to "office.datamancy.net",
                "jupyterhub" to "notebooks.datamancy.net", "jupyter-notebook" to "notebooks.datamancy.net",
                "ntfy" to "ntfy-native.datamancy.net",
                "homeassistant" to "home.datamancy.net", "jellyfin" to "media.datamancy.net",
                "qbittorrent" to "torrents.datamancy.net", "searxng" to "search.datamancy.net",
                "bookstack" to "bookstack.datamancy.net", "erpnext" to "erp.datamancy.net",
                "firefly-iii" to "firefly.datamancy.net", "forgejo" to "forgejo.datamancy.net",
                "donetick" to "donetick.datamancy.net")
                .getValue(request.serviceId)
        } else {
            val manifestFile = suite.resolve("cases/manifest.json")
            require(Files.isRegularFile(manifestFile, NOFOLLOW_LINKS) &&
                Files.size(manifestFile) in 1..1048576)
            val manifestBytes = Files.readAllBytes(manifestFile)
            require(ReleaseLocks.sha256(manifestBytes) == intent.getValue("manifestSha256").jsonPrimitive.content)
            val cases = json.parseToJsonElement(manifestBytes.decodeToString(throwOnInvalidSequence = true))
                .jsonObject.getValue("cases").jsonArray
            val selected = cases.map { it.jsonObject }.single { definition ->
                listOf("serviceId", "surface", "variant", "journey").all {
                    definition.getValue(it) == intent.getValue(it)
                }
            }
            val url = java.net.URI(selected.getValue("url").jsonPrimitive.content)
            require(url.scheme == "https" && url.port == -1 && url.rawUserInfo == null && url.host != null)
            url.host
        }
        val required = setOf(primary) + (if (request.serviceId == "seafile")
            setOf("files.datamancy.net","files-native.datamancy.net") else emptySet()) +
            (if (request.serviceId == "ntfy" && request.surface == "WEB")
            setOf("ntfy.datamancy.net","ntfy-native.datamancy.net",
                "auth.datamancy.net","keycloak-auth.datamancy.net") else emptySet()) +
            (if (request.serviceId == "onlyoffice")
            setOf("office.datamancy.net","files.datamancy.net","files-native.datamancy.net") else emptySet()) +
            (if (request.surface == "ANDROID" && request.serviceId in
                setOf("element","synapse","matrix-authentication-service","livekit"))
            setOf("chat.datamancy.net","matrix.datamancy.net","matrix-auth.datamancy.net",
                "matrix-rtc.datamancy.net","auth.datamancy.net") else emptySet()) +
            (if (request.serviceId in setOf("bookstack", "erpnext",
                "firefly-iii", "forgejo", "donetick")) setOf("auth.datamancy.net")
            else emptySet()) + (if (request.serviceId in setOf("erpnext", "donetick"))
            setOf("keycloak-auth.datamancy.net") else emptySet()) +
            (if (request.serviceId == "firefly-iii" && request.surface == "HEADLESS")
            setOf("firefly-importer.datamancy.net") else emptySet())
        require(required.all { it in approvedHosts } && request.publicCertificateRevisions.isEmpty()) {
            "Unselected ingress host or obsolete ACME revision"
        }
        val generationRoot = generationBase.resolve(request.generationId)
        val bundleBytes = ReleasePrivateFiles.read(generationRoot.resolve("bundle.json"))
        val bundleSha = ReleaseLocks.sha256(bundleBytes)
        val bundle = json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString(throwOnInvalidSequence = true))
        require(bundle.request.id == request.generationId)
        SiteOwnerships.checkSealed(bundle)
        val proof = QualificationPrivateTls.observe(bundle,required,bundleSha)
        require(ReleasePrivateFiles.read(Path.of(request.certificate.path),1048576)
            .contentEquals(proof.roots) && request.certificate.sha256 == ReleaseLocks.sha256(proof.roots) &&
            request.certificateLeafSha256 == proof.leaves.getValue(primary) &&
            (request.serviceId !in setOf("onlyoffice","seafile") ||
                record(Path.of(request.caseDirectory).resolve("context.json"))
                    .getValue("nativeApi").jsonObject.getValue("leafSha256").jsonPrimitive.content ==
                    proof.leaves.getValue("files-native.datamancy.net")) &&
            (request.serviceId != "onlyoffice" ||
                record(Path.of(request.caseDirectory).resolve("context.json"))
                    .getValue("sourceFilesLeafSha256").jsonPrimitive.content ==
                    proof.leaves.getValue("files.datamancy.net") &&
                record(Path.of(request.caseDirectory).resolve("context.json"))
                    .getValue("nativeFilesLeafSha256").jsonPrimitive.content ==
                    proof.leaves.getValue("files-native.datamancy.net") &&
                record(Path.of(request.caseDirectory).resolve("context.json"))
                    .getValue("filesNativeOrigin").jsonPrimitive.content ==
                    "https://files-native.datamancy.net/") &&
            ("auth.datamancy.net" !in required ||
                record(Path.of(request.caseDirectory).resolve("context.json"))
                    .getValue("sourceIdentityLeafSha256").jsonPrimitive.content ==
                    proof.leaves.getValue("auth.datamancy.net")) &&
            ("keycloak-auth.datamancy.net" !in required ||
                record(Path.of(request.caseDirectory).resolve("context.json"))
                    .getValue("sourceGatewayLeafSha256").jsonPrimitive.content ==
                    proof.leaves.getValue("keycloak-auth.datamancy.net")) &&
            ("firefly-importer.datamancy.net" !in required ||
                record(Path.of(request.caseDirectory).resolve("context.json"))
                    .getValue("sourceImporterLeafSha256").jsonPrimitive.content ==
                    proof.leaves.getValue("firefly-importer.datamancy.net"))) {
            "Mounted private trust or current native served leaf changed since case preparation"
        }
    }

    private fun check(request: QualificationClientRequest): Triple<Path, String, String> {
        PrivateDeployment.validate(spec)
        require(spec.store == RuntimeStore.CANONICAL_V2 && generationId == request.generationId &&
            spec.name.startsWith("${request.generationId}-") &&
            fingerprint == request.fingerprint && hash.matches(fingerprint) &&
            request.operation.matches(Regex("qc-[a-f0-9]{12}")) && id.matches(request.invocationId) &&
            request.phase in setOf("INSTALL", "RESTORE") &&
            request.clientMode in setOf("NORMAL", "NATIVE_NETWORK_DENIAL") &&
            (request.clientMode == "NATIVE_NETWORK_DENIAL" &&
                request.serviceId in setOf("alloy", "loki") && request.surface == "HEADLESS" &&
                request.variant == "NATIVE" || request.clientMode == "NORMAL" &&
            (request.surface == "WEB" && request.variant == "BROWSER" ||
                request.surface == "ANDROID" && request.variant in setOf("API34", "API36") ||
                request.surface == "HEADLESS" && request.variant == "NATIVE" &&
                    request.serviceId in setOf("grafana", "prometheus", "alertmanager",
                        "mastodon", "sogo", "seafile", "homeassistant", "jellyfin", "qbittorrent", "searxng",
                        "bookstack", "erpnext", "firefly-iii", "forgejo", "donetick"))) &&
            admittedSeafileTools(request, approvedHosts, reviewedSeafileProducerPublicKeySha256) &&
            request.serviceId.matches(id) && request.caseIntentSha256.matches(hash) &&
            request.runnerSha256.matches(hash) && request.adapterSha256.matches(hash) &&
            request.certificate.sha256.matches(hash) && request.certificateLeafSha256.matches(hash) &&
            request.imageId.matches(hash) && request.imageManifestSha256.matches(Regex("sha256:[a-f0-9]{64}")) &&
            request.maximumMemoryMiB in 1024..8192 && request.maximumDiskMiB in 512..8192 &&
            request.maximumPids in 128..1024 && approvedHosts.isNotEmpty() && approvedHosts.size <= 64 &&
            approvedHosts.all(AcmePreflight.hostPattern::matches) &&
            (mapOf("homeassistant" to "home.datamancy.net", "jellyfin" to "media.datamancy.net",
                "qbittorrent" to "torrents.datamancy.net", "searxng" to "search.datamancy.net")[request.serviceId]?.let { it in approvedHosts && request.clientMode == "NORMAL" } ?: true) &&
            spec.networks.contains(NETWORK) &&
            NETWORK in spec.processes.single { it.id == "caddy" }.networks &&
            NETWORK in spec.processes.single { it.id == "livekit" }.networks &&
            spec.processes.none { it.id !in setOf("caddy", "livekit") && NETWORK in it.networks }) {
            "Only the fixed native qualification client network and bounded resource policy are admitted"
        }
        require(inventory.schemaVersion == 1 && inventory.status == "acquired" &&
            inventory.images.count { it.product == "qualification-client" } == 1)
        val image = inventory.images.single { it.product == "qualification-client" }
        require(image.os == "linux" && image.architecture == "amd64" && image.imageId == request.imageId &&
            image.pinnedImage == request.pinnedImage && image.selectedManifestDigest == request.imageManifestSha256 &&
            image.pinnedImage.endsWith("@${image.selectedManifestDigest}")) { "Unacquired image or unpinned native client" }
        val case = Path.of(request.caseDirectory); val suite = Path.of(request.suiteDirectory)
        require(case.isAbsolute && case.normalize() == case && suite.isAbsolute && suite.normalize() == suite &&
            case.toRealPath() == case && suite.toRealPath() == suite &&
            Files.getPosixFilePermissions(case) == ownerMode &&
            Files.isDirectory(suite, NOFOLLOW_LINKS))
        val intentBytes = ReleasePrivateFiles.read(case.resolve("intent.json"), 65536)
        val intent = json.parseToJsonElement(intentBytes.decodeToString()).jsonObject
        val binding = intent.getValue("binding").jsonObject
        require(ReleaseLocks.sha256(intentBytes) == request.caseIntentSha256 &&
            intent.getValue("invocationId").jsonPrimitive.content == request.invocationId &&
            intent.getValue("serviceId").jsonPrimitive.content == request.serviceId &&
            intent.getValue("surface").jsonPrimitive.content == request.surface &&
            intent.getValue("variant").jsonPrimitive.content == request.variant &&
            intent.getValue("runnerSha256").jsonPrimitive.content == request.runnerSha256 &&
            intent.getValue("contextSha256").jsonPrimitive.content.matches(hash) &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(case.resolve("context.json"))) ==
                intent.getValue("contextSha256").jsonPrimitive.content &&
            binding.getValue("generationId").jsonPrimitive.content == request.generationId &&
            binding.getValue("phase").jsonPrimitive.content == request.phase)
        nativeCaseGate(request)
        // Legacy bytes remain readable, but cannot authorize an unpinned checkout mount.
        QualificationClientSuites.verify(request, intent)
        val context = record(case.resolve("context.json"))
        privateIngressGate(request, intent, suite)
        val grafanaNative = request.serviceId == "grafana" && request.surface == "WEB" &&
            request.variant == "BROWSER" && request.phase == "INSTALL"
        require(if (grafanaNative) {
            val prior = requireNotNull(request.grafanaNativeOracle)
            val native = requireNotNull(request.grafanaNativeObservation)
            require(prior.sha256.matches(hash) && native.sha256.matches(hash) &&
                context.getValue("sourceNativeOracleFile").jsonPrimitive.content == prior.path &&
                context.getValue("sourceNativeOracleSha256").jsonPrimitive.content == prior.sha256 &&
                context.getValue("sourceNativeObservationFile").jsonPrimitive.content == native.path &&
                context.getValue("sourceNativeObservationSha256").jsonPrimitive.content == native.sha256)
            val source = Path.of(prior.path).parent
            val oldCase = Path.of(native.path).parent
            require(source == oldCase && source.parent == case.parent && source != case &&
                ':' !in source.toString() && '\n' !in source.toString() &&
                prior.path == source.resolve("oracle.json").toString() &&
                native.path == source.resolve("native-result.json").toString() &&
                source.toRealPath() == source && Files.getPosixFilePermissions(source) == ownerMode)
            val priorBytes = ReleasePrivateFiles.read(Path.of(prior.path), 1048576)
            val nativeBytes = ReleasePrivateFiles.read(Path.of(native.path), 1048576)
            val intent = record(source.resolve("intent.json"))
            val result = record(source.resolve("result.json"))
            val observation = json.parseToJsonElement(nativeBytes.decodeToString()).jsonObject
            ReleaseLocks.sha256(priorBytes) == prior.sha256 &&
                ReleaseLocks.sha256(nativeBytes) == native.sha256 &&
                intent.getValue("serviceId").jsonPrimitive.content == "grafana" &&
                intent.getValue("surface").jsonPrimitive.content == "HEADLESS" &&
                intent.getValue("variant").jsonPrimitive.content == "NATIVE" &&
                intent.getValue("binding").jsonObject == binding &&
                result.getValue("passed").jsonPrimitive.boolean &&
                result.getValue("finished").jsonPrimitive.boolean &&
                result.getValue("exitCode").jsonPrimitive.int == 0 &&
                result.getValue("observationSha256").jsonPrimitive.content == native.sha256 &&
                result.getValue("artifactHashes").jsonObject.getValue("oracle.json").jsonPrimitive.content == prior.sha256 &&
                observation.getValue("serviceId").jsonPrimitive.content == "grafana" &&
                observation.getValue("generationId").jsonPrimitive.content == request.generationId &&
                observation.getValue("phase").jsonPrimitive.content == "INSTALL" &&
                observation.getValue("artifacts").jsonObject.getValue("oracle.json").jsonPrimitive.content == prior.sha256 &&
                observation.getValue("assertions").jsonObject.values.all { it.jsonPrimitive.boolean }
        } else request.grafanaNativeOracle == null && request.grafanaNativeObservation == null) {
            "Only executor-generated completed same-case Grafana NATIVE original may enter its browser QClient"
        }
        if (request.phase == "INSTALL") {
            val fields = QualificationExecutionPolicy.predecessor(request.serviceId,request.surface,request.variant)
                ?.fields.orEmpty()
            val originals = fields.filter { it.endsWith("OracleFile") || it.endsWith("ObservationFile") }
                .map { context.getValue(it).jsonPrimitive.content }.toSet()
            if (grafanaNative) require(originals == setOf(requireNotNull(request.grafanaNativeOracle).path,
                requireNotNull(request.grafanaNativeObservation).path))
            require(request.predecessorFiles.map { it.path }.toSet() == originals &&
                request.predecessorFiles.size == originals.size &&
                fields.filter { it.endsWith("OracleFile") || it.endsWith("ObservationFile") }.all { field ->
                    val source = request.predecessorFiles.single { it.path == context.getValue(field).jsonPrimitive.content }
                    val shaField = field.removeSuffix("File") + "Sha256"
                    shaField !in fields || context.getValue(shaField).jsonPrimitive.content == source.sha256
                }) { "No broad or unsolicited predecessor file mount" }
            request.predecessorFiles.forEach { pin ->
                val source = Path.of(pin.path)
                require(source.parent.parent == case.parent && source.parent != case &&
                    source.fileName.toString() in setOf("oracle.json", "native-result.json") &&
                    pin.sha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(source, 1048576)))
                val result = record(source.parent.resolve("result.json"))
                val prior = record(source.parent.resolve("intent.json"))
                require(prior.getValue("binding") == binding &&
                    QualificationExecutionPolicy.predecessor(request.serviceId,request.surface,request.variant)?.let { edge ->
                        prior.getValue("serviceId").jsonPrimitive.content == edge.service &&
                        prior.getValue("surface").jsonPrimitive.content == edge.surface &&
                        prior.getValue("variant").jsonPrimitive.content == edge.variant
                    } != false &&
                    result.getValue("passed").jsonPrimitive.boolean &&
                    result.getValue("finished").jsonPrimitive.boolean && result.getValue("exitCode").jsonPrimitive.int == 0 &&
                    result.getValue("invocation").jsonObject.getValue("invocationId") == prior.getValue("invocationId") &&
                    (if (source.fileName.toString() == "oracle.json")
                        result.getValue("artifactHashes").jsonObject.getValue("oracle.json").jsonPrimitive.content
                     else result.getValue("observationSha256").jsonPrimitive.content) == pin.sha256)
            }
        }
        if (request.phase == "RESTORE") {
            val source = Path.of(context.getValue("sourceObservation").jsonPrimitive.content)
            val original = Path.of(context.getValue("sourceInvocation").jsonPrimitive.content)
            require(source.isAbsolute && source.normalize() == source && source.toRealPath() == source &&
                source.fileName.toString() == "native-result.json" &&
                original == source.parent.resolve("intent.json") &&
                source.parent.toRealPath() == source.parent &&
                Files.getPosixFilePermissions(source.parent) == ownerMode &&
                request.sourceObservationSha256?.matches(hash) == true &&
                ReleaseLocks.sha256(ReleasePrivateFiles.read(source, 4194304)) == request.sourceObservationSha256 &&
                context.getValue("sourceObservation").jsonPrimitive.content == source.toString()) {
                "Original INSTALL source oracle must be read-only and independently pinned"
            }
            val oldIntent = record(original)
            val oldResult = record(source.parent.resolve("result.json"))
            require(oldIntent.getValue("serviceId") == intent.getValue("serviceId") &&
                oldIntent.getValue("surface") == intent.getValue("surface") &&
                oldIntent.getValue("variant") == intent.getValue("variant") &&
                oldIntent.getValue("journey") == intent.getValue("journey") &&
                oldIntent.getValue("binding").jsonObject.getValue("phase").jsonPrimitive.content == "INSTALL" &&
                oldIntent.getValue("binding").jsonObject.getValue("trialId") == binding.getValue("trialId") &&
                oldIntent.getValue("binding").jsonObject.getValue("candidate") == binding.getValue("candidate") &&
                oldResult.getValue("passed").jsonPrimitive.boolean && oldResult.getValue("finished").jsonPrimitive.boolean &&
                oldResult.getValue("exitCode").jsonPrimitive.int == 0 &&
                oldResult.getValue("observationSha256").jsonPrimitive.content == request.sourceObservationSha256)
            val exact = mutableMapOf(source.toString() to request.sourceObservationSha256,
                original.toString() to ReleaseLocks.sha256(ReleasePrivateFiles.read(original, 65536)))
            if (request.serviceId == "alertmanager" && request.surface == "HEADLESS") {
                require(oldResult.getValue("invocation") == oldIntent &&
                    oldIntent.getValue("binding").jsonObject.getValue("phase").jsonPrimitive.content == "INSTALL")
                val resultPath = source.parent.resolve("result.json")
                exact[resultPath.toString()] = ReleaseLocks.sha256(ReleasePrivateFiles.read(resultPath, 1048576))
            }
            for ((relative, digest) in oldResult.getValue("artifactHashes").jsonObject) {
                val item = Path.of(relative)
                require(!item.isAbsolute && item.normalize() == item && relative.isNotEmpty() &&
                    relative !in setOf("intent.json", "context.json", "result.json", "native-result.json") &&
                    digest.jsonPrimitive.content.matches(hash))
                val path = source.parent.resolve(item).normalize()
                require(path.startsWith(source.parent) && path != source.parent)
                exact[path.toString()] = digest.jsonPrimitive.content
            }
            val edge = QualificationExecutionPolicy.predecessor(request.serviceId,request.surface,request.variant)
            val fields = edge?.restoreOriginalFields.orEmpty()
            for (field in fields.filter { it.endsWith("OracleFile") || it.endsWith("ObservationFile") }) {
                val sourceEdge = requireNotNull(edge)
                val path = Path.of(context.getValue(field).jsonPrimitive.content)
                val originalCase = path.parent
                require(originalCase.parent == source.parent.parent && originalCase != source.parent &&
                    path.fileName.toString() in setOf("oracle.json", "native-result.json") &&
                    originalCase.fileName.toString().startsWith("${sourceEdge.service}--"))
                val old = record(originalCase.resolve("intent.json"))
                val prior = record(originalCase.resolve("result.json"))
                val priorOracle = originalCase.resolve("oracle.json")
                val priorObservation = originalCase.resolve("native-result.json")
                require(old.getValue("binding") == oldIntent.getValue("binding") &&
                    old.getValue("serviceId").jsonPrimitive.content == sourceEdge.service &&
                    old.getValue("surface").jsonPrimitive.content == sourceEdge.surface &&
                    old.getValue("variant").jsonPrimitive.content == sourceEdge.variant &&
                    prior.getValue("invocation") == old &&
                    prior.getValue("passed").jsonPrimitive.boolean && prior.getValue("finished").jsonPrimitive.boolean &&
                    prior.getValue("exitCode").jsonPrimitive.int == 0 &&
                    prior.getValue("artifactHashes").jsonObject.getValue("oracle.json").jsonPrimitive.content ==
                        ReleaseLocks.sha256(ReleasePrivateFiles.read(priorOracle,1048576)) &&
                    prior.getValue("observationSha256").jsonPrimitive.content ==
                        ReleaseLocks.sha256(ReleasePrivateFiles.read(priorObservation,1048576)))
                val sha = ReleaseLocks.sha256(ReleasePrivateFiles.read(path,1048576))
                val shaField = field.removeSuffix("File") + "Sha256"
                require(shaField !in fields || context.getValue(shaField).jsonPrimitive.content == sha)
                exact[path.toString()] = sha
            }
            for ((field, name, digestField) in listOf(
                Triple("sourceOracleFile", "source-oracle.json", "sourceOracleFileSha256"),
                Triple("restoreStartupReceiptFile", "restore-startup.json", "restoreStartupReceiptSha256"))) {
                val path = case.resolve("owner-proofs/$name")
                require(context.getValue(field).jsonPrimitive.content == path.toString())
                val raw = ReleasePrivateFiles.read(path, 1048576)
                val sha = ReleaseLocks.sha256(raw)
                require(sha == context.getValue(digestField).jsonPrimitive.content)
                exact[path.toString()] = sha
            }
            require(exact.size in 5..71 && request.predecessorFiles.size == exact.size &&
                request.predecessorFiles.associate { it.path to it.sha256 } == exact)
            request.predecessorFiles.forEach { pin ->
                require(ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(pin.path), 64 * 1024 * 1024)) == pin.sha256)
            }
        } else require(request.sourceObservationSha256 == null &&
            "sourceObservation" !in context && "sourceInvocation" !in context)
        val filesApiCase = request.serviceId in setOf("seafile","onlyoffice")
        require((request.filesNativeCa != null) == filesApiCase)
        if (filesApiCase) {
            val ca = requireNotNull(request.filesNativeCa)
            val native = context.getValue("nativeApi").jsonObject
            require(ca.path == case.resolve("owner-proofs/files-native-api-ca.pem").toString() &&
                ca.sha256 == native.getValue("caSha256").jsonPrimitive.content &&
                native.getValue("originalHost").jsonPrimitive.content == "files-native.datamancy.net" &&
                native.getValue("caFile").jsonPrimitive.content == "/case/owner-proofs/files-native-api-ca.pem" &&
                native.getValue("bundleSha256").jsonPrimitive.content ==
                    context.getValue("bundleSha256").jsonPrimitive.content &&
                native.getValue("generationId").jsonPrimitive.content == request.generationId &&
                ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(ca.path),65536)) == ca.sha256)
        }
        // The original owner credentials are inputs; a GROUP session is produced
        // by this very browser QClient and checked by C1 only after it exits.
        val ntfyFields = if (request.serviceId == "ntfy") listOf("ntfyOriginalGrant","ntfySealedConfig") +
            if (request.surface == "WEB") listOf("ntfyOriginalOwner",
                "ntfyCompletedPassword","ntfyCompletedTotp") else emptyList()
        else emptyList()
        require(request.ntfyPrivateFiles.size == ntfyFields.size &&
            request.ntfyPrivateFiles.map { it.path }.toSet() == ntfyFields.map { field ->
                case.resolve("owner-proofs/${when (field) {
                    "ntfyOriginalGrant" -> "ntfy-original-grant.json"
                    "ntfySealedConfig" -> "ntfy-sealed-config.yml"
                    "ntfyOriginalOwner" -> "identity-original-owner.json"
                    "ntfyCompletedPassword" -> "identity-operator-password.txt"
                    else -> "identity-browser-totp.json"
                }}").toString()
            }.toSet() && request.ntfyPrivateFiles.all { pin ->
                ntfyFields.any { field ->
                    val guest = "/case/owner-proofs/${Path.of(pin.path).fileName}"
                    context.getValue("${field}File").jsonPrimitive.content == guest &&
                        context.getValue("${field}Sha256").jsonPrimitive.content == pin.sha256
                } && ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(pin.path),65536)) == pin.sha256
            })
        val hubCase = request.serviceId in setOf("jupyterhub","jupyter-notebook") &&
            request.surface in setOf("HEADLESS","WEB")
        val hubNames = listOf("hubAccountFile" to "hubAccountSha256",
            "hubDatabaseReadOnlyFile" to "hubDatabaseSha256",
            "hubOwnerVolumeCustodyFile" to "hubOwnerVolumeCustodySha256",
            "hubAliceEpisodeFile" to "hubAliceEpisodeSha256",
            "hubBobEpisodeFile" to "hubBobEpisodeSha256")
        require(request.hubPrivateFiles.size == (if (hubCase) 5 else 0) &&
            request.hubHomeReadOnlyPaths.size == (if (hubCase) 2 else 0))
        if (hubCase) {
            require(request.hubPrivateFiles.map { it.path }.toSet().size == 5 &&
                request.hubPrivateFiles.map { it.path to it.sha256 }.toSet() == hubNames.map { (field,sha) ->
                    context.getValue(field).jsonPrimitive.content to context.getValue(sha).jsonPrimitive.content
                }.toSet() && request.hubPrivateFiles.all { pin ->
                    ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(pin.path),1048576)) == pin.sha256
                } && request.hubHomeReadOnlyPaths == listOf("aliceHomeReadOnlyPath","bobHomeReadOnlyPath")
                    .map { context.getValue(it).jsonPrimitive.content } &&
                request.hubHomeReadOnlyPaths.toSet().size == 2 &&
                request.hubHomeReadOnlyPaths.all { path ->
                    val home = Path.of(path)
                    home.isAbsolute && home.normalize() == home &&
                        Files.isDirectory(home,NOFOLLOW_LINKS) && home.toRealPath() == home
                } && context.getValue("managedHub").jsonPrimitive.boolean)
        }
        val identityBrowser = request.serviceId in setOf("keycloak", "identity-onboarding") &&
            request.surface == "WEB" && request.variant == "BROWSER"
        val identityOwner = case.resolve("owner-proofs/identity-original-owner.json")
        require(request.identityPrivateFiles.size == (if (identityBrowser) 1 else 0) &&
            (!identityBrowser || request.identityPrivateFiles.single().let { input ->
                input.path == identityOwner.toString() &&
                    input.sha256 == context.getValue("originalOnboardingCustodySha256").jsonPrimitive.content &&
                    context.getValue("originalOnboardingCustodyFile").jsonPrimitive.content ==
                        "/case/owner-proofs/identity-original-owner.json" &&
                    ReleaseLocks.sha256(ReleasePrivateFiles.read(identityOwner,65536)) == input.sha256
            })) { "Original owner first-use custody is not sealed case-local authority" }
        if (identityBrowser) {
            val firstUse = request.serviceId == "keycloak" && request.phase == "INSTALL"
            require(context.getValue("originalSubjectFirstUse").jsonPrimitive.boolean == firstUse &&
                context.getValue("newPasswordFile").jsonPrimitive.content ==
                    "/case/owner-proofs/identity-operator-password.txt")
            if (firstUse) require(context.getValue("custodyDirectory").jsonPrimitive.content ==
                "/case/owner-proofs" && "originalTotpFile" !in context &&
                !Files.exists(case.resolve("owner-proofs/identity-operator-password.txt"),NOFOLLOW_LINKS))
            else require("custodyDirectory" !in context &&
                context.getValue("originalTotpFile").jsonPrimitive.content ==
                    "/case/owner-proofs/identity-browser-totp.json" &&
                ReleasePrivateFiles.read(case.resolve("owner-proofs/identity-operator-password.txt"),8192).isNotEmpty() &&
                ReleasePrivateFiles.read(case.resolve("owner-proofs/identity-browser-totp.json"),8192).isNotEmpty())
        }
        val officeFields = if (request.serviceId == "onlyoffice") when (request.surface) {
            "WEB" -> listOf("seafileAccountsFile")
            "HEADLESS" -> listOf("seafileCredentialsFile", "officeJwtSecretFile")
            "ANDROID" -> listOf("scopedAccountFile", "nativeCredentialsFile")
            else -> error("Unknown Office client surface")
        } else emptyList()
        require(request.officePrivateFiles.size == officeFields.size &&
            request.officePrivateFiles.map { it.path }.toSet() == officeFields.map { field ->
                case.resolve("owner-proofs/office-$field.json").toString()
            }.toSet() && request.officePrivateFiles.size <= 2)
        request.officePrivateFiles.forEach { file ->
            require(file.path in officeFields.map { field ->
                case.resolve("owner-proofs/office-$field.json").toString()
            } && file.sha256.matches(hash) &&
                context.getValue(officeFields.single { field ->
                    file.path == case.resolve("owner-proofs/office-$field.json").toString()
                }).jsonPrimitive.content == "/case/owner-proofs/${Path.of(file.path).fileName}" &&
                ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(file.path), 65536)) == file.sha256)
        }
        val seafileFields = if (request.serviceId == "seafile") when (request.surface) {
            "HEADLESS" -> listOf("credentialsFile")
            "WEB" -> listOf("scopedAccountFile")
            "ANDROID" -> listOf("credentialsFile","nativeCredentialsFile")
            else -> emptyList()
        } else emptyList()
        require(request.seafilePrivateFiles.size == seafileFields.size &&
            request.seafilePrivateFiles.map { it.path }.toSet() == seafileFields.map {
                case.resolve("owner-proofs/seafile-$it.json").toString()
            }.toSet())
        request.seafilePrivateFiles.forEach { file ->
            val path = Path.of(file.path)
            require(path.parent == case.resolve("owner-proofs") && file.sha256.matches(hash) &&
                context.getValue(seafileFields.single { field ->
                    path.fileName.toString() == "seafile-$field.json"
                }).jsonPrimitive.content == "/case/owner-proofs/${path.fileName}" &&
                ReleaseLocks.sha256(ReleasePrivateFiles.read(path,65536)) == file.sha256)
        }
        val actorKeys = listOf("ownerCredentialFile", "outsiderCredentialFile",
            "bookstackApiGrantFile", "outsiderBookstackApiGrantFile").filter { it in context }
        val actorRoot = generationBase.resolve(request.generationId).resolve(
            if (request.phase == "INSTALL") "qualification-original-actors" else "qualification-actors")
        val expectedActorPaths = actorKeys.map { key ->
            val role = when (key) {
                "ownerCredentialFile" -> "owner"
                "outsiderCredentialFile" -> "outsider"
                "bookstackApiGrantFile" -> "api-owner"
                else -> "api-outsider"
            }
            require(role !in setOf("api-owner", "api-outsider") || request.serviceId == "bookstack")
            val expected = actorRoot.resolve("${request.serviceId}-$role.json")
            require(context.getValue(key).jsonPrimitive.content == expected.toString())
            expected
        }
        require(request.credentialFiles.size == actorKeys.size && request.credentialFiles.size <= 4 &&
            request.credentialFiles.map { it.path }.toSet() == expectedActorPaths.map { it.toString() }.toSet()) {
            "Only exact original first-use or restored actor inputs may be mounted"
        }
        request.credentialFiles.forEach { input ->
            val path = Path.of(input.path)
            require(path.isAbsolute && path.parent == actorRoot &&
                path in expectedActorPaths &&
                ReleaseLocks.sha256(ReleasePrivateFiles.read(path, 16384)) == input.sha256) {
                "Bound phase-specific original actor credential changed after case preparation"
            }
        }
        val runner = suite.resolve("scripts/qualified-runner.py")
        require(Files.isRegularFile(runner, NOFOLLOW_LINKS) && Files.size(runner) in 1L..16777216L)
        val bytes = Files.readAllBytes(runner)
        require(bytes.size in 1..16777216 &&
            ReleaseLocks.sha256(bytes) == request.runnerSha256) { "Qualified-runner source bytes changed" }
        if (request.surface == "ANDROID") {
            val apk = requireNotNull(request.officialApk)
            val path = Path.of(apk.path)
            require(path.isAbsolute && path.normalize() == path &&
                path.startsWith(Path.of("/mnt/media/p0-v3/qualified-clients")) &&
                path.toRealPath() == path && Files.isRegularFile(path, NOFOLLOW_LINKS) &&
                Files.size(path) in 1L..536870912L && apk.sha256.matches(hash))
            val digest = java.security.MessageDigest.getInstance("SHA-256")
            Files.newInputStream(path, NOFOLLOW_LINKS).use { input ->
                val bytes = ByteArray(65536)
                while (true) { val read = input.read(bytes); if (read < 0) break; digest.update(bytes, 0, read) }
            }
            require(digest.digest().joinToString("") { "%02x".format(it) } == apk.sha256 &&
                record(case.resolve("context.json")).getValue("android").jsonObject
                    .getValue("apk").jsonPrimitive.content == apk.path) {
                "Only the externally acquired, case-bound official APK may enter the client image"
            }
        } else require(request.officialApk == null)
        val secondary = request.secondaryOfficialApk
        if (request.serviceId == "onlyoffice" && request.surface == "ANDROID") {
            val pin = requireNotNull(secondary) { "Original Seadroid fixture APK authority required" }
            val catalog = record(suite.resolve("cases/android-apps.json"))
            val apps = catalog.getValue("apps").jsonArray.map { it.jsonObject }
            val seafile = apps.single { "seafile" in it.getValue("serviceIds").jsonArray.map { id -> id.jsonPrimitive.content } }
            require(context.getValue("seafileFixtureApkFile").jsonPrimitive.content == pin.path &&
                context.getValue("seafileFixtureApkSha256").jsonPrimitive.content == pin.sha256 &&
                context.getValue("seafileInstalledClientReceiptFile").jsonPrimitive.content ==
                    case.resolve("owner-proofs/seafile-installed-client.json").toString() &&
                seafile.getValue("packageName").jsonPrimitive.content == "com.seafile.seadroid2" &&
                seafile.getValue("sha256").jsonPrimitive.content == pin.sha256 &&
                seafile.getValue("signerSha256").jsonPrimitive.content.matches(hash) &&
                pin.path != request.officialApk?.path && pin.sha256 != request.officialApk?.sha256)
            val path = Path.of(pin.path)
            require(path.isAbsolute && path.normalize() == path && path.toRealPath() == path &&
                path.startsWith(Path.of("/mnt/media/p0-v3/qualified-clients")) &&
                Files.isRegularFile(path, NOFOLLOW_LINKS) && Files.size(path) in 1L..536870912L)
            val digest = java.security.MessageDigest.getInstance("SHA-256")
            Files.newInputStream(path, NOFOLLOW_LINKS).use { stream ->
                val buffer = ByteArray(65536)
                while (true) { val n = stream.read(buffer); if (n < 0) break; digest.update(buffer, 0, n) }
            }
            require(digest.digest().joinToString("") { "%02x".format(it) } == pin.sha256)
        } else require(secondary == null) { "No unsolicited secondary APK mount" }
        val ca = ReleasePrivateFiles.read(Path.of(request.certificate.path), 1048576)
        require(ReleaseLocks.sha256(ca) == request.certificate.sha256 &&
            ca.decodeToString(throwOnInvalidSequence = true).contains("-----BEGIN CERTIFICATE-----"))
        return Triple(case, address("caddy"), address("livekit"))
    }
    /** Only selected, signed Android cases use the newer user test-VM exception;
     * all other platform and deployment runtimes remain VM-free. */
    private fun requireAndroidTestScope(request: QualificationClientRequest) {
        if (request.surface == "ANDROID") require(request.variant in setOf("API34","API36") &&
            request.clientMode == "NORMAL" && request.officialApk != null &&
            request.serviceId in setOf("donetick","element","homeassistant","jellyfin",
                "livekit","mastodon","matrix-authentication-service","ntfy","onlyoffice",
                "seafile","synapse")) {
            "Only the pinned Android API34/API36 QClient test guest is VM-exempt"
        }
    }
    /** One durable intent precedes Podman; no retry on an uncertain detached start. */
    fun start(request: QualificationClientRequest): QualificationClientNative {
        requireAndroidTestScope(request)
        PrivateDeployment.validate(spec) // Pure composition before any private journal directory.
        require(request.maximumMemoryMiB in 1024..8192 && request.maximumDiskMiB in 512..8192 &&
            request.maximumPids in 128..1024)
        require(UnixSystem().uid > 0 && UnixSystem().gid > 0)
        val free = capacity()
        require(free.availableMemoryMiB - request.maximumMemoryMiB >= 16384L &&
            free.usableDiskMiB - request.maximumDiskMiB >= 10240L) {
            "Bounded browser/Android client memory+disk with platform headroom required before effects"
        }
        dir()
        return ReleasePrivateFiles.locked(root) {
            val (case, caddy, livekit) = check(request)
            require(caddy != livekit)
            val journal = caseRoot(request)
            require(!Files.exists(journal, NOFOLLOW_LINKS)) { "Client continuation uncertain; reconcile or fence first" }
            Files.createDirectory(journal, PosixFilePermissions.asFileAttribute(ownerMode))
            ReleasePrivateFiles.sync(root)
            val name = "p0v3-qc-${request.generationId}-${request.invocationId}".also { require(it.length <= 120) }
            ReleasePrivateFiles.save(journal.resolve("intent.json"), json.encodeToString(
                QualificationClientIntent(ReleaseLocks.sha256(json.encodeToString(request).encodeToByteArray()),
                    name, fingerprint, NETWORK, caddy, livekit)).encodeToByteArray())
            val argv = arguments(request, name, case, caddy)
            val started = podman.run(argv)
            require(started.exitCode == 0 && started.output.trim().matches(hash)) {
                "Uncertain native client start retained; never issue another run"
            }
            val native = observed(request, started.output.trim(), journal)
            ReleasePrivateFiles.save(journal.resolve("native.json"), json.encodeToString(native).encodeToByteArray())
            return@locked native
        }
    }
    /** Pure bounded Podman invocation: no arbitrary entrypoint, shell, host network, port or
     * host home/workspace mount. Guest reads only frozen suite+case+exact approved CA. */
    internal fun arguments(request: QualificationClientRequest, name: String, case: Path, caddy: String): List<String> {
        requireAndroidTestScope(request)
        require(caddy.matches(ip) && name.matches(Regex("p0v3-qc-[a-z0-9-]{1,112}")))
        // This is the pinned ROOTFUL canonical store (sudo Podman), not a rootless store.
        // keep-id maps the Podman caller (root) and is not valid custody for our native user.
        val nativeUser = UnixSystem()
        require(nativeUser.uid > 0 && nativeUser.gid > 0)
        val hosts = approvedHosts
        require(hosts.isNotEmpty() && hosts.size <= 64 && hosts.all(AcmePreflight.hostPattern::matches))
        require(UnixSystem().uid > 0 && UnixSystem().gid > 0)
        return listOf("run", "--detach",  "--name", name, "--label", "io.p0v3.qualification-invocation=${request.invocationId}",
            "--label", "io.p0v3.runtime-fingerprint=$fingerprint", "--label", "io.p0v3.private-deployment=${spec.name}",
            "--network", "p0v3-live-${spec.name}-$NETWORK", "--pull=never", "--read-only", "--cap-drop=all",
            "--security-opt", "no-new-privileges", "--security-opt", "apparmor=p0v3-private-v1", "--pids-limit", request.maximumPids.toString(),
            "--memory", "${request.maximumMemoryMiB}m", "--memory-swap", "${request.maximumMemoryMiB}m",
            "--storage-opt", "size=${request.maximumDiskMiB}m", "--tmpfs", "/tmp:rw,nosuid,nodev,size=512m,mode=700,uid=${nativeUser.uid},gid=${nativeUser.gid}",
            "--sysctl", "net.ipv4.ip_unprivileged_port_start=0",
            "--env", "P0V3_CLIENT_REQUEST_SHA256=${ReleaseLocks.sha256(json.encodeToString(request).encodeToByteArray())}",
            "--env", "P0V3_CLIENT_MODE=${request.clientMode}",
            *(request.nativeCaseClaimSha256?.let {
                arrayOf("--env", "P0V3_NATIVE_CASE_CLAIM_SHA256=$it")
            } ?: emptyArray()),
            "--env", "P0V3_CLIENT_HOSTS=${hosts.sorted().joinToString(",")}",
            "--env", "P0V3_CLIENT_CADDY_IP=$caddy",
            "--env", "P0V3_CASE_ADAPTER_SHA256=${request.adapterSha256}",
            "--env", "P0V3_CLIENT_CERTIFICATE_SHA256=${request.certificate.sha256}",
            "--env", "P0V3_CLIENT_LEAF_SHA256=${request.certificateLeafSha256}",
            "--user", "${nativeUser.uid}:${nativeUser.gid}", "--volume", "${request.suiteDirectory}:/opt/p0v3/acceptance:ro",
            "--volume", "${case}:/case:rw", "--volume", "${request.certificate.path}:/run/secrets/source-ca.pem:ro",
            "--dns=127.0.0.1") + hosts.sorted().flatMap { listOf("--add-host", "$it:$caddy") } +
            (if (request.surface == "ANDROID") listOf("--device", "/dev/kvm:/dev/kvm",
                "--volume", "${requireNotNull(request.officialApk).path}:${requireNotNull(request.officialApk).path}:ro") else emptyList()) +
            (request.secondaryOfficialApk?.let { listOf("--volume", "${it.path}:${it.path}:ro") } ?: emptyList()) +
            (request.predecessorFiles + request.credentialFiles + request.hubPrivateFiles).flatMap { pin ->
                listOf("--volume", "${pin.path}:${pin.path}:ro") } +
            request.hubHomeReadOnlyPaths.flatMap { path -> listOf("--volume", "$path:$path:ro") } +
            (request.officePrivateFiles + request.seafilePrivateFiles + request.identityPrivateFiles +
                request.ntfyPrivateFiles + listOfNotNull(request.filesNativeCa)).flatMap { pin ->
                listOf("--volume", "${pin.path}:/case/owner-proofs/${Path.of(pin.path).fileName}:ro") } +
            listOf("--entrypoint", "/usr/bin/python3", request.pinnedImage,
                "/opt/p0v3/qualified-client-entry.py", "/case", request.invocationId)
    }
    private fun observed(request: QualificationClientRequest, id: String, journal: Path): QualificationClientNative {
        val inspected = podman.run(listOf("inspect", "--type", "container", "p0v3-qc-${request.generationId}-${request.invocationId}"))
        require(inspected.exitCode == 0 && inspected.output.length in 1..MAX_READBACK)
        val entry = json.parseToJsonElement(inspected.output).jsonArray.single().jsonObject
        val cfg = entry.getValue("Config").jsonObject; val state = entry.getValue("State").jsonObject
        val network = entry.getValue("NetworkSettings").jsonObject.getValue("Networks").jsonObject
        val pid = state.getValue("Pid").jsonPrimitive.int
        val mounts = entry.getValue("Mounts").jsonArray.map { it.jsonObject }
        val originals = (request.predecessorFiles + request.credentialFiles + request.hubPrivateFiles).map { it.path }.toSet()
        require(originals.size == request.predecessorFiles.size + request.credentialFiles.size +
            request.hubPrivateFiles.size && request.hubHomeReadOnlyPaths.all { path -> mounts.count { mount ->
                mount.getValue("Destination").jsonPrimitive.content == path &&
                    mount.getValue("Source").jsonPrimitive.content == path &&
                    !mount.getValue("RW").jsonPrimitive.boolean
            } == 1 } &&
            (request.officePrivateFiles + request.seafilePrivateFiles + request.identityPrivateFiles +
                request.ntfyPrivateFiles + listOfNotNull(request.filesNativeCa)).all { pin -> mounts.count { mount ->
                mount.getValue("Destination").jsonPrimitive.content ==
                    "/case/owner-proofs/${Path.of(pin.path).fileName}" &&
                    mount.getValue("Source").jsonPrimitive.content == pin.path &&
                    !mount.getValue("RW").jsonPrimitive.boolean
            } == 1 } && originals.all { path -> mounts.count { mount ->
                mount.getValue("Destination").jsonPrimitive.content == path &&
                    mount.getValue("Source").jsonPrimitive.content == path &&
                    !mount.getValue("RW").jsonPrimitive.boolean
            } == 1 } &&
            mounts.none { mount -> originals.any { original ->
                val parent = Path.of(original).parent.toString()
                mount.getValue("Destination").jsonPrimitive.content == parent ||
                    mount.getValue("Source").jsonPrimitive.content == parent
            } }) { "Only exact predecessor raw files may be mounted read-only" }
        require(entry.getValue("Id").jsonPrimitive.content == id &&
            entry.getValue("Image").jsonPrimitive.content.removePrefix("sha256:") == request.imageId &&
            cfg.getValue("Image").jsonPrimitive.content == request.pinnedImage &&
            cfg.getValue("User").jsonPrimitive.content == UnixSystem().let { "${it.uid}:${it.gid}" } &&
            cfg.getValue("Labels").jsonObject.getValue("io.p0v3.qualification-invocation").jsonPrimitive.content == request.invocationId &&
            cfg.getValue("Labels").jsonObject.getValue("io.p0v3.runtime-fingerprint").jsonPrimitive.content == fingerprint &&
            cfg.getValue("Labels").jsonObject.getValue("io.p0v3.private-deployment").jsonPrimitive.content == spec.name &&
            state.getValue("Running").jsonPrimitive.boolean && pid > 1 &&
            network.keys == setOf("p0v3-live-${spec.name}-$NETWORK") &&
            entry.getValue("HostConfig").jsonObject.getValue("NetworkMode").jsonPrimitive.content ==
                "p0v3-live-${spec.name}-$NETWORK" &&
            entry.getValue("HostConfig").jsonObject.getValue("Privileged").jsonPrimitive.boolean == false &&
            entry.getValue("HostConfig").jsonObject.getValue("ReadonlyRootfs").jsonPrimitive.boolean &&
            entry.getValue("HostConfig").jsonObject.getValue("PidsLimit").jsonPrimitive.long == request.maximumPids.toLong() &&
            entry.getValue("HostConfig").jsonObject.getValue("Memory").jsonPrimitive.long in
                1L..(request.maximumMemoryMiB.toLong() * 1048576L) &&
            entry.getValue("HostConfig").jsonObject.getValue("CapDrop").jsonArray.any {
                it.jsonPrimitive.content.equals("all", ignoreCase = true)
            } && (entry.getValue("HostConfig").jsonObject["CapAdd"]?.let {
                it == JsonNull || it.jsonArray.isEmpty()
            } ?: true) &&
            cfg.getValue("Env").jsonArray.map { it.jsonPrimitive.content }.containsAll(listOf(
                "P0V3_CLIENT_REQUEST_SHA256=${ReleaseLocks.sha256(json.encodeToString(request).encodeToByteArray())}",
                "P0V3_CLIENT_MODE=${request.clientMode}",
                "P0V3_CLIENT_HOSTS=${approvedHosts.sorted().joinToString(",")}",
                "P0V3_CLIENT_CADDY_IP=${address("caddy")}",
                "P0V3_CASE_ADAPTER_SHA256=${request.adapterSha256}")) &&
            cfg.getValue("Env").jsonArray.map { it.jsonPrimitive.content }
                .filter { it.startsWith("P0V3_NATIVE_CASE_CLAIM_SHA256=") } ==
                (request.nativeCaseClaimSha256?.let { listOf("P0V3_NATIVE_CASE_CLAIM_SHA256=$it") } ?: emptyList<String>()) &&
            (entry.getValue("HostConfig").jsonObject["PortBindings"] == null ||
                entry.getValue("HostConfig").jsonObject["PortBindings"] == JsonNull ||
                entry.getValue("HostConfig").jsonObject.getValue("PortBindings").jsonObject.isEmpty())) {
            "Native image/network/identity mismatches the admitted qualification client"
        }
        val clientIp = network.values.single().jsonObject.getValue("IPAddress").jsonPrimitive.content
        require(clientIp.matches(ip) && java.net.InetAddress.getByName(clientIp).isSiteLocalAddress)
        val link = Files.readSymbolicLink(Path.of("/proc/$pid/ns/net")).toString()
        val inode = requireNotNull(Regex("net:\\[([0-9]+)]").matchEntire(link)).groupValues[1].toLong()
        require(inode > 1)
        QualificationClientUidMapping.observe(pid)
        val native = QualificationClientNative(id, pid, inode, clientIp, request.imageId)
        return native
    }
    /** An actual stopped Podman process, not a PID liveness inference or caller teardown flag.
     * Called on the owner thread while servicing the bounded case-native spool. */
    fun observeExit(request: QualificationClientRequest, native: QualificationClientNative): Int? {
        val journal = caseRoot(request)
        require(json.decodeFromString<QualificationClientNative>(ReleasePrivateFiles.read(journal.resolve("native.json"))
            .decodeToString(throwOnInvalidSequence = true)) == native &&
            json.decodeFromString<QualificationClientIntent>(ReleasePrivateFiles.read(journal.resolve("intent.json"))
                .decodeToString(throwOnInvalidSequence = true)).requestSha256 ==
                ReleaseLocks.sha256(json.encodeToString(request).encodeToByteArray()))
        val response = podman.run(listOf("inspect", "--type", "container",
            "p0v3-qc-${request.generationId}-${request.invocationId}"))
        require(response.exitCode == 0 && response.output.length in 1..MAX_READBACK)
        val container = json.parseToJsonElement(response.output).jsonArray.single().jsonObject
        val state = container.getValue("State").jsonObject
        require(container.getValue("Id").jsonPrimitive.content == native.containerId &&
            container.getValue("Image").jsonPrimitive.content.removePrefix("sha256:") == native.imageId &&
            container.getValue("Config").jsonObject.getValue("Labels").jsonObject
                .getValue("io.p0v3.qualification-invocation").jsonPrimitive.content == request.invocationId &&
            !state.getValue("OOMKilled").jsonPrimitive.boolean)
        if (state.getValue("Running").jsonPrimitive.boolean) {
            require(state.getValue("Pid").jsonPrimitive.int == native.pid &&
                Files.readSymbolicLink(Path.of("/proc/${native.pid}/ns/net")).toString() == "net:[${native.netnsInode}]")
            QualificationClientUidMapping.observe(native.pid)
            return null
        }
        require(state.getValue("Pid").jsonPrimitive.int == 0 &&
            state.getValue("FinishedAt").jsonPrimitive.content.isNotBlank() &&
            !Files.exists(Path.of("/proc/${native.pid}/ns/net"), NOFOLLOW_LINKS))
        val code = state.getValue("ExitCode").jsonPrimitive.int
        require(code in 0..255)
        val receipt = journal.resolve("completion.json")
        val bytes = json.encodeToString(buildJsonObject {
            put("invocationId", request.invocationId); put("containerId", native.containerId)
            put("imageId", native.imageId); put("finishedAt", state.getValue("FinishedAt"))
            put("exitCode", code)
        }).encodeToByteArray()
        if (Files.exists(receipt, NOFOLLOW_LINKS)) require(ReleasePrivateFiles.read(receipt).contentEquals(bytes))
        else ReleasePrivateFiles.save(receipt, bytes)
        return code
    }
    /** Read-only adoption after uncertain start; never resends Podman run. */
    fun reconcile(request: QualificationClientRequest): QualificationClientNative = ReleasePrivateFiles.locked(root) {
        val journal = caseRoot(request); val intent = json.decodeFromString<QualificationClientIntent>(
            ReleasePrivateFiles.read(journal.resolve("intent.json")).decodeToString())
        require(intent.requestSha256 == ReleaseLocks.sha256(json.encodeToString(request).encodeToByteArray()) &&
            intent.generationFingerprint == fingerprint && intent.network == NETWORK &&
            intent.caddyIp == address("caddy") && intent.livekitIp == address("livekit"))
        val inspected = podman.run(listOf("inspect", "--type", "container", intent.containerName))
        require(inspected.exitCode == 0 && inspected.output.length <= MAX_READBACK)
        val container = json.parseToJsonElement(inspected.output).jsonArray.single().jsonObject
        val native = observed(request, container.getValue("Id").jsonPrimitive.content, journal)
        val saved = json.encodeToString(native).encodeToByteArray()
        if (Files.exists(journal.resolve("native.json"), NOFOLLOW_LINKS))
            require(ReleasePrivateFiles.read(journal.resolve("native.json")).contentEquals(saved))
        else ReleasePrivateFiles.save(journal.resolve("native.json"), saved) // Read-only native adoption, never a second run.
        native
    }
    /** Owner-only, post-start projection of ACTUAL selected CIDs. Keep Env, mounts,
     * credentials and raw inspect output out of the QClient receipt. The gate is
     * published only after this and the exact journal copies are durable. */
    private fun selectedNativeObservation(request: QualificationClientRequest,
        native: QualificationClientNative, policy: QualificationTurnPolicy,
        journal: Path, case: Path): String? {
        val matrixWeb = request.surface == "WEB" && request.serviceId in setOf(
            "element","synapse","matrix-authentication-service","livekit")
        val sogo = request.serviceId == "sogo" && request.surface in setOf("HEADLESS","WEB")
        if (!matrixWeb && !sogo) return null
        val expected = if (matrixWeb) setOf("postgres","keycloak","mas","element-web",
            "synapse","livekit","rtc-authorizer","rtc-web","caddy") else
            setOf("sogod","groupware","mail","postgres","memcached","caddy")
        require(spec.name == "${request.generationId}-v2" && request.fingerprint == fingerprint &&
            spec.processes.filter { it.id in expected }.map { it.id }.toSet() == expected)
        fun observed(name: String, definition: String?, expectedId: String? = null): JsonObject {
            val response = podman.run(listOf("inspect","--type","container",name))
            require(response.exitCode == 0 && response.output.length in 1..4194304)
            val raw = json.parseToJsonElement(response.output).jsonArray.single().jsonObject
            val labels = raw.getValue("Config").jsonObject.getValue("Labels").jsonObject
            val state = raw.getValue("State").jsonObject
            val networks = raw.getValue("NetworkSettings").jsonObject.getValue("Networks").jsonObject
            val identity = raw.getValue("Id").jsonPrimitive.content
            require(identity.matches(hash) && (expectedId == null || identity == expectedId) &&
                raw.getValue("Name").jsonPrimitive.content.removePrefix("/") == name &&
                labels["io.p0v3.private-deployment"] == JsonPrimitive(spec.name) &&
                labels["io.p0v3.runtime-fingerprint"] == JsonPrimitive(fingerprint) &&
                state.getValue("Running").jsonPrimitive.boolean && state.getValue("Pid").jsonPrimitive.int > 1)
            val networkNames = if (definition != null) spec.processes.single { it.id == definition }
                .networks.map { "p0v3-live-${spec.name}-$it" }.toSet() else
                setOf("p0v3-live-${spec.name}-$NETWORK")
            require(networks.keys == networkNames && networks.values.all { entry ->
                java.net.InetAddress.getByName(entry.jsonObject.getValue("IPAddress").jsonPrimitive.content)
                    .isSiteLocalAddress })
            if (definition != null) require(raw.getValue("Image").jsonPrimitive.content
                .removePrefix("sha256:") == spec.processes.single { it.id == definition }.imageId)
            return buildJsonObject {
                put("Id",identity); put("Name",raw.getValue("Name")); put("Image",raw.getValue("Image"))
                put("Config",buildJsonObject { put("Labels",buildJsonObject {
                    put("io.p0v3.private-deployment",spec.name)
                    put("io.p0v3.runtime-fingerprint",fingerprint)
                }) })
                put("State",buildJsonObject { put("Running",true); put("Pid",state.getValue("Pid")) })
                put("NetworkSettings",buildJsonObject { put("Networks",buildJsonObject {
                    for ((network,entry) in networks) put(network,buildJsonObject {
                        put("IPAddress",entry.jsonObject.getValue("IPAddress"))
                    })
                }) })
            }
        }
        val client = observed("p0v3-qc-${request.generationId}-${request.invocationId}",null,
            native.containerId)
        require(client.getValue("State").jsonObject.getValue("Pid").jsonPrimitive.int == native.pid)
        val processes = buildJsonObject {
            for (process in expected.sorted()) put(process,observed(
                "p0v3-live-${spec.name}-$process",process))
        }
        val caddy = processes.getValue("caddy").jsonObject
        val shared = "p0v3-live-${spec.name}-$NETWORK"
        require(caddy.getValue("NetworkSettings").jsonObject.getValue("Networks").jsonObject
            .getValue(shared).jsonObject.getValue("IPAddress").jsonPrimitive.content ==
            policy.caddyClientIp && policy.containerId == native.containerId &&
            policy.containerNetnsInode == native.netnsInode)
        val context = record(case.resolve("context.json"))
        val manifest = context.getValue("manifest").jsonObject
        val bundleBytes = ReleasePrivateFiles.read(generationBase.resolve(request.generationId)
            .resolve("bundle.json"),4194304)
        val generation = json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString(
            throwOnInvalidSequence = true))
        val selected = QualificationCanonicalTopology.require(generation,request.phase == "RESTORE")
        require(ReleaseLocks.sha256(bundleBytes) == context.getValue("bundleSha256").jsonPrimitive.content &&
            selected.manifestSha256 == manifest.getValue("sha256").jsonPrimitive.content &&
            selected.spec == spec && selected.runtimeFingerprint == fingerprint)
        val receipt = buildJsonObject {
            put("generationId",request.generationId); put("bundleSha256",ReleaseLocks.sha256(bundleBytes))
            put("manifestSha256",selected.manifestSha256); put("processes",processes)
            put("client",JsonObject(client + ("netnsInode" to JsonPrimitive(native.netnsInode))))
            put("caddyClientIp",policy.caddyClientIp)
            if (sogo) put("clientNetworkInternal",true)
            if (request.phase == "RESTORE") put("sourceStoppedProofSha256",
                context.getValue("sourceStoppedProofSha256"))
        }
        val raw = json.encodeToString(receipt).encodeToByteArray()
        require(raw.size in 256..262144)
        val observation = case.resolve("selected-native-observation.json")
        ReleasePrivateFiles.save(observation,raw)
        val copies = mapOf("qualification-client-intent.json" to "intent.json",
            "qualification-client-native.json" to "native.json",
            "qualification-client-policy.json" to "turn-policy.json")
        for ((name,source) in copies) ReleasePrivateFiles.save(case.resolve(name),
            ReleasePrivateFiles.read(journal.resolve(source),65536))
        return ReleaseLocks.sha256(raw)
    }
    /** Journal a single scoped TURN namespace policy before nft, then read back native rules
     * before releasing the container's short one-use gate. A07 must independently prove packet
     * round trip, browser/Android guest policy and direct-SFU drop counters; a policy is not PASS. */
    fun admitAndOpen(request: QualificationClientRequest): QualificationTurnPolicy = ReleasePrivateFiles.locked(root) {
        requireAndroidTestScope(request)
        val journal = caseRoot(request)
        val intent = json.decodeFromString<QualificationClientIntent>(
            ReleasePrivateFiles.read(journal.resolve("intent.json")).decodeToString())
        val native = json.decodeFromString<QualificationClientNative>(
            ReleasePrivateFiles.read(journal.resolve("native.json")).decodeToString())
        require(intent.requestSha256 == ReleaseLocks.sha256(json.encodeToString(request).encodeToByteArray()) &&
            native.imageId == request.imageId && native.containerId.matches(hash))
        val observed = observed(request, native.containerId, journal)
        require(observed == native &&
            Files.readSymbolicLink(Path.of("/proc/${native.pid}/ns/net")).toString() == "net:[${native.netnsInode}]" &&
            intent.caddyIp == address("caddy") && intent.livekitIp == address("livekit") &&
            !Files.exists(journal.resolve("policy-intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(journal.resolve("turn-policy.json"), NOFOLLOW_LINKS)) {
            "A native client/policy was changed or gate acknowledgement is uncertain"
        }
        val table = "p0v3_qc_${request.operation.removePrefix("qc-")}"
        val rules = nftRules(table, intent.caddyIp, intent.livekitIp)
        val claimed = buildJsonObject {
            put("requestSha256", intent.requestSha256); put("containerId", native.containerId)
            put("netnsInode", native.netnsInode); put("rulesSha256", ReleaseLocks.sha256(rules))
            put("table", table)
        }
        ReleasePrivateFiles.save(journal.resolve("policy-intent.json"), claimed.toString().encodeToByteArray())
        val before = namespace(native.pid, listOf("/usr/sbin/nft", "-j", "list", "tables"), null)
        require(before.exitCode == 0 && before.output.length in 1..MAX_READBACK &&
            json.parseToJsonElement(before.output).jsonObject.getValue("nftables").jsonArray.none {
                it.jsonObject["table"]?.jsonObject?.get("name")?.jsonPrimitive?.content == table
            }) { "Owned namespace policy already exists or cannot be audited; never overwrite" }
        val applied = namespace(native.pid, listOf("/usr/sbin/nft", "-f", "-"), rules)
        require(applied.exitCode == 0) { "nft acknowledgement uncertain; retain client and policy intent" }
        val readback = namespace(native.pid, listOf("/usr/sbin/nft", "-j", "list", "table", "inet", table), null)
        require(readback.exitCode == 0 && readback.output.length in 1..MAX_READBACK)
        val records = json.parseToJsonElement(readback.output).jsonObject.getValue("nftables").jsonArray
        val chains = records.mapNotNull { it.jsonObject["chain"]?.jsonObject }.associateBy {
            it.getValue("name").jsonPrimitive.content
        }
        val rulesRead = records.mapNotNull { it.jsonObject["rule"]?.jsonObject }
        require(chains.keys == setOf("dst", "out", "in") && rulesRead.size == 11 &&
            chains.getValue("dst").getValue("hook").jsonPrimitive.content == "output" &&
            chains.getValue("out").getValue("policy").jsonPrimitive.content == "drop" &&
            chains.getValue("in").getValue("policy").jsonPrimitive.content == "drop" &&
            rulesRead.groupingBy { it.getValue("chain").jsonPrimitive.content }.eachCount() ==
                mapOf("dst" to 2, "out" to 7, "in" to 2) &&
            setOf(intent.caddyIp, intent.livekitIp).all { it in readback.output } &&
            listOf("3478", "5349", "7880", "50000", "50020").all { it in readback.output }) {
            "Native client network policy does not equal the fixed TURN/SFU-denial scope"
        }
        val policy = QualificationTurnPolicy(request.operation, request.invocationId, request.generationId,
            caddyClientIp = intent.caddyIp, livekitClientIp = intent.livekitIp,
            containerId = native.containerId, containerPid = native.pid, containerNetnsInode = native.netnsInode,
            nftTable = table, rulesSha256 = ReleaseLocks.sha256(rules),
            nativeRulesReadbackSha256 = ReleaseLocks.sha256(readback.output.encodeToByteArray()))
        ReleasePrivateFiles.save(journal.resolve("turn-policy.json"), json.encodeToString(policy).encodeToByteArray())
        val case = Path.of(request.caseDirectory)
        val selectedNativeSha = selectedNativeObservation(request,native,policy,journal,case)
        // The entrypoint may run the exact runner only after this CREATE_NEW gate exists.
        val caseGate = Path.of(request.caseDirectory).resolve("qualification-client-gate.json")
        ReleasePrivateFiles.save(caseGate, buildJsonObject {
            put("invocationId", request.invocationId)
            put("requestSha256", intent.requestSha256)
            put("nativeContainerId", native.containerId)
            put("policySha256", ReleaseLocks.sha256(json.encodeToString(policy).encodeToByteArray()))
            if (selectedNativeSha != null) put("selectedNativeObservationSha256",selectedNativeSha)
            val publicNativeHost = mapOf("homeassistant" to "home.datamancy.net",
                "jellyfin" to "media.datamancy.net", "qbittorrent" to "torrents.datamancy.net",
                "searxng" to "search.datamancy.net")[request.serviceId]
            val seafileNative = request.serviceId == "seafile" && request.surface == "HEADLESS" &&
                request.variant == "NATIVE"
            if (seafileNative || publicNativeHost != null && request.clientMode == "NORMAL") {
                put("generationId", request.generationId)
                put("caseIntentSha256", request.caseIntentSha256)
                put("nativePid", native.pid); put("nativeNetnsInode", native.netnsInode)
                put("imageId", native.imageId); put("imageManifestSha256", request.imageManifestSha256)
                put("originalHost", if (seafileNative) "files.datamancy.net" else requireNotNull(publicNativeHost))
                put("originalCaSha256", request.certificate.sha256)
                put("originalLeafSha256", request.certificateLeafSha256)
                put("scopedCaddyIp", intent.caddyIp)
                put("nativeNftReadbackSha256", policy.nativeRulesReadbackSha256)
                if (seafileNative) {
                    put("deviceRoots", buildJsonObject {
                        put("owner", "/case/sync-device-a"); put("reader", "/case/sync-device-b")
                    })
                    put("nativeToolPins", json.encodeToJsonElement(requireNotNull(request.seafileToolPins)))
                }
            }
        }.toString().encodeToByteArray())
        policy
    }
    /** Android TEST VM exception only: prove the official emulator is a CHILD of this one pinned, still-running QClient and
     * shares its OUTER namespace. Guest namespace firewall/return evidence is owned by A07. */
    fun auditGuest(request: QualificationClientRequest, role: String = "owner"): QualificationGuestBridge = ReleasePrivateFiles.locked(root) {
        requireAndroidTestScope(request)
        require(request.surface == "ANDROID" && request.variant in setOf("API34", "API36") &&
            role in setOf("owner", "reader") &&
            (role != "reader" || request.serviceId == "livekit"))
        val journal = caseRoot(request)
        val native = json.decodeFromString<QualificationClientNative>(
            ReleasePrivateFiles.read(journal.resolve("native.json")).decodeToString())
        val policy = json.decodeFromString<QualificationTurnPolicy>(
            ReleasePrivateFiles.read(journal.resolve("turn-policy.json")).decodeToString())
        require(policy.containerId == native.containerId && policy.containerPid == native.pid &&
            policy.containerNetnsInode == native.netnsInode &&
            observed(request, native.containerId, journal) == native)
        val case = Path.of(request.caseDirectory)
        val context = record(case.resolve("context.json"))
        val serial = context.getValue(if (role == "owner") "android" else "peerAndroid")
            .jsonObject.getValue("serial").jsonPrimitive.content
        val avd = "p0v3-api${request.variant.removePrefix("API")}${if (role == "reader") "-reader" else ""}".also {
            require(it in setOf("p0v3-api34", "p0v3-api36", "p0v3-api34-reader", "p0v3-api36-reader"))
        }
        if (role == "reader") require(serial != context.getValue("android").jsonObject
            .getValue("serial").jsonPrimitive.content) { "Reader must use another emulator serial" }
        require(serial.matches(Regex("emulator-[0-9]{4,5}")))
        val rootHandle = ProcessHandle.of(native.pid.toLong()).orElseThrow {
            IllegalStateException("Native QClient disappeared before emulator parentage readback")
        }
        val candidates = rootHandle.descendants().use { descendants -> descendants.toList() }.mapNotNull { handle ->
            val pid = handle.pid().toInt()
            val cmdline = try { Files.readAllBytes(Path.of("/proc/$pid/cmdline")) } catch (_: java.io.IOException) { return@mapNotNull null }
            if (cmdline.size !in 1..32768) return@mapNotNull null
            val argv = cmdline.decodeToString(throwOnInvalidSequence = true).split('\u0000').filter { it.isNotEmpty() }
            if (argv.firstOrNull()?.endsWith("/emulator") == true &&
                argv.windowed(2).any { it == listOf("-avd", avd) } &&
                argv.windowed(2).any { it == listOf("-dns-server", "127.0.0.1") }) pid else null
        }
        require(candidates.size == 1) { "Exactly one owned AVD process must belong to the client image" }
        val qemuPid = candidates.single()
        val qemuNs = Files.readSymbolicLink(Path.of("/proc/$qemuPid/ns/net")).toString()
        require(qemuNs == "net:[${native.netnsInode}]" &&
            (Files.getAttribute(Path.of("/proc/$qemuPid"), "unix:uid", NOFOLLOW_LINKS) as Number).toInt() == 1000) {
            "Emulator host process/namespace is not the audited private client"
        }
        val guestFile = case.resolve(if (role == "owner") "android-turn-policy.json" else "android-turn-policy-reader.json")
        val receipt = QualificationGuestBridge(request.invocationId, request.generationId, native.containerId,
            native.pid, native.netnsInode, qemuPid, native.netnsInode, role, serial, avd, guestFile.toString())
        val receiptPath = journal.resolve(if (role == "owner") "guest-bridge.json" else "guest-bridge-reader.json")
        if (Files.exists(receiptPath, NOFOLLOW_LINKS))
            require(ReleasePrivateFiles.read(receiptPath).contentEquals(json.encodeToString(receipt).encodeToByteArray()))
        else ReleasePrivateFiles.save(receiptPath, json.encodeToString(receipt).encodeToByteArray())
        if (role == "reader" || request.serviceId != "livekit") {
            val ownerBytes = ReleasePrivateFiles.read(journal.resolve("guest-bridge.json"))
            val owner = json.decodeFromString<QualificationGuestBridge>(ownerBytes.decodeToString())
            require(owner.role == "owner" && owner.containerId == native.containerId &&
                owner.emulatorHostPid != receipt.emulatorHostPid && owner.serial != receipt.serial ||
                role == "owner" && request.serviceId != "livekit" && owner == receipt) {
                "Distinct official owner and reader emulator parentage required"
            }
            val gate = buildJsonObject {
                put("invocationId", request.invocationId)
                put("containerId", native.containerId)
                put("ownerBridgeSha256", ReleaseLocks.sha256(ownerBytes))
                if (role == "reader") put("readerBridgeSha256", ReleaseLocks.sha256(
                    ReleasePrivateFiles.read(journal.resolve("guest-bridge-reader.json"))))
                val original = mapOf("homeassistant" to "home.datamancy.net",
                    "jellyfin" to "media.datamancy.net", "qbittorrent" to "torrents.datamancy.net",
                    "searxng" to "search.datamancy.net", "donetick" to "donetick.datamancy.net",
                    "mastodon" to "social.datamancy.net", "ntfy" to "ntfy-native.datamancy.net")[request.serviceId]
                if (original != null) {
                    val policyBytes = ReleasePrivateFiles.read(journal.resolve("turn-policy.json"), 16384)
                    val policy = json.decodeFromString<QualificationTurnPolicy>(policyBytes.decodeToString())
                    require(original in approvedHosts && policy.containerId == native.containerId &&
                        policy.containerPid == native.pid && policy.containerNetnsInode == native.netnsInode)
                    put("generationId", request.generationId)
                    put("nativeContainerPid", native.pid); put("nativeContainerNetnsInode", native.netnsInode)
                    put("ownerEmulatorHostPid", owner.emulatorHostPid)
                    put("ownerEmulatorHostNetnsInode", owner.emulatorHostNetnsInode)
                    if (role == "reader") put("readerEmulatorHostPid", receipt.emulatorHostPid)
                    put("originalHost", original)
                    put("originalCaSha256", request.certificate.sha256)
                    put("originalLeafSha256", request.certificateLeafSha256)
                    put("nftPolicySha256", ReleaseLocks.sha256(policyBytes))
                    put("nativeNftReadbackSha256", policy.nativeRulesReadbackSha256)
                }
            }
            val path = case.resolve("qualification-guest-gate.json")
            if (Files.exists(path, NOFOLLOW_LINKS))
                require(ReleasePrivateFiles.read(path).contentEquals(gate.toString().encodeToByteArray()))
            else ReleasePrivateFiles.save(path, gate.toString().encodeToByteArray())
        }
        receipt
    }
    /** Owner reopens the actual selected Android system AND Conscrypt stores via the
     * still-running, CID-bound QClient, never merely accepts an entrypoint claim. */
    fun auditGuestTrust(request: QualificationClientRequest, role: String = "owner"): String {
        val bridge = auditGuest(request, role)
        val native = json.decodeFromString<QualificationClientNative>(ReleasePrivateFiles.read(
            caseRoot(request).resolve("native.json"), 65536).decodeToString(throwOnInvalidSequence = true))
        require(bridge.containerId == native.containerId && bridge.containerPid == native.pid &&
            bridge.containerNetnsInode == native.netnsInode &&
            observed(request, native.containerId, caseRoot(request)) == native)
        val case = Path.of(request.caseDirectory)
        val file = case.resolve("owner-proofs/guest-ca-adoption${if (role == "owner") "" else "-reader"}.json")
        val bytes = ReleasePrivateFiles.read(file, 8192)
        val receipt = json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val selected = ReleasePrivateFiles.read(Path.of(request.certificate.path), 65536)
        val pemText = selected.decodeToString(throwOnInvalidSequence = true)
        val pieces = Regex("-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----")
            .findAll(pemText).map { it.value.trimEnd() + "\n" }.toList()
        val matrix = request.serviceId in setOf("element", "synapse", "matrix-authentication-service", "livekit")
        require(pieces.isNotEmpty() && pieces.size <= (if (matrix) 5 else if (request.serviceId == "onlyoffice") 3 else if (request.serviceId == "seafile") 2 else 1) &&
            pemText.replace(Regex("-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----"), "")
                .isBlank() && pieces.map { ReleaseLocks.sha256(it.encodeToByteArray()) }.toSet().size == pieces.size)
        val expected = if (pieces.size == 1) {
            mapOf(receipt.getValue("guestFilename").jsonPrimitive.content to pieces.single().encodeToByteArray())
        } else {
            val issuers = receipt.getValue("guestIssuers").jsonArray
            require(issuers.size == pieces.size)
            issuers.mapIndexed { index, item ->
                val entry = item.jsonObject
                require(entry.keys == setOf("guestFilename", "sha256") &&
                    entry.getValue("sha256").jsonPrimitive.content ==
                        ReleaseLocks.sha256(pieces[index].encodeToByteArray()))
                entry.getValue("guestFilename").jsonPrimitive.content to pieces[index].encodeToByteArray()
            }.toMap().also { require(it.size == pieces.size) }
        }
        require(ReleaseLocks.sha256(selected) == request.certificate.sha256 &&
            expected.keys.all { it.matches(Regex("[a-f0-9]{8}\\.0")) } &&
            receipt.getValue("invocationId").jsonPrimitive.content == request.invocationId &&
            receipt.getValue("generationId").jsonPrimitive.content == request.generationId &&
            receipt.getValue("role").jsonPrimitive.content == role &&
            receipt.getValue("serial").jsonPrimitive.content == bridge.serial &&
            receipt.getValue("avd").jsonPrimitive.content == bridge.avd &&
            receipt.getValue("caSha256").jsonPrimitive.content == request.certificate.sha256 &&
            receipt.getValue("systemCaSha256").jsonPrimitive.content == request.certificate.sha256 &&
            receipt.getValue("conscryptCaSha256").jsonPrimitive.content == request.certificate.sha256)
        val owner = ReleasePrivateFiles.read(caseRoot(request).resolve("guest-bridge.json"), 65536)
        require(receipt.getValue("ownerBridgeSha256").jsonPrimitive.content == ReleaseLocks.sha256(owner))
        val name = "p0v3-qc-${request.generationId}-${request.invocationId}"
        for (store in listOf("/system/etc/security/cacerts", "/apex/com.android.conscrypt/cacerts")) {
            for ((filename, pem) in expected) {
                val actual = podman.run(listOf("exec", "--user", "1000", name,
                    "/opt/android-sdk/platform-tools/adb", "-s", bridge.serial, "exec-out", "cat",
                    "$store/$filename"))
                require(actual.exitCode == 0 && actual.output.encodeToByteArray().contentEquals(pem)) {
                    "Selected CA is absent from actual original Android app-visible trust store"
                }
            }
        }
        return ReleaseLocks.sha256(bytes)
    }
    /** One owner-selected Seadroid package, independently reread from the same native
     * guest. Only bounded digest/signature metadata exits the QClient; base APK stays there. */
    fun auditOfficeFixture(request: QualificationClientRequest): JsonObject {
        require(request.serviceId == "onlyoffice" && request.surface == "ANDROID" &&
            request.secondaryOfficialApk != null)
        val bridge = auditGuest(request)
        val journal = caseRoot(request)
        val native = json.decodeFromString<QualificationClientNative>(ReleasePrivateFiles.read(
            journal.resolve("native.json"), 65536).decodeToString(throwOnInvalidSequence = true))
        require(bridge.containerId == native.containerId && observed(request, native.containerId, journal) == native)
        val original = json.parseToJsonElement(ReleasePrivateFiles.read(Path.of(request.caseDirectory).resolve(
            "owner-proofs/seafile-fixture.install-observed.json"), 8192)
            .decodeToString(throwOnInvalidSequence = true)).jsonObject
        val peer = requireNotNull(request.secondaryOfficialApk)
        require(original.getValue("invocationId").jsonPrimitive.content == request.invocationId &&
            original.getValue("generationId").jsonPrimitive.content == request.generationId &&
            original.getValue("serial").jsonPrimitive.content == bridge.serial &&
            original.getValue("packageName").jsonPrimitive.content == "com.seafile.seadroid2" &&
            original.getValue("apkSha256").jsonPrimitive.content == peer.sha256)
        val script = """import hashlib,json,re,subprocess,tempfile,pathlib,sys
adb='/opt/android-sdk/platform-tools/adb'; signer='/opt/android-sdk/build-tools/36.0.0/apksigner'; serial=sys.argv[1]
package='com.seafile.seadroid2'
path=subprocess.check_output([adb,'-s',serial,'shell','pm','path',package],timeout=15).decode().strip()
assert re.fullmatch(r'package:/data/app/[A-Za-z0-9_./=+~-]+/base\.apk',path)
with tempfile.TemporaryDirectory(prefix='p0v3-office-base-') as tmp:
 file=pathlib.Path(tmp)/'base.apk'
 subprocess.run([adb,'-s',serial,'pull',path[8:],str(file)],timeout=120,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 assert file.stat().st_size in range(1,536870913)
 with file.open('rb') as stream: sha=hashlib.file_digest(stream,'sha256').hexdigest()
 certs=re.findall(r'Signer #\d+ certificate SHA-256 digest: ([a-fA-F0-9]+)',subprocess.check_output([signer,'verify','--print-certs',str(file)],timeout=30).decode())
 assert len(certs)==1
 print(json.dumps({'packageName':package,'guestApkPath':path[8:],'apkSha256':sha,'signerSha256':certs[0].lower()},sort_keys=True))
"""
        val result = podman.run(listOf("exec", "--user", "1000",
            "p0v3-qc-${request.generationId}-${request.invocationId}", "/usr/bin/python3", "-c", script,
            bridge.serial))
        require(result.exitCode == 0 && result.output.length in 20..8192)
        val readback = json.parseToJsonElement(result.output).jsonObject
        val catalog = json.parseToJsonElement(ReleasePrivateFiles.read(Path.of(request.suiteDirectory)
            .resolve("cases/android-apps.json"), 1048576)
            .decodeToString(throwOnInvalidSequence = true)).jsonObject.getValue("apps").jsonArray
            .map { it.jsonObject }.single { "seafile" in it.getValue("serviceIds").jsonArray.map { tag -> tag.jsonPrimitive.content } }
        require(readback.keys == setOf("packageName", "guestApkPath", "apkSha256", "signerSha256") &&
            readback.getValue("packageName").jsonPrimitive.content == "com.seafile.seadroid2" &&
            readback.getValue("guestApkPath") == original.getValue("guestApkPath") &&
            readback.getValue("apkSha256").jsonPrimitive.content == peer.sha256 &&
            readback.getValue("apkSha256") == catalog.getValue("sha256") &&
            readback.getValue("signerSha256") == catalog.getValue("signerSha256") &&
            readback.getValue("signerSha256") == original.getValue("signerSha256"))
        return readback
    }
    /** Stop-only durable fence; no delete/re-run. COORD must hold this through bridge removal
     * and source resume. Native process exit plus netns disappearance are mandatory readback. */
    /** Missing original intent proves this actor could not send Podman run. No name/CID
     * absence is inferred from Podman errors or an untrusted caller Boolean. */
    fun neverStarted(request: QualificationClientRequest): Boolean {
        require(request.generationId == generationId && request.invocationId.matches(
            Regex("case-[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}")))
        val journal = caseRoot(request)
        if (!Files.exists(root, NOFOLLOW_LINKS) || !Files.exists(journal, NOFOLLOW_LINKS)) return true
        ReleasePrivateFiles.directory(journal)
        val absent = !Files.exists(journal.resolve("intent.json"), NOFOLLOW_LINKS)
        if (absent) require(!Files.exists(journal.resolve("native.json"), NOFOLLOW_LINKS))
        return absent
    }
    /** Only the ORIGINAL start intent may be observed for lost ACK. Absence before that
     * intent proves this actor never sent Podman run; an unknown CID cannot be guessed. */
    fun fenceKnown(request: QualificationClientRequest): QualificationClientFence? {
        require(request.generationId == generationId && request.invocationId.matches(
            Regex("case-[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}")))
        val journal = caseRoot(request)
        if (!Files.exists(root, NOFOLLOW_LINKS) || !Files.exists(journal, NOFOLLOW_LINKS)) return null
        ReleasePrivateFiles.directory(journal)
        val intentPath = journal.resolve("intent.json")
        if (!Files.exists(intentPath, NOFOLLOW_LINKS)) {
            require(!Files.exists(journal.resolve("native.json"), NOFOLLOW_LINKS))
            return null
        }
        val intent = json.decodeFromString<QualificationClientIntent>(ReleasePrivateFiles.read(intentPath)
            .decodeToString(throwOnInvalidSequence = true))
        require(intent.requestSha256 == ReleaseLocks.sha256(json.encodeToString(request).encodeToByteArray()) &&
            intent.containerName == "p0v3-qc-${request.generationId}-${request.invocationId}" &&
            intent.generationFingerprint == fingerprint && intent.network == NETWORK)
        if (!Files.exists(journal.resolve("native.json"), NOFOLLOW_LINKS)) reconcile(request)
        return fenced(request)
    }
    fun fenced(request: QualificationClientRequest): QualificationClientFence = ReleasePrivateFiles.locked(root) {
        val journal = caseRoot(request)
        require(Files.exists(journal.resolve("intent.json"), NOFOLLOW_LINKS) &&
            Files.exists(journal.resolve("native.json"), NOFOLLOW_LINKS))
        val intent = json.decodeFromString<QualificationClientIntent>(ReleasePrivateFiles.read(journal.resolve("intent.json")).decodeToString())
        val native = json.decodeFromString<QualificationClientNative>(ReleasePrivateFiles.read(journal.resolve("native.json")).decodeToString())
        require(intent.requestSha256 == ReleaseLocks.sha256(json.encodeToString(request).encodeToByteArray()))
        val before = podman.run(listOf("inspect", "--type", "container", intent.containerName))
        require(before.exitCode == 0 && before.output.length in 1..MAX_READBACK &&
            json.parseToJsonElement(before.output).jsonArray.single().jsonObject
                .getValue("Id").jsonPrimitive.content == native.containerId)
        val stopIntent = journal.resolve("stop.intent.json")
        val stopBytes = json.encodeToString(buildJsonObject {
            put("requestSha256", intent.requestSha256); put("containerName", intent.containerName)
            put("containerId", native.containerId); put("netnsInode", native.netnsInode)
        }).encodeToByteArray()
        if (Files.exists(stopIntent, NOFOLLOW_LINKS))
            require(ReleasePrivateFiles.read(stopIntent).contentEquals(stopBytes))
        if (json.parseToJsonElement(before.output).jsonArray.single().jsonObject
                .getValue("State").jsonObject.getValue("Running").jsonPrimitive.boolean) {
            require(!Files.exists(stopIntent, NOFOLLOW_LINKS)) {
                "Unknown previous stop response; observe only, never send another stop"
            }
            ReleasePrivateFiles.save(stopIntent, stopBytes)
            val result = podman.run(listOf("stop", "--time", "8", intent.containerName))
            require(result.exitCode == 0) { "Client stop uncertain; do not remove target bridge or resume source" }
        }
        val inspected = podman.run(listOf("inspect", "--type", "container", intent.containerName))
        require(inspected.exitCode == 0 && inspected.output.length in 1..MAX_READBACK &&
            json.parseToJsonElement(inspected.output).jsonArray.single().jsonObject.let { container ->
                container.getValue("Id").jsonPrimitive.content == native.containerId &&
                    !container.getValue("State").jsonObject.getValue("Running").jsonPrimitive.boolean
            } && !Files.exists(Path.of("/proc/${native.pid}/ns/net"), NOFOLLOW_LINKS)) {
            "Native client/netns not stopped; source resume forbidden"
        }
        val caAdoption = Path.of(request.caseDirectory).resolve("client-ca-adoption.json")
        val adoptionSha = if (Files.exists(caAdoption, NOFOLLOW_LINKS)) {
            val bytes = ReleasePrivateFiles.read(caAdoption, 16384)
            val receipt = json.parseToJsonElement(bytes.decodeToString()).jsonObject
            require(receipt.getValue("invocationId").jsonPrimitive.content == request.invocationId &&
                receipt.getValue("certificateSha256").jsonPrimitive.content == request.certificate.sha256 &&
                receipt.getValue("leafSha256").jsonPrimitive.content == request.certificateLeafSha256 &&
                receipt.getValue("nssReadbackSha256").jsonPrimitive.content.matches(hash) &&
                receipt.getValue("javaReadbackSha256").jsonPrimitive.content.matches(hash))
            ReleaseLocks.sha256(bytes)
        } else null
        val fence = QualificationClientFence(request.invocationId, request.generationId, native.containerId,
            native.netnsInode, ReleaseLocks.sha256(inspected.output.encodeToByteArray()),
            ReleaseLocks.sha256(ReleasePrivateFiles.read(journal.resolve("native.json"))), adoptionSha)
        if (Files.exists(journal.resolve("fenced.json"), NOFOLLOW_LINKS))
            require(ReleasePrivateFiles.read(journal.resolve("fenced.json")).contentEquals(json.encodeToString(fence).encodeToByteArray()))
        else ReleasePrivateFiles.save(journal.resolve("fenced.json"), json.encodeToString(fence).encodeToByteArray())
        fence
    }
}
