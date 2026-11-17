package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** Only the reviewed RTC hostname and the two TURN ingress transports. Stored in a V2
 * spec default-omitted by A02; this value NEVER publishes ports during staging/restore. */
@Serializable data class RuntimeNativeIngressPublication(val site: String,
    val approvedHost: String = "rtc.datamancy.net", val listenAddress: String,
    val processId: String = "livekit", val udpPort: Int = 3478, val tlsPort: Int = 5349)
@OptIn(ExperimentalSerializationApi::class)
@Serializable internal data class RuntimeNativeIngressBinding(val operation: String, val generationId: String,
    val fingerprint: String, val publication: RuntimeNativeIngressPublication,
    val expectedCaddyConfigurationSha256: String, val caddySite: CaddySiteBinding,
    val expectedSiteSelectionSha256: String,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val publicTrust: ActivationInput? = null)
@Serializable internal data class RuntimeNativeIngressIntent(val binding: RuntimeNativeIngressBinding,
    val livekitIp: String, val gatewayIp: String, val caddyPublicIp: String,
    val nativeTable: String, val rulesSha256: String, val beforeInventorySha256: String)
@Serializable internal data class RuntimeNativeIngressResult(val operation: String, val action: String,
    val intentSha256: String, val nativeTableSha256: String, val caddyListenerInode: Long,
    val siteSelectionSha256: String, val status: String = "installed-needs-native-return-proof")
@Serializable internal data class RuntimeNativeIngressRollbackIntent(val operation: String,
    val originalOperation: String, val originalIntentSha256: String,
    val originalResultSha256: String, val ownedTable: String, val observedTableSha256: String)

/** No shell, installer, host firewall flush or arbitrary host command. This transport only
 * reads ruleset or atomically creates/deletes the one operation-owned nft table. */
internal fun interface NativeIngressCommands {
    fun run(args: List<String>, input: ByteArray?): RuntimeCommandResult
}

/** Native public TURN succession is NOT the restored private qualification policy. Its
 * initial install is explicitly pending functional TURN allocation + real packet return;
 * a rule being present cannot qualify or activate media. Caller retains the site/target
 * locks through a later accepted external flow proof, rollback or permanent isolation. */
internal class RuntimeNativeIngress(private val root: Path, private val spec: PrivateDeploymentSpec,
    private val fingerprint: String, private val commands: NativeIngressCommands,
    private val gateway: () -> String, private val livekitIp: () -> String,
    private val caddyPublicIp: () -> String, private val publicListener: () -> Long,
    private val caddyPolicy: (String) -> String,
    private val committed: () -> ActiveSiteSelection,
    private val socketInventory: (Int, String) -> Boolean) {
    companion object {
        private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
        private val hash = Regex("[a-f0-9]{64}")
        private val addr = Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")
        private val tableName = Regex("p0v3_rtc_[a-f0-9]{12}")
        private fun privateAddress(value: String): Boolean = addr.matches(value) &&
            java.net.InetAddress.getByName(value).isSiteLocalAddress
        private fun nativeCommand(args: List<String>, input: ByteArray?): RuntimeCommandResult {
            require(args == listOf("-j", "list", "ruleset") ||
                args == listOf("-f", "-") ||
                args.size == 5 && args.take(4) == listOf("-j", "list", "table", "ip") &&
                tableName.matches(args.last()) ||
                args.size == 4 && args.take(3) == listOf("delete", "table", "ip") &&
                tableName.matches(args.last()))
            val process = ProcessBuilder(listOf("/usr/bin/sudo", "-n", "/usr/sbin/nft") + args)
                .redirectError(ProcessBuilder.Redirect.DISCARD).start()
            if (input == null) process.outputStream.close() else process.outputStream.use { it.write(input) }
            if (!process.waitFor(20, TimeUnit.SECONDS)) {
                process.destroyForcibly().waitFor(); throw PrivateCommandTimeout()
            }
            val output = process.inputStream.readNBytes(8 * 1024 * 1024 + 1)
            require(output.size <= 8 * 1024 * 1024)
            return RuntimeCommandResult(process.exitValue(), output.decodeToString(throwOnInvalidSequence = true))
        }
        /** Checked for ALL host sockets, not just a guessed TCP PID; IPv6 is a conflict. */
        internal fun hostPortFree(port: Int, protocol: String): Boolean {
            require(protocol in setOf("udp", "tcp") && port in setOf(3478, 5349))
            val files = listOf("/proc/net/$protocol", "/proc/net/${protocol}6")
            return files.all { name ->
                val lines = Files.readAllLines(Path.of(name))
                require(lines.size in 1..131072)
                lines.drop(1).none { line ->
                    val fields = line.trim().split(Regex("\\s+"))
                    require(fields.size >= 4)
                    fields[1].substringAfter(':').toInt(16) == port &&
                        (protocol == "udp" || fields[3] == "0A")
                }
            }
        }
        internal fun fixedRules(table: String, publicIp: String, livekit: String, gateway: String): ByteArray {
            require(tableName.matches(table) && addr.matches(publicIp) &&
                privateAddress(livekit) && privateAddress(gateway) &&
                listOf(publicIp, livekit, gateway).toSet().size == 3)
            return """table ip $table {
                chain incoming { type nat hook prerouting priority dstnat; policy accept;
                    ip daddr $publicIp udp dport 3478 counter dnat to $livekit:3478
                    ip daddr $publicIp tcp dport 5349 counter dnat to $livekit:5349
                }
                chain reply { type nat hook postrouting priority srcnat; policy accept;
                    ip daddr $livekit udp dport 3478 counter snat to $gateway
                    ip daddr $livekit tcp dport 5349 counter snat to $gateway
                }
            }
            """.trimIndent().encodeToByteArray()
        }
        fun real(root: Path, spec: PrivateDeploymentSpec, fingerprint: String,
            caddySite: CaddySiteBinding, committed: () -> ActiveSiteSelection): RuntimeNativeIngress {
            val publication = requireNotNull(spec.nativeIngress)
            require(spec.name.matches(Regex("q-[a-f0-9]{12}-[a-z][a-z0-9-]{0,39}")) &&
                root == Path.of("/mnt/media/p0-v3/native-ingress").resolve(publication.site)
                    .resolve(spec.name.substring(0, 14)) &&
                fingerprint.matches(hash) && caddySite.site == publication.site)
            privateControlDirectory(root.parent.parent); privateControlDirectory(root.parent); privateControlDirectory(root)
            val podman = PrivateRootfulCommands(30, spec.store)
            val nativeGateway = {
                val inspected = podman.run(listOf("inspect", "--type", "container", "p0v3-live-${spec.name}-livekit"))
                require(inspected.exitCode == 0 && inspected.output.length in 1..262144)
                val container = json.parseToJsonElement(inspected.output).jsonArray.single().jsonObject
                require(container.getValue("Config").jsonObject.getValue("Labels").jsonObject
                    .getValue("io.p0v3.runtime-fingerprint").jsonPrimitive.content == fingerprint &&
                    container.getValue("State").jsonObject.getValue("Running").jsonPrimitive.boolean)
                container.getValue("NetworkSettings").jsonObject.getValue("Networks").jsonObject
                    .getValue("p0v3-live-${spec.name}-qualification-web").jsonObject
                    .getValue("Gateway").jsonPrimitive.content
            }
            return RuntimeNativeIngress(root, spec, fingerprint, NativeIngressCommands(::nativeCommand),
                nativeGateway,
                { NamespaceCaddyTransport.ownedProcessAddress(spec, fingerprint, "livekit", "qualification-web") },
                { NamespaceCaddyTransport.ownedPublicAddress(spec, fingerprint) },
                { NamespaceCaddyTransport.auditPublicListeners(spec, fingerprint,
                    NamespaceCaddyTransport.ownedPublicAddress(spec, fingerprint), true) },
                { expected -> CaddyHttpsProvisioner.inRuntime(Path.of("/mnt/media/p0-v3/caddy-https").resolve(caddySite.site),
                    caddySite, spec, fingerprint).ownedAutomaticRenewalPolicy(expected) },
                committed, ::hostPortFree)
        }
    }
    private fun admitted(binding: RuntimeNativeIngressBinding): Triple<String, String, Long> {
        PrivateDeployment.validate(spec)
        val publication = requireNotNull(spec.nativeIngress)
        require(binding.operation.matches(Regex("r-[a-f0-9]{12}")) &&
            binding.generationId.matches(Regex("q-[a-f0-9]{12}")) && spec.name.startsWith("${binding.generationId}-") &&
            binding.fingerprint == fingerprint && hash.matches(fingerprint) &&
            binding.publication == publication && binding.caddySite.site == publication.site &&
            binding.caddySite.approvedHosts == spec.ingress?.approvedHosts &&
            binding.expectedCaddyConfigurationSha256.matches(hash) &&
            binding.expectedSiteSelectionSha256.matches(hash) &&
            publication.approvedHost == "rtc.datamancy.net" && publication.approvedHost in binding.caddySite.approvedHosts &&
            publication.processId == "livekit" && publication.udpPort == 3478 && publication.tlsPort == 5349 &&
            publication.listenAddress == spec.ingress?.listenAddress &&
            publication.listenAddress.matches(addr) && publication.listenAddress != "0.0.0.0" &&
            java.util.Collections.list(java.net.NetworkInterface.getNetworkInterfaces()).any { iface ->
                java.util.Collections.list(iface.inetAddresses).any { it.hostAddress == publication.listenAddress }
            } && spec.ingress?.site == publication.site && spec.store == RuntimeStore.CANONICAL_V2 &&
            "ingress-egress" in spec.networks && "qualification-web" in spec.networks &&
            "qualification-web" in spec.processes.single { it.id == "livekit" }.networks &&
            "ingress-egress" !in spec.processes.single { it.id == "livekit" }.networks &&
            Files.readString(Path.of("/proc/sys/net/ipv4/ip_forward")).trim() == "1") {
            "Only a committed fresh RTC source may publish fixed TURN ports with real return routing"
        }
        val selected = committed()
        require(selected.fresh && selected.siteId == publication.site &&
            selected.deployment.generationId == binding.generationId &&
            selected.hosts.toSet() == binding.caddySite.approvedHosts &&
            selected.ordinal > 0 && hash.matches(selected.consumptionSha256) &&
            ReleaseLocks.sha256(json.encodeToString(selected).encodeToByteArray()) ==
                binding.expectedSiteSelectionSha256) { "Active-site record is not the accepted source" }
        require(caddyPolicy(binding.expectedCaddyConfigurationSha256).matches(hash)) {
            "Actual same-Caddy public TLS policy/renewal is not committed"
        }
        // A native UDP/TCP rule is an external public grant: BOTH Caddy public ACME
        // key/leaf and LiveKit 5349 key/leaf must already match the same effective revision.
        // Observe actual LiveKit TLS and bound native adoption receipt before journaling nft.
        val trust = requireNotNull(binding.publicTrust)
        require(trust.sha256.matches(hash))
        val bundleBytes = ReleasePrivateFiles.read(GenerationRuntime.BASE.resolve(binding.generationId).resolve("bundle.json"))
        val bundle = json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString(throwOnInvalidSequence = true))
        require(bundle.request.id == binding.generationId && bundle.members.any {
            it.spec == spec && it.runtimeFingerprint == fingerprint
        })
        SiteOwnerships.checkSealed(bundle)
        NativeCredentialRevision.requireTurnAdopted(bundle, binding.caddySite.approvedHosts, trust,
            NativeCaddyCertificateCollector(Path.of(trust.path), trust.sha256))
        val publicCaddy = caddyPublicIp()
        val livekit = livekitIp(); val gateway = gateway()
        require(privateAddress(publicCaddy) && privateAddress(livekit) && privateAddress(gateway) &&
            publicCaddy != livekit && gateway != livekit)
        val native = publicListener(); require(native > 1)
        return Triple(livekit, gateway, native)
    }
    private fun snapshot(args: List<String>): String {
        val result = commands.run(args, null)
        require(result.exitCode == 0 && result.output.length in 1..8 * 1024 * 1024)
        return result.output
    }
    /** Install only a fixed site-owned table after BOTH ports are unoccupied. No return/media
     * success is asserted by a native rule being configured; a later real flow is mandatory. */
    fun install(binding: RuntimeNativeIngressBinding): RuntimeNativeIngressResult {
        val (livekit, gateway, inode) = admitted(binding)
        val table = "p0v3_rtc_${binding.generationId.removePrefix("q-")}"
        val rules = fixedRules(table, binding.publication.listenAddress, livekit, gateway)
        val inventory = snapshot(listOf("-j", "list", "ruleset"))
        require(socketInventory(3478, "udp") && socketInventory(5349, "tcp") &&
            !Regex("(?i)(3478|5349)").containsMatchIn(inventory) &&
            json.parseToJsonElement(inventory).jsonObject.getValue("nftables").jsonArray.none {
                it.jsonObject["table"]?.jsonObject?.get("name")?.jsonPrimitive?.content == table
            }) { "An unrelated TURN socket/NAT rule or old owned lease cannot be taken over" }
        val intent = RuntimeNativeIngressIntent(binding, livekit, gateway, caddyPublicIp(),
            table, ReleaseLocks.sha256(rules), ReleaseLocks.sha256(inventory.encodeToByteArray()))
        val bytes = json.encodeToString(intent).encodeToByteArray()
        ReleasePrivateFiles.locked(root) {
            require(!Files.exists(root.resolve("pending.json"), NOFOLLOW_LINKS) &&
                !Files.exists(root.resolve("${binding.operation}.intent.json"), NOFOLLOW_LINKS))
            ReleasePrivateFiles.save(root.resolve("${binding.operation}.intent.json"), bytes)
            ReleasePrivateFiles.save(root.resolve("pending.json"), bytes)
        }
        val wrote = commands.run(listOf("-f", "-"), rules)
        require(wrote.exitCode == 0) { "Native TURN publication uncertain; no replay" }
        val current = snapshot(listOf("-j", "list", "table", "ip", table))
        val entries = json.parseToJsonElement(current).jsonObject.getValue("nftables").jsonArray
        val rulesRead = entries.mapNotNull { it.jsonObject["rule"]?.jsonObject }
        require(rulesRead.size == 4 &&
            rulesRead.groupingBy { it.getValue("chain").jsonPrimitive.content }.eachCount() ==
                mapOf("incoming" to 2, "reply" to 2) &&
            listOf(binding.publication.listenAddress, livekit, gateway, "3478", "5349").all { it in current } &&
            publicListener() == inode) { "Native TURN ingress/return route is not the fixed owned table" }
        val result = RuntimeNativeIngressResult(binding.operation, "install", ReleaseLocks.sha256(bytes),
            ReleaseLocks.sha256(current.encodeToByteArray()), inode,
            binding.expectedSiteSelectionSha256)
        ReleasePrivateFiles.locked(root) {
            require(ReleasePrivateFiles.read(root.resolve("pending.json")).contentEquals(bytes))
            ReleasePrivateFiles.save(root.resolve("${binding.operation}.result.json"), json.encodeToString(result).encodeToByteArray())
            ReleasePrivateFiles.removeExact(root.resolve("pending.json"), bytes)
        }
        return result
    }
    /** Roll back only our fresh source's exact table; no broad GC, host-wide rule flush,
     * recovered generation bind or implicit retry when a native deletion is uncertain. */
    fun rollback(operation: String, originalOperation: String,
        originalResultSha256: String): RuntimeNativeIngressResult {
        require(operation.matches(Regex("r-[a-f0-9]{12}")) &&
            originalOperation.matches(Regex("r-[a-f0-9]{12}")) && operation != originalOperation &&
            originalResultSha256.matches(hash))
        val originalBytes = ReleasePrivateFiles.read(root.resolve("$originalOperation.intent.json"))
        val original = json.decodeFromString<RuntimeNativeIngressIntent>(originalBytes.decodeToString())
        val resultBytes = ReleasePrivateFiles.read(root.resolve("$originalOperation.result.json"))
        val installed = json.decodeFromString<RuntimeNativeIngressResult>(resultBytes.decodeToString())
        require(original.binding.operation == originalOperation && original.binding.fingerprint == fingerprint &&
            installed.operation == originalOperation && installed.action == "install" &&
            installed.intentSha256 == ReleaseLocks.sha256(originalBytes) &&
            originalResultSha256 == ReleaseLocks.sha256(resultBytes) &&
            original.nativeTable.matches(tableName))
        val before = snapshot(listOf("-j", "list", "table", "ip", original.nativeTable))
        val rules = json.parseToJsonElement(before).jsonObject.getValue("nftables").jsonArray
            .mapNotNull { it.jsonObject["rule"]?.jsonObject }
        require(rules.size == 4 && rules.groupingBy { it.getValue("chain").jsonPrimitive.content }.eachCount() ==
            mapOf("incoming" to 2, "reply" to 2) &&
            listOf(original.binding.publication.listenAddress, original.livekitIp, original.gatewayIp,
                "3478", "5349").all { it in before }) { "Changed or foreign native table cannot be rolled back broadly" }
        val rollback = RuntimeNativeIngressRollbackIntent(operation, originalOperation,
            ReleaseLocks.sha256(originalBytes), originalResultSha256, original.nativeTable,
            ReleaseLocks.sha256(before.encodeToByteArray()))
        val bytes = json.encodeToString(rollback).encodeToByteArray()
        ReleasePrivateFiles.locked(root) {
            require(!Files.exists(root.resolve("pending.json"), NOFOLLOW_LINKS) &&
                !Files.exists(root.resolve("$operation.rollback.intent.json"), NOFOLLOW_LINKS))
            ReleasePrivateFiles.save(root.resolve("$operation.rollback.intent.json"), bytes)
            ReleasePrivateFiles.save(root.resolve("pending.json"), bytes)
        }
        val removed = commands.run(listOf("delete", "table", "ip", original.nativeTable), null)
        require(removed.exitCode == 0) { "Native rollback uncertain; keep owned site TURN exclusion" }
        return reconcileRollback(operation, ReleaseLocks.sha256(bytes))
    }
    /** Read-only rollback adoption; never resends nft delete after lost acknowledgement. */
    fun reconcileRollback(operation: String, expectedIntentSha256: String): RuntimeNativeIngressResult {
        require(operation.matches(Regex("r-[a-f0-9]{12}")) && expectedIntentSha256.matches(hash))
        val bytes = ReleasePrivateFiles.locked(root) { ReleasePrivateFiles.read(root.resolve("pending.json")) }
        require(ReleaseLocks.sha256(bytes) == expectedIntentSha256 &&
            ReleasePrivateFiles.read(root.resolve("$operation.rollback.intent.json")).contentEquals(bytes))
        val intent = json.decodeFromString<RuntimeNativeIngressRollbackIntent>(bytes.decodeToString())
        require(intent.operation == operation && intent.ownedTable.matches(tableName) &&
            intent.originalIntentSha256.matches(hash) && intent.originalResultSha256.matches(hash))
        val inventory = snapshot(listOf("-j", "list", "ruleset"))
        require(json.parseToJsonElement(inventory).jsonObject.getValue("nftables").jsonArray.none {
            it.jsonObject["table"]?.jsonObject?.get("name")?.jsonPrimitive?.content == intent.ownedTable ||
                it.jsonObject["rule"]?.jsonObject?.get("table")?.jsonPrimitive?.content == intent.ownedTable
        } && socketInventory(3478, "udp") && socketInventory(5349, "tcp")) {
            "Owned public TURN sockets or native rules remain after rollback"
        }
        val prior = json.decodeFromString<RuntimeNativeIngressIntent>(ReleasePrivateFiles.read(
            root.resolve("${intent.originalOperation}.intent.json")).decodeToString())
        val result = RuntimeNativeIngressResult(operation, "rollback", expectedIntentSha256,
            ReleaseLocks.sha256(inventory.encodeToByteArray()), publicListener(),
            prior.binding.expectedSiteSelectionSha256, "removed-native-ports")
        ReleasePrivateFiles.locked(root) {
            require(ReleasePrivateFiles.read(root.resolve("pending.json")).contentEquals(bytes))
            ReleasePrivateFiles.save(root.resolve("$operation.rollback.result.json"), json.encodeToString(result).encodeToByteArray())
            ReleasePrivateFiles.removeExact(root.resolve("pending.json"), bytes)
        }
        return result
    }
    /** Read-only lost-ack adoption. Absence/mismatch retains the pending exclusion forever. */
    fun reconcile(operation: String, expectedIntentSha256: String): RuntimeNativeIngressResult {
        require(operation.matches(Regex("r-[a-f0-9]{12}")) && expectedIntentSha256.matches(hash))
        val bytes = ReleasePrivateFiles.locked(root) { ReleasePrivateFiles.read(root.resolve("pending.json")) }
        require(ReleaseLocks.sha256(bytes) == expectedIntentSha256 &&
            ReleasePrivateFiles.read(root.resolve("$operation.intent.json")).contentEquals(bytes))
        val intent = json.decodeFromString<RuntimeNativeIngressIntent>(bytes.decodeToString())
        require(intent.binding.operation == operation && intent.binding.fingerprint == fingerprint &&
            intent.rulesSha256.matches(hash) && admitted(intent.binding).let {
                it.first == intent.livekitIp && it.second == intent.gatewayIp
            })
        val current = snapshot(listOf("-j", "list", "table", "ip", intent.nativeTable))
        require(current.contains(intent.livekitIp) && current.contains(intent.gatewayIp) &&
            current.contains(intent.binding.publication.listenAddress) &&
            json.parseToJsonElement(current).jsonObject.getValue("nftables").jsonArray
                .count { "rule" in it.jsonObject } == 4) { "Uncertain public TURN rule not present: no retry" }
        val result = RuntimeNativeIngressResult(operation, "install", expectedIntentSha256,
            ReleaseLocks.sha256(current.encodeToByteArray()), publicListener(),
            intent.binding.expectedSiteSelectionSha256)
        ReleasePrivateFiles.locked(root) {
            require(ReleasePrivateFiles.read(root.resolve("pending.json")).contentEquals(bytes))
            ReleasePrivateFiles.save(root.resolve("$operation.result.json"), json.encodeToString(result).encodeToByteArray())
            ReleasePrivateFiles.removeExact(root.resolve("pending.json"), bytes)
        }
        return result
    }
}
