package net.datamancy.platform

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.json.*
import kotlinx.serialization.Serializable

/** One genuine second qBittorrent process in the same isolated transfer-data graph.
 * No tracker/NAT/host peer, no separate unreviewed image, no public swarm capability.
 * The intent and generated source payload MUST be sealed before any one-shot writer.
 */
@Serializable internal data class QbittorrentPrivatePeerSource(val payloadBase64: String,
    val payloadSha256: String, val torrentBase64: String, val torrentSha256: String,
    val infoHash: String, val expectedBytes: Int = 131072)
@Serializable internal enum class QbittorrentPrivatePeerAction { ADD_PEER, READ_DOWNLOADED, STOP_PEER, RESTORED_READ }
@Serializable internal data class QbittorrentPrivatePeerNativeRequest(val operation: String,
    val binding: NativeQualificationCaseBinding, val action: QbittorrentPrivatePeerAction,
    val infoHash: String, val torrentSha256: String, val payloadSha256: String,
    val originalSourceOracleSha256: String? = null)
@Serializable internal data class QbittorrentPrivatePeerResult(val generationId: String,
    val invocationId: String, val targetContainerId: String, val peerContainerId: String,
    val targetPid: Int, val peerPid: Int, val targetNetnsInode: Long, val peerNetnsInode: Long,
    val peerAddress: String, val payloadSha256: String, val infoHash: String,
    val targetDownloadedSha256: String, val downloadedBytes: Long,
    val peerStoppedProofSha256: String, val sourceOracleSha256: String)

internal object QbittorrentPrivatePeer {
    const val NAME = "p0v3-original-private.bin"
    private val digest = Regex("[a-f0-9]{64}")
    private fun encoded(bytes: ByteArray): ByteArray = bytes.size.toString().toByteArray() + byteArrayOf(':'.code.toByte()) + bytes
    private fun encoded(value: Long): ByteArray = "i${value}e".toByteArray()
    private fun dictionary(entries: Map<String, ByteArray>): ByteArray =
        byteArrayOf('d'.code.toByte()) + entries.toSortedMap().entries.fold(ByteArray(0)) { memo, (key, value) ->
            memo + encoded(key.toByteArray(StandardCharsets.UTF_8)) + value
        } + byteArrayOf('e'.code.toByte())
    private fun hash(kind: String, data: ByteArray): String = MessageDigest.getInstance(kind)
        .digest(data).joinToString("") { "%02x".format(it) }

    fun original(random: SecureRandom = SecureRandom()): QbittorrentPrivatePeerSource {
        val payload = ByteArray(131072).also(random::nextBytes)
        val info = dictionary(mapOf("length" to encoded(payload.size.toLong()),
            "name" to encoded(NAME.toByteArray(StandardCharsets.UTF_8)),
            "piece length" to encoded(262144L),
            "pieces" to encoded(MessageDigest.getInstance("SHA-1").digest(payload)),
            "private" to encoded(1L)))
        val torrent = dictionary(mapOf("info" to info)) // deliberately NO tracker/announce key
        return QbittorrentPrivatePeerSource(Base64.getEncoder().encodeToString(payload),
            hash("SHA-256", payload), Base64.getEncoder().encodeToString(torrent),
            hash("SHA-256", torrent), hash("SHA-1", info))
    }
    fun verify(source: QbittorrentPrivatePeerSource) {
        require(source.expectedBytes == 131072 && source.payloadBase64.length in 174762..174764 &&
            source.payloadSha256.matches(digest) && source.torrentSha256.matches(digest) &&
            source.infoHash.matches(Regex("[a-f0-9]{40}")))
        val payload = Base64.getDecoder().decode(source.payloadBase64)
        require(payload.size == source.expectedBytes && hash("SHA-256", payload) == source.payloadSha256)
        val info = dictionary(mapOf("length" to encoded(payload.size.toLong()),
            "name" to encoded(NAME.toByteArray(StandardCharsets.UTF_8)),
            "piece length" to encoded(262144L),
            "pieces" to encoded(MessageDigest.getInstance("SHA-1").digest(payload)),
            "private" to encoded(1L)))
        val torrent = dictionary(mapOf("info" to info))
        require(Base64.getDecoder().decode(source.torrentBase64).contentEquals(torrent) &&
            hash("SHA-256", torrent) == source.torrentSha256 && hash("SHA-1", info) == source.infoHash)
    }
    /** Same exact reviewed image ID as the target. Separate process, two extra fixed
     * private state volumes and 512MiB + 512MiB disk are admitted before effects. */
    fun withPeer(fragment: CanonicalProviderFragment, source: QbittorrentPrivatePeerSource,
        targetConfig: String): CanonicalProviderFragment {
        verify(source)
        require(fragment.product == "qbittorrent" && fragment.spec.store == RuntimeStore.CANONICAL_V2 &&
            fragment.spec.processes.map { it.id }.toSet() == setOf("qbittorrent-config-init", "qbittorrent") &&
            fragment.spec.networks == listOf("transfer-data", "transfer-web") &&
            targetConfig.contains("WebUI\\HostHeaderValidation=true\n") &&
            targetConfig.contains("Session\\DHTEnabled=false\n") &&
            targetConfig.contains("Session\\PeXEnabled=false\n") &&
            targetConfig.contains("Session\\LSDEnabled=false\n"))
        val target = fragment.spec.processes.single { it.id == "qbittorrent" }
        val mounts = listOf(RuntimeMount("private-peer-config", "/config"),
            RuntimeMount("private-peer-data", "/downloads"))
        val init = target.copy(id = "qbittorrent-private-peer-init", dependencies = emptyList(),
            oneShot = true, entrypoint = "/bin/sh", environmentFile = null,
            files = listOf(RuntimeFile("qbittorrent-peer.conf", "/run/secrets/peer.conf"),
                RuntimeFile("qbittorrent-peer-payload.b64", "/run/secrets/payload.b64")),
            volumes = mounts, networks = listOf("transfer-data"), memoryMiB = 512,
            readinessHttpPort = null, readinessHttpPath = "/",
            command = listOf("-ec", """
                umask 077
                test -z "${'$'}(ls -A /config)" && test -z "${'$'}(ls -A /downloads)"
                mkdir -p /config/qBittorrent
                cp /run/secrets/peer.conf /config/qBittorrent/qBittorrent.conf
                base64 -d /run/secrets/payload.b64 > /downloads/$NAME
                test "${'$'}(sha256sum /downloads/$NAME | cut -d' ' -f1)" = "${source.payloadSha256}"
            """.trimIndent()))
        val peer = target.copy(id = "qbittorrent-private-peer", dependencies = listOf(init.id),
            oneShot = false, environmentFile = "qbittorrent-peer.env", files = emptyList(),
            volumes = mounts, networks = listOf("transfer-data"), memoryMiB = 512)
        val spec = fragment.spec.copy(volumes = fragment.spec.volumes + listOf(
            RuntimeVolume("private-peer-config", 1000), RuntimeVolume("private-peer-data", 1000)),
            processes = fragment.spec.processes + init + peer)
        PrivateDeployment.validate(spec)
        return fragment.copy(spec = spec)
    }
    fun peerInputs(source: QbittorrentPrivatePeerSource, targetConfig: String, targetEnvironment: String): Map<String,String> {
        verify(source)
        require("WebUI\\ServerDomains=qbittorrent;torrents.datamancy.net\n" in targetConfig &&
            "P0V3_QBIT_PASSWORD=" in targetEnvironment)
        val config = targetConfig.replace("WebUI\\ServerDomains=qbittorrent;torrents.datamancy.net\n",
            "WebUI\\ServerDomains=qbittorrent-private-peer\n")
        return mapOf("qbittorrent-peer.conf" to config,
            "qbittorrent-peer.env" to targetEnvironment,
            "qbittorrent-peer-payload.b64" to source.payloadBase64 + "\n")
    }
    fun cold(fragment: CanonicalProviderFragment): CanonicalProviderFragment {
        require(fragment.product == "qbittorrent" && fragment.spec.processes.map { it.id }.toSet() ==
            setOf("qbittorrent-config-init", "qbittorrent", "qbittorrent-private-peer-init", "qbittorrent-private-peer") &&
            fragment.spec.volumes.map { it.id }.toSet() == setOf("config", "downloads", "private-peer-config", "private-peer-data"))
        val reduced = fragment.copy(spec = fragment.spec.copy(
            processes = fragment.spec.processes.filter { it.id in setOf("qbittorrent-config-init", "qbittorrent") },
            volumes = fragment.spec.volumes.filter { it.id in setOf("config", "downloads") }))
        return QbittorrentRuntime.coldRestoreFragment(reduced)
    }
    /** Inspect TWO actual separate containers in one owned transfer-data network.
     * A peer's HTTP health, caller-chosen IP or registry state cannot supply this. */
    fun inspectPair(fragment: CanonicalProviderFragment, fingerprint: String,
        command: RuntimeCommands): Pair<NativeQualificationTarget, NativeQualificationTarget> {
        val spec = fragment.spec
        require(fragment.product == "qbittorrent" && spec.store == RuntimeStore.CANONICAL_V2 &&
            spec.name.matches(Regex("q-[a-f0-9]{12}-qbittorrent")) && fingerprint.matches(digest) &&
            spec.networks == listOf("transfer-data", "transfer-web"))
        val selected = spec.processes.filter { it.id in setOf("qbittorrent", "qbittorrent-private-peer") }
        require(selected.size == 2 && selected.map { it.imageId }.distinct().size == 1 &&
            selected.all { it.userId == 1000 && it.capabilities.isEmpty() && !it.oneShot })
        fun inspect(id: String, expectedNetworks: Set<String>, expectedVolumes: Map<String,String>): NativeQualificationTarget {
            val receipt = command.run(listOf("inspect", "--type", "container", "p0v3-live-${spec.name}-$id"))
            require(receipt.exitCode == 0 && receipt.output.length in 1..262144)
            val native = Json.parseToJsonElement(receipt.output).jsonArray.single().jsonObject
            val state = native.getValue("State").jsonObject
            val config = native.getValue("Config").jsonObject
            val nets = native.getValue("NetworkSettings").jsonObject.getValue("Networks").jsonObject
            val mounts = native.getValue("Mounts").jsonArray
            val process = selected.single { it.id == id }
            val cid = native.getValue("Id").jsonPrimitive.content
            val pid = state.getValue("Pid").jsonPrimitive.int
            require(cid.matches(digest) && state.getValue("Running").jsonPrimitive.boolean && pid > 1 &&
                native.getValue("Image").jsonPrimitive.content.removePrefix("sha256:") == process.imageId &&
                config.getValue("Labels").jsonObject.getValue("io.p0v3.private-deployment").jsonPrimitive.content == spec.name &&
                config.getValue("Labels").jsonObject.getValue("io.p0v3.runtime-fingerprint").jsonPrimitive.content == fingerprint &&
                nets.keys == expectedNetworks.map { "p0v3-live-${spec.name}-$it" }.toSet() &&
                mounts.size == expectedVolumes.size &&
                mounts.associate { it.jsonObject.getValue("Name").jsonPrimitive.content to
                    it.jsonObject.getValue("Destination").jsonPrimitive.content } == expectedVolumes)
            val inode = requireNotNull(Regex("net:\\[([0-9]+)]").matchEntire(
                Files.readSymbolicLink(Path.of("/proc/$pid/ns/net")).toString())).groupValues[1].toLong()
            val address = nets.getValue("p0v3-live-${spec.name}-transfer-data").jsonObject
                .getValue("IPAddress").jsonPrimitive.content
            require(inode > 1 && address.matches(Regex("[0-9]{1,3}(?:\\.[0-9]{1,3}){3}")) &&
                java.net.InetAddress.getByName(address).isSiteLocalAddress)
            return NativeQualificationTarget(cid, pid, inode, address, 8080)
        }
        val base = "p0v3-live-${spec.name}-volume-"
        val owner = inspect("qbittorrent", setOf("transfer-data","transfer-web"), mapOf(
            "${base}config" to "/config", "${base}downloads" to "/downloads"))
        val peer = inspect("qbittorrent-private-peer", setOf("transfer-data"), mapOf(
            "${base}private-peer-config" to "/config", "${base}private-peer-data" to "/downloads"))
        require(owner.containerId != peer.containerId && owner.pid != peer.pid &&
            owner.netnsInode != peer.netnsInode && owner.address != peer.address)
        return owner to peer
    }
    fun requireNativeRequest(request: QbittorrentPrivatePeerNativeRequest, source: QbittorrentPrivatePeerSource) {
        verify(source)
        val bound = request.binding
        require(request.operation.matches(Regex("qp-[a-f0-9]{12}")) &&
            bound.serviceId == "qbittorrent" && bound.phase in setOf("INSTALL", "RESTORE") &&
            bound.targetMemberName == "${bound.generationId}-qbittorrent" &&
            bound.targetFingerprint.matches(digest) &&
            request.infoHash == source.infoHash && request.torrentSha256 == source.torrentSha256 &&
            request.payloadSha256 == source.payloadSha256 &&
            (bound.phase == "INSTALL" && request.originalSourceOracleSha256 == null &&
                request.action in setOf(QbittorrentPrivatePeerAction.ADD_PEER,
                    QbittorrentPrivatePeerAction.READ_DOWNLOADED,QbittorrentPrivatePeerAction.STOP_PEER) ||
                bound.phase == "RESTORE" && request.originalSourceOracleSha256?.matches(digest) == true &&
                    request.action == QbittorrentPrivatePeerAction.RESTORED_READ)) {
            "Only the original trackerless peer and source-bound cold target may run native fixed actions"
        }
    }
    fun verifyOriginal(result: QbittorrentPrivatePeerResult, source: QbittorrentPrivatePeerSource,
        generation: String, invocation: String, oracleSha256: String) {
        verify(source)
        require(result.generationId == generation && generation.matches(Regex("q-[a-f0-9]{12}")) &&
            result.invocationId == invocation && invocation.matches(Regex("[a-z][a-z0-9-]{0,95}")) &&
            result.targetContainerId.matches(digest) && result.peerContainerId.matches(digest) &&
            result.targetContainerId != result.peerContainerId &&
            result.targetPid > 1 && result.peerPid > 1 && result.targetPid != result.peerPid &&
            result.targetNetnsInode > 1 && result.peerNetnsInode > 1 &&
            result.targetNetnsInode != result.peerNetnsInode &&
            result.peerAddress.matches(Regex("[0-9]{1,3}(?:\\.[0-9]{1,3}){3}")) &&
            java.net.InetAddress.getByName(result.peerAddress).isSiteLocalAddress &&
            result.payloadSha256 == source.payloadSha256 && result.infoHash == source.infoHash &&
            result.targetDownloadedSha256 == source.payloadSha256 && result.downloadedBytes >= 131072 &&
            result.peerStoppedProofSha256.matches(digest) && oracleSha256.matches(digest) &&
            result.sourceOracleSha256 == oracleSha256) {
            "No actual two-peer private transfer, original downloaded bytes, stopped peer or source oracle"
        }
    }
}
