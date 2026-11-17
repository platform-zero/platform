package net.datamancy.platform

import java.security.SecureRandom
import kotlin.test.*

class QbittorrentPrivatePeerTest {
    private val pinned = "example.org/qbittorrent@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf(AcquiredImage("qbittorrent", "upstream",
        "example.org/qbittorrent:1", pinned, "b".repeat(64), emptyList(), pinned.substringAfter('@'), "amd64", "linux")))
    private val generation = "q-111111111111"
    private fun original() = QbittorrentPrivatePeer.original(SecureRandom.getInstance("SHA1PRNG").also {
        it.setSeed(byteArrayOf(1,2,3,4))
    })

    @Test fun `real private torrent encodes exactly one 131072 byte original piece and NO tracker`(): Unit {
        val source = original()
        QbittorrentPrivatePeer.verify(source)
        val raw = java.util.Base64.getDecoder().decode(source.torrentBase64)
        assertEquals(131072, java.util.Base64.getDecoder().decode(source.payloadBase64).size)
        assertContains(String(raw, Charsets.ISO_8859_1), "7:privatei1e")
        assertFalse(String(raw, Charsets.ISO_8859_1).contains("announce"))
        assertFalse(String(raw, Charsets.ISO_8859_1).contains("tracker"))
        assertFails { QbittorrentPrivatePeer.verify(source.copy(payloadSha256 = "0".repeat(64))) }
        assertFails { QbittorrentPrivatePeer.verify(source.copy(infoHash = "0".repeat(40))) }
    }

    @Test fun `install physical seeder has same pinned actual image and separate confined volume`(): Unit {
        val source = original()
        val main = QbittorrentRuntime.canonicalFragment(inventory,"$generation-qbittorrent")
        val inputs = QbittorrentRuntime.canonicalInputs()
        val combined = QbittorrentPrivatePeer.withPeer(main,source,
            inputs.getValue("qbittorrent-qbittorrent.conf"))
        val peer = combined.spec.processes.single { it.id == "qbittorrent-private-peer" }
        val owner = combined.spec.processes.single { it.id == "qbittorrent" }
        assertEquals(owner.imageId,peer.imageId)
        assertNotEquals(owner.volumes,peer.volumes)
        assertEquals(listOf("transfer-data"), peer.networks)
        assertFalse(peer.oneShot)
        assertEquals(8080, peer.readinessHttpPort)
        assertEquals(owner.readinessHttpPort, peer.readinessHttpPort)
        assertEquals(setOf("private-peer-config","private-peer-data"),
            combined.spec.volumes.map { it.id }.toSet() - main.spec.volumes.map { it.id }.toSet())
        val peerInputs = QbittorrentPrivatePeer.peerInputs(source,
            inputs.getValue("qbittorrent-qbittorrent.conf"),inputs.getValue("qbittorrent-qbittorrent.env"))
        assertEquals(setOf("qbittorrent-peer.conf","qbittorrent-peer.env","qbittorrent-peer-payload.b64"),peerInputs.keys)
        val cold = QbittorrentPrivatePeer.cold(combined)
        assertEquals(setOf("config","downloads"),cold.spec.volumes.map { it.id }.toSet())
        assertEquals(listOf("qbittorrent"),cold.spec.processes.map { it.id })
        assertFails { QbittorrentPrivatePeer.cold(main) }
    }

    @Test fun `private peer native request never starts a seeder or overwrites original download on cold restore`(): Unit {
        val source = original()
        val binding = NativeQualificationCaseBinding(generation,"qbittorrent-original-1",
            "/mnt/media/p0-v3/qualified-clients/qbittorrent-original-1", "a".repeat(64),"b".repeat(64),
            "qbittorrent","INSTALL","$generation-qbittorrent","c".repeat(64))
        val first = QbittorrentPrivatePeerNativeRequest("qp-111111111111",binding,
            QbittorrentPrivatePeerAction.ADD_PEER,source.infoHash,source.torrentSha256,source.payloadSha256)
        QbittorrentPrivatePeer.requireNativeRequest(first,source)
        val restored = first.copy(binding = binding.copy(phase = "RESTORE"),
            action = QbittorrentPrivatePeerAction.RESTORED_READ,
            originalSourceOracleSha256 = "d".repeat(64))
        QbittorrentPrivatePeer.requireNativeRequest(restored,source)
        assertFails { QbittorrentPrivatePeer.requireNativeRequest(restored.copy(
            action = QbittorrentPrivatePeerAction.ADD_PEER),source) }
        assertFails { QbittorrentPrivatePeer.requireNativeRequest(restored.copy(
            originalSourceOracleSha256 = null),source) }
        assertFails { QbittorrentPrivatePeer.requireNativeRequest(first.copy(
            infoHash = "0".repeat(40)),source) }
    }

    @Test fun `two peer proof requires distinct native namespaces on shared network and original bytes stopped peer`(): Unit {
        val source = original()
        val result = QbittorrentPrivatePeerResult(generation,"qbittorrent-original-1", "a".repeat(64),
            "b".repeat(64),42,43,72,73,"10.27.0.9",source.payloadSha256,source.infoHash,
            source.payloadSha256,131072,"c".repeat(64),"d".repeat(64))
        QbittorrentPrivatePeer.verifyOriginal(result,source,generation,result.invocationId,"d".repeat(64))
        assertFails { QbittorrentPrivatePeer.verifyOriginal(result.copy(targetNetnsInode = 73),source,
            generation,result.invocationId,"d".repeat(64)) }
        assertFails { QbittorrentPrivatePeer.verifyOriginal(result.copy(peerStoppedProofSha256 = ""),source,
            generation,result.invocationId,"d".repeat(64)) }
        assertFails { QbittorrentPrivatePeer.verifyOriginal(result.copy(targetDownloadedSha256 = "e".repeat(64)),source,
            generation,result.invocationId,"d".repeat(64)) }
    }
}
