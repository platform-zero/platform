package net.datamancy.platform

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class QualificationMatrixPcapTest {
    private val client = byteArrayOf(10, 42, 0, 10)
    private val turn = byteArrayOf(10, 42, 0, 20)
    private val sfu = byteArrayOf(10, 42, 0, 30)
    private fun net16(n: Int) = byteArrayOf((n shr 8).toByte(), n.toByte())
    private fun little(vararg n: Int): ByteArray = ByteBuffer.allocate(n.size * 4).order(ByteOrder.LITTLE_ENDIAN)
        .also { b -> n.forEach(b::putInt) }.array()
    private val tx = ByteArray(12) { (it + 1).toByte() }
    private fun stun(kind: Int, attrs: ByteArray = byteArrayOf()) =
        net16(kind) + net16(attrs.size) + byteArrayOf(0x21, 0x12, 0xa4.toByte(), 0x42) + tx + attrs
    private fun attribute(kind: Int, body: ByteArray) = net16(kind) + net16(body.size) + body +
        ByteArray((4 - body.size % 4) % 4)
    private fun event(outgoing: Boolean, payload: ByteArray): ByteArray {
        val ip = byteArrayOf(0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0) +
            (if (outgoing) client + turn else turn + client)
        val udp = net16(if (outgoing) 41111 else 3478) + net16(if (outgoing) 3478 else 41111) +
            net16(payload.size + 8) + byteArrayOf(0, 0)
        val packet = byteArrayOf(*ByteArray(12), 0x08, 0x00) + ip + udp + payload
        require(packet.size <= 512)
        return little(0, 0, packet.size, packet.size) + packet
    }
    private fun channel(payload: ByteArray) = net16(0x4001) + net16(payload.size) + payload
    private fun fixture(peer: ByteArray = sfu): ByteArray {
        val xor = ByteArray(4) { i -> (peer[i].toInt() xor
            byteArrayOf(0x21, 0x12, 0xa4.toByte(), 0x42)[i].toInt()).toByte() }
        val bind = attribute(0x000c, net16(0x4001) + byteArrayOf(0, 0)) +
            attribute(0x0012, byteArrayOf(0, 1) + net16(50000 xor 0x2112) + xor)
        val records = listOf(event(true, stun(0x0003)), event(false, stun(0x0103)),
            event(true, stun(0x0009, bind)), event(false, stun(0x0109)),
            event(true, channel(stun(0x0001, attribute(0x0025, byteArrayOf()))))) +
            (0 until 3).flatMap { listOf(event(true, channel(byteArrayOf(0x80.toByte()) + ByteArray(399))),
                event(false, channel(byteArrayOf(0x80.toByte()) + ByteArray(399)))) }
        val header = byteArrayOf(0xd4.toByte(), 0xc3.toByte(), 0xb2.toByte(), 0xa1.toByte(),
            2, 0, 4, 0) + ByteArray(8) + little(512, 1)
        return header + records.fold(byteArrayOf()) { prior, record -> prior + record }
    }
    @Test fun `only nominated bidirectional bound TURN bytes qualify`() {
        val media = QualificationMatrixPcap.parse(fixture(), "10.42.0.10", "10.42.0.20", "10.42.0.30")
        assertEquals("relay", media.getValue("iceLocalCandidateType").jsonPrimitive.content)
        assertEquals(1200, media.getValue("iceBytesSent").jsonPrimitive.int)
        assertEquals(1200, media.getValue("iceBytesReceived").jsonPrimitive.int)
    }
    @Test fun `rejects foreign SFU changed snapshot and truncated packets`() {
        assertThrows(IllegalArgumentException::class.java) {
            QualificationMatrixPcap.parse(fixture(byteArrayOf(10, 42, 0, 31)), "10.42.0.10", "10.42.0.20", "10.42.0.30")
        }
        assertThrows(IllegalArgumentException::class.java) {
            QualificationMatrixPcap.parse(fixture().copyOf(20), "10.42.0.10", "10.42.0.20", "10.42.0.30")
        }
        val changed = fixture().copyOf().also { it[17] = 0 }
        assertThrows(IllegalArgumentException::class.java) {
            QualificationMatrixPcap.parse(changed, "10.42.0.10", "10.42.0.20", "10.42.0.30")
        }
    }
}
