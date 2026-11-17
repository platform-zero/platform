package net.datamancy.platform

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlinx.serialization.json.*

/** Bounded owner-only pcap verifier: actual TURN Allocate + ChannelBind response,
 * nominated ICE and >1KiB bidirectional media on one selected client/relay/SFU pair.
 * Raw pcap and authentication attributes never leave the owner thread. */
internal object QualificationMatrixPcap {
    private data class Event(val outgoing: Boolean, val clientPort: Int, val payload: ByteArray)
    private data class Stun(val method: Int, val klass: Int, val transaction: String,
        val attributes: Map<Int, ByteArray>)
    private data class Channel(val number: Int, val port: Int, val accepted: Boolean)
    private fun u16(data: ByteArray, at: Int) = ((data[at].toInt() and 255) shl 8) or
        (data[at + 1].toInt() and 255)
    private fun address(data: ByteArray, at: Int) = (at until at + 4).joinToString(".") { (data[it].toInt() and 255).toString() }
    private fun sha(data: ByteArray) = ReleaseLocks.sha256(data)
    private fun ByteArray.hex(): String = joinToString("") { byte ->
        val n = byte.toInt() and 255
        "0123456789abcdef"[n ushr 4].toString() + "0123456789abcdef"[n and 15]
    }
    private fun String.unhex(): ByteArray {
        require(length % 2 == 0 && all { it in "0123456789abcdef" })
        return ByteArray(length / 2) { i -> substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }
    private fun stun(data: ByteArray): Stun? {
        if (data.size < 20 || (data[0].toInt() and 192) != 0 || u16(data, 4) != 0x2112 ||
            u16(data, 6) != 0xa442) return null
        val kind = u16(data, 0)
        val length = u16(data, 2)
        require(length % 4 == 0 && length <= 4096 && 20 + length <= data.size)
        val attrs = mutableMapOf<Int, ByteArray>()
        var index = 20
        while (index < 20 + length) {
            require(index + 4 <= 20 + length)
            val attribute = u16(data, index)
            val size = u16(data, index + 2)
            require(index + 4 + size <= 20 + length)
            if (attribute in setOf(0x000c, 0x0012, 0x0025)) attrs[attribute] = data.copyOfRange(index + 4, index + 4 + size)
            index += 4 + ((size + 3) / 4) * 4
        }
        require(index == 20 + length)
        return Stun((kind and 15) or ((kind and 0xe0) shr 1) or ((kind and 0x3e00) shr 2),
            ((kind shr 4) and 1) or ((kind shr 7) and 2), data.copyOfRange(8, 20).hex(), attrs)
    }
    fun parse(pcap: ByteArray, client: String, turn: String, sfu: String): JsonObject {
        require(pcap.size in 24..(32 * 1024 * 1024) && setOf(client, turn, sfu).size == 3 &&
            listOf(client, turn, sfu).all { it.matches(Regex("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) })
        val little = when (pcap.copyOfRange(0, 4).hex()) {
            "d4c3b2a1" -> true; "a1b2c3d4" -> false; else -> error("Foreign pcap encoding")
        }
        val buffer = ByteBuffer.wrap(pcap).order(if (little) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN)
        fun number(at: Int): Int = buffer.getInt(at)
        require(buffer.getShort(4).toInt() == 2 && buffer.getShort(6).toInt() == 4 &&
            number(16) == 512 && number(20) in setOf(1, 113, 276))
        val link = number(20)
        val events = mutableListOf<Event>()
        var at = 24
        while (at < pcap.size) {
            require(at + 16 <= pcap.size)
            val size = number(at + 8)
            require(size in 1..640 && at + 16 + size <= pcap.size)
            val frame = pcap.copyOfRange(at + 16, at + 16 + size)
            at += size + 16
            val header = when (link) { 1 -> 14; 113 -> 16; else -> 20 }
            require(frame.size >= header)
            val ipv4 = when (link) { 1 -> u16(frame, 12) == 0x0800
                113 -> u16(frame, 14) == 0x0800
                else -> u16(frame, 0) == 0x0800 }
            if (!ipv4 || frame.size < header + 28 || (frame[header].toInt() ushr 4) != 4) continue
            val ip = frame.copyOfRange(header, frame.size)
            val ihl = (ip[0].toInt() and 15) * 4
            require(ihl in 20..60 && ip.size >= ihl + 8 && (u16(ip, 6) and 0x3fff) == 0)
            if (ip[9].toInt() != 17) continue
            val src = address(ip, 12); val dst = address(ip, 16)
            val sport = u16(ip, ihl); val dport = u16(ip, ihl + 2)
            if (!(src == client && dst == turn && dport == 3478 ||
                    src == turn && dst == client && sport == 3478)) continue
            val payload = ip.copyOfRange(ihl + 8, ip.size)
            require(payload.size >= 4)
            events += Event(src == client, if (src == client) sport else dport, payload)
        }
        require(at == pcap.size)
        val allocations = mutableMapOf<Pair<Int, String>, Boolean>()
        val bindings = mutableMapOf<Pair<Int, String>, Channel>()
        val nominees = mutableSetOf<Triple<Int, Int, String>>()
        val media = mutableMapOf<Pair<Int, Int>, IntArray>()
        for (event in events) {
            val bytes = event.payload
            val decoded = if (u16(bytes, 0) < 0x4000) stun(bytes) else null
            if (decoded != null) {
                val key = event.clientPort to decoded.transaction
                val attrs = decoded.attributes
                if (decoded.method == 3 && decoded.klass == 0 && event.outgoing) allocations[key] = false
                if (decoded.method == 3 && decoded.klass == 2 && !event.outgoing && key in allocations) allocations[key] = true
                if (decoded.method == 9 && decoded.klass == 0 && event.outgoing) {
                    val channel = attrs[0x000c]; val peer = attrs[0x0012]
                    if (channel != null && channel.size == 4 && peer != null && peer.size >= 8 && peer[1].toInt() == 1) {
                        val ch = u16(channel, 0)
                        val peerIp = ByteArray(4) { index -> (peer[index + 4].toInt() xor
                            byteArrayOf(0x21, 0x12, 0xa4.toByte(), 0x42)[index].toInt()).toByte() }
                        val port = u16(peer, 2) xor 0x2112
                        if (ch in 0x4000..0x7fff && address(peerIp, 0) == sfu && port in 50000..50020)
                            bindings[key] = Channel(ch, port, false)
                    }
                }
                if (decoded.method == 9 && decoded.klass == 2 && !event.outgoing && key in bindings)
                    bindings[key] = bindings.getValue(key).copy(accepted = true)
                continue
            }
            val channel = u16(bytes, 0)
            if (channel !in 0x4000..0x7fff) continue
            val length = u16(bytes, 2)
            require(length <= bytes.size - 4)
            val inner = bytes.copyOfRange(4, 4 + length)
            val ice = if (inner.size >= 20 && (inner[0].toInt() and 192) == 0) stun(inner) else null
            if (ice != null && ice.method == 1 && ice.klass == 0 && 0x0025 in ice.attributes)
                nominees += Triple(event.clientPort, channel, ice.transaction)
            else if (ice == null && inner.size >= 40 && (inner[0].toInt() and 255) in 0x80..0xbf)
                media.getOrPut(event.clientPort to channel) { intArrayOf(0, 0) }[if (event.outgoing) 0 else 1] += length
        }
        val approved = nominees.filter { (port, channel, _) ->
            bindings.any { (key, value) -> key.first == port && value.number == channel &&
                value.port in 50000..50020 && value.accepted } &&
                allocations.any { (key, accepted) -> key.first == port && accepted } &&
                media[port to channel]?.all { it > 1024 } == true
        }
        require(approved.size == 1) { "No unique allocated channel-bound nominated two-way TURN media path" }
        val (port, channel, transaction) = approved.single()
        val traffic = media.getValue(port to channel)
        val digest = sha(client.encodeToByteArray() + turn.encodeToByteArray() + sfu.encodeToByteArray() +
            byteArrayOf((port shr 8).toByte(), port.toByte(), (channel shr 8).toByte(), channel.toByte()) +
            transaction.unhex())
        // Same sorted-key JSON bytes as the client readback, without exposing packet payload.
        val observation = "{\"client\":\"$client\",\"mediaBytes\":[${traffic[0]},${traffic[1]}]," +
            "\"nomination\":\"$digest\",\"sfu\":\"$sfu\",\"turn\":\"$turn\"}"
        return buildJsonObject {
            put("nominatedPairDigest", digest); put("iceLocalCandidateType", "relay")
            put("iceBytesSent", traffic[0]); put("iceBytesReceived", traffic[1])
            put("turnSocketObservationSha256", sha(observation.encodeToByteArray()))
        }
    }
}
