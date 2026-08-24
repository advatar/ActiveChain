package dev.activechain.wallet

import java.io.DataInputStream
import java.io.DataOutputStream
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

internal object KanalenNetwork {
    const val host = "rpc.kanalen.actum.network"
    const val port = 443
    const val protocolRevision = 1L
    const val schemaRevision = 4L
    val chainID = hex(
        "b12c1c316717e9669cec36f7632a9080702c57a3125d90c72154f8a7298e4f0" +
            "b095e6cfe944bd2c9f6535b4c927782f1",
    )
    val genesis = hex(
        "5d3d2587b77cd7f149b0955dba3eee22d5795bf2f23732bd4ecc5b5fb0155fed" +
            "6c2079b3f83da1610132f6588b519f7c",
    )

    private fun hex(value: String): ByteArray {
        require(value.length == 96)
        return ByteArray(48) { index ->
            value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }
}

internal sealed interface KanalenNetworkState {
    data object Checking : KanalenNetworkState
    data class Healthy(val finalizedHeight: Long) : KanalenNetworkState
    data class Stale(val finalizedHeight: Long) : KanalenNetworkState
    data object Unavailable : KanalenNetworkState
    data object Incompatible : KanalenNetworkState
}

internal data class KanalenRPCStatus(
    val chainID: ByteArray,
    val genesis: ByteArray,
    val protocolRevision: Long,
    val schemaRevision: Long,
    val finalizedHeight: Long,
    val health: Int,
) {
    fun networkState(): KanalenNetworkState {
        if (!chainID.contentEquals(KanalenNetwork.chainID) ||
            !genesis.contentEquals(KanalenNetwork.genesis) ||
            protocolRevision != KanalenNetwork.protocolRevision ||
            schemaRevision != KanalenNetwork.schemaRevision
        ) {
            return KanalenNetworkState.Incompatible
        }
        return when (health) {
            0 -> KanalenNetworkState.Healthy(finalizedHeight)
            1 -> KanalenNetworkState.Stale(finalizedHeight)
            else -> KanalenNetworkState.Incompatible
        }
    }
}

internal class KanalenRPCException(message: String) : Exception(message)

internal object KanalenRPCCodec {
    const val maximumFrameLength = 4 * 1_024 * 1_024
    private const val maximumStatusBodyLength = 151
    val framedStatusRequest = byteArrayOf(0, 0, 0, 6, 1, 7, 0, 3, 1, 0)

    fun decodeStatus(envelope: ByteArray): KanalenRPCStatus {
        val decoder = Decoder(envelope)
        requireRPC(decoder.readUnsignedShort() == 0x00a1, "unexpected response type")
        requireRPC(decoder.readUnsignedShort() == 1, "unexpected envelope schema")
        val bodyLength = decoder.readULEB128(maximumStatusBodyLength)
        requireRPC(bodyLength == decoder.remaining, "status body length mismatch")
        requireRPC(decoder.readUnsignedByte() == 0, "unexpected response variant")
        val chainID = decoder.read(48)
        val genesis = decoder.read(48)
        requireRPC(chainID.any { it.toInt() != 0 }, "zero chain ID")
        requireRPC(genesis.any { it.toInt() != 0 }, "zero genesis")
        val protocolRevision = decoder.readLong()
        val schemaRevision = decoder.readUnsignedInt()
        val finalizedHeight = decoder.readLong()
        val finalizedAt = decoder.readLong()
        val servedAt = decoder.readLong()
        val maximumStaleness = decoder.readLong()
        val health = decoder.readUnsignedByte()
        requireRPC(protocolRevision > 0, "zero protocol revision")
        requireRPC(finalizedHeight >= 0, "negative finalized height")
        requireRPC(finalizedAt >= 0 && servedAt >= finalizedAt, "invalid status timestamps")
        requireRPC(maximumStaleness > 0, "invalid staleness bound")
        val expectedHealth = if (servedAt - finalizedAt > maximumStaleness) 1 else 0
        requireRPC(health == expectedHealth, "health does not match staleness")
        val proofCount = decoder.readULEB128(8)
        requireRPC(proofCount > 0, "empty proof set")
        var previous = -1
        repeat(proofCount) {
            val proof = decoder.readUnsignedByte()
            requireRPC(proof in 0..3 && proof > previous, "invalid proof set")
            previous = proof
        }
        requireRPC(decoder.remaining == 0, "trailing status bytes")
        return KanalenRPCStatus(
            chainID,
            genesis,
            protocolRevision,
            schemaRevision,
            finalizedHeight,
            health,
        )
    }

    private class Decoder(private val data: ByteArray) {
        private var offset = 0
        val remaining: Int get() = data.size - offset

        fun read(count: Int): ByteArray {
            requireRPC(count >= 0 && remaining >= count, "truncated response")
            val result = data.copyOfRange(offset, offset + count)
            offset += count
            return result
        }

        fun readUnsignedByte(): Int = read(1)[0].toInt() and 0xff

        fun readUnsignedShort(): Int = (readUnsignedByte() shl 8) or readUnsignedByte()

        fun readUnsignedInt(): Long {
            var value = 0L
            repeat(4) { value = (value shl 8) or readUnsignedByte().toLong() }
            return value
        }

        fun readLong(): Long {
            var value = 0L
            repeat(8) { value = (value shl 8) or readUnsignedByte().toLong() }
            return value
        }

        fun readULEB128(maximum: Int): Int {
            var value = 0L
            var shift = 0
            var count = 0
            while (count < 5) {
                val byte = readUnsignedByte()
                val payload = byte and 0x7f
                if (shift == 28) requireRPC(payload <= 0x0f, "length overflow")
                value = value or (payload.toLong() shl shift)
                count += 1
                if (byte and 0x80 == 0) {
                    requireRPC(count == 1 || payload != 0, "non-minimal length")
                    requireRPC(value <= maximum, "length exceeds bound")
                    return value.toInt()
                }
                shift += 7
            }
            throw KanalenRPCException("length overflow")
        }
    }

    private fun requireRPC(condition: Boolean, message: String) {
        if (!condition) throw KanalenRPCException(message)
    }
}

internal class KanalenRPCClient {
    fun status(): KanalenRPCStatus {
        val socket = SSLSocketFactory.getDefault()
            .createSocket(KanalenNetwork.host, KanalenNetwork.port) as SSLSocket
        socket.use {
            socket.soTimeout = 8_000
            val parameters = socket.sslParameters
            parameters.endpointIdentificationAlgorithm = "HTTPS"
            socket.sslParameters = parameters
            socket.startHandshake()
            DataOutputStream(socket.outputStream).use { output ->
                output.write(KanalenRPCCodec.framedStatusRequest)
                output.flush()
                val input = DataInputStream(socket.inputStream)
                val length = input.readInt()
                if (length <= 0 || length > KanalenRPCCodec.maximumFrameLength) {
                    throw KanalenRPCException("invalid RPC frame length")
                }
                val body = ByteArray(length)
                input.readFully(body)
                return KanalenRPCCodec.decodeStatus(body)
            }
        }
    }
}
