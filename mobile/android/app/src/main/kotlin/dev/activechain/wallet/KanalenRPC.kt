package dev.activechain.wallet

import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.SecureRandom
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

internal object KanalenNetwork {
    const val host = "rpc.kanalen.activechain.dev"
    const val port = 443
    const val protocolRevision = 1L
    const val schemaRevision = 2L
    val chainID = hex(
        "b12c1c316717e9669cec36f7632a9080702c57a3125d90c72154f8a7298e4f0" +
            "b095e6cfe944bd2c9f6535b4c927782f1",
    )
    val genesis = hex(
        "466ba6bb38dbf6c17a67994ee7c0edcc0858755c937f7c519b9cc144c2b64290" +
            "282174ad6899466aeb7078da49a998be",
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
    val supportedProofs: Set<Int>,
) {
    fun supports(proof: Int) = proof in supportedProofs
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
    private const val maximumBlobLength = 256 * 1_024
    val framedStatusRequest = byteArrayOf(0, 0, 0, 6, 1, 7, 0, 1, 1, 0)
    val framedFaucetTermsRequest = framedRequest(byteArrayOf(7))

    fun decodeStatus(envelope: ByteArray): KanalenRPCStatus {
        val decoder = Decoder(envelope)
        requireRPC(decoder.readUnsignedShort() == 0x010a, "unexpected response type")
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
        val proofs = buildSet {
            repeat(proofCount) {
            val proof = decoder.readUnsignedByte()
            requireRPC(proof in 0..3 && proof > previous, "invalid proof set")
            previous = proof
                add(proof)
            }
        }
        requireRPC(decoder.remaining == 0, "trailing status bytes")
        return KanalenRPCStatus(
            chainID,
            genesis,
            protocolRevision,
            schemaRevision,
            finalizedHeight,
            health,
            proofs,
        )
    }

    fun framedOwnerCoinCellRequest(owner: ByteArray, limit: Int = 4): ByteArray {
        requireRPC(owner.size == 48 && owner.any { it.toInt() != 0 }, "invalid owner")
        requireRPC(limit in 1..4, "invalid owner page limit")
        return framedRequest(byteArrayOf(8) + owner + byteArrayOf(0, 0, limit.toByte()))
    }

    fun framedFaucetRequest(
        owner: ByteArray,
        idempotencyKey: ByteArray,
        sourceCommitment: ByteArray,
    ): ByteArray {
        for (digest in listOf(owner, idempotencyKey, sourceCommitment)) {
            requireRPC(digest.size == 48 && digest.any { it.toInt() != 0 }, "invalid faucet digest")
        }
        return framedRequest(
            byteArrayOf(5) + KanalenNetwork.chainID + KanalenNetwork.genesis + owner +
                idempotencyKey + sourceCommitment + ByteArray(8) + byteArrayOf(0),
        )
    }

    fun decodeFaucetTerms(envelope: ByteArray): WalletFaucetTerms {
        val decoder = responseBody(envelope, 7)
        val chain = decoder.read(48)
        val genesis = decoder.read(48)
        decoder.readLong(); decoder.readLong(); decoder.read(16); decoder.readLong()
        decoder.readUnsignedShort(); decoder.readLong(); decoder.readUnsignedShort()
        decoder.readLong(); decoder.readUnsignedInt()
        val challenge = decoder.readUnsignedByte()
        val difficulty = decoder.readUnsignedByte()
        requireRPC(decoder.remaining == 0 && chain.any { it.toInt() != 0 } &&
            genesis.any { it.toInt() != 0 } && challenge in 0..1 &&
            ((challenge == 0) == (difficulty == 0)), "malformed faucet terms")
        return WalletFaucetTerms(chain, genesis, challenge)
    }

    fun decodeFaucetReceipt(envelope: ByteArray): WalletFaucetReceipt {
        val decoder = responseBody(envelope, 6)
        val reference = decoder.read(48)
        decoder.read(48); decoder.read(16)
        val state = decoder.readUnsignedByte()
        val hasTransaction = decoder.readUnsignedByte()
        requireRPC(hasTransaction in 0..1, "invalid transaction option")
        if (hasTransaction == 1) decoder.read(48)
        val hasHeight = decoder.readUnsignedByte()
        requireRPC(hasHeight in 0..1, "invalid height option")
        val height = if (hasHeight == 1) decoder.readLong() else null
        val hasBlock = decoder.readUnsignedByte()
        requireRPC(hasBlock in 0..1, "invalid block option")
        if (hasBlock == 1) decoder.read(48)
        val proof = decoder.readBlob(maximumBlobLength)
        requireRPC(reference.any { it.toInt() != 0 } && state in 0..2 && decoder.remaining == 0,
            "malformed faucet receipt")
        requireRPC((state == 1) == (hasTransaction == 1 && height != null && hasBlock == 1 && proof.isNotEmpty()),
            "inconsistent faucet receipt")
        requireRPC(state == 1 || (height == null && hasBlock == 0 && proof.isEmpty()),
            "unexpected pending evidence")
        return WalletFaucetReceipt(reference, state, height)
    }

    fun decodeOwnerCoinPage(envelope: ByteArray): WalletOwnerCoinPage {
        val decoder = responseBody(envelope, 2)
        val count = decoder.readULEB128(4)
        val records = ArrayList<WalletOwnerCoinRecord>(count)
        var previous: ByteArray? = null
        repeat(count) {
            requireRPC(decoder.readUnsignedByte() == 4, "unexpected owner record kind")
            val key = decoder.read(48)
            requireRPC(key.any { it.toInt() != 0 } && (previous == null || previous!!.lexicographicBefore(key)),
                "unordered owner record")
            val height = decoder.readLong()
            val value = decoder.readBlob(maximumBlobLength)
            val proof = decoder.readBlob(maximumBlobLength)
            val finality = decoder.readBlob(maximumBlobLength)
            requireRPC(value.isNotEmpty() && proof.isNotEmpty() && finality.isNotEmpty(),
                "empty owner evidence")
            records += WalletOwnerCoinRecord(key, height, value, proof, finality)
            previous = key
        }
        val next = when (decoder.readUnsignedByte()) {
            0 -> null
            1 -> decoder.read(48).also { cursor ->
                requireRPC(cursor.any { it.toInt() != 0 } &&
                    (records.lastOrNull()?.key?.let { !cursor.lexicographicBefore(it) } != false),
                    "invalid owner cursor")
            }
            else -> throw KanalenRPCException("invalid cursor option")
        }
        requireRPC(decoder.remaining == 0, "trailing owner page bytes")
        return WalletOwnerCoinPage(records, next)
    }

    private fun responseBody(envelope: ByteArray, variant: Int): Decoder {
        val decoder = Decoder(envelope)
        requireRPC(decoder.readUnsignedShort() == 0x010a, "unexpected response type")
        requireRPC(decoder.readUnsignedShort() == 1, "unexpected envelope schema")
        requireRPC(decoder.readULEB128(maximumFrameLength) == decoder.remaining,
            "response body length mismatch")
        requireRPC(decoder.readUnsignedByte() == variant, "unexpected response variant")
        return decoder
    }

    private fun framedRequest(body: ByteArray): ByteArray {
        val envelope = byteArrayOf(1, 7, 0, 1) + uleb128(body.size) + body
        return ByteArray(4) { index -> (envelope.size ushr ((3 - index) * 8)).toByte() } + envelope
    }

    private fun uleb128(input: Int): ByteArray {
        var value = input
        val output = ArrayList<Byte>()
        do {
            var byte = value and 0x7f
            value = value ushr 7
            if (value != 0) byte = byte or 0x80
            output += byte.toByte()
        } while (value != 0)
        return output.toByteArray()
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

        fun readBlob(maximum: Int): ByteArray = read(readULEB128(maximum))

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
        return KanalenRPCCodec.decodeStatus(roundTrip(KanalenRPCCodec.framedStatusRequest))
    }

    fun faucetTerms() = KanalenRPCCodec.decodeFaucetTerms(
        roundTrip(KanalenRPCCodec.framedFaucetTermsRequest),
    )

    fun requestFaucet(owner: ByteArray): WalletFaucetReceipt {
        val random = SecureRandom()
        fun digest() = ByteArray(48).also { random.nextBytes(it) }
        return KanalenRPCCodec.decodeFaucetReceipt(
            roundTrip(KanalenRPCCodec.framedFaucetRequest(owner, digest(), digest())),
        )
    }

    fun verifiedOwnerCoinCells(
        profile: WalletDeviceProfile,
        finalizedHeight: Long,
        verifier: WalletOwnerCoinProofVerifier = NativeOwnerCoinProofVerifier,
    ): WalletOwnerCoinPage = KanalenRPCCodec.decodeOwnerCoinPage(
        roundTrip(KanalenRPCCodec.framedOwnerCoinCellRequest(profile.owner)),
    ).validated(profile.owner, profile.chainGenesis, finalizedHeight, verifier)

    private fun roundTrip(request: ByteArray): ByteArray {
        val socket = SSLSocketFactory.getDefault()
            .createSocket(KanalenNetwork.host, KanalenNetwork.port) as SSLSocket
        socket.use {
            socket.soTimeout = 8_000
            val parameters = socket.sslParameters
            parameters.endpointIdentificationAlgorithm = "HTTPS"
            socket.sslParameters = parameters
            socket.startHandshake()
            DataOutputStream(socket.outputStream).use { output ->
                output.write(request)
                output.flush()
                val input = DataInputStream(socket.inputStream)
                val length = input.readInt()
                if (length <= 0 || length > KanalenRPCCodec.maximumFrameLength) {
                    throw KanalenRPCException("invalid RPC frame length")
                }
                val body = ByteArray(length)
                input.readFully(body)
                return body
            }
        }
    }
}

internal fun ByteArray.lexicographicBefore(other: ByteArray): Boolean {
    for (index in indices) {
        val left = this[index].toInt() and 0xff
        val right = other[index].toInt() and 0xff
        if (left != right) return left < right
    }
    return false
}
