package dev.activechain.wallet

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class KanalenRPCTest {
    @Test
    fun statusRequestUsesCanonicalFraming() {
        assertContentEquals(
            byteArrayOf(0, 0, 0, 6, 1, 7, 0, 3, 1, 0),
            KanalenRPCCodec.framedStatusRequest,
        )
    }

    @Test
    fun schemaFourKanalenStatusIsHealthy() {
        val status = KanalenRPCCodec.decodeStatus(statusEnvelope())
        assertContentEquals(KanalenNetwork.chainID, status.chainID)
        assertContentEquals(KanalenNetwork.genesis, status.genesis)
        assertEquals(KanalenNetworkState.Healthy(5_794), status.networkState())
    }

    @Test
    fun wrongChainGenesisOrSchemaIsIncompatible() {
        assertEquals(
            KanalenNetworkState.Incompatible,
            KanalenRPCCodec.decodeStatus(
                statusEnvelope(chainID = ByteArray(48) { 0x44.toByte() }),
            ).networkState(),
        )
        assertEquals(
            KanalenNetworkState.Incompatible,
            KanalenRPCCodec.decodeStatus(
                statusEnvelope(genesis = ByteArray(48) { 0x55.toByte() }),
            ).networkState(),
        )
        assertEquals(
            KanalenNetworkState.Incompatible,
            KanalenRPCCodec.decodeStatus(statusEnvelope(schema = 1)).networkState(),
        )
    }

    @Test
    fun malformedHealthAndTrailingBytesFailClosed() {
        assertFailsWith<KanalenRPCException> { KanalenRPCCodec.decodeStatus(statusEnvelope(health = 1)) }
        assertFailsWith<KanalenRPCException> {
            KanalenRPCCodec.decodeStatus(statusEnvelope() + byteArrayOf(0))
        }
    }

    private fun statusEnvelope(
        chainID: ByteArray = KanalenNetwork.chainID,
        genesis: ByteArray = KanalenNetwork.genesis,
        schema: Int = 4,
        health: Int = 0,
    ): ByteArray {
        val bodyBytes = ByteArrayOutputStream()
        DataOutputStream(bodyBytes).use { body ->
            body.writeByte(0)
            body.write(chainID)
            body.write(genesis)
            body.writeLong(1)
            body.writeInt(schema)
            body.writeLong(5_794)
            body.writeLong(1_785_233_700)
            body.writeLong(1_785_233_703)
            body.writeLong(300)
            body.writeByte(health)
            body.writeByte(2)
            body.writeByte(1)
            body.writeByte(2)
        }
        val body = bodyBytes.toByteArray()
        return ByteArrayOutputStream().also { envelopeBytes ->
            DataOutputStream(envelopeBytes).use { envelope ->
                envelope.writeShort(0x00a1)
                envelope.writeShort(1)
                envelope.write(uleb128(body.size))
                envelope.write(body)
            }
        }.toByteArray()
    }

    private fun uleb128(input: Int): ByteArray {
        var value = input
        val bytes = mutableListOf<Byte>()
        do {
            var byte = value and 0x7f
            value = value ushr 7
            if (value != 0) byte = byte or 0x80
            bytes.add(byte.toByte())
        } while (value != 0)
        return bytes.toByteArray()
    }
}
