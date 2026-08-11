package dev.activechain.wallet

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.net.URI
import java.net.URLDecoder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class WalletParityTest {
    @Test
    fun liveKanalenGenesisMatchesApplePin() {
        assertEquals(
            "466ba6bb38dbf6c17a67994ee7c0edcc0858755c937f7c519b9cc144c2b64290" +
                "282174ad6899466aeb7078da49a998be",
            KanalenNetwork.genesis.toHex(),
        )
    }

    @Test
    fun ownerRequestIsCanonicalAndBounded() {
        val frame = KanalenRPCCodec.framedOwnerCoinCellRequest(ByteArray(48) { 7 })
        assertEquals(61, frame.size)
        assertContentEquals(byteArrayOf(1, 7, 0, 1), frame.copyOfRange(4, 8))
        assertEquals(52, frame[8].toInt())
        assertEquals(8, frame[9].toInt())
        assertFailsWith<KanalenRPCException> {
            KanalenRPCCodec.framedOwnerCoinCellRequest(ByteArray(48), 4)
        }
        assertFailsWith<KanalenRPCException> {
            KanalenRPCCodec.framedOwnerCoinCellRequest(ByteArray(48) { 1 }, 5)
        }
    }

    @Test
    fun ownerPageRequiresFinalizedVerifierAcceptance() {
        val record = WalletOwnerCoinRecord(
            ByteArray(48) { 3 }, 4, byteArrayOf(1), byteArrayOf(2), byteArrayOf(3),
        )
        val page = WalletOwnerCoinPage(listOf(record), null)
        assertFailsWith<IllegalArgumentException> {
            page.validated(ByteArray(48) { 1 }, KanalenNetwork.genesis, 4) { _, _, _ -> false }
        }
        assertFailsWith<IllegalArgumentException> {
            WalletOwnerCoinPage(emptyList(), null).validated(
                ByteArray(48) { 1 }, KanalenNetwork.genesis, 4,
            ) { _, _, _ -> true }
        }
        assertEquals(page, page.validated(
            ByteArray(48) { 1 }, KanalenNetwork.genesis, 4,
        ) { _, _, _ -> true })
    }

    @Test
    fun ownerPageDecoderAcceptsProofBearingLargeBody() {
        val body = ByteArrayOutputStream()
        DataOutputStream(body).use { output ->
            output.writeByte(2); output.writeByte(1); output.writeByte(4)
            output.write(ByteArray(48) { 1 }); output.writeLong(9)
            repeat(3) { marker -> output.writeByte(60); output.write(ByteArray(60) { (marker + 2).toByte() }) }
            output.writeByte(0)
        }
        val payload = body.toByteArray()
        val envelope = byteArrayOf(1, 10, 0, 1) + uleb128(payload.size) + payload
        val page = KanalenRPCCodec.decodeOwnerCoinPage(envelope)
        assertEquals(1, page.records.size)
        assertEquals(9, page.records.single().finalizedHeight)
    }

    @Test
    fun receiveRequestBindsNetworkGenesisAndAddress() {
        val first = ReceiveRequest("kanalen", "genesis-1", "did:activechain:alice")
        val second = ReceiveRequest("other", "genesis-2", "did:activechain:alice")
        assertNotEquals(first.payload, second.payload)
        val uri = URI(first.payload)
        assertEquals("activechain", uri.scheme)
        assertEquals("receive", uri.host)
        val query = uri.rawQuery.split('&').associate {
            val (key, value) = it.split('=', limit = 2)
            key to URLDecoder.decode(value, Charsets.UTF_8)
        }
        assertEquals("kanalen", query["network"])
        assertEquals("genesis-1", query["genesis"])
    }

    @Test
    fun openWalletRejectsCredentialAndSessionReplay() {
        val adapter = OpenWalletAdapter()
        val credential = OpenWalletCredentialReference("cred-1", "schema-1", "issuer-1")
        assertTrue(adapter.register(credential))
        assertFalse(adapter.register(credential))
        val session = OpenWalletApplicationSession("session-1", "rp", 10uL)
        assertTrue(adapter.open(session, 1uL))
        assertFalse(adapter.open(session, 1uL))
    }

    @Test
    fun enrollmentRequiresCanonicalSortedCapabilities() {
        val first = "11".repeat(48)
        val second = "22".repeat(48)
        val valid = AgentEnrollmentDraft(
            "Invoice assistant", "aa".repeat(48), "$first\n$second",
            budget = 100uL, expiresAt = 500uL,
        )
        valid.validate()
        assertEquals(96, valid.capabilityBytes().size)
        assertFailsWith<AgentEnrollmentException> {
            valid.copy(capabilityIDs = "$second\n$first").validate()
        }
        assertFailsWith<AgentEnrollmentException> { valid.copy(budget = 0uL).validate() }
    }

    @Test
    fun explicitWalletRoutesDoNotAcceptArbitraryUrls() {
        assertEquals(
            WalletRoute.AGENTS,
            WalletIntentRouter.route("activechain-wallet://agents"),
        )
        assertEquals(null, WalletIntentRouter.route("activechain-wallet://agents?approve=true"))
        assertEquals(null, WalletIntentRouter.route("https://example.test/agents"))
    }

    private fun uleb128(input: Int): ByteArray {
        var value = input
        val bytes = ArrayList<Byte>()
        do {
            var byte = value and 0x7f
            value = value ushr 7
            if (value != 0) byte = byte or 0x80
            bytes += byte.toByte()
        } while (value != 0)
        return bytes.toByteArray()
    }
}
