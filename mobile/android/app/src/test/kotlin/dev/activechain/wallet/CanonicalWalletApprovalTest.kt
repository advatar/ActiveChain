package dev.activechain.wallet

import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class CanonicalWalletApprovalTest {
    @Test
    fun sharedVectorProducesTheExactPlatformReview() {
        val workingDirectory = requireNotNull(System.getProperty("user.dir"))
        val vectorFile = generateSequence(File(workingDirectory)) { it.parentFile }
            .map { File(it, "testing/vectors/wallet-canonical-approval-v1.txt") }
            .first { it.isFile }
        val vector = vectorFile.readLines()
            .filter { it.isNotBlank() && !it.startsWith('#') }
            .associate { line -> line.substringBefore('=') to line.substringAfter('=') }
        val summary = listOf(
            "chain_id", "signer", "recipient", "fee_reserve", "session_id", "intent_id",
            "nonce", "session_expires_at", "amount_high", "amount_low", "fee_high", "fee_low",
            "valid_until", "input_count",
        ).joinToString("\t") { vector.getValue(it) }
        val request = vector.getValue("request_hex").decodeHex()
        val approval = parseCanonicalApproval(request, summary)

        assertContentEquals(vector.getValue("intent_id").decodeHex(), approval.approvedIntent())
        assertEquals(vector.getValue("recipient"), approval.recipient)
        assertEquals(7uL, approval.nonce)
        assertEquals(Unsigned128(0uL, 50uL), approval.amount)
    }

    @Test
    fun parserRetainsCanonicalRequestAndExactIntent() {
        val request = byteArrayOf(1, 2, 3)
        val digests = (1..6).joinToString("\t") { value -> value.toString(16).repeat(96) }
        val approval = parseCanonicalApproval(
            request,
            "$digests\t7\t9\t0\t50\t0\t2\t10\t1",
        )
        request[0] = 9
        assertContentEquals(byteArrayOf(1, 2, 3), approval.request)
        assertEquals(7uL, approval.nonce)
        assertEquals(Unsigned128(0uL, 50uL), approval.amount)
        assertEquals(48, approval.approvedIntent().size)
        assertContentEquals(ByteArray(48) { 0x66 }, approval.approvedIntent())
    }

    @Test
    fun parserRejectsAmbiguousOrMalformedNativeSummaries() {
        assertFailsWith<IllegalArgumentException> {
            parseCanonicalApproval(byteArrayOf(1), "not-a-summary")
        }
        val uppercase = "A".repeat(96)
        val fields = List(6) { uppercase }.joinToString("\t")
        assertFailsWith<IllegalArgumentException> {
            parseCanonicalApproval(byteArrayOf(1), "$fields\t1\t2\t0\t1\t0\t0\t2\t1")
        }
    }
}

private fun String.decodeHex(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
