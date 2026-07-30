package dev.activechain.wallet

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class CanonicalWalletApprovalTest {
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
