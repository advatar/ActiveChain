package dev.activechain.wallet

import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class McpProposalApprovalTest {
    private val digest = "ab".repeat(48)

    @Test
    fun parserReconstructsCanonicalOriginAuthorityAndValueFields() {
        val intent = byteArrayOf(1, 2, 3)
        val summary = listOf(
            "request-7", "activechain-devnet", "wallet-primary", "nonce-7",
            digest, digest, digest, digest, digest, digest, digest,
            "0", "3", "17", "0", "9", "500",
        ).joinToString("\t")
        val approval = parseMcpProposalApproval(intent, summary)
        intent[0] = 9

        assertContentEquals(byteArrayOf(1, 2, 3), approval.intent)
        assertEquals("request-7", approval.requestID)
        assertEquals(McpAction.TRANSFER, approval.action)
        assertEquals(Unsigned128(3uL, 17uL), approval.amount)
        assertEquals(500uL, approval.expiresAtHeight)
        assertContentEquals(ByteArray(48) { 0xab.toByte() }, approval.approvedCommitment())
    }

    @Test
    fun parserRejectsSpoofableOrAmbiguousSummaries() {
        assertFailsWith<IllegalArgumentException> {
            parseMcpProposalApproval(byteArrayOf(1), "agent supplied label")
        }
        val fields = listOf(
            "request-7", "chain", "wallet", "nonce", digest.uppercase(), digest, digest,
            digest, digest, digest, digest, "0", "0", "1", "0", "0", "2",
        ).joinToString("\t")
        assertFailsWith<IllegalArgumentException> {
            parseMcpProposalApproval(byteArrayOf(1), fields)
        }
    }

    @Test
    fun lifecycleSurvivesRestartAndRejectsConcurrentOrRepeatedApproval() {
        val directory = Files.createTempDirectory("activechain-mcp-lifecycle").toFile()
        try {
            val file = File(directory, "store.tsv")
            val summary = listOf(
                "request-7", "chain", "wallet", "nonce", digest, digest, digest, digest,
                digest, digest, digest, "0", "0", "17", "0", "9", "500",
            ).joinToString("\t")
            val approval = parseMcpProposalApproval(byteArrayOf(1, 2, 3), summary)
            val store = McpProposalLifecycleStore(file)
            assertEquals(McpProposalLifecycle.PENDING, store.admit(approval, 100uL).state)
            assertEquals(
                McpProposalLifecycle.APPROVED,
                store.transition(digest, 1uL, McpProposalLifecycle.APPROVED, "08".repeat(48), 101uL).state,
            )
            assertFailsWith<IllegalStateException> {
                store.transition(digest, 1uL, McpProposalLifecycle.REJECTED, "09".repeat(48), 101uL)
            }
            val restarted = McpProposalLifecycleStore(file)
            assertEquals(McpProposalLifecycle.APPROVED, restarted.record(digest)?.state)
            assertEquals(2uL, restarted.record(digest)?.revision)
        } finally {
            directory.deleteRecursively()
        }
    }
}
