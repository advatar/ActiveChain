package dev.activechain.wallet

import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean

enum class McpAction { TRANSFER, SUBMIT_ANCHOR }

data class CanonicalMcpProposalApproval(
    val intent: ByteArray,
    val requestID: String,
    val chainID: String,
    val walletID: String,
    val requestNonce: String,
    val agentPrincipal: String,
    val capabilityID: String,
    val resource: String,
    val recipient: String,
    val replayDomain: String,
    val intentCommitment: String,
    val proposalID: String,
    val action: McpAction,
    val amount: Unsigned128,
    val maximumFee: Unsigned128,
    val expiresAtHeight: ULong,
) {
    init {
        require(intent.isNotEmpty())
        require(listOf(requestID, chainID, walletID, requestNonce).all { it.isNotBlank() && it.length <= 128 })
        require(listOf(agentPrincipal, capabilityID, resource, recipient, replayDomain,
            intentCommitment, proposalID).all { value ->
            value.length == 96 && value.all { it in '0'..'9' || it in 'a'..'f' }
        })
        require(expiresAtHeight > 0uL)
    }

    fun approvedCommitment(): ByteArray = intentCommitment.decodeLowerHex()

    companion object {
        fun review(intent: ByteArray, finalizedHeight: Long): CanonicalMcpProposalApproval =
            parseMcpProposalApproval(
                intent,
                NativeProposalApproval.review(intent, finalizedHeight),
            )
    }
}

internal object NativeProposalApproval {
    init { System.loadLibrary("activechain_wallet_ffi") }

    fun review(intent: ByteArray, finalizedHeight: Long): String =
        nativeReviewProposal(intent, finalizedHeight)
    fun signingPayload(intent: ByteArray, commitment: ByteArray, finalizedHeight: Long): ByteArray =
        nativeProposalSigningPayload(intent, commitment, finalizedHeight)
    fun authorize(
        intent: ByteArray, commitment: ByteArray, finalizedHeight: Long,
        publicKey: ByteArray, signature: ByteArray,
    ): ByteArray = nativeAuthorizeProposal(intent, commitment, finalizedHeight, publicKey, signature)
    fun verifyForSubmission(envelope: ByteArray, finalizedHeight: Long): ByteArray =
        nativeVerifyProposalForSubmission(envelope, finalizedHeight)

    @JvmStatic private external fun nativeReviewProposal(intent: ByteArray, height: Long): String
    @JvmStatic private external fun nativeProposalSigningPayload(
        intent: ByteArray, commitment: ByteArray, height: Long,
    ): ByteArray
    @JvmStatic private external fun nativeAuthorizeProposal(
        intent: ByteArray, commitment: ByteArray, height: Long,
        publicKey: ByteArray, signature: ByteArray,
    ): ByteArray
    @JvmStatic private external fun nativeVerifyProposalForSubmission(
        envelope: ByteArray, height: Long,
    ): ByteArray
}

class CanonicalMcpProposalApprovalSession(private val approval: CanonicalMcpProposalApproval) {
    private val consumed = AtomicBoolean(false)

    fun sign(
        custody: AndroidNativeCustodyProvider,
        slotID: String,
        minimumVersion: Int,
        finalizedHeight: Long,
    ): ByteArray {
        val reviewed = CanonicalMcpProposalApproval.review(approval.intent, finalizedHeight)
        require(reviewed.sameReview(approval)) { "canonical MCP proposal was substituted" }
        check(consumed.compareAndSet(false, true)) { "canonical MCP proposal was already consumed" }
        val commitment = approval.approvedCommitment()
        val payload = NativeProposalApproval.signingPayload(
            approval.intent, commitment, finalizedHeight,
        )
        val publicKey = custody.publicKey(slotID)
        val signature = custody.sign(
            slotID, payload, minimumVersion, finalizedHeight,
            "Approve the reviewed ${approval.action.name.lowercase()} proposal from " +
                approval.agentPrincipal,
        )
        return NativeProposalApproval.authorize(
            approval.intent, commitment, finalizedHeight, publicKey, signature,
        )
    }
}

private fun CanonicalMcpProposalApproval.sameReview(other: CanonicalMcpProposalApproval): Boolean =
    intent.contentEquals(other.intent) && requestID == other.requestID && chainID == other.chainID &&
        walletID == other.walletID && requestNonce == other.requestNonce &&
        agentPrincipal == other.agentPrincipal && capabilityID == other.capabilityID &&
        resource == other.resource && recipient == other.recipient && replayDomain == other.replayDomain &&
        intentCommitment == other.intentCommitment && proposalID == other.proposalID &&
        action == other.action && amount == other.amount && maximumFee == other.maximumFee &&
        expiresAtHeight == other.expiresAtHeight

internal fun parseMcpProposalApproval(intent: ByteArray, encoded: String): CanonicalMcpProposalApproval {
    val fields = encoded.split('\t')
    require(fields.size == 17) { "malformed canonical MCP proposal summary" }
    return CanonicalMcpProposalApproval(
        intent.copyOf(), fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6],
        fields[7], fields[8], fields[9], fields[10],
        when (fields[11].toUInt()) { 0u -> McpAction.TRANSFER; 1u -> McpAction.SUBMIT_ANCHOR
            else -> throw IllegalArgumentException("unknown MCP proposal action") },
        Unsigned128(fields[12].toULong(), fields[13].toULong()),
        Unsigned128(fields[14].toULong(), fields[15].toULong()), fields[16].toULong(),
    )
}

private fun String.decodeLowerHex(): ByteArray {
    require(length == 96 && all { it in '0'..'9' || it in 'a'..'f' })
    return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

enum class McpProposalLifecycle { PENDING, APPROVED, REJECTED, EXPIRED, SUBMITTED, FINALIZED, FAILED }

data class McpProposalLifecycleRecord(
    val proposalID: String,
    val intent: ByteArray,
    val state: McpProposalLifecycle,
    val revision: ULong,
    val evidence: String?,
    val expiresAtHeight: ULong,
)

class McpProposalLifecycleStore(private val file: File) {
    private val records = linkedMapOf<String, McpProposalLifecycleRecord>()

    init {
        if (file.isFile) {
            file.readLines().filter { it.isNotEmpty() }.forEach { line ->
                val fields = line.split('\t')
                require(fields.size == 6) { "malformed MCP lifecycle snapshot" }
                val id = fields[0]
                require(id.length == 96 && !records.containsKey(id))
                val record = McpProposalLifecycleRecord(
                    id, Base64.getDecoder().decode(fields[1]),
                    McpProposalLifecycle.valueOf(fields[2]), fields[3].toULong(),
                    fields[4].ifEmpty { null }, fields[5].toULong(),
                )
                require(record.intent.isNotEmpty() && record.revision > 0uL)
                require(record.evidence == null || record.evidence.length == 96)
                records[id] = record
            }
            require(records.size <= 4_096)
        }
    }

    @Synchronized
    fun admit(approval: CanonicalMcpProposalApproval, finalizedHeight: ULong): McpProposalLifecycleRecord {
        require(finalizedHeight < approval.expiresAtHeight) { "canonical MCP proposal expired" }
        records[approval.proposalID]?.let {
            require(it.intent.contentEquals(approval.intent)) { "proposal ID collision" }
            return it
        }
        check(records.size < 4_096) { "MCP proposal store capacity exceeded" }
        val record = McpProposalLifecycleRecord(
            approval.proposalID, approval.intent.copyOf(), McpProposalLifecycle.PENDING,
            1uL, null, approval.expiresAtHeight,
        )
        records[approval.proposalID] = record
        persist()
        return record
    }

    @Synchronized
    fun transition(
        proposalID: String, expectedRevision: ULong, next: McpProposalLifecycle,
        evidence: String, finalizedHeight: ULong,
    ): McpProposalLifecycleRecord {
        require(evidence.length == 96 && evidence.all { it in '0'..'9' || it in 'a'..'f' })
        val current = requireNotNull(records[proposalID]) { "unknown MCP proposal" }
        check(current.revision == expectedRevision) { "concurrent MCP proposal review" }
        require(next == McpProposalLifecycle.EXPIRED || finalizedHeight < current.expiresAtHeight) {
            "canonical MCP proposal expired"
        }
        val allowed = when (current.state to next) {
            McpProposalLifecycle.PENDING to McpProposalLifecycle.APPROVED,
            McpProposalLifecycle.PENDING to McpProposalLifecycle.REJECTED,
            McpProposalLifecycle.PENDING to McpProposalLifecycle.EXPIRED,
            McpProposalLifecycle.APPROVED to McpProposalLifecycle.SUBMITTED,
            McpProposalLifecycle.APPROVED to McpProposalLifecycle.FAILED,
            McpProposalLifecycle.APPROVED to McpProposalLifecycle.EXPIRED,
            McpProposalLifecycle.SUBMITTED to McpProposalLifecycle.FINALIZED,
            McpProposalLifecycle.SUBMITTED to McpProposalLifecycle.FAILED -> true
            else -> false
        }
        check(allowed && current.revision < ULong.MAX_VALUE) { "invalid MCP proposal transition" }
        val updated = current.copy(
            state = next, revision = current.revision + 1uL, evidence = evidence,
        )
        records[proposalID] = updated
        persist()
        return updated
    }

    @Synchronized
    fun record(proposalID: String): McpProposalLifecycleRecord? = records[proposalID]

    private fun persist() {
        file.parentFile?.mkdirs()
        val temporary = File(file.parentFile, ".${file.name}.${Thread.currentThread().id}.tmp")
        temporary.writeText(records.toSortedMap().values.joinToString("\n") { record ->
            listOf(
                record.proposalID, Base64.getEncoder().encodeToString(record.intent),
                record.state.name, record.revision.toString(), record.evidence.orEmpty(),
                record.expiresAtHeight.toString(),
            ).joinToString("\t")
        })
        Files.move(
            temporary.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING,
            StandardCopyOption.ATOMIC_MOVE,
        )
    }
}
