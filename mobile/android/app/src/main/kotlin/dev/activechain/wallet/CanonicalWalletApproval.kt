package dev.activechain.wallet

import java.util.concurrent.atomic.AtomicBoolean

data class Unsigned128(val high: ULong, val low: ULong)

data class CanonicalWalletApproval(
    val request: ByteArray,
    val chainID: String,
    val signer: String,
    val recipient: String,
    val feeReserve: String,
    val sessionID: String,
    val intentID: String,
    val nonce: ULong,
    val sessionExpiresAt: ULong,
    val amount: Unsigned128,
    val fee: Unsigned128,
    val validUntil: ULong,
    val inputCount: UInt,
) {
    init {
        require(request.isNotEmpty())
        require(listOf(chainID, signer, recipient, feeReserve, sessionID, intentID).all {
            it.length == 96 && it.all { character -> character.isLowerCaseHexDigit() }
        })
        require(inputCount > 0u)
    }

    fun approvedIntent(): ByteArray = intentID.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    companion object {
        fun review(request: ByteArray): CanonicalWalletApproval =
            parseCanonicalApproval(request, NativeCanonicalApproval.review(request))

        private fun Char.isLowerCaseHexDigit(): Boolean = this in '0'..'9' || this in 'a'..'f'
    }
}

internal object NativeCanonicalApproval {
    init { System.loadLibrary("activechain_wallet_ffi") }
    fun review(request: ByteArray): String = nativeReview(request)
    fun signingPayload(request: ByteArray, intent: ByteArray): ByteArray =
        nativeSigningPayload(request, intent)
    fun authorize(
        request: ByteArray, intent: ByteArray, publicKey: ByteArray, signature: ByteArray,
    ): ByteArray = nativeAuthorize(request, intent, publicKey, signature)
    fun verifyForSubmission(envelope: ByteArray, publicKey: ByteArray): ByteArray =
        nativeVerifyForSubmission(envelope, publicKey)
    @JvmStatic private external fun nativeReview(request: ByteArray): String
    @JvmStatic private external fun nativeSigningPayload(request: ByteArray, intent: ByteArray): ByteArray
    @JvmStatic private external fun nativeAuthorize(
        request: ByteArray, intent: ByteArray, publicKey: ByteArray, signature: ByteArray,
    ): ByteArray
    @JvmStatic private external fun nativeVerifyForSubmission(
        envelope: ByteArray, publicKey: ByteArray,
    ): ByteArray
}

class CanonicalWalletApprovalSession(private val approval: CanonicalWalletApproval) {
    private val consumed = AtomicBoolean(false)

    fun sign(
        custody: AndroidNativeCustodyProvider,
        slotID: String,
        minimumVersion: Int,
        minimumFinalizedHeight: Long,
    ): ByteArray {
        val reviewed = CanonicalWalletApproval.review(approval.request)
        require(reviewed.sameReview(approval)) { "canonical approval was substituted" }
        check(consumed.compareAndSet(false, true)) { "canonical approval was already consumed" }
        val intent = approval.approvedIntent()
        val payload = NativeCanonicalApproval.signingPayload(approval.request, intent)
        val publicKey = custody.publicKey(slotID)
        val signature = custody.sign(
            slotID, payload, minimumVersion, minimumFinalizedHeight,
            "Approve the reviewed ActiveChain transfer",
        )
        return NativeCanonicalApproval.authorize(approval.request, intent, publicKey, signature)
    }
}

private fun CanonicalWalletApproval.sameReview(other: CanonicalWalletApproval): Boolean =
    request.contentEquals(other.request) && chainID == other.chainID && signer == other.signer &&
        recipient == other.recipient && feeReserve == other.feeReserve && sessionID == other.sessionID &&
        intentID == other.intentID && nonce == other.nonce && sessionExpiresAt == other.sessionExpiresAt &&
        amount == other.amount && fee == other.fee && validUntil == other.validUntil &&
        inputCount == other.inputCount

internal fun parseCanonicalApproval(request: ByteArray, encoded: String): CanonicalWalletApproval {
    val fields = encoded.split('\t')
    require(fields.size == 14) { "malformed canonical approval summary" }
    return CanonicalWalletApproval(
        request.copyOf(), fields[0], fields[1], fields[2], fields[3], fields[4], fields[5],
        fields[6].toULong(), fields[7].toULong(),
        Unsigned128(fields[8].toULong(), fields[9].toULong()),
        Unsigned128(fields[10].toULong(), fields[11].toULong()),
        fields[12].toULong(), fields[13].toUInt(),
    )
}
