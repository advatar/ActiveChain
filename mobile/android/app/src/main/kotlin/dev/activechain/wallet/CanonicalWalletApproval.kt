package dev.activechain.wallet

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

private object NativeCanonicalApproval {
    init { System.loadLibrary("activechain_wallet_ffi") }
    fun review(request: ByteArray): String = nativeReview(request)
    @JvmStatic private external fun nativeReview(request: ByteArray): String
}

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
