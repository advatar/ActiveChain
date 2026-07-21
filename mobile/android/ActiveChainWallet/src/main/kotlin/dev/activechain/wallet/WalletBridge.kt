package dev.activechain.wallet

data class WalletIntentPreview(val recipient: String, val amount: Long, val feeReserve: Long,
                               val validUntil: Long, val policyAllowed: Boolean)

class LocalWalletBridge(private val dailyLimit: Long = 1_000) {
    fun previewTransfer(recipient: String, amount: Long, feeReserve: Long,
                        validUntil: Long, currentHeight: Long) =
        WalletIntentPreview(recipient, amount, feeReserve, validUntil,
            amount > 0 && amount <= dailyLimit && currentHeight <= validUntil)

    fun approveTransfer(preview: WalletIntentPreview): ByteArray {
        require(preview.policyAllowed) { "policy denied" }
        return "ACTIVECHAIN-LOCAL-INTENT-V1|${preview.recipient}|${preview.amount}|${preview.feeReserve}|${preview.validUntil}"
            .toByteArray(Charsets.UTF_8)
    }
}
