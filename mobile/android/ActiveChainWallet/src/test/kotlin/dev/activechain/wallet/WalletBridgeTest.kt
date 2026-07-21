package dev.activechain.wallet

import kotlin.test.Test
import kotlin.test.assertTrue

class WalletBridgeTest {
    @Test fun policyGatesLocalApproval() {
        val bridge = LocalWalletBridge(100)
        val preview = bridge.previewTransfer("did:activechain:test", 10, 2, 20, 1)
        assertTrue(preview.policyAllowed)
        assertTrue(bridge.approveTransfer(preview).isNotEmpty())
    }
}
