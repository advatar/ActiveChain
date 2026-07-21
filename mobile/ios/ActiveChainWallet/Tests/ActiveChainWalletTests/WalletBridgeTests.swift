import XCTest
@testable import ActiveChainWallet

final class WalletBridgeTests: XCTestCase {
    func testPolicyGatesLocalApproval() throws {
        let bridge = LocalWalletBridge(dailyLimit: 100)
        let preview = bridge.previewTransfer(recipient: "did:activechain:test", amount: 10, feeReserve: 2, validUntil: 20, currentHeight: 1)
        XCTAssertTrue(preview.policyAllowed)
        XCTAssertFalse(try bridge.approveTransfer(preview).isEmpty)
    }
}
