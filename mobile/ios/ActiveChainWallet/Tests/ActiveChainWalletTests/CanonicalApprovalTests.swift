import ActiveChainWallet
import Foundation
import XCTest

final class CanonicalApprovalTests: XCTestCase {
    func testApprovalContractRetainsExactRequestAndIntent() {
        let request = Data([1, 2, 3])
        let approval = CanonicalCashApproval(
            request: request, chainID: Data(repeating: 1, count: 48),
            signer: Data(repeating: 2, count: 48), recipient: Data(repeating: 3, count: 48),
            feeReserve: Data(repeating: 4, count: 48), sessionID: Data(repeating: 5, count: 48),
            intentID: Data(repeating: 6, count: 48), nonce: 7, sessionExpiresAt: 9,
            amount: Unsigned128Words(high: 0, low: 50),
            fee: Unsigned128Words(high: 0, low: 2), validUntil: 10, inputCount: 1
        )
        XCTAssertEqual(approval.request, request)
        XCTAssertEqual(approval.intentID, Data(repeating: 6, count: 48))
    }
}
