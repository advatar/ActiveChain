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

    func testMcpApprovalRetainsCanonicalProvenanceAndCommitment() {
        let approval = CanonicalMcpProposalApproval(
            intent: Data([1, 2, 3]), requestID: "request-7", chainID: "devnet",
            walletID: "primary", requestNonce: "nonce-7",
            agentPrincipal: Data(repeating: 1, count: 48),
            capabilityID: Data(repeating: 2, count: 48),
            resource: Data(repeating: 3, count: 48), recipient: Data(repeating: 4, count: 48),
            replayDomain: Data(repeating: 5, count: 48),
            intentCommitment: Data(repeating: 6, count: 48),
            proposalID: Data(repeating: 7, count: 48), action: .transfer,
            amount: Unsigned128Words(high: 3, low: 17),
            maximumFee: Unsigned128Words(high: 0, low: 9), expiresAtHeight: 500
        )
        XCTAssertEqual(approval.agentPrincipal, Data(repeating: 1, count: 48))
        XCTAssertEqual(approval.intentCommitment, Data(repeating: 6, count: 48))
        XCTAssertEqual(approval.amount, Unsigned128Words(high: 3, low: 17))
    }

    func testMcpLifecyclePersistsAndRejectsConcurrentOrInvalidReview() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("activechain-mcp-lifecycle-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("store.json")
        let approval = CanonicalMcpProposalApproval(
            intent: Data([1, 2, 3]), requestID: "request-7", chainID: "devnet",
            walletID: "primary", requestNonce: "nonce-7",
            agentPrincipal: Data(repeating: 1, count: 48),
            capabilityID: Data(repeating: 2, count: 48),
            resource: Data(repeating: 3, count: 48), recipient: Data(repeating: 4, count: 48),
            replayDomain: Data(repeating: 5, count: 48),
            intentCommitment: Data(repeating: 6, count: 48),
            proposalID: Data(repeating: 7, count: 48), action: .transfer,
            amount: Unsigned128Words(high: 0, low: 17),
            maximumFee: Unsigned128Words(high: 0, low: 9), expiresAtHeight: 500
        )
        let store = try McpProposalLifecycleStore(file: file)
        let pending = try await store.admit(approval, finalizedHeight: 100)
        XCTAssertEqual(pending.state, .pending)
        let approved = try await store.transition(
            proposalID: approval.proposalID, expectedRevision: 1, to: .approved,
            evidence: Data(repeating: 8, count: 48), finalizedHeight: 101
        )
        XCTAssertEqual(approved.revision, 2)
        do {
            _ = try await store.transition(
                proposalID: approval.proposalID, expectedRevision: 1, to: .rejected,
                evidence: Data(repeating: 9, count: 48), finalizedHeight: 101
            )
            XCTFail("stale concurrent review accepted")
        } catch McpProposalLifecycleError.concurrentReview {}

        let restarted = try McpProposalLifecycleStore(file: file)
        let restored = await restarted.record(proposalID: approval.proposalID)
        XCTAssertEqual(restored?.state, .approved)
        XCTAssertEqual(restored?.revision, 2)
    }
}
