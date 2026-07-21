import XCTest
@testable import ActiveChainWallet

final class ActiveChainWalletTests: XCTestCase {
    func testLocalApproval() throws {
        let bridge = LocalWalletBridge()
        let preview = bridge.previewTransfer(recipient: "did:activechain:test", amount: 1, feeReserve: 1, validUntil: 10, currentHeight: 1)
        XCTAssertNoThrow(try bridge.approveTransfer(preview))
    }

    func testOpenWalletCredentialAndSessionReplayRules() {
        let adapter = OpenWalletAdapter()
        let credential = OpenWalletCredentialReference(credentialID: "cred-1", schemaID: "schema-1", issuer: "issuer-1")
        XCTAssertTrue(adapter.register(credential))
        XCTAssertFalse(adapter.register(credential))
        let session = OpenWalletApplicationSession(sessionID: "session-1", relyingParty: "rp", expiresAt: 10)
        XCTAssertTrue(adapter.open(session, at: 1))
        XCTAssertFalse(adapter.open(session, at: 1))
    }

    func testNetworkSwitchUpdatesVisibleAssets() {
        let profiles = [
            NetworkProfile(id: "kanalen", displayName: "Kanalen", genesis: "g1", rpcURL: URL(string: "https://kanalen.example")!, faucetURL: nil, assets: ["ACT"]),
            NetworkProfile(id: "roslagen", displayName: "Roslagen", genesis: "g2", rpcURL: URL(string: "https://roslagen.example")!, faucetURL: nil, assets: ["ACT", "TEST"])
        ]
        let selection = NetworkSelection(profiles: profiles)
        XCTAssertEqual(selection.visibleAssets, ["ACT"])
        XCTAssertTrue(selection.switchTo("roslagen"))
        XCTAssertEqual(selection.visibleAssets, ["ACT", "TEST"])
    }
}
