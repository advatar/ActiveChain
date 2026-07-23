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
        let store = UserDefaults(suiteName: "network-test")!
        store.removePersistentDomain(forName: "network-test")
        let selection = NetworkSelection(profiles: profiles, store: store)
        XCTAssertEqual(selection.visibleAssets, ["ACT"])
        XCTAssertTrue(selection.switchTo("roslagen"))
        XCTAssertEqual(selection.visibleAssets, ["ACT", "TEST"])
        let restored = NetworkSelection(profiles: profiles, store: store)
        XCTAssertEqual(restored.selected.id, "roslagen")
    }

    func testAgentDelegationPauseResumeAndFinalizedRevocation() {
        let store = AgentWalletStore()
        let agent = AgentDelegation(id: "agent-1", label: "Research agent",
                                    capabilities: ["transfer"], dailyLimit: 100, expiresAt: 100,
                                    connection: .thirdParty)
        XCTAssertTrue(store.delegate(agent))
        XCTAssertFalse(store.delegate(agent))
        store.pause(agentID: "agent-1")
        XCTAssertEqual(store.agents[0].lifecycle, .paused)
        store.resume(agentID: "agent-1")
        XCTAssertEqual(store.agents[0].lifecycle, .active)
        store.revoke(agentID: "agent-1")
        XCTAssertEqual(store.agents[0].lifecycle, .revocationPending)
        XCTAssertFalse(store.agents[0].revoked)
        store.resume(agentID: "agent-1")
        XCTAssertEqual(store.agents[0].lifecycle, .revocationPending)
        store.finalizeRevocation(agentID: "agent-1", height: 42)
        XCTAssertEqual(store.agents[0].lifecycle, .revoked(finalizedHeight: 42))
        XCTAssertTrue(store.agents[0].revoked)
    }

    func testAgentIntentRouteIsExplicitAndOneShot() {
        let defaults = UserDefaults(suiteName: "agent-intent-test")!
        defaults.removePersistentDomain(forName: "agent-intent-test")
        XCTAssertNil(AgentIntentRouter.consume(defaults: defaults))
        AgentIntentRouter.request(.management, defaults: defaults)
        XCTAssertEqual(AgentIntentRouter.consume(defaults: defaults), .management)
        XCTAssertNil(AgentIntentRouter.consume(defaults: defaults))
    }
}
