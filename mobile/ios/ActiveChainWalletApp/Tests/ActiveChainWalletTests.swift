import XCTest
import Security
@testable import ActiveChainWalletApp

final class ActiveChainWalletTests: XCTestCase {
    func testReceiveRequestBindsAddressToNetworkAndGenesis() throws {
        let request = ReceiveRequest(
            networkID: "roslagen",
            genesis: "genesis-42",
            address: "did:activechain:roslagen:alice"
        )
        let components = try XCTUnwrap(URLComponents(string: request.payload))
        let values = Dictionary(uniqueKeysWithValues: (components.queryItems ?? []).map {
            ($0.name, $0.value)
        })

        XCTAssertEqual(components.scheme, "activechain")
        XCTAssertEqual(components.host, "receive")
        XCTAssertEqual(values["network"]!, "roslagen")
        XCTAssertEqual(values["genesis"]!, "genesis-42")
        XCTAssertEqual(values["address"]!, "did:activechain:roslagen:alice")
    }

    func testReceiveRequestPayloadChangesAcrossNetworks() {
        let address = "did:activechain:wallet:alice"
        let first = ReceiveRequest(networkID: "one", genesis: "g1", address: address)
        let second = ReceiveRequest(networkID: "two", genesis: "g2", address: address)

        XCTAssertNotEqual(first.payload, second.payload)
    }

    func testSharedKeychainConfigurationIsExplicitAndOptInForSynchronization() throws {
        let group = "L2AF8KFX35.dev.activechain.wallet.shared"
        let configuration = try SharedKeychainConfiguration(accessGroup: group)
        let local = configuration.query(
            service: "wallet",
            account: "primary",
            synchronizeAcrossDevices: false
        )
        let synchronized = configuration.query(
            service: "wallet",
            account: "primary",
            synchronizeAcrossDevices: true
        )

        XCTAssertEqual(local[kSecAttrAccessGroup] as? String, group)
        XCTAssertEqual(local[kSecAttrSynchronizable] as? Bool, false)
        XCTAssertEqual(synchronized[kSecAttrSynchronizable] as? Bool, true)
#if os(macOS)
        XCTAssertEqual(local[kSecUseDataProtectionKeychain] as? Bool, true)
#endif
    }

    func testSharedKeychainRejectsUnscopedAccessGroups() {
        XCTAssertThrowsError(try SharedKeychainConfiguration(accessGroup: "dev.activechain.wallet"))
    }

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

    func testRustAgentRegistryPersistsLifecycleTransitions() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let snapshot = directory.appendingPathComponent("agents-v1.bin")
        defer { try? FileManager.default.removeItem(at: directory) }

        let initial = RustAgentRegistryStore(snapshotURL: snapshot)
        XCTAssertEqual(initial.agents.count, 2)
        let agentID = try XCTUnwrap(initial.agents.first?.id)

        initial.pause(agentID: agentID)
        XCTAssertEqual(initial.agents.first?.lifecycle, .paused)

        let restored = RustAgentRegistryStore(snapshotURL: snapshot)
        XCTAssertEqual(restored.agents.first?.lifecycle, .paused)
        restored.resume(agentID: agentID)
        XCTAssertEqual(restored.agents.first?.lifecycle, .active)
        restored.revoke(agentID: agentID)
        XCTAssertEqual(restored.agents.first?.lifecycle, .revocationPending)
        restored.finalizeRevocation(agentID: agentID, height: 42)
        XCTAssertEqual(restored.agents.first?.lifecycle, .revoked(finalizedHeight: 42))

        let finalized = RustAgentRegistryStore(snapshotURL: snapshot)
        XCTAssertEqual(finalized.agents.first?.lifecycle, .revoked(finalizedHeight: 42))
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
