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

    func testRustAgentRegistryDoesNotInventDevelopmentAgents() {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let snapshot = directory.appendingPathComponent("agents-v1.bin")
        defer { try? FileManager.default.removeItem(at: directory) }

        XCTAssertTrue(RustAgentRegistryStore(snapshotURL: snapshot).agents.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: snapshot.path))
    }

    func testAgentEnrollmentDraftRequiresCanonicalSortedCapabilityIDs() throws {
        let first = String(repeating: "11", count: 48)
        let second = String(repeating: "22", count: 48)
        var draft = AgentEnrollmentDraft(
            label: "Invoice assistant",
            principal: String(repeating: "aa", count: 48),
            capabilityIDs: "\(first)\n\(second)",
            connection: .thirdParty,
            budget: 100,
            expiresAt: 500
        )

        XCTAssertNoThrow(try draft.validate())
        XCTAssertEqual(try draft.principalBytes().count, 48)
        XCTAssertEqual(try draft.capabilityBytes().count, 96)

        draft.capabilityIDs = "\(second)\n\(first)"
        XCTAssertThrowsError(try draft.validate())
        draft.capabilityIDs = "\(first)\n\(first)"
        XCTAssertThrowsError(try draft.validate())
    }

    func testAgentEnrollmentDraftRejectsInvalidAuthority() {
        var draft = AgentEnrollmentDraft(
            label: "Invoice assistant",
            principal: String(repeating: "aa", count: 48),
            capabilityIDs: String(repeating: "11", count: 48),
            connection: .remote,
            budget: 0,
            expiresAt: 500
        )

        XCTAssertThrowsError(try draft.validate())
        draft.budget = 1
        draft.expiresAt = 0
        XCTAssertThrowsError(try draft.validate())
    }

    func testRPCStatusDecoderUsesFinalizedHealthInsteadOfDisplayFixtures() throws {
        let response = makeStatusResponse(
            protocolRevision: 1,
            schemaRevision: 1,
            finalizedHeight: 23,
            finalizedAt: 10,
            servedAt: 100,
            maximumStaleness: 30,
            health: 1
        )
        let status = try WalletRPCCodec.decodeStatus(response)
        XCTAssertEqual(status.networkState, .stale(finalizedHeight: 23))
        XCTAssertThrowsError(try WalletRPCCodec.decodeStatus(Data(response.dropLast())))
    }

    func testOwnerCoinCellRequestUsesBoundedCanonicalEnvelope() throws {
        let frame = try WalletRPCCodec.framedOwnerCoinCellRequest(owner: Data(repeating: 7, count: 48))
        XCTAssertEqual(frame.count, 4 + 4 + 1 + 48 + 1 + 2 + 1)
        XCTAssertEqual(Array(frame[4..<8]), [0, 0xa0, 0, 1])
        XCTAssertEqual(frame[8], 52)
        XCTAssertEqual(frame[9], 8)
        XCTAssertThrowsError(try WalletRPCCodec.framedOwnerCoinCellRequest(owner: Data(repeating: 0, count: 47)))
        XCTAssertThrowsError(try WalletRPCCodec.framedOwnerCoinCellRequest(owner: Data(repeating: 0, count: 48), limit: 5))
    }

    func testOwnerCoinPageDecoderRejectsWrongRecordKind() throws {
        var body = Data([2, 1, 1])
        body.append(Data(repeating: 1, count: 48))
        body.append(contentsOf: [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0])
        var envelope = Data([0, 0xa1, 0, 1, UInt8(body.count)])
        envelope.append(body)
        XCTAssertThrowsError(try WalletRPCCodec.decodeOwnerCoinPage(envelope))
    }

    func testOwnerCoinPageValidationFailsClosedWithoutProofVerifierAcceptance() throws {
        let record = WalletOwnerCoinRecord(key: Data(repeating: 3, count: 48), finalizedHeight: 4, value: Data([1]), proof: Data([2]), finality: Data([3]))
        let page = WalletOwnerCoinPage(records: [record], next: nil)
        let verifier = RejectingOwnerProofVerifier()
        XCTAssertThrowsError(try page.validated(owner: Data(repeating: 1, count: 48), chainGenesis: Data(repeating: 2, count: 48), finalizedHeight: 4, verifier: verifier))
    }

    private struct RejectingOwnerProofVerifier: WalletOwnerCoinProofVerifier {
        func verify(record: WalletOwnerCoinRecord, owner: Data, chainGenesis: Data) -> Bool { false }
    }

    func testWalletUISourceContainsNoFormerFabricatedValues() throws {
        let sources = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Sources")
        let forbidden = [
            "12,480.42", "2,742.69", "184,291", "184_291", "Test Euro",
            "240.00", "281.35", "Research agent", "Travel planner",
            "Kanalen Test ID", "Johan’s wallet", "3 validators", "2 agent actions"
        ]
        let source = try FileManager.default.contentsOfDirectory(
            at: sources,
            includingPropertiesForKeys: nil
        )
        .filter { $0.pathExtension == "swift" }
        .map { try String(contentsOf: $0, encoding: .utf8) }
        .joined(separator: "\n")
        for value in forbidden {
            XCTAssertFalse(source.contains(value), "fabricated UI value remains: \(value)")
        }
    }

    func testAgentIntentRouteIsExplicitAndOneShot() {
        let defaults = UserDefaults(suiteName: "agent-intent-test")!
        defaults.removePersistentDomain(forName: "agent-intent-test")
        XCTAssertNil(AgentIntentRouter.consume(defaults: defaults))
        AgentIntentRouter.request(.management, defaults: defaults)
        XCTAssertEqual(AgentIntentRouter.consume(defaults: defaults), .management)
        XCTAssertNil(AgentIntentRouter.consume(defaults: defaults))
    }

    private func makeStatusResponse(
        protocolRevision: UInt64,
        schemaRevision: UInt32,
        finalizedHeight: UInt64,
        finalizedAt: UInt64,
        servedAt: UInt64,
        maximumStaleness: UInt64,
        health: UInt8
    ) -> Data {
        var body = Data([0])
        body.append(Data(repeating: 0x11, count: 48))
        body.append(Data(repeating: 0x22, count: 48))
        body.append(contentsOf: protocolRevision.bigEndianBytes)
        body.append(contentsOf: schemaRevision.bigEndianBytes)
        body.append(contentsOf: finalizedHeight.bigEndianBytes)
        body.append(contentsOf: finalizedAt.bigEndianBytes)
        body.append(contentsOf: servedAt.bigEndianBytes)
        body.append(contentsOf: maximumStaleness.bigEndianBytes)
        body.append(health)
        body.append(contentsOf: [2, 0, 1])
        var envelope = Data([0, 0xa1, 0, 1, 0x91, 0x01])
        envelope.append(body)
        return envelope
    }
}

private extension FixedWidthInteger {
    var bigEndianBytes: [UInt8] {
        withUnsafeBytes(of: bigEndian) { Array($0) }
    }
}
