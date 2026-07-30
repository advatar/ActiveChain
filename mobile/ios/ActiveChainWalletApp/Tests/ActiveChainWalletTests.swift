import XCTest
import Security
@testable import ActiveChainWalletApp

final class ActiveChainWalletTests: XCTestCase {
    func testFundingPresentationNeverCreditsPendingOrRejectedRequests() {
        let states: [WalletFundingState] = [
            .unavailable(reason: "missing key"),
            .ready,
            .requesting,
            .pending(reference: "abc"),
            .rejected(reference: "abc", reason: "limit")
        ]
        XCTAssertTrue(states.allSatisfy { !$0.creditsBalance })
        XCTAssertTrue(WalletFundingState.finalized(reference: "abc", height: 7).creditsBalance)
    }

    func testFundingPresentationUsesHonestLifecycleLabels() {
        XCTAssertEqual(WalletFundingState.ready.title, "Request testnet ACT")
        XCTAssertEqual(WalletFundingState.requesting.title, "Submitting signed request")
        XCTAssertEqual(WalletFundingState.pending(reference: "abc").title, "Funding pending")
        XCTAssertEqual(
            WalletFundingState.finalized(reference: "abc", height: 7).title,
            "Funding finalized"
        )
        XCTAssertEqual(
            WalletFundingState.rejected(reference: nil, reason: "disabled").title,
            "Funding rejected"
        )
    }

    func testFaucetRequestUsesPlainBoundedCanonicalRPCShape() throws {
        let frame = try WalletRPCCodec.framedFaucetRequest(
            owner: Data(repeating: 3, count: 48),
            idempotencyKey: Data(repeating: 4, count: 48),
            sourceCommitment: Data(repeating: 5, count: 48)
        )
        XCTAssertEqual(Array(frame.prefix(4)), [0, 0, 1, 0])
        XCTAssertEqual(Array(frame[4..<8]), [0, 0xa0, 0, 1])
        XCTAssertEqual(Array(frame[8..<10]), [0xfa, 0x01])
        XCTAssertEqual(frame[10], 5)
        XCTAssertEqual(frame.count, 260)
        XCTAssertThrowsError(
            try WalletRPCCodec.framedFaucetRequest(
                owner: Data(repeating: 0, count: 48),
                idempotencyKey: Data(repeating: 4, count: 48),
                sourceCommitment: Data(repeating: 5, count: 48)
            )
        )
    }

    func testFaucetTermsAndPendingReceiptDecodeWithoutCreditingBalance() throws {
        var termsBody = Data([7])
        termsBody.append(WalletKanalen.chainID)
        termsBody.append(WalletKanalen.genesis)
        termsBody.append(contentsOf: UInt64(1).bigEndianBytes)
        termsBody.append(contentsOf: UInt64(1_000).bigEndianBytes)
        termsBody.append(Data(repeating: 0, count: 15) + Data([10]))
        termsBody.append(contentsOf: UInt64(60).bigEndianBytes)
        termsBody.append(contentsOf: UInt16(2).bigEndianBytes)
        termsBody.append(contentsOf: UInt64(60).bigEndianBytes)
        termsBody.append(contentsOf: UInt16(2).bigEndianBytes)
        termsBody.append(contentsOf: UInt64(60).bigEndianBytes)
        termsBody.append(contentsOf: UInt32(10).bigEndianBytes)
        termsBody.append(contentsOf: [0, 0])
        let terms = try WalletRPCCodec.decodeFaucetTerms(rpcResponse(body: termsBody))
        XCTAssertEqual(terms.chainID, WalletKanalen.chainID)
        XCTAssertEqual(terms.genesis, WalletKanalen.genesis)
        XCTAssertEqual(terms.challengeKind, 0)

        var receiptBody = Data([6])
        receiptBody.append(Data(repeating: 7, count: 48))
        receiptBody.append(Data(repeating: 8, count: 48))
        receiptBody.append(Data(repeating: 0, count: 15) + Data([10]))
        receiptBody.append(contentsOf: [0, 1])
        receiptBody.append(Data(repeating: 9, count: 48))
        receiptBody.append(contentsOf: [0, 0, 0])
        let receipt = try WalletRPCCodec.decodeFaucetReceipt(rpcResponse(body: receiptBody))
        XCTAssertEqual(receipt.state, 0)
        XCTAssertNil(receipt.finalizedHeight)
        XCTAssertFalse(WalletFundingState.pending(reference: "07").creditsBalance)
    }

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

    func testAgentEnrollmentCannotCreateActiveLocalAuthorityWithoutSubmission() {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let snapshot = directory.appendingPathComponent("agents-v1.bin")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = RustAgentRegistryStore(snapshotURL: snapshot)
        let draft = AgentEnrollmentDraft(
            label: "Unsubmitted agent",
            principal: String(repeating: "aa", count: 48),
            capabilityIDs: String(repeating: "11", count: 48),
            connection: .thirdParty,
            budget: 100,
            expiresAt: 500
        )

        XCTAssertThrowsError(try store.prepareEnrollment(draft))
        XCTAssertTrue(store.agents.isEmpty)
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
            schemaRevision: 2,
            finalizedHeight: 23,
            finalizedAt: 10,
            servedAt: 100,
            maximumStaleness: 30,
            health: 1
        )
        let status = try WalletRPCCodec.decodeStatus(response)
        XCTAssertEqual(status.networkState, .stale(finalizedHeight: 23))
        XCTAssertTrue(status.supports(0))
        XCTAssertFalse(status.supports(4))
        XCTAssertEqual(status.chainID, WalletKanalen.chainID)
        XCTAssertEqual(status.genesis, WalletKanalen.genesis)
        XCTAssertThrowsError(try WalletRPCCodec.decodeStatus(Data(response.dropLast())))
    }

    func testRPCStatusRejectsWrongKanalenIdentityAndSchema() throws {
        let wrongChain = try WalletRPCCodec.decodeStatus(
            makeStatusResponse(chainID: Data(repeating: 0x44, count: 48))
        )
        XCTAssertEqual(wrongChain.networkState, .incompatible)
        let wrongGenesis = try WalletRPCCodec.decodeStatus(
            makeStatusResponse(genesis: Data(repeating: 0x55, count: 48))
        )
        XCTAssertEqual(wrongGenesis.networkState, .incompatible)
        let wrongSchema = try WalletRPCCodec.decodeStatus(makeStatusResponse(schemaRevision: 1))
        XCTAssertEqual(wrongSchema.networkState, .incompatible)
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

    func testOwnerCoinPageDecoderAcceptsProofBearingBodiesLargerThanStatus() throws {
        var body = Data([2, 1, 4])
        body.append(Data(repeating: 1, count: 48))
        body.append(contentsOf: UInt64(9).bigEndianBytes)
        for marker: UInt8 in [2, 3, 4] {
            body.append(60)
            body.append(Data(repeating: marker, count: 60))
        }
        body.append(0)
        var envelope = Data([0, 0xa1, 0, 1])
        envelope.append(contentsOf: uleb128(body.count))
        envelope.append(body)

        let page = try WalletRPCCodec.decodeOwnerCoinPage(envelope)
        XCTAssertEqual(page.records.count, 1)
        XCTAssertEqual(page.records[0].finalizedHeight, 9)
    }

    func testOwnerCoinPageValidationFailsClosedWithoutProofVerifierAcceptance() throws {
        let record = WalletOwnerCoinRecord(key: Data(repeating: 3, count: 48), finalizedHeight: 4, value: Data([1]), proof: Data([2]), finality: Data([3]))
        let page = WalletOwnerCoinPage(records: [record], next: nil)
        let verifier = RejectingOwnerProofVerifier()
        XCTAssertThrowsError(try page.validated(owner: Data(repeating: 1, count: 48), chainGenesis: Data(repeating: 2, count: 48), finalizedHeight: 4, verifier: verifier))
    }

    func testOwnerCoinPageValidationRejectsUnauthenticatedAbsenceAndWrongGenesis() {
        let verifier = RejectingOwnerProofVerifier()
        XCTAssertThrowsError(
            try WalletOwnerCoinPage(records: [], next: nil).validated(
                owner: Data(repeating: 1, count: 48),
                chainGenesis: WalletKanalen.genesis,
                finalizedHeight: 4,
                verifier: verifier
            )
        )
        let record = WalletOwnerCoinRecord(
            key: Data(repeating: 3, count: 48),
            finalizedHeight: 4,
            value: Data([1]),
            proof: Data([2]),
            finality: Data([3])
        )
        XCTAssertThrowsError(
            try WalletOwnerCoinPage(records: [record], next: nil).validated(
                owner: Data(repeating: 1, count: 48),
                chainGenesis: Data(repeating: 2, count: 48),
                finalizedHeight: 4,
                verifier: verifier
            )
        )
    }

    private struct RejectingOwnerProofVerifier: WalletOwnerCoinProofVerifier {
        func verify(record: WalletOwnerCoinRecord, owner: Data, chainGenesis: Data) -> Bool { false }
    }

    func testLinkedRustOwnerProofVerifierFailsClosedOnMalformedEvidence() {
        let record = WalletOwnerCoinRecord(
            key: Data(repeating: 3, count: 48),
            finalizedHeight: 4,
            value: Data([1]),
            proof: Data([2]),
            finality: Data([3])
        )
        XCTAssertFalse(
            RustWalletOwnerCoinProofVerifier().verify(
                record: record,
                owner: Data(repeating: 1, count: 48),
                chainGenesis: WalletKanalen.genesis
            )
        )
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
        chainID: Data = WalletKanalen.chainID,
        genesis: Data = WalletKanalen.genesis,
        protocolRevision: UInt64 = 1,
        schemaRevision: UInt32 = 2,
        finalizedHeight: UInt64 = 23,
        finalizedAt: UInt64 = 10,
        servedAt: UInt64 = 100,
        maximumStaleness: UInt64 = 30,
        health: UInt8 = 1
    ) -> Data {
        var body = Data([0])
        body.append(chainID)
        body.append(genesis)
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

    private func rpcResponse(body: Data) -> Data {
        var envelope = Data([0, 0xa1, 0, 1])
        envelope.append(contentsOf: uleb128(body.count))
        envelope.append(body)
        return envelope
    }

    private func uleb128(_ value: Int) -> [UInt8] {
        var value = value
        var result: [UInt8] = []
        repeat {
            var byte = UInt8(value & 0x7f)
            value >>= 7
            if value != 0 { byte |= 0x80 }
            result.append(byte)
        } while value != 0
        return result
    }
}

private extension FixedWidthInteger {
    var bigEndianBytes: [UInt8] {
        withUnsafeBytes(of: bigEndian) { Array($0) }
    }
}
