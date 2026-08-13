import XCTest
import Security
import CryptoKit
import ActiveChainWallet
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
        XCTAssertEqual(Array(frame[4..<8]), [0x01, 0x07, 0, 2])
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

    func testSharedCanonicalApprovalVectorCrossesTheRustCAndSwiftBoundaries() throws {
        var directory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        var vectorURL: URL?
        while directory.path != "/" {
            let candidate = directory.appendingPathComponent(
                "testing/vectors/wallet-canonical-approval-v1.txt"
            )
            if FileManager.default.fileExists(atPath: candidate.path) {
                vectorURL = candidate
                break
            }
            directory.deleteLastPathComponent()
        }
        let contents = try String(contentsOf: try XCTUnwrap(vectorURL), encoding: .utf8)
        let vector = Dictionary(uniqueKeysWithValues: contents.split(separator: "\n")
            .filter { !$0.hasPrefix("#") && $0.contains("=") }
            .map { line -> (String, String) in
                let fields = line.split(separator: "=", maxSplits: 1)
                return (String(fields[0]), String(fields[1]))
            })
        let request = try XCTUnwrap(Data(strictHex: vector["request_hex"]!))
        let approval = try RustCanonicalApproval.review(request)

        XCTAssertEqual(approval.intentID, Data(strictHex: vector["intent_id"]!))
        XCTAssertEqual(approval.recipient, Data(strictHex: vector["recipient"]!))
        XCTAssertEqual(approval.nonce, 7)
        XCTAssertEqual(approval.amount, Unsigned128Words(high: 0, low: 50))

        var alternate = request
        alternate.append(0)
        XCTAssertThrowsError(try RustCanonicalApproval.review(alternate))
    }

    func testCanonicalApprovalSessionFailsClosedAfterOneAuthenticatedSigningAttempt() throws {
        let approval = try sharedCanonicalApproval()
        let fixture = AppleCustodyFixture()
        var recoveryKey = Data(repeating: 0x91, count: 32)
        _ = try fixture.provider.provision(
            slotID: "wallet-primary", keyVersion: 1, finalizedHeight: 20,
            recoveryKey: &recoveryKey
        )
        let session = CanonicalCashApprovalSession(approval: approval)

        XCTAssertThrowsError(try session.sign(
            with: fixture.provider, slotID: "wallet-primary",
            minimumVersion: 1, minimumFinalizedHeight: 20
        ))
        XCTAssertEqual(fixture.hardware.unwrapCount, 1)
        XCTAssertThrowsError(try session.sign(
            with: fixture.provider, slotID: "wallet-primary",
            minimumVersion: 1, minimumFinalizedHeight: 20
        )) { error in
            XCTAssertEqual(error as? CanonicalApprovalError, .alreadyConsumed)
        }
        XCTAssertEqual(fixture.hardware.unwrapCount, 1)
    }

    func testCanonicalApprovalSessionRejectsSubstitutedHumanReviewBeforeCustody() throws {
        let approval = try sharedCanonicalApproval()
        let substituted = CanonicalCashApproval(
            request: approval.request, chainID: approval.chainID, signer: approval.signer,
            recipient: Data(repeating: 0xff, count: 48), feeReserve: approval.feeReserve,
            sessionID: approval.sessionID, intentID: approval.intentID, nonce: approval.nonce,
            sessionExpiresAt: approval.sessionExpiresAt, amount: approval.amount, fee: approval.fee,
            validUntil: approval.validUntil, inputCount: approval.inputCount
        )
        let fixture = AppleCustodyFixture()
        XCTAssertThrowsError(try CanonicalCashApprovalSession(approval: substituted).sign(
            with: fixture.provider, slotID: "missing", minimumVersion: 1,
            minimumFinalizedHeight: 0
        )) { error in
            XCTAssertEqual(error as? CanonicalApprovalError, .substitutedReview)
        }
        XCTAssertEqual(fixture.hardware.unwrapCount, 0)
    }

    func testRustNativeMLDSAEngineProducesWireCompatibleLengths() throws {
        let engine = RustAppleMLDSA44Engine()
        var seed = Data(repeating: 73, count: AppleNativeCustodyProvider.seedLength)
        let publicKey = try engine.publicKey(seed: &seed)
        let repeatedPublicKey = try engine.publicKey(seed: &seed)
        let signature = try engine.sign(payload: Data("canonical payload".utf8), seed: &seed)

        XCTAssertEqual(publicKey.count, AppleNativeCustodyProvider.publicKeyLength)
        XCTAssertEqual(publicKey, repeatedPublicKey)
        XCTAssertEqual(signature.count, AppleNativeCustodyProvider.signatureLength)
        XCTAssertEqual(seed, Data(repeating: 73, count: AppleNativeCustodyProvider.seedLength))
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

    func testSharedKeychainQueryIsAppScopedAndOptInForSynchronization() throws {
        let configuration = try SharedKeychainConfiguration.application()
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

        // No access group: a group shares only within one device and team, so
        // it cannot open the same wallet across iOS and macOS, and an unsigned
        // build has no team prefix to name one with.
        XCTAssertNil(local[kSecAttrAccessGroup])
        XCTAssertNil(synchronized[kSecAttrAccessGroup])
        XCTAssertEqual(local[kSecAttrService] as? String, "wallet")
        XCTAssertEqual(local[kSecAttrAccount] as? String, "primary")
        XCTAssertEqual(local[kSecAttrSynchronizable] as? Bool, false)
        XCTAssertEqual(synchronized[kSecAttrSynchronizable] as? Bool, true)
#if os(macOS)
        XCTAssertEqual(local[kSecUseDataProtectionKeychain] as? Bool, true)
#endif
    }


    /// Proves the cross-device claim: a wallet provisioned on one device can be
    /// recovered on another and keeps the same identity.
    ///
    /// Custody takes its store, hardware and engine as protocols, so two
    /// devices are modelled as two stores with two independent wrapping keys
    /// while the real ML-DSA-44 engine derives the keys. The Secure Enclave is
    /// stood in for because it is device bound by construction; everything that
    /// determines identity — the seed, its sealing, and the derived public
    /// key — is exercised for real.
    func testRecoveryEnvelopeMovesTheSameWalletToAnotherDevice() throws {
        let deviceA = AppleNativeCustodyProvider(
            store: InMemoryCustodyStore(),
            hardware: InMemoryWrapping(),
            engine: RustAppleMLDSA44Engine()
        )
        let deviceB = AppleNativeCustodyProvider(
            store: InMemoryCustodyStore(),
            hardware: InMemoryWrapping(),
            engine: RustAppleMLDSA44Engine()
        )
        var recoveryKey = Data(repeating: 0x5A, count: 32)

        let originPublicKey = try deviceA.provision(
            slotID: "primary",
            keyVersion: 1,
            finalizedHeight: 100,
            recoveryKey: &recoveryKey
        )
        let envelope = try deviceA.exportRecoveryEnvelope(slotID: "primary")

        let recoveredPublicKey = try deviceB.recover(
            envelopeBytes: envelope,
            expectedPublicKey: originPublicKey,
            newVersion: 2,
            finalizedHeight: 100,
            recoveryKey: &recoveryKey
        )

        // Same public key on both devices means the same owner principal, which
        // is what "the same wallet" has to mean.
        XCTAssertEqual(recoveredPublicKey, originPublicKey)
        XCTAssertEqual(try deviceB.publicKey(slotID: "primary"), originPublicKey)

        // And the recovered device can actually authorize.
        let signature = try deviceB.sign(
            slotID: "primary",
            payload: Data("cross device authorization".utf8),
            minimumVersion: 2,
            minimumFinalizedHeight: 100,
            reason: "test"
        )
        XCTAssertEqual(signature.count, AppleNativeCustodyProvider.signatureLength)
    }

    func testRecoveryRejectsAWrongKeyAndARolledBackVersion() throws {
        let deviceA = AppleNativeCustodyProvider(
            store: InMemoryCustodyStore(),
            hardware: InMemoryWrapping(),
            engine: RustAppleMLDSA44Engine()
        )
        var recoveryKey = Data(repeating: 0x11, count: 32)
        let originPublicKey = try deviceA.provision(
            slotID: "primary",
            keyVersion: 3,
            finalizedHeight: 200,
            recoveryKey: &recoveryKey
        )
        let envelope = try deviceA.exportRecoveryEnvelope(slotID: "primary")

        var wrongKey = Data(repeating: 0x22, count: 32)
        let deviceB = AppleNativeCustodyProvider(
            store: InMemoryCustodyStore(),
            hardware: InMemoryWrapping(),
            engine: RustAppleMLDSA44Engine()
        )
        XCTAssertThrowsError(
            try deviceB.recover(
                envelopeBytes: envelope,
                expectedPublicKey: originPublicKey,
                newVersion: 4,
                finalizedHeight: 200,
                recoveryKey: &wrongKey
            )
        )
        // Anti-rollback: the receiving version must exceed the envelope's.
        XCTAssertThrowsError(
            try deviceB.recover(
                envelopeBytes: envelope,
                expectedPublicKey: originPublicKey,
                newVersion: 3,
                finalizedHeight: 200,
                recoveryKey: &recoveryKey
            )
        )
    }

    func testCanonicalApprovalComesFromExactRustRequest() throws {
        func digest(_ byte: UInt8) -> UnsafeMutablePointer<UInt8> {
            let pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 48)
            pointer.initialize(repeating: byte, count: 48)
            return pointer
        }
        let chain = digest(1), signer = digest(2), recipient = digest(3)
        let input = digest(4), reserve = digest(5), session = digest(6)
        defer { [chain, signer, recipient, input, reserve, session].forEach { $0.deallocate() } }
        var required: UInt32 = 0
        var intent = Data(repeating: 0, count: 48)
        let query = intent.withUnsafeMutableBytes {
            activechain_wallet_build_cash_intent(
                chain, signer, recipient, input, reserve, 7, session, 9,
                0, 50, 0, 2, 10, nil, 0, &required,
                $0.bindMemory(to: UInt8.self).baseAddress
            )
        }
        XCTAssertEqual(query, UInt32(ACTIVECHAIN_WALLET_BUFFER_TOO_SMALL))
        var request = Data(repeating: 0, count: Int(required))
        let code = request.withUnsafeMutableBytes { requestBytes in
            intent.withUnsafeMutableBytes { intentBytes in
                activechain_wallet_build_cash_intent(
                    chain, signer, recipient, input, reserve, 7, session, 9,
                    0, 50, 0, 2, 10,
                    requestBytes.bindMemory(to: UInt8.self).baseAddress, required, &required,
                    intentBytes.bindMemory(to: UInt8.self).baseAddress
                )
            }
        }
        XCTAssertEqual(code, UInt32(ACTIVECHAIN_WALLET_OK))
        let approval = try RustCanonicalApproval.review(request)
        XCTAssertEqual(approval.intentID, intent)
        XCTAssertEqual(approval.recipient, Data(repeating: 3, count: 48))
        XCTAssertEqual(approval.amount, Unsigned128Words(high: 0, low: 50))
        XCTAssertEqual(approval.fee, Unsigned128Words(high: 0, low: 2))
        XCTAssertEqual(approval.validUntil, 10)
        XCTAssertEqual(approval.inputCount, 1)

        request[request.index(before: request.endIndex)] ^= 1
        XCTAssertNotEqual(try RustCanonicalApproval.review(request).intentID, approval.intentID)
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
            schemaRevision: 3,
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

    func testLiveKanalenStatusWhenEnabled() async throws {
        guard ProcessInfo.processInfo.environment["ACTIVECHAIN_LIVE_KANALEN"] == "1" else {
            throw XCTSkip("set ACTIVECHAIN_LIVE_KANALEN=1 for the bounded live RPC test")
        }
        let status = try await WalletRPCClient().status()
        XCTAssertEqual(status.chainID, WalletKanalen.chainID)
        XCTAssertEqual(status.genesis, WalletKanalen.genesis)
        guard case let .healthy(finalizedHeight) = status.networkState else {
            return XCTFail("live Kanalen status is not healthy and identity-compatible")
        }
        XCTAssertGreaterThan(finalizedHeight, 0)
    }

    func testLiveKanalenFaucetWhenExplicitlyEnabled() async throws {
        let mode = ProcessInfo.processInfo.environment["ACTIVECHAIN_LIVE_KANALEN_FAUCET"]
        guard mode == "submit" || mode == "verify" else {
            throw XCTSkip("set ACTIVECHAIN_LIVE_KANALEN_FAUCET=submit or verify")
        }
        let owner = Data(repeating: 0xa7, count: 48)
        let client = WalletRPCClient()
        if mode == "submit" {
            let terms = try await client.faucetTerms()
            XCTAssertEqual(terms.chainID, WalletKanalen.chainID)
            XCTAssertEqual(terms.genesis, WalletKanalen.genesis)
            let receipt = try await client.requestFaucet(owner: owner)
            XCTAssertEqual(receipt.state, 0)
            XCTAssertNil(receipt.finalizedHeight)
        } else {
            let status = try await client.status()
            guard case let .healthy(height) = status.networkState else {
                return XCTFail("Kanalen is not healthy")
            }
            let page = try await client.verifiedOwnerCoinCells(
                profile: WalletDeviceProfile(owner: owner, chainGenesis: WalletKanalen.genesis),
                finalizedHeight: height,
                verifier: RustWalletOwnerCoinProofVerifier()
            )
            XCTAssertFalse(page.records.isEmpty)
        }
    }

    func testOwnerCoinCellRequestUsesBoundedCanonicalEnvelope() throws {
        let frame = try WalletRPCCodec.framedOwnerCoinCellRequest(owner: Data(repeating: 7, count: 48))
        XCTAssertEqual(frame.count, 4 + 4 + 1 + 48 + 1 + 2 + 1)
        XCTAssertEqual(Array(frame[4..<8]), [0x01, 0x07, 0, 2])
        XCTAssertEqual(frame[8], 52)
        XCTAssertEqual(frame[9], 8)
        XCTAssertThrowsError(try WalletRPCCodec.framedOwnerCoinCellRequest(owner: Data(repeating: 0, count: 47)))
        XCTAssertThrowsError(try WalletRPCCodec.framedOwnerCoinCellRequest(owner: Data(repeating: 0, count: 48), limit: 5))
    }

    func testOwnerCoinPageDecoderRejectsWrongRecordKind() throws {
        var body = Data([2, 1, 1])
        body.append(Data(repeating: 1, count: 48))
        body.append(contentsOf: [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0])
        var envelope = Data([0x01, 0x0a, 0, 3, UInt8(body.count)])
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
        // RpcResponse is canonical schema revision 3.
        var envelope = Data([0x01, 0x0a, 0, 3])
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

    func testOwnerCoinPageValidationAcceptsVerifiedAbsenceButRejectsWrongGenesis() throws {
        let verifier = RejectingOwnerProofVerifier()
        // A page carrying no records is a verified statement that this owner
        // holds no spendable Coin Cells. There is no proof to reject, so the
        // verifier is never consulted, and the wallet must report a zero
        // balance rather than a protocol failure — treating absence as
        // malformed made every unfunded wallet look like a broken node.
        let empty = try WalletOwnerCoinPage(records: [], next: nil).validated(
            owner: Data(repeating: 1, count: 48),
            chainGenesis: WalletKanalen.genesis,
            finalizedHeight: 4,
            verifier: verifier
        )
        XCTAssertTrue(empty.records.isEmpty)

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

    /// The chain advances between the status call and the page call, so a
    /// record proved at an earlier finalized height is the ordinary case. The
    /// old equality check turned that race into a refresh failure.
    func testOwnerCoinPageAcceptsRecordsProvedBelowTheObservedHeight() throws {
        let record = WalletOwnerCoinRecord(
            key: Data(repeating: 3, count: 48),
            finalizedHeight: 4,
            value: Data([1]),
            proof: Data([2]),
            finality: Data([3])
        )
        let page = try WalletOwnerCoinPage(records: [record], next: nil).validated(
            owner: Data(repeating: 1, count: 48),
            chainGenesis: WalletKanalen.genesis,
            finalizedHeight: 5,
            verifier: AcceptingOwnerProofVerifier()
        )
        XCTAssertEqual(page.records.count, 1)
    }

    /// Nothing above the height we observed has been proved to this wallet, so
    /// a record claiming one is refused even when its own proof verifies.
    func testOwnerCoinPageRejectsRecordsAboveTheObservedHeight() {
        let record = WalletOwnerCoinRecord(
            key: Data(repeating: 3, count: 48),
            finalizedHeight: 6,
            value: Data([1]),
            proof: Data([2]),
            finality: Data([3])
        )
        XCTAssertThrowsError(
            try WalletOwnerCoinPage(records: [record], next: nil).validated(
                owner: Data(repeating: 1, count: 48),
                chainGenesis: WalletKanalen.genesis,
                finalizedHeight: 5,
                verifier: AcceptingOwnerProofVerifier()
            )
        )
    }

    private struct RejectingOwnerProofVerifier: WalletOwnerCoinProofVerifier {
        func verify(record: WalletOwnerCoinRecord, owner: Data, chainGenesis: Data) -> Bool { false }
    }

    private struct AcceptingOwnerProofVerifier: WalletOwnerCoinProofVerifier {
        func verify(record: WalletOwnerCoinRecord, owner: Data, chainGenesis: Data) -> Bool { true }
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

    func testNativeCustodySignsOnlyAtCurrentRollbackAnchors() throws {
        let fixture = AppleCustodyFixture()
        var recoveryKey = Data(repeating: 9, count: 32)
        let publicKey = try fixture.provider.provision(
            slotID: "primary",
            keyVersion: 1,
            finalizedHeight: 10,
            recoveryKey: &recoveryKey
        )

        XCTAssertEqual(publicKey.count, 1_312)
        XCTAssertEqual(
            try fixture.provider.sign(
                slotID: "primary",
                payload: Data([7]),
                minimumVersion: 1,
                minimumFinalizedHeight: 10,
                reason: "Approve"
            ).count,
            2_420
        )
        XCTAssertThrowsError(
            try fixture.provider.sign(
                slotID: "primary",
                payload: Data([7]),
                minimumVersion: 2,
                minimumFinalizedHeight: 10,
                reason: "Approve"
            )
        ) { XCTAssertEqual($0 as? AppleCustodyError, .rollback) }
        XCTAssertThrowsError(
            try fixture.provider.sign(
                slotID: "primary",
                payload: Data([7]),
                minimumVersion: 1,
                minimumFinalizedHeight: 11,
                reason: "Approve"
            )
        ) { XCTAssertEqual($0 as? AppleCustodyError, .rollback) }
    }

    func testNativeCustodyRejectsCancellationLockedWrongAndRevokedKeys() throws {
        let fixture = AppleCustodyFixture()
        var recoveryKey = Data(repeating: 4, count: 32)
        _ = try fixture.provider.provision(
            slotID: "primary",
            keyVersion: 1,
            finalizedHeight: 10,
            recoveryKey: &recoveryKey
        )
        fixture.hardware.failure = .authenticationCancelled
        XCTAssertThrowsError(
            try fixture.provider.sign(
                slotID: "primary", payload: Data([1]), minimumVersion: 1,
                minimumFinalizedHeight: 10, reason: "Approve"
            )
        ) { XCTAssertEqual($0 as? AppleCustodyError, .authenticationCancelled) }
        fixture.hardware.failure = .deviceLocked
        XCTAssertThrowsError(
            try fixture.provider.sign(
                slotID: "primary", payload: Data([1]), minimumVersion: 1,
                minimumFinalizedHeight: 10, reason: "Approve"
            )
        ) { XCTAssertEqual($0 as? AppleCustodyError, .deviceLocked) }
        fixture.hardware.failure = nil
        fixture.hardware.substitutePlaintext = Data(repeating: 99, count: 32)
        XCTAssertThrowsError(
            try fixture.provider.sign(
                slotID: "primary", payload: Data([1]), minimumVersion: 1,
                minimumFinalizedHeight: 10, reason: "Approve"
            )
        ) { XCTAssertEqual($0 as? AppleCustodyError, .wrongKey) }
        fixture.hardware.substitutePlaintext = nil
        try fixture.provider.revoke(slotID: "primary")
        XCTAssertThrowsError(
            try fixture.provider.sign(
                slotID: "primary", payload: Data([1]), minimumVersion: 1,
                minimumFinalizedHeight: 10, reason: "Approve"
            )
        ) { XCTAssertEqual($0 as? AppleCustodyError, .revoked) }
        XCTAssertThrowsError(try fixture.provider.exportRecoveryEnvelope(slotID: "primary")) {
            XCTAssertEqual($0 as? AppleCustodyError, .revoked)
        }
    }

    func testNativeCustodyRotationStoresReplacementBeforeDeletingOldKey() throws {
        let fixture = AppleCustodyFixture()
        var recoveryKey = Data(repeating: 4, count: 32)
        _ = try fixture.provider.provision(
            slotID: "primary", keyVersion: 1, finalizedHeight: 10,
            recoveryKey: &recoveryKey
        )
        let oldTag = try XCTUnwrap(fixture.hardware.tags.first)
        fixture.store.failNextSave = true
        XCTAssertThrowsError(
            try fixture.provider.rotate(
                slotID: "primary", newVersion: 2, finalizedHeight: 11,
                recoveryKey: &recoveryKey
            )
        ) { XCTAssertEqual($0 as? AppleCustodyError, .storageFailure) }
        XCTAssertTrue(fixture.hardware.tags.contains(oldTag))
        XCTAssertEqual(fixture.hardware.tags.count, 1)

        _ = try fixture.provider.rotate(
            slotID: "primary", newVersion: 2, finalizedHeight: 11,
            recoveryKey: &recoveryKey
        )
        XCTAssertFalse(fixture.hardware.tags.contains(oldTag))
        XCTAssertThrowsError(
            try fixture.provider.rotate(
                slotID: "primary", newVersion: 2, finalizedHeight: 12,
                recoveryKey: &recoveryKey
            )
        ) { XCTAssertEqual($0 as? AppleCustodyError, .rollback) }
    }

    func testNativeCustodyRecoveryBindsKeyVersionAndMetadata() throws {
        let fixture = AppleCustodyFixture()
        var recoveryKey = Data(repeating: 4, count: 32)
        let publicKey = try fixture.provider.provision(
            slotID: "primary", keyVersion: 1, finalizedHeight: 10,
            recoveryKey: &recoveryKey
        )
        let envelope = try fixture.provider.exportRecoveryEnvelope(slotID: "primary")
        try fixture.provider.revoke(slotID: "primary")

        let replacement = AppleCustodyFixture()
        XCTAssertEqual(
            try replacement.provider.recover(
                envelopeBytes: envelope,
                expectedPublicKey: publicKey,
                newVersion: 2,
                finalizedHeight: 11,
                recoveryKey: &recoveryKey
            ),
            publicKey
        )
        XCTAssertThrowsError(
            try AppleCustodyFixture().provider.recover(
                envelopeBytes: envelope,
                expectedPublicKey: Data(repeating: 0, count: 1_312),
                newVersion: 2,
                finalizedHeight: 11,
                recoveryKey: &recoveryKey
            )
        ) { XCTAssertEqual($0 as? AppleCustodyError, .wrongKey) }
        var wrongRecoveryKey = Data(repeating: 8, count: 32)
        XCTAssertThrowsError(
            try AppleCustodyFixture().provider.recover(
                envelopeBytes: envelope,
                expectedPublicKey: publicKey,
                newVersion: 2,
                finalizedHeight: 11,
                recoveryKey: &wrongRecoveryKey
            )
        ) { XCTAssertEqual($0 as? AppleCustodyError, .cryptographicFailure) }
        XCTAssertThrowsError(
            try AppleCustodyFixture().provider.recover(
                envelopeBytes: Data([1, 2, 3]),
                expectedPublicKey: publicKey,
                newVersion: 2,
                finalizedHeight: 11,
                recoveryKey: &recoveryKey
            )
        ) { XCTAssertEqual($0 as? AppleCustodyError, .unsupportedRecord) }
    }

    private func makeStatusResponse(
        chainID: Data = WalletKanalen.chainID,
        genesis: Data = WalletKanalen.genesis,
        protocolRevision: UInt64 = 1,
        schemaRevision: UInt32 = 3,
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
        var envelope = Data([0x01, 0x0a, 0, 3, 0x91, 0x01])
        envelope.append(body)
        return envelope
    }

    /// The node names why it refused. Before this, every refusal reached the
    /// wallet as a generic invalid-request and read on screen as a transport
    /// fault — which is how a wedged treasury looked like a client-side error.
    func testFaucetRefusalIsNamedRatherThanReadAsAMalformedReply() throws {
        var cooldown = Data([10, 3, 1])
        cooldown.append(contentsOf: UInt64(3_600).bigEndianBytes)
        cooldown.append(0)
        let envelope = rpcResponse(body: cooldown)

        let rejection = try XCTUnwrap(WalletRPCCodec.faucetRejection(envelope))
        XCTAssertEqual(rejection.code, 3)
        XCTAssertEqual(rejection.retryAfterSeconds, 3_600)
        XCTAssertNil(rejection.existingReference)
        XCTAssertTrue(
            rejection.summary.contains("Already funded"),
            "a cooldown must read as a wait, got '\(rejection.summary)'"
        )

        // An operator-side failure must never be phrased as the caller's fault
        // and must not invite a pointless retry.
        let unavailable = try XCTUnwrap(
            WalletRPCCodec.faucetRejection(rpcResponse(body: Data([10, 8, 0, 0])))
        )
        XCTAssertEqual(unavailable.code, 8)
        XCTAssertNil(unavailable.retryAfterSeconds)
        XCTAssertTrue(
            unavailable.summary.contains("cannot settle"),
            "an operator outage must say so, got '\(unavailable.summary)'"
        )

        // Decoding a receipt from a refusal surfaces the named reason rather
        // than the malformed-response it used to be mistaken for.
        XCTAssertThrowsError(try WalletRPCCodec.decodeFaucetReceipt(envelope)) { error in
            guard case let WalletRPCError.faucetRejected(named) = error else {
                return XCTFail("expected a named faucet refusal, got \(error)")
            }
            XCTAssertEqual(named.code, 3)
        }
    }

    /// A grant reaches finality some blocks after it is accepted. Nothing asked
    /// what became of it, so the funding card went on asserting "no balance has
    /// been credited" while the balance card showed the Coin Cell that same
    /// grant had produced — two claims about one ledger, one of them false.
    func testPendingGrantCanBeResolvedAfterItReachesFinality() throws {
        let reference = Data(repeating: 7, count: 48)
        let frame = try WalletRPCCodec.framedResolveFaucetRequest(reference: reference)
        // Request variant 6 is ResolveFaucet, carrying just the reference. The
        // 49-byte body needs a single uleb128 length byte, so the variant sits
        // one earlier than in the larger faucet request above.
        XCTAssertEqual(Array(frame[4..<8]), [0x01, 0x07, 0, 2])
        XCTAssertEqual(frame[8], 49)
        XCTAssertEqual(frame[9], 6)
        XCTAssertEqual(Array(frame.suffix(48)), Array(reference))

        // A zero or malformed reference is refused rather than asked about.
        XCTAssertThrowsError(
            try WalletRPCCodec.framedResolveFaucetRequest(reference: Data(repeating: 0, count: 48))
        )
        XCTAssertThrowsError(
            try WalletRPCCodec.framedResolveFaucetRequest(reference: Data(repeating: 7, count: 47))
        )

        // The finalized receipt the node sends back must decode with its height,
        // which is what lets the card stop claiming nothing was credited.
        var body = Data([6])
        body.append(reference)
        body.append(Data(repeating: 8, count: 48))
        body.append(Data(repeating: 0, count: 15) + Data([10]))
        body.append(contentsOf: [1, 1])
        body.append(Data(repeating: 9, count: 48))
        body.append(1)
        body.append(contentsOf: UInt64(1_147).bigEndianBytes)
        body.append(1)
        body.append(Data(repeating: 3, count: 48))
        body.append(contentsOf: [1, 5])
        let receipt = try WalletRPCCodec.decodeFaucetReceipt(rpcResponse(body: body))
        XCTAssertEqual(receipt.state, 1)
        XCTAssertEqual(receipt.finalizedHeight, 1_147)
        XCTAssertTrue(
            WalletFundingState.finalized(reference: "07", height: 1_147).creditsBalance,
            "a finalized grant is the one funding state that may credit a balance"
        )
    }

    private func rpcResponse(body: Data) -> Data {
        var envelope = Data([0x01, 0x0a, 0, 3])
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

    private func sharedCanonicalApproval() throws -> CanonicalCashApproval {
        var directory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        while directory.path != "/" {
            let candidate = directory.appendingPathComponent(
                "testing/vectors/wallet-canonical-approval-v1.txt"
            )
            if FileManager.default.fileExists(atPath: candidate.path) {
                let contents = try String(contentsOf: candidate, encoding: .utf8)
                let requestLine = try XCTUnwrap(contents.split(separator: "\n")
                    .first { $0.hasPrefix("request_hex=") })
                let request = try XCTUnwrap(Data(strictHex: String(requestLine.dropFirst(12))))
                return try RustCanonicalApproval.review(request)
            }
            directory.deleteLastPathComponent()
        }
        throw CanonicalApprovalError.malformed
    }
}

private extension Data {
    init?(strictHex: String) {
        guard strictHex.count.isMultiple(of: 2),
              strictHex.allSatisfy({ $0.isNumber || $0 >= "a" && $0 <= "f" }) else { return nil }
        self.init()
        reserveCapacity(strictHex.count / 2)
        var index = strictHex.startIndex
        while index < strictHex.endIndex {
            let next = strictHex.index(index, offsetBy: 2)
            guard let byte = UInt8(strictHex[index..<next], radix: 16) else { return nil }
            append(byte)
            index = next
        }
    }
}

private final class AppleCustodyFixture {
    let store = AppleMemoryCustodyStore()
    let hardware = AppleFakeHardwareWrapping()
    lazy var provider = AppleNativeCustodyProvider(
        store: store,
        hardware: hardware,
        engine: AppleFakeMLDSA44Engine()
    )
}

private final class AppleMemoryCustodyStore: AppleCustodyRecordStore {
    private var records: [String: Data] = [:]
    var failNextSave = false

    func loadCustodyRecord(slotID: String) throws -> Data? { records[slotID] }

    func saveCustodyRecord(_ data: Data, slotID: String) throws {
        if failNextSave {
            failNextSave = false
            throw AppleCustodyError.storageFailure
        }
        records[slotID] = data
    }

    func deleteCustodyRecord(slotID: String) throws { records.removeValue(forKey: slotID) }
}

private final class AppleFakeHardwareWrapping: AppleHardwareWrapping {
    let capability = AppleCustodyCapability.secureEnclaveWrappedMLDSA44
    private(set) var tags: Set<Data> = []
    var substitutePlaintext: Data?
    var failure: AppleCustodyError?
    private(set) var unwrapCount = 0

    func createAndWrap(secret: Data, tag: Data) throws -> Data {
        tags.insert(tag)
        return Data(secret.map { $0 ^ 0x5a })
    }

    func unwrap(ciphertext: Data, tag: Data, reason: String) throws -> Data {
        unwrapCount += 1
        if let failure { throw failure }
        guard tags.contains(tag) else { throw AppleCustodyError.missingSlot }
        return substitutePlaintext ?? Data(ciphertext.map { $0 ^ 0x5a })
    }

    func deleteWrappingKey(tag: Data) throws { tags.remove(tag) }
}

private final class AppleFakeMLDSA44Engine: AppleMLDSA44Engine {
    private var next: UInt8 = 1

    func generateSeed() throws -> Data {
        defer { next &+= 1 }
        return Data(repeating: next, count: 32)
    }

    func publicKey(seed: inout Data) throws -> Data {
        Data((0..<1_312).map { seed[$0 % seed.count] ^ UInt8(truncatingIfNeeded: $0) })
    }

    func sign(payload: Data, seed: inout Data) throws -> Data {
        Data((0..<2_420).map {
            seed[$0 % seed.count] ^ payload[$0 % payload.count]
        })
    }
}

private extension FixedWidthInteger {
    var bigEndianBytes: [UInt8] {
        withUnsafeBytes(of: bigEndian) { Array($0) }
    }
}

/// Stands in for the keychain. Custody stores an opaque record per slot, so an
/// in-memory dictionary is a faithful substitute.
private final class InMemoryCustodyStore: AppleCustodyRecordStore {
    private var records: [String: Data] = [:]

    func loadCustodyRecord(slotID: String) throws -> Data? { records[slotID] }
    func saveCustodyRecord(_ data: Data, slotID: String) throws { records[slotID] = data }
    func deleteCustodyRecord(slotID: String) throws { records[slotID] = nil }
}

/// Stands in for one device's Secure Enclave.
///
/// An enclave key cannot leave its device, which is exactly why recovery
/// re-wraps rather than copies. Each instance therefore holds its own wrapping
/// secret, so a record sealed by one instance is meaningless to another — the
/// property that makes this a real two-device test.
private final class InMemoryWrapping: AppleHardwareWrapping {
    let capability = AppleCustodyCapability.secureEnclaveWrappedMLDSA44
    private var keys: [Data: SymmetricKey] = [:]

    func createAndWrap(secret: Data, tag: Data) throws -> Data {
        let key = SymmetricKey(size: .bits256)
        keys[tag] = key
        return try AES.GCM.seal(secret, using: key).combined ?? Data()
    }

    func unwrap(ciphertext: Data, tag: Data, reason: String) throws -> Data {
        guard let key = keys[tag] else { throw AppleCustodyError.hardwareUnavailable }
        return try AES.GCM.open(try AES.GCM.SealedBox(combined: ciphertext), using: key)
    }

    func deleteWrappingKey(tag: Data) throws { keys[tag] = nil }
}
