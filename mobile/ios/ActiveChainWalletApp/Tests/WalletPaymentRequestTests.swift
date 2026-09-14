import ActiveChainWallet
import XCTest
@testable import ActiveChainWalletApp

final class WalletPaymentRequestTests: XCTestCase {
    func testExactACTParsingUsesNoFloatingPoint() throws {
        XCTAssertEqual(try WalletPaymentRequestService.atomicUnits("1"), "1000000000000000000")
        XCTAssertEqual(try WalletPaymentRequestService.atomicUnits("1.5"), "1500000000000000000")
        XCTAssertEqual(try WalletPaymentRequestService.atomicUnits("0.000000000000000001"), "1")
        XCTAssertEqual(try WalletPaymentRequestService.atomicUnits("001.2300"), "1230000000000000000")
        XCTAssertThrowsError(try WalletPaymentRequestService.atomicUnits("0"))
        XCTAssertThrowsError(try WalletPaymentRequestService.atomicUnits("-1"))
        XCTAssertThrowsError(try WalletPaymentRequestService.atomicUnits("1.0000000000000000001"))
    }

    func testDeepLinkRoundTripsSignedEnvelopeBytes() throws {
        let body = WalletPaymentRequestV1.Body(
            version: WalletPaymentRequestV1.version,
            chainID: Data(repeating: 1, count: 48),
            genesis: Data(repeating: 2, count: 48),
            recipient: Data(repeating: 3, count: 48),
            amountAtomicUnits: "2500000000000000000",
            reference: Data(repeating: 4, count: 48),
            memo: "Dinner",
            expiresAtHeight: 42,
            publicKey: Data(repeating: 5, count: AppleNativeCustodyProvider.publicKeyLength)
        )
        let request = try WalletPaymentRequestV1(
            body: body,
            signature: Data(repeating: 6, count: AppleNativeCustodyProvider.signatureLength)
        )
        let decoded = try WalletPaymentRequestV1.decode(request.deepLink)
        XCTAssertEqual(decoded, request)
        XCTAssertEqual(decoded.body.memo, "Dinner")
        XCTAssertEqual(decoded.body.expiresAtHeight, 42)
    }

    func testSigningPayloadBindsEveryHumanVisibleField() throws {
        let base = WalletPaymentRequestV1.Body(
            version: WalletPaymentRequestV1.version,
            chainID: Data(repeating: 1, count: 48),
            genesis: Data(repeating: 2, count: 48),
            recipient: Data(repeating: 3, count: 48),
            amountAtomicUnits: "1",
            reference: Data(repeating: 4, count: 48),
            memo: "A",
            expiresAtHeight: 10,
            publicKey: Data(repeating: 5, count: AppleNativeCustodyProvider.publicKeyLength)
        )
        let original = try base.signingPayload()
        let memoChanged = WalletPaymentRequestV1.Body(
            version: base.version,
            chainID: base.chainID,
            genesis: base.genesis,
            recipient: base.recipient,
            amountAtomicUnits: base.amountAtomicUnits,
            reference: base.reference,
            memo: "B",
            expiresAtHeight: base.expiresAtHeight,
            publicKey: base.publicKey
        )
        XCTAssertNotEqual(try memoChanged.signingPayload(), original)

        let amountChanged = WalletPaymentRequestV1.Body(
            version: base.version,
            chainID: base.chainID,
            genesis: base.genesis,
            recipient: base.recipient,
            amountAtomicUnits: "2",
            reference: base.reference,
            memo: base.memo,
            expiresAtHeight: base.expiresAtHeight,
            publicKey: base.publicKey
        )
        XCTAssertNotEqual(try amountChanged.signingPayload(), original)
    }

    func testOpenAmountRequestIsRepresentable() throws {
        let body = WalletPaymentRequestV1.Body(
            version: WalletPaymentRequestV1.version,
            chainID: Data(repeating: 1, count: 48),
            genesis: Data(repeating: 2, count: 48),
            recipient: Data(repeating: 3, count: 48),
            amountAtomicUnits: nil,
            reference: Data(repeating: 4, count: 48),
            memo: "Tip",
            expiresAtHeight: nil,
            publicKey: Data(repeating: 5, count: AppleNativeCustodyProvider.publicKeyLength)
        )
        XCTAssertFalse(try body.signingPayload().isEmpty)
    }

    func testReceiverVerifiesSignatureRecipientAndSessionCorrelation() throws {
        let request = try signedFixture(network: .kanalen, expiresAtHeight: 50)
        let verified = try WalletPaymentRequestService.verify(
            request,
            network: .kanalen,
            finalizedHeight: 20
        )
        XCTAssertEqual(verified.recipient, request.body.recipient)
        XCTAssertEqual(verified.reference, request.body.reference)
        XCTAssertEqual(verified.cashSessionID, request.body.reference)
        XCTAssertEqual(verified.amountAtomicUnits, "2500000000000000000")
    }

    func testReceiverRejectsTamperingWrongNetworkAndExpiry() throws {
        let request = try signedFixture(network: .kanalen, expiresAtHeight: 50)

        var signature = request.signature
        signature[100] ^= 1
        let tampered = try WalletPaymentRequestV1(body: request.body, signature: signature)
        XCTAssertThrowsError(
            try WalletPaymentRequestService.verify(tampered, network: .kanalen, finalizedHeight: 20)
        ) { error in
            XCTAssertEqual(error as? WalletPaymentRequestError, .invalidSignature)
        }

        let wrongGenesisBody = WalletPaymentRequestV1.Body(
            version: request.body.version,
            chainID: request.body.chainID,
            genesis: Data(repeating: 0xEE, count: 48),
            recipient: request.body.recipient,
            amountAtomicUnits: request.body.amountAtomicUnits,
            reference: request.body.reference,
            memo: request.body.memo,
            expiresAtHeight: request.body.expiresAtHeight,
            publicKey: request.body.publicKey
        )
        let wrongGenesis = try WalletPaymentRequestV1(body: wrongGenesisBody, signature: request.signature)
        XCTAssertThrowsError(
            try WalletPaymentRequestService.verify(wrongGenesis, network: .kanalen, finalizedHeight: 20)
        ) { error in
            XCTAssertEqual(error as? WalletPaymentRequestError, .wrongNetwork)
        }

        XCTAssertThrowsError(
            try WalletPaymentRequestService.verify(request, network: .kanalen, finalizedHeight: 51)
        ) { error in
            XCTAssertEqual(error as? WalletPaymentRequestError, .expired)
        }
    }

    func testReceiverRejectsRecipientNotDerivedFromSignedKey() throws {
        let request = try signedFixture(network: .kanalen, expiresAtHeight: 50)
        let mismatchedBody = WalletPaymentRequestV1.Body(
            version: request.body.version,
            chainID: request.body.chainID,
            genesis: request.body.genesis,
            recipient: Data(repeating: 0xA5, count: 48),
            amountAtomicUnits: request.body.amountAtomicUnits,
            reference: request.body.reference,
            memo: request.body.memo,
            expiresAtHeight: request.body.expiresAtHeight,
            publicKey: request.body.publicKey
        )
        let mismatched = try WalletPaymentRequestV1(body: mismatchedBody, signature: request.signature)
        XCTAssertThrowsError(
            try WalletPaymentRequestService.verify(mismatched, network: .kanalen, finalizedHeight: 20)
        ) { error in
            XCTAssertEqual(error as? WalletPaymentRequestError, .recipientKeyMismatch)
        }
    }

    private func signedFixture(
        network: WalletNetwork,
        expiresAtHeight: UInt64
    ) throws -> WalletPaymentRequestV1 {
        let seed = Data(repeating: 42, count: AppleNativeCustodyProvider.seedLength)
        var publicKey = Data(count: AppleNativeCustodyProvider.publicKeyLength)
        let keyCode = seed.withUnsafeBytes { seedBytes in
            publicKey.withUnsafeMutableBytes { output in
                activechain_wallet_mldsa44_public_key(
                    seedBytes.bindMemory(to: UInt8.self).baseAddress,
                    UInt32(seedBytes.count),
                    output.bindMemory(to: UInt8.self).baseAddress,
                    UInt32(output.count)
                )
            }
        }
        XCTAssertEqual(keyCode, ACTIVECHAIN_WALLET_OK)

        var recipient = Data(count: 48)
        let principalCode = publicKey.withUnsafeBytes { key in
            recipient.withUnsafeMutableBytes { output in
                activechain_wallet_principal_id(
                    key.bindMemory(to: UInt8.self).baseAddress,
                    UInt32(key.count),
                    output.bindMemory(to: UInt8.self).baseAddress,
                    UInt32(output.count)
                )
            }
        }
        XCTAssertEqual(principalCode, ACTIVECHAIN_WALLET_OK)

        let body = WalletPaymentRequestV1.Body(
            version: WalletPaymentRequestV1.version,
            chainID: network.chainID,
            genesis: network.genesis,
            recipient: recipient,
            amountAtomicUnits: "2500000000000000000",
            reference: Data(repeating: 17, count: 48),
            memo: "Dinner",
            expiresAtHeight: expiresAtHeight,
            publicKey: publicKey
        )
        let payload = try body.signingPayload()
        var signature = Data(count: AppleNativeCustodyProvider.signatureLength)
        let signCode = seed.withUnsafeBytes { seedBytes in
            payload.withUnsafeBytes { payloadBytes in
                signature.withUnsafeMutableBytes { output in
                    activechain_wallet_mldsa44_sign(
                        seedBytes.bindMemory(to: UInt8.self).baseAddress,
                        UInt32(seedBytes.count),
                        payloadBytes.bindMemory(to: UInt8.self).baseAddress,
                        UInt32(payloadBytes.count),
                        output.bindMemory(to: UInt8.self).baseAddress,
                        UInt32(output.count)
                    )
                }
            }
        }
        XCTAssertEqual(signCode, ACTIVECHAIN_WALLET_OK)
        return try WalletPaymentRequestV1(body: body, signature: signature)
    }
}
