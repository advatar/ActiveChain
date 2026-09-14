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
}
