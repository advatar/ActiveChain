import XCTest
import ActiveChainWallet
@testable import ActiveChainWalletApp

final class DemoMerchantTests: XCTestCase {
    private let owner = Data(repeating: 8, count: 48)
    private func coin(key: UInt8, amount: DemoAmount, owner: Data? = nil) -> WalletOwnerCoinRecord {
        let body = Data(repeating: 9, count: 48) + DemoMerchant.integer(UInt16(0)) + (owner ?? self.owner) + DemoMerchant.integer(amount.high) + DemoMerchant.integer(amount.low) + DemoMerchant.integer(UInt64(10))
        return WalletOwnerCoinRecord(key: Data(repeating: key, count: 48), finalizedHeight: 10,
            value: Data([1, 0x2d, 0, 1, 0xaa, 1]) + Data(repeating: key, count: 48) + body, proof: Data([1]), finality: Data([1]))
    }
    func testPriceAndFeeSelectionUseDistinctOwnedCellsAndExactNativeReview() throws {
        let first = coin(key: 2, amount: DemoAmount(high: 2, low: 13_106_511_852_580_896_768))
        let second = coin(key: 3, amount: DemoAmount(high: 2, low: 13_106_511_852_580_896_768))
        let page = WalletOwnerCoinPage(records: [first, second], next: nil)
        let review = try DemoMerchant.review(network: .kanalen, owner: owner, page: page, height: 20, nonce: 3)
        XCTAssertEqual(review.recipient, DemoMerchant.owner)
        XCTAssertEqual(review.amount, Unsigned128Words(high: 0, low: DemoMerchant.price))
        XCTAssertEqual(review.fee, Unsigned128Words(high: 0, low: DemoMerchant.fee))
        XCTAssertEqual(review.nonce, 3)
        XCTAssertEqual(try DemoMerchant.selectedInput(review), first.key)
        XCTAssertEqual(review.feeReserve, second.key)
        XCTAssertThrowsError(try DemoMerchant.review(network: .kanalen, owner: owner, page: WalletOwnerCoinPage(records: [first], next: nil), height: 20, nonce: 0))
        let foreign = coin(key: 4, amount: DemoAmount(high: 3, low: 0), owner: Data(repeating: 7, count: 48))
        XCTAssertThrowsError(try DemoMerchant.review(network: .kanalen, owner: owner, page: WalletOwnerCoinPage(records: [first, foreign], next: nil), height: 20, nonce: 0))
    }
    func testAmountsHandleBorrowAndInsufficientFundsWithoutFloatingPoint() throws {
        XCTAssertEqual(try DemoAmount(high: 1, low: 0).subtracting(1), DemoAmount(high: 0, low: UInt64.max))
        XCTAssertThrowsError(try DemoAmount(high: 0, low: 4).subtracting(5))
        XCTAssertEqual(try DemoAmount(high: 0, low: DemoMerchant.price).subtracting(DemoMerchant.price), DemoAmount(high: 0, low: 0))
    }
    func testVerifiedACTAmountsAreExactAndPartialPagesCannotClaimTotals() throws {
        let fifty = DemoAmount(high: 2, low: 13_106_511_852_580_896_768)
        let first = coin(key: 1, amount: fifty), second = coin(key: 2, amount: fifty)
        let total = try DemoAmount.total(in: WalletOwnerCoinPage(records: [first, second], next: nil))
        XCTAssertEqual(total.actText, "100 ACT")
        XCTAssertEqual(try total.subtracting(DemoMerchant.price).subtracting(DemoMerchant.fee).actText, "94.999 ACT")
        XCTAssertEqual(DemoAmount(high: 0, low: 1).actText, "0.000000000000000001 ACT")
        XCTAssertEqual(DemoAmount(high: 0, low: 0).actText, "0 ACT")
        XCTAssertEqual(DemoAmount(high: .max, low: .max).actText, "340282366920938463463.374607431768211455 ACT")
        XCTAssertThrowsError(try DemoAmount(high: .max, low: .max).adding(DemoAmount(high: 0, low: 1)))
        XCTAssertThrowsError(try DemoAmount.total(in: WalletOwnerCoinPage(records: [first], next: owner)))
        XCTAssertThrowsError(try DemoAmount.total(in: WalletOwnerCoinPage(records: [first, first], next: nil)))
    }
    func testCoinDecodingRejectsWrongTypeTruncationAndTrailingBytes() throws {
        let value = coin(key: 1, amount: DemoAmount(high: 0, low: 7)).value
        XCTAssertEqual(try DemoCoin(value: value).amount, DemoAmount(high: 0, low: 7))
        XCTAssertThrowsError(try DemoCoin(value: value.dropLast()))
        XCTAssertThrowsError(try DemoCoin(value: value + Data([0])))
        var altered = value; altered[1] = 0x84
        XCTAssertThrowsError(try DemoCoin(value: altered))
    }
    func testRPCRecordMatchesRustCanonicalEncoding() throws {
        // Produced by activechain_canonical_codec::encode_envelope(CoinCellRecord::new(
        // id=[7;48], CoinCell(origin=([9;48], 2), owner=[8;48], amount=50e18, height=20890))).
        // RPC values contain the record ID before the cell, without a nested cell envelope.
        let hex =
            "012d0001aa010707070707070707070707070707070707070707070707070707070707070707070707070707" +
            "0707070707070707070709090909090909090909090909090909090909090909090909090909090909090909" +
            "0909090909090909090909090909000208080808080808080808080808080808080808080808080808080808" +
            "08080808080808080808080808080808080808080000000000000002b5e3af16b1880000000000000000519a"
        let value = Data(stride(from: 0, to: hex.count, by: 2).map { offset in
            let start = hex.index(hex.startIndex, offsetBy: offset)
            return UInt8(hex[start..<hex.index(start, offsetBy: 2)], radix: 16)!
        })
        let cell = try DemoCoin(value: value)
        XCTAssertEqual(cell.id, Data(repeating: 7, count: 48))
        XCTAssertEqual(cell.origin, Data(repeating: 9, count: 48))
        XCTAssertEqual(cell.outputIndex, 2)
        XCTAssertEqual(cell.owner, owner)
        XCTAssertEqual(cell.amount.actText, "50 ACT")
        XCTAssertEqual(cell.creationHeight, 20890)
        let standalone = Data([0, 0x83, 0, 1, 122]) + value.suffix(122)
        XCTAssertThrowsError(try DemoCoin(value: standalone))
    }
    func testPendingJournalSurvivesRelaunchWithoutClaimingPayment() throws {
        let purchase = DemoPurchase(request: Data([1]), reference: owner, session: Data([2]), transfer: Data([3]), paymentChange: DemoAmount(high: 0, low: 4), feeChange: DemoAmount(high: 0, low: 5))
        let journal = DemoJournal(owner: owner, genesis: WalletNetwork.kanalen.genesis, enrollment: DemoEnrollment(bytes: Data([4]), reference: owner), purchase: purchase)
        let loaded = try JSONDecoder().decode(DemoJournal.self, from: JSONEncoder().encode(journal))
        XCTAssertEqual(loaded.purchase?.transfer, purchase.transfer)
        XCTAssertEqual(loaded.purchase?.session, purchase.session)
        XCTAssertEqual(loaded.nextNonce, 0)
        XCTAssertNil(try loaded.purchase?.verifiedPaidHeight(network: .kanalen, owner: owner))
    }
    func testForgedFinalityAndOutputProofsNeverShowPaid() throws {
        let evidence = DemoCashEvidence(ids: owner, finality: Data([1]))
        XCTAssertThrowsError(try evidence.verifiedHeight(reference: owner, network: .kanalen))
        XCTAssertThrowsError(try DemoCashEvidence(ids: owner + owner, finality: Data([1])).verifiedHeight(reference: owner, network: .kanalen))
        let record = coin(key: 1, amount: DemoAmount(high: 0, low: DemoMerchant.price), owner: DemoMerchant.owner)
        XCTAssertThrowsError(try DemoPurchase.verifyOutput(record, owner: DemoMerchant.owner, reference: Data(repeating: 9, count: 48), index: 0, amount: DemoAmount(high: 0, low: DemoMerchant.price), height: 10, network: .kanalen))
    }
    private func response(_ body: Data) -> Data {
        Data([1, 10, 0, 5]) + Data(WalletRPCCodec.uleb128(body.count)) + body
    }
    func testCashReceiptDistinguishesPendingUnknownAndFinalizedAndRejectsContradictions() throws {
        for state: UInt8 in [0, 3] {
            let receipt = try WalletRPCCodec.decodeCashReceipt(response(Data([11]) + owner + Data([state, 0, 0, 0, 0])))
            XCTAssertEqual(receipt.state, state); XCTAssertNil(receipt.height)
        }
        let finalized = Data([11]) + owner + Data([1, 1]) + owner + Data([1]) + DemoMerchant.integer(UInt64(40)) + Data([1]) + Data(repeating: 2, count: 48) + Data([0])
        XCTAssertEqual(try WalletRPCCodec.decodeCashReceipt(response(finalized)).height, 40)
        var substituted = finalized; substituted[51] ^= 1
        XCTAssertThrowsError(try WalletRPCCodec.decodeCashReceipt(response(substituted)))
        XCTAssertThrowsError(try WalletRPCCodec.decodeCashReceipt(response(finalized + Data([0]))))
        XCTAssertThrowsError(try WalletRPCCodec.decodeCashReceipt(response(Data([11]) + owner + Data([0, 1]) + owner + Data([0, 0, 0]))))
    }
}

private final class DemoTestStore: AppleCustodyRecordStore {
    var data: [String: Data] = [:]
    func loadCustodyRecord(slotID: String) throws -> Data? { data[slotID] }
    func saveCustodyRecord(_ value: Data, slotID: String) throws { data[slotID] = value }
    func deleteCustodyRecord(slotID: String) throws { data.removeValue(forKey: slotID) }
}
private final class DemoTestHardware: AppleHardwareWrapping {
    let capability = AppleCustodyCapability.secureEnclaveWrappedMLDSA44
    func createAndWrap(secret: Data, tag: Data) throws -> Data { secret }
    func unwrap(ciphertext: Data, tag: Data, reason: String) throws -> Data { ciphertext }
    func deleteWrappingKey(tag: Data) throws {}
}
extension DemoMerchantTests {
    func testProductionEnrollmentAndSessionTranscriptsCrossSwiftAndRust() throws {
        let provider = AppleNativeCustodyProvider(store: DemoTestStore(), hardware: DemoTestHardware())
        var recovery = Data(repeating: 61, count: 32)
        let publicKey = try provider.provision(slotID: "demo-test", keyVersion: 1, finalizedHeight: 10, recoveryKey: &recovery)
        defer { recovery.zeroize() }
        var owner = Data(count: 48)
        let code = publicKey.withUnsafeBytes { key in owner.withUnsafeMutableBytes { output in
            activechain_wallet_principal_id(key.bindMemory(to: UInt8.self).baseAddress, UInt32(publicKey.count), output.bindMemory(to: UInt8.self).baseAddress, 48)
        } }
        XCTAssertEqual(code, UInt32(ACTIVECHAIN_WALLET_OK))
        let (bytes, reference) = try DemoMerchant.enrollment(network: .kanalen, slot: "demo-test", height: 10, provider: provider)
        let enrollment = DemoEnrollment(bytes: bytes, reference: reference)
        XCTAssertNil(try enrollment.verifiedHeight(network: .kanalen, owner: owner))
        XCTAssertThrowsError(try enrollment.verifiedHeight(network: .kanalen, owner: Data(repeating: 7, count: 48)))
        let page = WalletOwnerCoinPage(records: [coin(key: 1, amount: DemoAmount(high: 1, low: 0), owner: owner), coin(key: 2, amount: DemoAmount(high: 1, low: 0), owner: owner)], next: nil)
        let approval = try DemoMerchant.review(network: .kanalen, owner: owner, page: page, height: 20, nonce: 0)
        let session = try DemoMerchant.signedSession(approval: approval, slot: "demo-test", height: 20, provider: provider)
        XCTAssertEqual(session.prefix(4), Data([0, 0x98, 0, 1]))
        let transfer = try CanonicalCashApprovalSession(approval: approval).sign(with: provider, slotID: "demo-test", minimumVersion: 1, minimumFinalizedHeight: 10)
        XCTAssertGreaterThan(transfer.count, 2420)
    }
}

extension DemoMerchantTests {
    func testDeviceKeychainPersistsTheBoundedProofJournal() throws {
        let keychain = try SharedKeychain()
        let service = "dev.activechain.demo-tests.\(UUID().uuidString)"
        defer { try? keychain.delete(service: service, account: "journal") }
        let proofJournal = Data(repeating: 0x52, count: 1_048_576)
        try keychain.save(proofJournal, service: service, account: "journal")
        XCTAssertEqual(try keychain.load(service: service, account: "journal"), proofJournal)
    }
}
