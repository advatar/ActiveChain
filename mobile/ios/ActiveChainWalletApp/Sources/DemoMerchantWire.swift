import ActiveChainWallet
import Foundation
import Security

struct DemoShopError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
    init(_ message: String) { self.message = message }
}

enum DemoMerchant {
    static let name = "Kanalen Coffee"
    static let price: UInt64 = 5_000_000_000_000_000_000
    static let fee: UInt64 = 1_000_000_000_000_000
    static let owner = Data(stride(from: 0, to: 96, by: 2).map { index in
        let bytes = Array("23cfa78e90c6566bc708752e2079a0c5f6ec030eff3b9e83a36ccee673aca3b7412de87592b6c34579803d1bd4480bae".utf8)
        return UInt8(String(decoding: bytes[index..<index + 2], as: UTF8.self), radix: 16)!
    })

    static func randomID() throws -> Data {
        var data = Data(count: 48)
        guard data.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 48, $0.baseAddress!) }) == errSecSuccess else { throw DemoShopError("Could not create a payment identifier.") }
        return data
    }
    static func integer<T: FixedWidthInteger>(_ value: T) -> Data {
        var value = value.bigEndian
        return withUnsafeBytes(of: &value) { Data($0) }
    }
    static func withPointers<T>(_ values: [Data], _ body: ([UnsafePointer<UInt8>]) throws -> T) rethrows -> T {
        func visit(_ index: Int, _ pointers: [UnsafePointer<UInt8>]) throws -> T {
            if index == values.count { return try body(pointers) }
            return try values[index].withUnsafeBytes { try visit(index + 1, pointers + [$0.bindMemory(to: UInt8.self).baseAddress!]) }
        }
        return try visit(0, [])
    }
    static func custody() throws -> AppleNativeCustodyProvider {
        AppleNativeCustodyProvider(store: try SharedKeychain(), hardware: SecureEnclaveWrappingBackend())
    }
    static func enrollment(network: WalletNetwork, slot: String, height: UInt64, provider: AppleNativeCustodyProvider? = nil) throws -> (Data, Data) {
        guard height > 0, height <= UInt64.max - 120 else { throw DemoShopError("Invalid enrollment height.") }
        let custody = try provider ?? Self.custody()
        let key = try custody.publicKey(slotID: slot)
        let payload = Data("ACTIVECHAIN-CASH-KEY-ENROLLMENT-ML-DSA-44-V1".utf8) + network.chainID + key + integer(height) + integer(height + 120)
        let signature = try custody.sign(slotID: slot, payload: payload, minimumVersion: 1, minimumFinalizedHeight: 0, reason: "Register this wallet key for testnet spending")
        var bytes = Data(count: 4096), reference = Data(count: 48), length: UInt32 = 0
        let code = withPointers([network.chainID, key, signature]) { p in
            bytes.withUnsafeMutableBytes { out in reference.withUnsafeMutableBytes { id in
                activechain_wallet_encode_key_enrollment(p[0], p[1], height, height + 120, p[2], out.bindMemory(to: UInt8.self).baseAddress, 4096, &length, id.bindMemory(to: UInt8.self).baseAddress)
            } }
        }
        guard code == ACTIVECHAIN_WALLET_OK else { throw DemoShopError("Native enrollment verification failed (\(code)).") }
        return (Data(bytes.prefix(Int(length))), reference)
    }
    static func review(network: WalletNetwork, owner: Data, page: WalletOwnerCoinPage, height: UInt64, nonce: UInt64) throws -> CanonicalCashApproval {
        guard network == .kanalen, owner != self.owner, height <= UInt64.max - 120 else { throw DemoShopError("The demo shop is available on Kanalen testnet.") }
        let coins = try page.records.map { ($0, try DemoCoin(value: $0.value)) }
        guard let input = coins.first(where: { $0.1.owner == owner && $0.1.amount.isAtLeast(price) }),
              let reserve = coins.first(where: { $0.0.key != input.0.key && $0.1.owner == owner && $0.1.amount.isAtLeast(fee) }) else { throw DemoShopError("The purchase needs a payment Coin Cell and a separate fee Coin Cell. Request faucet funding first.") }
        var bytes = Data(count: 4096), reference = Data(count: 48), length: UInt32 = 0
        let session = try randomID()
        let code = withPointers([network.chainID, owner, self.owner, input.0.key, reserve.0.key, session]) { p in
            bytes.withUnsafeMutableBytes { out in reference.withUnsafeMutableBytes { id in
                activechain_wallet_build_cash_intent(p[0], p[1], p[2], p[3], p[4], nonce, p[5], height + 120, 0, price, 0, fee, height + 120, out.bindMemory(to: UInt8.self).baseAddress, 4096, &length, id.bindMemory(to: UInt8.self).baseAddress)
            } }
        }
        guard code == ACTIVECHAIN_WALLET_OK else { throw DemoShopError("Could not construct the native payment (\(code)).") }
        return try RustCanonicalApproval.review(Data(bytes.prefix(Int(length))))
    }
    static func selectedInput(_ approval: CanonicalCashApproval) throws -> Data {
        guard try RustCanonicalApproval.review(approval.request) == approval else { throw DemoShopError("Payment review was substituted.") }
        var d = WalletBinaryDecoder(data: approval.request)
        _ = try d.read(count: 4)
        _ = try d.readULEB128(maximum: 262144)
        _ = try d.read(count: 48 + 48 + 8 + 48 + 8 + 48)
        guard try d.readUInt8() == 0 else { throw DemoShopError("Unexpected settlement reference.") }
        _ = try d.read(count: 96)
        guard try d.readULEB128(maximum: 16) == 1 else { throw DemoShopError("The demo requires a single payment input.") }
        return try d.read(count: 48)
    }
    static func signedSession(approval: CanonicalCashApproval, slot: String, height: UInt64, provider: AppleNativeCustodyProvider? = nil) throws -> Data {
        let custody = try provider ?? Self.custody()
        let key = try custody.publicKey(slotID: slot)
        // This transcript is checked by Rust against the exact reviewed request before export.
        let body = approval.chainID + approval.signer + approval.sessionID + integer(height) + integer(approval.sessionExpiresAt) + integer(UInt64(0)) + integer(price + fee)
        let grant = Data([0x00, 0x97, 0x00, 0x01]) + Data(WalletRPCCodec.uleb128(body.count)) + body
        let payload = Data("ACTIVECHAIN-CASH-SESSION-GRANT-ML-DSA-44-V1".utf8) + integer(UInt64(grant.count)) + grant
        let signature = try custody.sign(slotID: slot, payload: payload, minimumVersion: 1, minimumFinalizedHeight: 0, reason: "Authorize the reviewed demo purchase budget")
        var bytes = Data(count: 4096), length: UInt32 = 0
        let code = withPointers([approval.request, key, signature]) { p in bytes.withUnsafeMutableBytes { out in
            activechain_wallet_encode_cash_session(p[0], UInt32(approval.request.count), p[1], height, p[2], out.bindMemory(to: UInt8.self).baseAddress, 4096, &length)
        } }
        guard code == ACTIVECHAIN_WALLET_OK else { throw DemoShopError("The signed session did not match the reviewed purchase (\(code)).") }
        return Data(bytes.prefix(Int(length)))
    }
}

struct DemoAmount: Equatable, Codable {
    let high: UInt64
    let low: UInt64
    func adding(_ other: DemoAmount) throws -> DemoAmount {
        let (low, carry) = low.addingReportingOverflow(other.low)
        let (sum, overflow) = high.addingReportingOverflow(other.high)
        let (high, carryOverflow) = sum.addingReportingOverflow(carry ? 1 : 0)
        guard !overflow, !carryOverflow else { throw DemoShopError("Holdings exceed the native amount limit.") }
        return DemoAmount(high: high, low: low)
    }
    var actText: String {
        var high = high, low = low, digits = ""
        repeat {
            let division = UInt64(10).dividingFullWidth((high: high % 10, low: low))
            digits.append(String(division.remainder))
            high /= 10; low = division.quotient
        } while high != 0 || low != 0
        let decimal = String(digits.reversed())
        let padded = String(repeating: "0", count: max(0, 19 - decimal.count)) + decimal
        let split = padded.index(padded.endIndex, offsetBy: -18)
        var fraction = String(padded[split...])
        while fraction.last == "0" { fraction.removeLast() }
        return String(padded[..<split]) + (fraction.isEmpty ? "" : "." + fraction) + " ACT"
    }
    static func total(in page: WalletOwnerCoinPage) throws -> DemoAmount {
        guard page.next == nil, Set(page.records.map(\.key)).count == page.records.count else {
            throw DemoShopError("A partial or duplicate holdings page cannot supply a total.")
        }
        return try page.records.reduce(DemoAmount(high: 0, low: 0)) {
            try $0.adding(DemoCoin(value: $1.value).amount)
        }
    }
    func isAtLeast(_ value: UInt64) -> Bool { high > 0 || low >= value }
    func subtracting(_ value: UInt64) throws -> DemoAmount {
        guard isAtLeast(value) else { throw DemoShopError("Insufficient funds.") }
        let (low, borrow) = low.subtractingReportingOverflow(value)
        return DemoAmount(high: high - (borrow ? 1 : 0), low: low)
    }
}
struct DemoCoin: Equatable {
    let origin: Data
    let outputIndex: UInt16
    let owner: Data
    let amount: DemoAmount
    let creationHeight: UInt64
    init(value: Data) throws {
        var d = WalletBinaryDecoder(data: value)
        guard try d.readUInt16() == 0x0083, try d.readUInt16() == 1,
              try d.readULEB128(maximum: 122) == 122, d.remaining == 122 else { throw DemoShopError("Unsupported Coin Cell value.") }
        origin = try d.read(count: 48); outputIndex = try d.readUInt16(); owner = try d.read(count: 48)
        amount = try DemoAmount(high: d.readUInt64(), low: d.readUInt64()); creationHeight = try d.readUInt64()
    }
}

struct DemoCashReceipt: Equatable {
    let reference: Data
    let state: UInt8
    let height: UInt64?
}
struct DemoCashEvidence: Codable, Equatable {
    let ids: Data
    let finality: Data
    func verifiedHeight(reference: Data, network: WalletNetwork) throws -> UInt64 {
        guard reference.count == 48, !ids.isEmpty, ids.count <= 1536, ids.count % 48 == 0, !finality.isEmpty, finality.count <= 262144 else { throw DemoShopError("Malformed finality evidence.") }
        var height: UInt64 = 0
        let code = DemoMerchant.withPointers([network.chainID, network.genesis, reference, ids, finality]) { p in
            activechain_wallet_verify_cash_finality(p[0], p[1], p[2], p[3], UInt32(ids.count), p[4], UInt32(finality.count), &height)
        }
        guard code == ACTIVECHAIN_WALLET_OK, height > 0 else { throw DemoShopError("The native finality proof did not verify.") }
        return height
    }
}

extension WalletRPCCodec {
    static func decodeCashReceipt(_ data: Data) throws -> DemoCashReceipt {
        if let reason = serverError(data) { throw DemoShopError(reason) }
        var outer = WalletBinaryDecoder(data: data)
        guard try outer.readUInt16() == responseTypeTag, try outer.readUInt16() == responseSchemaRevision,
              try outer.readULEB128(maximum: maximumFrameLength) == outer.remaining else { throw WalletRPCError.malformedResponse }
        let variant = try outer.readUInt8()
        if variant == 12 { throw DemoShopError("The testnet refused this authorization (code \(try outer.readUInt8())).") }
        guard variant == 11 else { throw WalletRPCError.unexpectedResponse }
        let reference = try outer.read(count: 48), state = try outer.readUInt8()
        func optional(_ size: Int, _ decoder: inout WalletBinaryDecoder) throws -> Data? {
            switch try decoder.readUInt8() { case 0: return nil; case 1: return try decoder.read(count: size); default: throw WalletRPCError.malformedResponse }
        }
        let transaction = try optional(48, &outer), heightBytes = try optional(8, &outer), block = try optional(48, &outer)
        let rejection = try outer.readUInt8()
        if state == 2 {
            guard rejection == 1 else { throw WalletRPCError.malformedResponse }
            throw DemoShopError("The testnet rejected this action (code \(try outer.readUInt8())).")
        }
        guard rejection == 0, outer.remaining == 0, reference.contains(where: { $0 != 0 }) else { throw WalletRPCError.malformedResponse }
        if state == 1 {
            guard transaction == reference, let heightBytes, block?.contains(where: { $0 != 0 }) == true else { throw WalletRPCError.malformedResponse }
            return DemoCashReceipt(reference: reference, state: state, height: heightBytes.reduce(0) { ($0 << 8) | UInt64($1) })
        }
        guard state == 0 || state == 3, transaction == nil, heightBytes == nil, block == nil else { throw WalletRPCError.malformedResponse }
        return DemoCashReceipt(reference: reference, state: state, height: nil)
    }
    static func decodeCashEvidence(_ data: Data) throws -> DemoCashEvidence {
        var d = try responseBody(data, variant: 13)
        let count = try d.readULEB128(maximum: 32)
        guard count > 0 else { throw WalletRPCError.malformedResponse }
        let ids = try d.read(count: count * 48), finality = try d.readBlob(maximum: 262144)
        guard d.remaining == 0, !finality.isEmpty else { throw WalletRPCError.malformedResponse }
        return DemoCashEvidence(ids: ids, finality: finality)
    }
}
extension WalletRPCClient {
    func enrollKey(_ enrollment: Data) async throws -> DemoCashReceipt {
        guard !enrollment.isEmpty, enrollment.count <= 4096 else { throw WalletRPCError.malformedResponse }
        return try WalletRPCCodec.decodeCashReceipt(await roundTrip(WalletRPCCodec.framedRequest(body: Data([15]) + Data(WalletRPCCodec.uleb128(enrollment.count)) + enrollment)))
    }
    func submitPayment(session: Data, transfer: Data) async throws -> DemoCashReceipt {
        guard !session.isEmpty, session.count <= 24576, !transfer.isEmpty, transfer.count <= 24576 else { throw WalletRPCError.malformedResponse }
        let body = Data([13]) + Data(WalletRPCCodec.uleb128(session.count)) + session + Data(WalletRPCCodec.uleb128(transfer.count)) + transfer
        return try WalletRPCCodec.decodeCashReceipt(await roundTrip(WalletRPCCodec.framedRequest(body: body)))
    }
    func resolveCash(_ reference: Data) async throws -> DemoCashReceipt {
        guard reference.count == 48 else { throw WalletRPCError.malformedResponse }
        return try WalletRPCCodec.decodeCashReceipt(await roundTrip(WalletRPCCodec.framedRequest(body: Data([14]) + reference)))
    }
    func cashEvidence(_ reference: Data) async throws -> DemoCashEvidence {
        guard reference.count == 48 else { throw WalletRPCError.malformedResponse }
        return try WalletRPCCodec.decodeCashEvidence(await roundTrip(WalletRPCCodec.framedRequest(body: Data([16]) + reference)))
    }
}
