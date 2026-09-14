import ActiveChainWallet
import AppIntents
import CoreImage
import CoreImage.CIFilterBuiltins
import Foundation
import Security
import SwiftUI

@_silgen_name("activechain_wallet_mldsa44_verify")
private func activechain_wallet_mldsa44_verify_ffi(
    _ publicKey: UnsafePointer<UInt8>?,
    _ publicKeyLen: UInt32,
    _ payload: UnsafePointer<UInt8>?,
    _ payloadLen: UInt32,
    _ signature: UnsafePointer<UInt8>?,
    _ signatureLen: UInt32
) -> UInt32

/// A signed, non-authoritative request for a payment.
///
/// This object can ask for funds but can never move them. The payer must still
/// construct, review and authorize an ordinary ActiveChain cash transfer.
struct WalletPaymentRequestV1: Codable, Equatable, Sendable {
    static let scheme = "activechain"
    static let host = "pay"
    static let version: UInt16 = 1
    static let signingDomain = Data("ACTIVECHAIN-WALLET-PAYMENT-REQUEST-V1".utf8)

    struct Body: Codable, Equatable, Sendable {
        let version: UInt16
        let chainID: Data
        let genesis: Data
        let recipient: Data
        let amountAtomicUnits: String?
        let reference: Data
        let memo: String
        let expiresAtHeight: UInt64?
        let publicKey: Data

        func signingPayload() throws -> Data {
            guard version == WalletPaymentRequestV1.version,
                  chainID.count == 48, genesis.count == 48, recipient.count == 48,
                  reference.count == 48,
                  publicKey.count == AppleNativeCustodyProvider.publicKeyLength,
                  !chainID.allSatisfy({ $0 == 0 }), !genesis.allSatisfy({ $0 == 0 }),
                  !recipient.allSatisfy({ $0 == 0 }), !reference.allSatisfy({ $0 == 0 }),
                  memo.utf8.count <= 160, expiresAtHeight != .some(0),
                  amountAtomicUnits.map(Self.validAtomicAmount) ?? true else {
                throw WalletPaymentRequestError.malformed
            }
            var data = WalletPaymentRequestV1.signingDomain
            data.append(version.bigEndianData); data.append(chainID); data.append(genesis); data.append(recipient)
            if let amountAtomicUnits {
                data.append(1); let amount = Data(amountAtomicUnits.utf8)
                data.append(UInt16(amount.count).bigEndianData); data.append(amount)
            } else { data.append(0) }
            data.append(reference)
            let memoBytes = Data(memo.utf8); data.append(UInt16(memoBytes.count).bigEndianData); data.append(memoBytes)
            if let expiresAtHeight { data.append(1); data.append(expiresAtHeight.bigEndianData) } else { data.append(0) }
            data.append(publicKey)
            return data
        }

        private static func validAtomicAmount(_ value: String) -> Bool {
            guard !value.isEmpty, value.count <= 39, value.first != "0" || value == "0" else { return false }
            return value != "0" && value.utf8.allSatisfy { $0 >= 48 && $0 <= 57 }
        }
    }

    let body: Body
    let signature: Data

    init(body: Body, signature: Data) throws {
        guard signature.count == AppleNativeCustodyProvider.signatureLength else { throw WalletPaymentRequestError.malformed }
        _ = try body.signingPayload(); self.body = body; self.signature = signature
    }

    var deepLink: URL {
        get throws {
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
            let encoded = try encoder.encode(self).base64URLEncodedString()
            var components = URLComponents(); components.scheme = Self.scheme; components.host = Self.host
            components.queryItems = [URLQueryItem(name: "request", value: encoded)]
            guard let url = components.url else { throw WalletPaymentRequestError.malformed }
            return url
        }
    }

    static func decode(_ url: URL) throws -> Self {
        guard url.scheme?.lowercased() == scheme, url.host?.lowercased() == host,
              let value = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "request" })?.value,
              let data = Data(base64URL: value) else { throw WalletPaymentRequestError.malformed }
        let request = try JSONDecoder().decode(Self.self, from: data)
        return try Self(body: request.body, signature: request.signature)
    }
}

struct VerifiedWalletPaymentRequest: Equatable, Sendable {
    let request: WalletPaymentRequestV1
    let cashSessionID: Data
    var recipient: Data { request.body.recipient }
    var amountAtomicUnits: String? { request.body.amountAtomicUnits }
    var memo: String { request.body.memo }
    var reference: Data { request.body.reference }
}

enum WalletPaymentRequestError: Error, Equatable {
    case noWallet, malformed, wrongKey, amount, wrongNetwork, expired, invalidSignature, recipientKeyMismatch
}

struct WalletPaymentRequestService {
    @MainActor
    func create(amountACT: String?, memo: String, expiresAtHeight: UInt64? = nil) throws -> WalletPaymentRequestV1 {
        let network = WalletKanalen.current
        guard let profile = WalletDeviceProfileStore(network: network).load() else { throw WalletPaymentRequestError.noWallet }
        let amount = try amountACT.map(Self.atomicUnits)
        var reference = Data(count: 48)
        let randomStatus = reference.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
        guard randomStatus == errSecSuccess, reference.contains(where: { $0 != 0 }) else { throw WalletPaymentRequestError.malformed }
        let custody = AppleNativeCustodyProvider(store: try SharedKeychain(), hardware: SecureEnclaveWrappingBackend())
        let publicKey = try custody.publicKey(slotID: network.custodySlotID)
        var derived = Data(count: 48)
        let code = publicKey.withUnsafeBytes { key in derived.withUnsafeMutableBytes { output in
            activechain_wallet_principal_id(key.bindMemory(to: UInt8.self).baseAddress, UInt32(key.count),
                                            output.bindMemory(to: UInt8.self).baseAddress, UInt32(output.count))
        } }
        guard code == ACTIVECHAIN_WALLET_OK, derived == profile.owner else { throw WalletPaymentRequestError.wrongKey }
        let body = WalletPaymentRequestV1.Body(version: WalletPaymentRequestV1.version, chainID: network.chainID,
            genesis: network.genesis, recipient: profile.owner, amountAtomicUnits: amount, reference: reference,
            memo: memo, expiresAtHeight: expiresAtHeight, publicKey: publicKey)
        let payload = try body.signingPayload()
        let signature = try custody.sign(slotID: network.custodySlotID, payload: payload, minimumVersion: 1,
                                         minimumFinalizedHeight: 0, reason: "Create an ActiveChain payment request")
        return try WalletPaymentRequestV1(body: body, signature: signature)
    }

    static func verify(_ request: WalletPaymentRequestV1, network: WalletNetwork,
                       finalizedHeight: UInt64) throws -> VerifiedWalletPaymentRequest {
        guard request.body.chainID == network.chainID, request.body.genesis == network.genesis else { throw WalletPaymentRequestError.wrongNetwork }
        if let expiresAtHeight = request.body.expiresAtHeight, finalizedHeight > expiresAtHeight { throw WalletPaymentRequestError.expired }
        var derivedRecipient = Data(count: 48)
        let principalCode = request.body.publicKey.withUnsafeBytes { key in derivedRecipient.withUnsafeMutableBytes { output in
            activechain_wallet_principal_id(key.bindMemory(to: UInt8.self).baseAddress, UInt32(key.count),
                                            output.bindMemory(to: UInt8.self).baseAddress, UInt32(output.count))
        } }
        guard principalCode == ACTIVECHAIN_WALLET_OK else { throw WalletPaymentRequestError.malformed }
        guard derivedRecipient == request.body.recipient else { throw WalletPaymentRequestError.recipientKeyMismatch }
        let payload = try request.body.signingPayload()
        let signatureCode = request.body.publicKey.withUnsafeBytes { key in payload.withUnsafeBytes { body in request.signature.withUnsafeBytes { signature in
            activechain_wallet_mldsa44_verify_ffi(key.bindMemory(to: UInt8.self).baseAddress, UInt32(key.count),
                body.bindMemory(to: UInt8.self).baseAddress, UInt32(body.count),
                signature.bindMemory(to: UInt8.self).baseAddress, UInt32(signature.count))
        } } }
        guard signatureCode == ACTIVECHAIN_WALLET_OK else { throw WalletPaymentRequestError.invalidSignature }
        return VerifiedWalletPaymentRequest(request: request, cashSessionID: request.body.reference)
    }

    static func verify(_ url: URL, network: WalletNetwork, finalizedHeight: UInt64) throws -> VerifiedWalletPaymentRequest {
        try verify(WalletPaymentRequestV1.decode(url), network: network, finalizedHeight: finalizedHeight)
    }

    static func atomicUnits(_ text: String) throws -> String {
        let value = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty, !value.hasPrefix("-"), !value.hasPrefix("+") else { throw WalletPaymentRequestError.amount }
        let pieces = value.split(separator: ".", omittingEmptySubsequences: false)
        guard pieces.count <= 2, let whole = pieces.first, !whole.isEmpty,
              whole.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else { throw WalletPaymentRequestError.amount }
        let fraction: Substring = pieces.count == 2 ? pieces[1] : Substring("")
        guard fraction.count <= 18, fraction.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else { throw WalletPaymentRequestError.amount }
        let normalizedWhole = whole.drop(while: { $0 == "0" })
        let wholeDigits = normalizedWhole.isEmpty ? "0" : String(normalizedWhole)
        let paddedFraction = String(fraction) + String(repeating: "0", count: 18 - fraction.count)
        var atomic = wholeDigits + paddedFraction
        while atomic.first == "0" && atomic.count > 1 { atomic.removeFirst() }
        guard atomic != "0", atomic.count <= 39 else { throw WalletPaymentRequestError.amount }
        return atomic
    }
}

struct RequestActiveChainPaymentIntent: AppIntent {
    static var title: LocalizedStringResource = "Request ActiveChain Payment"
    static var description = IntentDescription("Create a signed payment request that another ActiveChain wallet can review and pay.")
    @Parameter(title: "Amount (ACT)") var amount: String
    @Parameter(title: "Memo") var memo: String?
    @MainActor func perform() async throws -> some IntentResult & ReturnsValue<String> & ProvidesDialog {
        let request = try WalletPaymentRequestService().create(amountACT: amount, memo: memo ?? "")
        return .result(value: try request.deepLink.absoluteString,
                       dialog: IntentDialog("Payment request created. Share the returned ActiveChain link with the payer."))
    }
}

struct ActiveChainPaymentRequestShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(intent: RequestActiveChainPaymentIntent(),
                    phrases: ["Request payment with \(.applicationName)", "Create a payment request in \(.applicationName)"],
                    shortTitle: "Request payment", systemImageName: "qrcode")
    }
}

struct WalletPaymentRequestQRCode: View {
    let request: WalletPaymentRequestV1
    var body: some View {
        Group {
            if let image = try? Self.image(for: request) {
                Image(decorative: image, scale: 1).interpolation(.none).resizable().scaledToFit()
                    .accessibilityLabel("ActiveChain payment request QR code")
            } else { ContentUnavailableView("QR unavailable", systemImage: "qrcode") }
        }
    }
    private static func image(for request: WalletPaymentRequestV1) throws -> CGImage {
        let filter = CIFilter.qrCodeGenerator(); filter.message = Data(try request.deepLink.absoluteString.utf8); filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)),
              let cg = CIContext().createCGImage(output, from: output.extent) else { throw WalletPaymentRequestError.malformed }
        return cg
    }
}

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    init?(base64URL: String) {
        var value = base64URL.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        value += String(repeating: "=", count: (4 - value.count % 4) % 4); self.init(base64Encoded: value)
    }
}
private extension FixedWidthInteger {
    var bigEndianData: Data { var value = bigEndian; return Data(bytes: &value, count: MemoryLayout<Self>.size) }
}
