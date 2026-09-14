import AppIntents
import CoreImage
import CoreImage.CIFilterBuiltins
import Foundation
import Security
import SwiftUI

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
        /// Exact native ACT amount in atomic units. Nil means an open-amount request.
        let amountAtomicUnits: String?
        let reference: Data
        let memo: String
        /// Finalized chain height after which a payer should reject this request.
        let expiresAtHeight: UInt64?
        let publicKey: Data

        func signingPayload() throws -> Data {
            guard version == WalletPaymentRequestV1.version,
                  chainID.count == 48,
                  genesis.count == 48,
                  recipient.count == 48,
                  reference.count == 48,
                  publicKey.count == AppleNativeCustodyProvider.publicKeyLength,
                  !chainID.allSatisfy({ $0 == 0 }),
                  !genesis.allSatisfy({ $0 == 0 }),
                  !recipient.allSatisfy({ $0 == 0 }),
                  !reference.allSatisfy({ $0 == 0 }),
                  memo.utf8.count <= 160,
                  expiresAtHeight != 0,
                  amountAtomicUnits.map(Self.validAtomicAmount) ?? true
            else { throw WalletPaymentRequestError.malformed }

            var data = WalletPaymentRequestV1.signingDomain
            data.append(version.bigEndianBytes)
            data.append(chainID)
            data.append(genesis)
            data.append(recipient)
            if let amountAtomicUnits {
                data.append(1)
                let amount = Data(amountAtomicUnits.utf8)
                data.append(UInt16(amount.count).bigEndianBytes)
                data.append(amount)
            } else {
                data.append(0)
            }
            data.append(reference)
            let memoBytes = Data(memo.utf8)
            data.append(UInt16(memoBytes.count).bigEndianBytes)
            data.append(memoBytes)
            if let expiresAtHeight {
                data.append(1)
                data.append(expiresAtHeight.bigEndianBytes)
            } else {
                data.append(0)
            }
            data.append(publicKey)
            return data
        }

        private static func validAtomicAmount(_ value: String) -> Bool {
            guard !value.isEmpty, value.count <= 39, value.first != "0" || value == "0" else {
                return false
            }
            return value != "0" && value.utf8.allSatisfy { $0 >= 48 && $0 <= 57 }
        }
    }

    let body: Body
    let signature: Data

    init(body: Body, signature: Data) throws {
        guard signature.count == AppleNativeCustodyProvider.signatureLength else {
            throw WalletPaymentRequestError.malformed
        }
        _ = try body.signingPayload()
        self.body = body
        self.signature = signature
    }

    var deepLink: URL {
        get throws {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let encoded = try encoder.encode(self).base64URLEncodedString()
            var components = URLComponents()
            components.scheme = Self.scheme
            components.host = Self.host
            components.queryItems = [URLQueryItem(name: "request", value: encoded)]
            guard let url = components.url else { throw WalletPaymentRequestError.malformed }
            return url
        }
    }

    static func decode(_ url: URL) throws -> Self {
        guard url.scheme?.lowercased() == scheme,
              url.host?.lowercased() == host,
              let value = URLComponents(url: url, resolvingAgainstBaseURL: false)?
                .queryItems?.first(where: { $0.name == "request" })?.value,
              let data = Data(base64URL: value) else {
            throw WalletPaymentRequestError.malformed
        }
        let request = try JSONDecoder().decode(Self.self, from: data)
        return try Self(body: request.body, signature: request.signature)
    }
}

enum WalletPaymentRequestError: Error, Equatable {
    case noWallet
    case malformed
    case wrongKey
    case amount
}

struct WalletPaymentRequestService {
    /// Creates and signs a request using the selected network's hardware-backed wallet key.
    /// User presence is required by the same Secure Enclave wrapping boundary used for payments.
    @MainActor
    func create(
        amountACT: String?,
        memo: String,
        expiresAtHeight: UInt64? = nil
    ) throws -> WalletPaymentRequestV1 {
        let network = WalletKanalen.current
        guard let profile = WalletDeviceProfileStore(network: network).load() else {
            throw WalletPaymentRequestError.noWallet
        }
        let amount = try amountACT.map(Self.atomicUnits)
        var reference = Data(count: 48)
        guard SecRandomCopyBytes(kSecRandomDefault, reference.count, &reference) == errSecSuccess,
              reference.contains(where: { $0 != 0 }) else {
            throw WalletPaymentRequestError.malformed
        }

        let custody = try AppleNativeCustodyProvider(
            store: SharedKeychain(),
            hardware: SecureEnclaveWrappingBackend()
        )
        let publicKey = try custody.publicKey(slotID: network.custodySlotID)
        var derived = Data(count: 48)
        let code = publicKey.withUnsafeBytes { key in
            derived.withUnsafeMutableBytes { output in
                activechain_wallet_principal_id(
                    key.bindMemory(to: UInt8.self).baseAddress,
                    UInt32(key.count),
                    output.bindMemory(to: UInt8.self).baseAddress,
                    UInt32(output.count)
                )
            }
        }
        guard code == ACTIVECHAIN_WALLET_OK, derived == profile.owner else {
            throw WalletPaymentRequestError.wrongKey
        }

        let body = WalletPaymentRequestV1.Body(
            version: WalletPaymentRequestV1.version,
            chainID: network.chainID,
            genesis: network.genesis,
            recipient: profile.owner,
            amountAtomicUnits: amount,
            reference: reference,
            memo: memo,
            expiresAtHeight: expiresAtHeight,
            publicKey: publicKey
        )
        let payload = try body.signingPayload()
        let signature = try custody.sign(
            slotID: network.custodySlotID,
            payload: payload,
            minimumVersion: 1,
            minimumFinalizedHeight: 0,
            reason: "Create an ActiveChain payment request"
        )
        return try WalletPaymentRequestV1(body: body, signature: signature)
    }

    /// Exact decimal ACT parser. No floating point enters a payment request.
    /// ACT has 18 atomic decimal places.
    static func atomicUnits(_ text: String) throws -> String {
        let value = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty, !value.hasPrefix("-"), !value.hasPrefix("+") else {
            throw WalletPaymentRequestError.amount
        }
        let pieces = value.split(separator: ".", omittingEmptySubsequences: false)
        guard pieces.count <= 2,
              let whole = pieces.first,
              !whole.isEmpty,
              whole.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else {
            throw WalletPaymentRequestError.amount
        }
        let fraction = pieces.count == 2 ? pieces[1] : Substring()
        guard fraction.count <= 18,
              fraction.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else {
            throw WalletPaymentRequestError.amount
        }
        let normalizedWhole = whole.drop(while: { $0 == "0" })
        let paddedFraction = String(fraction) + String(repeating: "0", count: 18 - fraction.count)
        var atomic = String(normalizedWhole.isEmpty ? "0" : normalizedWhole) + paddedFraction
        while atomic.first == "0" && atomic.count > 1 { atomic.removeFirst() }
        guard atomic != "0", atomic.count <= 39 else { throw WalletPaymentRequestError.amount }
        return atomic
    }
}

/// Siri/Shortcuts entry point. This makes payment requests usable without adding a parallel
/// signing path to the wallet UI; a later Wallet tab can call the exact same service.
struct RequestActiveChainPaymentIntent: AppIntent {
    static var title: LocalizedStringResource = "Request ActiveChain Payment"
    static var description = IntentDescription(
        "Create a signed payment request that another ActiveChain wallet can review and pay."
    )

    @Parameter(title: "Amount (ACT)") var amount: String
    @Parameter(title: "Memo") var memo: String?

    @MainActor
    func perform() async throws -> some IntentResult & ReturnsValue<String> & ProvidesDialog {
        let request = try WalletPaymentRequestService().create(
            amountACT: amount,
            memo: memo ?? ""
        )
        let link = try request.deepLink.absoluteString
        return .result(
            value: link,
            dialog: IntentDialog("Payment request created. Share the returned ActiveChain link with the payer.")
        )
    }
}

struct ActiveChainPaymentRequestShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(
            intent: RequestActiveChainPaymentIntent(),
            phrases: [
                "Request payment with \(.applicationName)",
                "Create a payment request in \(.applicationName)"
            ],
            shortTitle: "Request payment",
            systemImageName: "qrcode"
        )
    }
}

/// QR rendering shared by the wallet UI and share surfaces.
struct WalletPaymentRequestQRCode: View {
    let request: WalletPaymentRequestV1

    var body: some View {
        Group {
            if let image = try? Self.image(for: request) {
                Image(decorative: image, scale: 1)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
                    .accessibilityLabel("ActiveChain payment request QR code")
            } else {
                ContentUnavailableView("QR unavailable", systemImage: "qrcode")
            }
        }
    }

    private static func image(for request: WalletPaymentRequestV1) throws -> CGImage {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(try request.deepLink.absoluteString.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)),
              let cg = CIContext().createCGImage(output, from: output.extent) else {
            throw WalletPaymentRequestError.malformed
        }
        return cg
    }
}

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    init?(base64URL: String) {
        var value = base64URL
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        value += String(repeating: "=", count: (4 - value.count % 4) % 4)
        self.init(base64Encoded: value)
    }
}

private extension UInt16 {
    var bigEndianBytes: Data {
        var value = bigEndian
        return Data(bytes: &value, count: MemoryLayout<Self>.size)
    }
}
