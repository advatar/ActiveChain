import Foundation

public struct WalletIntentPreview: Equatable {
    public let recipient: String
    public let amount: UInt64
    public let feeReserve: UInt64
    public let validUntil: UInt64
    public let policyAllowed: Bool
}

public protocol WalletBridge {
    func previewTransfer(recipient: String, amount: UInt64, feeReserve: UInt64,
                         validUntil: UInt64, currentHeight: UInt64) -> WalletIntentPreview
    func approveTransfer(_ preview: WalletIntentPreview) throws -> Data
}

public enum WalletError: Error { case policyDenied, expired }

/// Deterministic local shell used until the Rust FFI artifact is linked.
public final class LocalWalletBridge: WalletBridge {
    private let dailyLimit: UInt64
    public init(dailyLimit: UInt64 = 1_000) { self.dailyLimit = dailyLimit }

    public func previewTransfer(recipient: String, amount: UInt64, feeReserve: UInt64,
                                validUntil: UInt64, currentHeight: UInt64) -> WalletIntentPreview {
        WalletIntentPreview(recipient: recipient, amount: amount, feeReserve: feeReserve,
                            validUntil: validUntil,
                            policyAllowed: amount > 0 && amount <= dailyLimit && currentHeight <= validUntil)
    }

    public func approveTransfer(_ preview: WalletIntentPreview) throws -> Data {
        guard preview.policyAllowed else { throw WalletError.policyDenied }
        guard preview.amount > 0 else { throw WalletError.policyDenied }
        return Data("ACTIVECHAIN-LOCAL-INTENT-V1|\(preview.recipient)|\(preview.amount)|\(preview.feeReserve)|\(preview.validUntil)".utf8)
    }
}
