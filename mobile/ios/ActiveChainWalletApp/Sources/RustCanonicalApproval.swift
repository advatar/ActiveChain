import ActiveChainWallet
import Foundation

enum CanonicalApprovalError: Error, Equatable {
    case ffi(UInt32)
    case malformed
}

enum RustCanonicalApproval {
    static func review(_ request: Data) throws -> CanonicalCashApproval {
        guard !request.isEmpty, request.count <= UInt32.max else {
            throw CanonicalApprovalError.malformed
        }
        var raw = ActivechainWalletCashApproval()
        let code = request.withUnsafeBytes {
            activechain_wallet_cash_approval(
                $0.bindMemory(to: UInt8.self).baseAddress,
                UInt32(request.count),
                &raw
            )
        }
        guard code == ACTIVECHAIN_WALLET_OK else { throw CanonicalApprovalError.ffi(code) }
        let approval = CanonicalCashApproval(
            request: request,
            chainID: data(raw.chain_id),
            signer: data(raw.signer),
            recipient: data(raw.recipient),
            feeReserve: data(raw.fee_reserve),
            sessionID: data(raw.session_id),
            intentID: data(raw.intent_id),
            nonce: raw.nonce,
            sessionExpiresAt: raw.session_expires_at,
            amount: Unsigned128Words(high: raw.amount_high, low: raw.amount_low),
            fee: Unsigned128Words(high: raw.fee_high, low: raw.fee_low),
            validUntil: raw.valid_until,
            inputCount: raw.input_count
        )
        guard approval.intentID.count == 48, approval.inputCount > 0 else {
            throw CanonicalApprovalError.malformed
        }
        return approval
    }

    private static func data<T>(_ tuple: T) -> Data {
        withUnsafeBytes(of: tuple) { Data($0) }
    }
}
