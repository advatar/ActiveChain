import ActiveChainWallet
import Foundation

enum CanonicalApprovalError: Error, Equatable {
    case ffi(UInt32)
    case malformed
    case alreadyConsumed
    case substitutedReview
    case custody
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

final class CanonicalCashApprovalSession {
    private let approval: CanonicalCashApproval
    private let lock = NSLock()
    private var consumed = false

    init(approval: CanonicalCashApproval) {
        self.approval = approval
    }

    func sign(
        with custody: AppleNativeCustodyProvider,
        slotID: String,
        minimumVersion: UInt32,
        minimumFinalizedHeight: UInt64
    ) throws -> Data {
        guard try RustCanonicalApproval.review(approval.request) == approval else {
            throw CanonicalApprovalError.substitutedReview
        }
        lock.lock()
        guard !consumed else {
            lock.unlock()
            throw CanonicalApprovalError.alreadyConsumed
        }
        consumed = true
        lock.unlock()

        let publicKey = try custody.publicKey(slotID: slotID)
        let context = AppleCanonicalSigningContext(
            custody: custody,
            slotID: slotID,
            minimumVersion: minimumVersion,
            minimumFinalizedHeight: minimumFinalizedHeight,
            reason: "Approve the reviewed ActiveChain transfer"
        )
        var required: UInt32 = 0
        let query = invokeSign(context: context, publicKey: publicKey, output: nil, capacity: 0,
                               required: &required)
        guard query == ACTIVECHAIN_WALLET_BUFFER_TOO_SMALL, required > 0 else {
            throw CanonicalApprovalError.ffi(query)
        }
        var authorized = Data(repeating: 0, count: Int(required))
        let code = authorized.withUnsafeMutableBytes { output in
            invokeSign(
                context: context,
                publicKey: publicKey,
                output: output.bindMemory(to: UInt8.self).baseAddress,
                capacity: required,
                required: &required
            )
        }
        if let error = context.error { throw error }
        guard code == ACTIVECHAIN_WALLET_OK else { throw CanonicalApprovalError.ffi(code) }
        return authorized
    }

    private func invokeSign(
        context: AppleCanonicalSigningContext,
        publicKey: Data,
        output: UnsafeMutablePointer<UInt8>?,
        capacity: UInt32,
        required: inout UInt32
    ) -> UInt32 {
        approval.request.withUnsafeBytes { request in
            approval.intentID.withUnsafeBytes { intent in
                publicKey.withUnsafeBytes { key in
                    activechain_wallet_sign_cash_intent(
                        request.bindMemory(to: UInt8.self).baseAddress,
                        UInt32(approval.request.count),
                        intent.bindMemory(to: UInt8.self).baseAddress,
                        key.bindMemory(to: UInt8.self).baseAddress,
                        appleCanonicalSignCallback,
                        Unmanaged.passUnretained(context).toOpaque(),
                        output,
                        capacity,
                        &required
                    )
                }
            }
        }
    }
}

private final class AppleCanonicalSigningContext {
    let custody: AppleNativeCustodyProvider
    let slotID: String
    let minimumVersion: UInt32
    let minimumFinalizedHeight: UInt64
    let reason: String
    var error: Error?

    init(
        custody: AppleNativeCustodyProvider, slotID: String, minimumVersion: UInt32,
        minimumFinalizedHeight: UInt64, reason: String
    ) {
        self.custody = custody
        self.slotID = slotID
        self.minimumVersion = minimumVersion
        self.minimumFinalizedHeight = minimumFinalizedHeight
        self.reason = reason
    }
}

private let appleCanonicalSignCallback: @convention(c) (
    UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, UInt32, UnsafeMutablePointer<UInt8>?, UInt32
) -> UInt32 = { rawContext, payload, payloadLength, signature, signatureLength in
    guard let rawContext, let payload, let signature,
          signatureLength == UInt32(AppleNativeCustodyProvider.signatureLength) else { return 1 }
    let context = Unmanaged<AppleCanonicalSigningContext>.fromOpaque(rawContext).takeUnretainedValue()
    do {
        let signed = try context.custody.sign(
            slotID: context.slotID,
            payload: Data(bytes: payload, count: Int(payloadLength)),
            minimumVersion: context.minimumVersion,
            minimumFinalizedHeight: context.minimumFinalizedHeight,
            reason: context.reason
        )
        guard signed.count == Int(signatureLength) else { return 1 }
        signed.copyBytes(to: signature, count: signed.count)
        return 0
    } catch {
        context.error = error
        return 1
    }
}
