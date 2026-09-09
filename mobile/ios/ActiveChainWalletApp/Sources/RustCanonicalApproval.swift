import ActiveChainWallet
import Foundation

enum CanonicalApprovalError: Error, Equatable {
    case ffi(UInt32)
    case malformed
    case alreadyConsumed
    case substitutedReview
    case custody
    case identityRequired
    case identityExpired
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

    static func reviewProposal(_ intent: Data, finalizedHeight: UInt64) throws
        -> CanonicalMcpProposalApproval
    {
        guard !intent.isEmpty, intent.count <= UInt32.max else {
            throw CanonicalApprovalError.malformed
        }
        var raw = ActivechainWalletProposalApproval()
        let code = intent.withUnsafeBytes {
            activechain_wallet_proposal_approval(
                $0.bindMemory(to: UInt8.self).baseAddress, UInt32(intent.count),
                finalizedHeight, &raw
            )
        }
        guard code == ACTIVECHAIN_WALLET_OK else { throw CanonicalApprovalError.ffi(code) }
        guard let action = McpAction(rawValue: raw.action) else {
            throw CanonicalApprovalError.malformed
        }
        return CanonicalMcpProposalApproval(
            intent: intent,
            requestID: try identifier(raw.request_id, length: raw.request_id_len),
            chainID: try identifier(raw.chain_id, length: raw.chain_id_len),
            walletID: try identifier(raw.wallet_id, length: raw.wallet_id_len),
            requestNonce: try identifier(raw.request_nonce, length: raw.request_nonce_len),
            agentPrincipal: data(raw.agent_principal), capabilityID: data(raw.capability_id),
            resource: data(raw.resource), recipient: data(raw.recipient),
            replayDomain: data(raw.replay_domain),
            intentCommitment: data(raw.intent_commitment), proposalID: data(raw.proposal_id),
            action: action,
            amount: Unsigned128Words(high: raw.amount_high, low: raw.amount_low),
            maximumFee: Unsigned128Words(
                high: raw.maximum_fee_high, low: raw.maximum_fee_low
            ),
            expiresAtHeight: raw.expires_at_height
        )
    }

    private static func identifier<T>(_ tuple: T, length: UInt32) throws -> String {
        let bytes = withUnsafeBytes(of: tuple) { Data($0.prefix(Int(length))) }
        guard let value = String(data: bytes, encoding: .utf8), !value.isEmpty else {
            throw CanonicalApprovalError.malformed
        }
        return value
    }
}

final class CanonicalMcpProposalApprovalSession {
    private let approval: CanonicalMcpProposalApproval
    private let lock = NSLock()
    private var consumed = false
    private let identity: (verifier: CompositeIdentityApprovalVerifier, challenge: CompositeIdentityChallenge)?

    init(approval: CanonicalMcpProposalApproval) {
        self.approval = approval
        identity = nil
    }

    private init(approval: CanonicalMcpProposalApproval, verifier: CompositeIdentityApprovalVerifier,
                 challenge: CompositeIdentityChallenge) {
        self.approval = approval
        identity = (verifier, challenge)
    }

    /// Application policy chooses this factory when composite identity is required. The
    /// challenge binds the actual Rust review; a reply cannot supply its own expected action.
    static func requiringIdentity(intent: Data, finalizedHeight: UInt64, audience: String,
                                  verifier: CompositeIdentityApprovalVerifier) async throws -> CanonicalMcpProposalApprovalSession {
        let approval = try RustCanonicalApproval.reviewProposal(intent, finalizedHeight: finalizedHeight)
        let challenge = try await verifier.issue(for: approval, audience: audience,
                                                  finalizedHeight: finalizedHeight, now: unixSeconds())
        return CanonicalMcpProposalApprovalSession(approval: approval, verifier: verifier, challenge: challenge)
    }

    var identityChallenge: CompositeIdentityChallenge? { identity?.challenge }

    func sign(
        with custody: AppleNativeCustodyProvider, slotID: String, minimumVersion: UInt32,
        finalizedHeight: UInt64
    ) throws -> Data {
        guard identity == nil else { throw CanonicalApprovalError.identityRequired }
        return try signNative(with: custody, slotID: slotID, minimumVersion: minimumVersion,
                              finalizedHeight: finalizedHeight)
    }

    func sign(with custody: AppleNativeCustodyProvider, slotID: String, minimumVersion: UInt32,
              finalizedHeight: UInt64, identityProof: Data) async throws -> Data {
        guard let identity else { throw CanonicalApprovalError.identityRequired }
        guard try RustCanonicalApproval.reviewProposal(approval.intent, finalizedHeight: finalizedHeight) == approval else {
            throw CanonicalApprovalError.substitutedReview
        }
        let started = try Self.unixSeconds()
        let verified = try await identity.verifier.verifyAndConsume(identityProof, challenge: identity.challenge.nonce,
                                                                    approval: approval, finalizedHeight: finalizedHeight, now: started)
        guard try Self.unixSeconds() < verified.validUntil else { throw CanonicalApprovalError.identityExpired }
        let signed = try signNative(with: custody, slotID: slotID, minimumVersion: minimumVersion,
                                    finalizedHeight: finalizedHeight)
        let completed = try Self.unixSeconds()
        guard completed >= started, completed < verified.validUntil else { throw CanonicalApprovalError.identityExpired }
        return signed
    }

    private static func unixSeconds() throws -> UInt64 {
        let time = Date().timeIntervalSince1970
        guard time >= 0, time < Double(UInt64.max) else { throw CanonicalApprovalError.identityExpired }
        return UInt64(time)
    }

    private func signNative(with custody: AppleNativeCustodyProvider, slotID: String, minimumVersion: UInt32,
                            finalizedHeight: UInt64) throws -> Data {
        guard try RustCanonicalApproval.reviewProposal(
            approval.intent, finalizedHeight: finalizedHeight
        ) == approval else { throw CanonicalApprovalError.substitutedReview }
        lock.lock()
        guard !consumed else { lock.unlock(); throw CanonicalApprovalError.alreadyConsumed }
        consumed = true
        lock.unlock()

        let publicKey = try custody.publicKey(slotID: slotID)
        let context = AppleCanonicalSigningContext(
            custody: custody, slotID: slotID, minimumVersion: minimumVersion,
            minimumFinalizedHeight: finalizedHeight,
            reason: "Approve reviewed MCP \(approval.action) from \(approval.agentPrincipal.hex)"
        )
        var required: UInt32 = 0
        let query = invokeSign(
            context: context, publicKey: publicKey, height: finalizedHeight,
            output: nil, capacity: 0, required: &required
        )
        guard query == ACTIVECHAIN_WALLET_BUFFER_TOO_SMALL, required > 0 else {
            throw CanonicalApprovalError.ffi(query)
        }
        var output = Data(repeating: 0, count: Int(required))
        let code = output.withUnsafeMutableBytes {
            invokeSign(
                context: context, publicKey: publicKey, height: finalizedHeight,
                output: $0.bindMemory(to: UInt8.self).baseAddress,
                capacity: required, required: &required
            )
        }
        if let error = context.error { throw error }
        guard code == ACTIVECHAIN_WALLET_OK else { throw CanonicalApprovalError.ffi(code) }
        return output
    }

    private func invokeSign(
        context: AppleCanonicalSigningContext, publicKey: Data, height: UInt64,
        output: UnsafeMutablePointer<UInt8>?, capacity: UInt32, required: inout UInt32
    ) -> UInt32 {
        approval.intent.withUnsafeBytes { intent in
            approval.intentCommitment.withUnsafeBytes { commitment in
                publicKey.withUnsafeBytes { key in
                    activechain_wallet_sign_proposal_intent(
                        intent.bindMemory(to: UInt8.self).baseAddress,
                        UInt32(approval.intent.count), height,
                        commitment.bindMemory(to: UInt8.self).baseAddress,
                        key.bindMemory(to: UInt8.self).baseAddress,
                        appleCanonicalSignCallback, Unmanaged.passUnretained(context).toOpaque(),
                        output, capacity, &required
                    )
                }
            }
        }
    }
}

private extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
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
