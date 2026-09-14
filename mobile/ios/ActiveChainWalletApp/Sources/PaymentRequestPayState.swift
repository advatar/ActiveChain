import ActiveChainWallet
import Foundation
import SwiftUI

struct WalletPaymentFlowError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

enum WalletCashLaneGuard {
    static let peerService = "dev.activechain.payment-request.v1"
    static let demoService = "dev.activechain.demo-merchant.v1"

    static func peerPaymentPending(network: WalletNetwork) -> Bool {
        guard let store = try? SharedKeychain(),
              let bytes = try? store.load(service: peerService, account: network.id),
              let decoded = try? JSONSerialization.jsonObject(with: bytes),
              let object = decoded as? [String: Any]
        else { return false }
        return object["pending"] != nil && !(object["pending"] is NSNull)
    }
}

private enum PaymentRequestFlow {
    static let fee: UInt64 = 1_000_000_000_000_000
    static let validityBlocks: UInt64 = 120
    static let journalService = WalletCashLaneGuard.peerService

    struct AmountWords: Equatable, Codable {
        let high: UInt64
        let low: UInt64

        init(atomic: String) throws {
            guard !atomic.isEmpty, atomic.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else {
                throw WalletPaymentFlowError("Invalid payment amount.")
            }
            var high: UInt64 = 0
            var low: UInt64 = 0
            for byte in atomic.utf8 {
                let product = low.multipliedFullWidth(by: 10)
                let (scaledHigh, overflow1) = high.multipliedReportingOverflow(by: 10)
                let (nextHigh, overflow2) = scaledHigh.addingReportingOverflow(product.high)
                let digit = UInt64(byte - 48)
                let (nextLow, carry) = product.low.addingReportingOverflow(digit)
                let (finalHigh, overflow3) = nextHigh.addingReportingOverflow(carry ? 1 : 0)
                guard !overflow1, !overflow2, !overflow3 else {
                    throw WalletPaymentFlowError("Payment amount exceeds the native amount limit.")
                }
                high = finalHigh
                low = nextLow
            }
            guard high != 0 || low != 0 else {
                throw WalletPaymentFlowError("Amount must be greater than zero.")
            }
            self.high = high
            self.low = low
        }

        var approvalWords: Unsigned128Words { Unsigned128Words(high: high, low: low) }
        var demoAmount: DemoAmount { DemoAmount(high: high, low: low) }
        func isCovered(by amount: DemoAmount) -> Bool {
            amount.high > high || (amount.high == high && amount.low >= low)
        }
    }

    struct Journal: Codable {
        let owner: Data
        let genesis: Data
        var enrollment: DemoEnrollment?
        var nextNonce: UInt64
        var pending: Pending?
    }

    struct Pending: Codable {
        let requestReference: Data
        let cashReference: Data
        let request: Data
        let session: Data
        let transfer: Data
        let recipient: Data
        let amount: AmountWords
        let outputOrigin: Data
    }

    static func load(wallet: WalletLiveState) throws -> Journal {
        guard let profile = wallet.deviceProfile, profile.chainGenesis == wallet.network.genesis else {
            throw WalletPaymentFlowError("Create a wallet on this network first.")
        }
        let store = try SharedKeychain()
        var journal: Journal
        if let bytes = try store.load(service: journalService, account: wallet.network.id) {
            guard bytes.count <= 1_048_576 else {
                throw WalletPaymentFlowError("Payment journal is too large.")
            }
            journal = try JSONDecoder().decode(Journal.self, from: bytes)
            guard journal.owner == profile.owner, journal.genesis == profile.chainGenesis else {
                throw WalletPaymentFlowError("Payment journal belongs to another wallet or chain.")
            }
        } else {
            journal = Journal(owner: profile.owner, genesis: profile.chainGenesis,
                              nextNonce: 0, pending: nil)
        }

        if let demoBytes = try store.load(service: WalletCashLaneGuard.demoService,
                                          account: wallet.network.id) {
            guard demoBytes.count <= 1_048_576 else {
                throw WalletPaymentFlowError("Legacy cash journal is too large.")
            }
            let demo = try JSONDecoder().decode(DemoJournal.self, from: demoBytes)
            guard demo.owner == profile.owner, demo.genesis == profile.chainGenesis else {
                throw WalletPaymentFlowError("Legacy cash journal belongs to another wallet or chain.")
            }
            if let purchase = demo.purchase,
               purchase.evidence == nil || purchase.merchantOutput == nil || purchase.customerOutputs == nil {
                throw WalletPaymentFlowError("Resolve the pending demo payment before starting another payment.")
            }
            journal.nextNonce = max(journal.nextNonce, demo.nextNonce)
            if journal.enrollment == nil { journal.enrollment = demo.enrollment }
        }
        return journal
    }

    static func save(_ journal: Journal, wallet: WalletLiveState) throws {
        guard wallet.deviceProfile?.owner == journal.owner, wallet.network.genesis == journal.genesis else {
            throw WalletPaymentFlowError("Wallet changed during payment.")
        }
        let store = try SharedKeychain()
        let bytes = try JSONEncoder().encode(journal)
        guard bytes.count <= 1_048_576 else {
            throw WalletPaymentFlowError("Payment journal is too large.")
        }
        try store.save(bytes, service: journalService, account: wallet.network.id)
        try mirrorCashLane(journal, store: store, wallet: wallet)
    }

    private static func mirrorCashLane(_ journal: Journal, store: SharedKeychain,
                                       wallet: WalletLiveState) throws {
        let existing = try store.load(service: WalletCashLaneGuard.demoService,
                                      account: wallet.network.id)
        var demo: DemoJournal
        if let existing {
            guard existing.count <= 1_048_576 else {
                throw WalletPaymentFlowError("Legacy cash journal is too large.")
            }
            demo = try JSONDecoder().decode(DemoJournal.self, from: existing)
            guard demo.owner == journal.owner, demo.genesis == journal.genesis else {
                throw WalletPaymentFlowError("Legacy cash journal belongs to another wallet or chain.")
            }
        } else {
            demo = DemoJournal(owner: journal.owner, genesis: journal.genesis)
        }
        demo.nextNonce = max(demo.nextNonce, journal.nextNonce)
        if demo.enrollment == nil { demo.enrollment = journal.enrollment }
        guard demo.revision < UInt64.max else {
            throw WalletPaymentFlowError("Cash journal revision exhausted.")
        }
        demo.revision += 1
        let encoded = try JSONEncoder().encode(demo)
        guard encoded.count <= 1_048_576 else {
            throw WalletPaymentFlowError("Legacy cash journal is too large.")
        }
        try store.save(encoded, service: WalletCashLaneGuard.demoService,
                       account: wallet.network.id)
    }

    static func custody() throws -> AppleNativeCustodyProvider {
        AppleNativeCustodyProvider(store: try SharedKeychain(),
                                   hardware: SecureEnclaveWrappingBackend())
    }

    static func buildApproval(verified: VerifiedWalletPaymentRequest, amount: AmountWords,
                              wallet: WalletLiveState, height: UInt64,
                              nonce: UInt64) throws -> CanonicalCashApproval {
        guard let page = wallet.verifiedOwnerPage, page.next == nil,
              let owner = wallet.deviceProfile?.owner else {
            throw WalletPaymentFlowError("Complete verified holdings are not available yet.")
        }
        let coins = try page.records.map { ($0, try DemoCoin(value: $0.value)) }
        guard let input = coins.first(where: {
            $0.1.owner == owner && amount.isCovered(by: $0.1.amount)
        }), let reserve = coins.first(where: {
            $0.0.key != input.0.key && $0.1.owner == owner && $0.1.amount.isAtLeast(fee)
        }) else {
            throw WalletPaymentFlowError(
                "This payment needs a value Coin Cell and a separate fee Coin Cell."
            )
        }
        guard height <= UInt64.max - validityBlocks else {
            throw WalletPaymentFlowError("Invalid finalized height.")
        }
        var bytes = Data(count: 4096)
        var reference = Data(count: 48)
        var length: UInt32 = 0
        let code = DemoMerchant.withPointers([
            wallet.network.chainID, owner, verified.recipient,
            input.0.key, reserve.0.key, verified.cashSessionID
        ]) { p in
            bytes.withUnsafeMutableBytes { out in
                reference.withUnsafeMutableBytes { id in
                    activechain_wallet_build_cash_intent(
                        p[0], p[1], p[2], p[3], p[4], nonce, p[5],
                        height + validityBlocks, 0,
                        amount.high, amount.low, 0, fee,
                        height + validityBlocks,
                        out.bindMemory(to: UInt8.self).baseAddress, 4096, &length,
                        id.bindMemory(to: UInt8.self).baseAddress
                    )
                }
            }
        }
        guard code == ACTIVECHAIN_WALLET_OK else {
            throw WalletPaymentFlowError(
                "Could not construct the canonical payment (\(code))."
            )
        }
        let approval = try RustCanonicalApproval.review(Data(bytes.prefix(Int(length))))
        guard approval.sessionID == verified.cashSessionID,
              approval.recipient == verified.recipient,
              approval.amount == amount.approvalWords else {
            throw WalletPaymentFlowError(
                "Canonical payment does not match the signed request."
            )
        }
        return approval
    }

    static func signedSession(approval: CanonicalCashApproval,
                              wallet: WalletLiveState,
                              height: UInt64) throws -> Data {
        let custody = try custody()
        let key = try custody.publicKey(slotID: wallet.primarySlotID)
        guard let budget = add128(approval.amount, approval.fee) else {
            throw WalletPaymentFlowError("Payment budget overflow.")
        }
        let body = approval.chainID + approval.signer + approval.sessionID
            + integer(height) + integer(approval.sessionExpiresAt)
            + integer(budget.high) + integer(budget.low)
        let grant = Data([0x00, 0x97, 0x00, 0x01])
            + Data(WalletRPCCodec.uleb128(body.count)) + body
        let payload = Data("ACTIVECHAIN-CASH-SESSION-GRANT-ML-DSA-44-V1".utf8)
            + integer(UInt64(grant.count)) + grant
        let signature = try custody.sign(
            slotID: wallet.primarySlotID, payload: payload,
            minimumVersion: 1, minimumFinalizedHeight: 0,
            reason: "Authorize this ActiveChain payment"
        )
        var output = Data(count: 4096)
        var length: UInt32 = 0
        let code = DemoMerchant.withPointers([approval.request, key, signature]) { p in
            output.withUnsafeMutableBytes { out in
                activechain_wallet_encode_cash_session(
                    p[0], UInt32(approval.request.count), p[1], height, p[2],
                    out.bindMemory(to: UInt8.self).baseAddress, 4096, &length
                )
            }
        }
        guard code == ACTIVECHAIN_WALLET_OK else {
            throw WalletPaymentFlowError(
                "Could not authorize the payment session (\(code))."
            )
        }
        return Data(output.prefix(Int(length)))
    }

    static func add128(_ lhs: Unsigned128Words,
                       _ rhs: Unsigned128Words) -> Unsigned128Words? {
        let (low, carry) = lhs.low.addingReportingOverflow(rhs.low)
        let (sum, overflow) = lhs.high.addingReportingOverflow(rhs.high)
        let (high, carryOverflow) = sum.addingReportingOverflow(carry ? 1 : 0)
        guard !overflow, !carryOverflow else { return nil }
        return Unsigned128Words(high: high, low: low)
    }

    static func integer<T: FixedWidthInteger>(_ value: T) -> Data {
        var value = value.bigEndian
        return withUnsafeBytes(of: &value) { Data($0) }
    }
}

@MainActor
final class PaymentRequestPayState: ObservableObject {
    enum Phase: Equatable {
        case review, preparing, authorizing, submitting, pending
        case paid(UInt64)
        case failed(String)
    }

    @Published private(set) var phase: Phase = .review
    @Published var openAmountACT = ""
    let verified: VerifiedWalletPaymentRequest
    private let rpc = WalletRPCClient()

    init(verified: VerifiedWalletPaymentRequest) { self.verified = verified }

    var amountDisplay: String {
        if let atomic = verified.amountAtomicUnits { return Self.actText(atomic) }
        return openAmountACT.isEmpty ? "Choose amount" : "\(openAmountACT) ACT"
    }

    var canPay: Bool {
        switch phase {
        case .review, .failed:
            return verified.amountAtomicUnits != nil || !openAmountACT.isEmpty
        default:
            return false
        }
    }

    func pay(wallet: WalletLiveState) async {
        guard canPay else { return }
        do {
            phase = .preparing
            await wallet.refresh()
            guard case let .healthy(height) = wallet.networkState else {
                throw WalletPaymentFlowError("The network is not healthy yet.")
            }
            let verifiedAgain = try WalletPaymentRequestService.verify(
                verified.request, network: wallet.network, finalizedHeight: height
            )
            let atomic = try verifiedAgain.amountAtomicUnits
                ?? WalletPaymentRequestService.atomicUnits(openAmountACT)
            let amount = try PaymentRequestFlow.AmountWords(atomic: atomic)
            var journal = try PaymentRequestFlow.load(wallet: wallet)
            try await ensureEnrollment(journal: &journal, wallet: wallet,
                                       height: height)
            if let pending = journal.pending {
                try await resolvePending(pending, journal: &journal, wallet: wallet)
                if journal.pending != nil { phase = .pending; return }
            }

            let status = try await rpc.status()
            guard case let .healthy(currentHeight) = status.networkState else {
                throw WalletPaymentFlowError(
                    "Network became unavailable before authorization."
                )
            }
            journal = try PaymentRequestFlow.load(wallet: wallet)
            let approval = try PaymentRequestFlow.buildApproval(
                verified: verifiedAgain, amount: amount, wallet: wallet,
                height: currentHeight, nonce: journal.nextNonce
            )
            phase = .authorizing
            let session = try PaymentRequestFlow.signedSession(
                approval: approval, wallet: wallet, height: currentHeight
            )
            let transfer = try CanonicalCashApprovalSession(approval: approval).sign(
                with: PaymentRequestFlow.custody(), slotID: wallet.primarySlotID,
                minimumVersion: 1, minimumFinalizedHeight: 0
            )
            let origin = try DemoMerchant.outputOrigin(request: approval.request)
            journal.pending = PaymentRequestFlow.Pending(
                requestReference: verifiedAgain.reference,
                cashReference: approval.intentID,
                request: approval.request,
                session: session,
                transfer: transfer,
                recipient: verifiedAgain.recipient,
                amount: amount,
                outputOrigin: origin
            )
            try PaymentRequestFlow.save(journal, wallet: wallet)
            phase = .submitting
            let receipt = try await rpc.submitPayment(session: session, transfer: transfer)
            guard receipt.reference == approval.intentID else {
                throw WalletPaymentFlowError("Payment submission reference mismatch.")
            }
            phase = .pending
            try await resolvePending(journal.pending!, journal: &journal,
                                     wallet: wallet)
        } catch {
            phase = .failed(error.localizedDescription)
        }
    }

    func refresh(wallet: WalletLiveState) async {
        do {
            var journal = try PaymentRequestFlow.load(wallet: wallet)
            guard let pending = journal.pending,
                  pending.requestReference == verified.reference else { return }
            phase = .pending
            try await resolvePending(pending, journal: &journal, wallet: wallet)
        } catch {
            phase = .failed(error.localizedDescription)
        }
    }

    private func ensureEnrollment(journal: inout PaymentRequestFlow.Journal,
                                  wallet: WalletLiveState,
                                  height: UInt64) async throws {
        if let enrollment = journal.enrollment,
           let enrolled = try enrollment.verifiedHeight(
               network: wallet.network, owner: journal.owner
           ), height > enrolled {
            return
        }
        if journal.enrollment == nil {
            let (bytes, reference) = try DemoMerchant.enrollment(
                network: wallet.network, slot: wallet.primarySlotID, height: height
            )
            journal.enrollment = DemoEnrollment(bytes: bytes, reference: reference)
            try PaymentRequestFlow.save(journal, wallet: wallet)
            let receipt = try await rpc.enrollKey(bytes)
            guard receipt.reference == reference else {
                throw WalletPaymentFlowError("Wallet setup submission mismatch.")
            }
        }
        guard var enrollment = journal.enrollment else { return }
        for _ in 0..<20 {
            let receipt = try await rpc.resolveCash(enrollment.reference)
            if receipt.state == 1 {
                let evidence = try await rpc.cashEvidence(enrollment.reference)
                let finalized = try evidence.verifiedHeight(
                    reference: enrollment.reference, network: wallet.network
                )
                guard receipt.height == finalized else {
                    throw WalletPaymentFlowError("Wallet setup finality mismatch.")
                }
                enrollment.evidence = evidence
                journal.enrollment = enrollment
                try PaymentRequestFlow.save(journal, wallet: wallet)
                return
            }
            if receipt.state == 3 { _ = try await rpc.enrollKey(enrollment.bytes) }
            try await Task.sleep(for: .seconds(2))
        }
        throw WalletPaymentFlowError(
            "Wallet setup is still finalizing. Try Pay again in a moment."
        )
    }

    private func resolvePending(_ pending: PaymentRequestFlow.Pending,
                                journal: inout PaymentRequestFlow.Journal,
                                wallet: WalletLiveState) async throws {
        for _ in 0..<20 {
            let receipt = try await rpc.resolveCash(pending.cashReference)
            if receipt.state == 3 {
                _ = try await rpc.submitPayment(
                    session: pending.session, transfer: pending.transfer
                )
            }
            if receipt.state == 1 {
                let evidence = try await rpc.cashEvidence(pending.cashReference)
                let height = try evidence.verifiedHeight(
                    reference: pending.cashReference, network: wallet.network
                )
                guard receipt.height == height else {
                    throw WalletPaymentFlowError("Payment finality mismatch.")
                }
                guard let output = try await findRecipientOutput(pending) else {
                    throw WalletPaymentFlowError(
                        "Payment finalized; waiting for the recipient proof."
                    )
                }
                try DemoPurchase.verifyOutput(
                    output, owner: pending.recipient,
                    reference: pending.outputOrigin, index: 0,
                    amount: pending.amount.demoAmount, height: height,
                    network: wallet.network
                )
                guard journal.nextNonce < UInt64.max else {
                    throw WalletPaymentFlowError("Wallet payment nonce exhausted.")
                }
                journal.nextNonce += 1
                journal.pending = nil
                try PaymentRequestFlow.save(journal, wallet: wallet)
                phase = .paid(height)
                await wallet.refresh()
                return
            }
            try await Task.sleep(for: .seconds(2))
        }
        phase = .pending
    }

    private func findRecipientOutput(
        _ pending: PaymentRequestFlow.Pending
    ) async throws -> WalletOwnerCoinRecord? {
        var cursor: Data?
        for _ in 0..<64 {
            let page = try await rpc.ownerCoinCells(
                owner: pending.recipient, after: cursor
            )
            if let output = try page.records.first(where: {
                let coin = try DemoCoin(value: $0.value)
                return coin.origin == pending.outputOrigin && coin.outputIndex == 0
            }) {
                return output
            }
            guard let next = page.next, next != cursor else { return nil }
            cursor = next
        }
        throw WalletPaymentFlowError(
            "Recipient proof history exceeds the wallet query limit."
        )
    }

    private static func actText(_ atomic: String) -> String {
        let padded = String(repeating: "0", count: max(0, 19 - atomic.count))
            + atomic
        let split = padded.index(padded.endIndex, offsetBy: -18)
        var fraction = String(padded[split...])
        while fraction.last == "0" { fraction.removeLast() }
        return String(padded[..<split])
            + (fraction.isEmpty ? "" : "." + fraction) + " ACT"
    }
}
