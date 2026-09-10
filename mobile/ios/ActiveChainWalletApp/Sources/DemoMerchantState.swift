import ActiveChainWallet
import Foundation
import SwiftUI

struct DemoEnrollment: Codable {
    let bytes: Data
    let reference: Data
    var evidence: DemoCashEvidence?
    func verifiedHeight(network: WalletNetwork, owner: Data) throws -> UInt64? {
        guard !bytes.isEmpty, bytes.count <= 4096, owner.count == 48, reference.count == 48 else { throw DemoShopError("Malformed enrollment journal.") }
        let code = DemoMerchant.withPointers([bytes, network.chainID, owner, reference]) { p in
            activechain_wallet_check_key_enrollment(p[0], UInt32(bytes.count), p[1], p[2], p[3])
        }
        guard code == ACTIVECHAIN_WALLET_OK else { throw DemoShopError("Enrollment does not belong to this wallet.") }
        return try evidence?.verifiedHeight(reference: reference, network: network)
    }
}
struct DemoPurchase: Codable {
    let request: Data
    let reference: Data
    let session: Data
    let transfer: Data
    let paymentChange: DemoAmount
    let feeChange: DemoAmount
    var evidence: DemoCashEvidence?
    var merchantOutput: WalletOwnerCoinRecord?
    var customerOutputs: [WalletOwnerCoinRecord]?

    func verifiedPaidHeight(network: WalletNetwork, owner: Data) throws -> UInt64? {
        guard let evidence, let merchantOutput, let customerOutputs else { return nil }
        let approval = try RustCanonicalApproval.review(request)
        guard approval.intentID == reference, approval.chainID == network.chainID, approval.signer == owner,
              approval.recipient == DemoMerchant.owner, approval.amount == Unsigned128Words(high: 0, low: DemoMerchant.price), approval.fee == Unsigned128Words(high: 0, low: DemoMerchant.fee) else { throw DemoShopError("Receipt does not match this purchase.") }
        let height = try evidence.verifiedHeight(reference: reference, network: network)
        try Self.verifyOutput(merchantOutput, owner: DemoMerchant.owner, reference: reference, index: 0, amount: DemoAmount(high: 0, low: DemoMerchant.price), height: height, network: network)
        for (index, amount) in [(UInt16(1), paymentChange), (UInt16(2), feeChange)] {
            if amount == DemoAmount(high: 0, low: 0) { continue }
            guard let output = try customerOutputs.first(where: { try DemoCoin(value: $0.value).outputIndex == index }) else { throw DemoShopError("Customer change has not been proved.") }
            try Self.verifyOutput(output, owner: owner, reference: reference, index: index, amount: amount, height: height, network: network)
        }
        return height
    }
    static func verifyOutput(_ record: WalletOwnerCoinRecord, owner: Data, reference: Data, index: UInt16, amount: DemoAmount, height: UInt64, network: WalletNetwork) throws {
        let coin = try DemoCoin(value: record.value)
        guard coin.owner == owner, coin.origin == reference, coin.outputIndex == index, coin.amount == amount,
              coin.creationHeight == height, record.finalizedHeight >= height,
              RustWalletOwnerCoinProofVerifier().verify(record: record, owner: owner, chainGenesis: network.genesis) else { throw DemoShopError("Payment output proof did not match this purchase.") }
    }
}
struct DemoJournal: Codable {
    let owner: Data
    let genesis: Data
    var enrollment: DemoEnrollment?
    var nextNonce: UInt64 = 0
    var purchase: DemoPurchase?
}

@MainActor
final class DemoMerchantState: ObservableObject {
    @Published private(set) var busy = false
    @Published private(set) var message = "Load a funded wallet to visit the demo shop."
    @Published private(set) var enrolledHeight: UInt64?
    @Published private(set) var paidHeight: UInt64?
    @Published private(set) var review: CanonicalCashApproval?
    @Published private(set) var pending = false
    @Published private(set) var reference: String?
    private var journal: DemoJournal?
    private let rpc = WalletRPCClient()
    private let service = "dev.activechain.demo-merchant.v1"

    private func load(wallet: WalletLiveState) throws -> DemoJournal {
        guard wallet.network == .kanalen, let profile = wallet.deviceProfile,
              profile.chainGenesis == wallet.network.genesis else { throw DemoShopError("Create a wallet on Kanalen testnet first.") }
        let bytes = try SharedKeychain().load(service: service, account: wallet.network.id)
        if let bytes {
            guard bytes.count <= 1_048_576 else { throw DemoShopError("The payment journal exceeds its limit.") }
            let saved = try JSONDecoder().decode(DemoJournal.self, from: bytes)
            guard saved.owner == profile.owner, saved.genesis == profile.chainGenesis else { throw DemoShopError("This payment journal belongs to a different wallet.") }
            return saved
        }
        return DemoJournal(owner: profile.owner, genesis: profile.chainGenesis)
    }
    private func save(_ next: DemoJournal, wallet: WalletLiveState) throws {
        guard wallet.network == .kanalen, wallet.deviceProfile?.owner == next.owner,
              wallet.network.genesis == next.genesis else { throw DemoShopError("Wallet changed during checkout.") }
        let bytes = try JSONEncoder().encode(next)
        guard bytes.count <= 1_048_576 else { throw DemoShopError("The payment journal exceeds its limit.") }
        try SharedKeychain().save(bytes, service: service, account: wallet.network.id)
        journal = next
    }
    func refresh(wallet: WalletLiveState) async {
        guard !busy else { return }
        busy = true; defer { busy = false }
        do { try await resolve(wallet: wallet) } catch { message = error.localizedDescription }
    }
    private func resolve(wallet: WalletLiveState) async throws {
        var saved = try load(wallet: wallet)
        journal = saved; paidHeight = nil; enrolledHeight = nil; pending = false; reference = nil
        guard let enrollment = saved.enrollment else {
            message = "Register your wallet key on chain to spend testnet ACT. Identity credentials are optional."
            return
        }
        if let height = try enrollment.verifiedHeight(network: wallet.network, owner: saved.owner) {
            enrolledHeight = height
        } else {
            pending = true; message = "Wallet-key enrollment pending."
            let receipt = try await rpc.resolveCash(enrollment.reference)
            guard receipt.reference == enrollment.reference else { throw DemoShopError("Enrollment receipt mismatch.") }
            if receipt.state == 3 {
                let submitted = try await rpc.enrollKey(enrollment.bytes)
                guard submitted.reference == enrollment.reference else { throw DemoShopError("Enrollment submission mismatch.") }
                return
            }
            guard receipt.state == 1 else { return }
            let evidence = try await rpc.cashEvidence(enrollment.reference)
            let height = try evidence.verifiedHeight(reference: enrollment.reference, network: wallet.network)
            guard receipt.height == height else { throw DemoShopError("Enrollment checkpoint mismatch.") }
            saved.enrollment?.evidence = evidence
            try save(saved, wallet: wallet)
            enrolledHeight = height; pending = false
        }
        guard var purchase = saved.purchase else { message = "Wallet key registered. Ready to buy a demo coffee."; return }
        reference = purchase.reference.map { String(format: "%02x", $0) }.joined()
        if let height = try purchase.verifiedPaidHeight(network: wallet.network, owner: saved.owner) {
            paidHeight = height; message = "Paid 5 ACT · network fee 0.001 ACT"; return
        }
        pending = true; message = "Payment pending. Checking merchant receipt and your change."
        let receipt = try await rpc.resolveCash(purchase.reference)
        guard receipt.reference == purchase.reference else { throw DemoShopError("Payment receipt mismatch.") }
        if receipt.state == 3 {
            let submitted = try await rpc.submitPayment(session: purchase.session, transfer: purchase.transfer)
            guard submitted.reference == purchase.reference else { throw DemoShopError("Payment submission mismatch.") }
            return
        }
        guard receipt.state == 1 else { return }
        let evidence = try await rpc.cashEvidence(purchase.reference)
        let height = try evidence.verifiedHeight(reference: purchase.reference, network: wallet.network)
        guard receipt.height == height else { throw DemoShopError("Payment checkpoint mismatch.") }
        purchase.evidence = evidence
        purchase.merchantOutput = try await findOutput(owner: DemoMerchant.owner, reference: purchase.reference)
        let customer = try await rpc.ownerCoinCells(owner: saved.owner)
        purchase.customerOutputs = try customer.records.filter { try DemoCoin(value: $0.value).origin == purchase.reference }
        guard try purchase.verifiedPaidHeight(network: wallet.network, owner: saved.owner) == height else { throw DemoShopError("Waiting for verified payment outputs.") }
        saved.purchase = purchase
        let approval = try RustCanonicalApproval.review(purchase.request)
        guard approval.nonce == saved.nextNonce, saved.nextNonce < UInt64.max else { throw DemoShopError("Payment nonce mismatch.") }
        saved.nextNonce += 1
        try save(saved, wallet: wallet)
        pending = false; paidHeight = height; message = "Paid 5 ACT · network fee 0.001 ACT"
        await wallet.refresh()
    }
    private func findOutput(owner: Data, reference: Data) async throws -> WalletOwnerCoinRecord? {
        var cursor: Data?
        for _ in 0..<64 {
            let page = try await rpc.ownerCoinCells(owner: owner, after: cursor)
            if let output = try page.records.first(where: { try DemoCoin(value: $0.value).origin == reference && DemoCoin(value: $0.value).outputIndex == 0 }) { return output }
            guard let next = page.next, next != cursor else { return nil }
            cursor = next
        }
        throw DemoShopError("Merchant history exceeds the demo query limit.")
    }
    func enroll(wallet: WalletLiveState) async {
        guard !busy else { return }
        busy = true; defer { busy = false }
        do {
            var saved = try load(wallet: wallet)
            guard saved.enrollment == nil, case let .healthy(height) = wallet.networkState,
                  let page = wallet.verifiedOwnerPage, !page.records.isEmpty else { throw DemoShopError("Fund a healthy Kanalen wallet before registering its key.") }
            let (bytes, reference) = try DemoMerchant.enrollment(network: wallet.network, slot: wallet.primarySlotID, height: height)
            saved.enrollment = DemoEnrollment(bytes: bytes, reference: reference)
            try save(saved, wallet: wallet) // Exact signed action is durable before any network send.
            pending = true; message = "Wallet-key enrollment pending."
            let receipt = try await rpc.enrollKey(bytes)
            guard receipt.reference == reference else { throw DemoShopError("Enrollment submission mismatch.") }
        } catch { message = error.localizedDescription }
    }
    func prepare(wallet: WalletLiveState) async {
        guard !busy, !pending else { return }
        busy = true; defer { busy = false }
        do {
            await wallet.refresh()
            let saved = try load(wallet: wallet)
            guard let enrollment = saved.enrollment else { throw DemoShopError("Register your wallet key first.") }
            guard let registered = try enrollment.verifiedHeight(network: wallet.network, owner: saved.owner) else { throw DemoShopError("Enrollment is not yet verified.") }
            guard case let .healthy(height) = wallet.networkState, height > registered, let page = wallet.verifiedOwnerPage else { throw DemoShopError("Waiting for a healthy block after enrollment.") }
            if let purchase = saved.purchase, try purchase.verifiedPaidHeight(network: wallet.network, owner: saved.owner) == nil { throw DemoShopError("Resolve the pending purchase first.") }
            review = try DemoMerchant.review(network: wallet.network, owner: saved.owner, page: page, height: height, nonce: saved.nextNonce)
        } catch { message = error.localizedDescription }
    }
    func cancelReview() { review = nil }
    func pay(wallet: WalletLiveState) async {
        guard !busy, let approval = review else { return }
        review = nil; busy = true; defer { busy = false }
        do {
            var saved = try load(wallet: wallet)
            let status = try await rpc.status()
            guard case let .healthy(height) = status.networkState, height < approval.validUntil,
                  approval.chainID == wallet.network.chainID, approval.signer == saved.owner,
                  approval.recipient == DemoMerchant.owner, approval.amount == Unsigned128Words(high: 0, low: DemoMerchant.price),
                  approval.fee == Unsigned128Words(high: 0, low: DemoMerchant.fee), approval.nonce == saved.nextNonce else { throw DemoShopError("This review expired or no longer matches the wallet.") }
            if let purchase = saved.purchase, try purchase.verifiedPaidHeight(network: wallet.network, owner: saved.owner) == nil { throw DemoShopError("A purchase is already pending.") }
            guard let page = wallet.verifiedOwnerPage else { throw DemoShopError("Wallet holdings are unverified.") }
            let inputID = try DemoMerchant.selectedInput(approval)
            guard let input = page.records.first(where: { $0.key == inputID }),
                  let reserve = page.records.first(where: { $0.key == approval.feeReserve }) else { throw DemoShopError("Reviewed inputs are no longer available.") }
            let change = try DemoCoin(value: input.value).amount.subtracting(DemoMerchant.price)
            let feeChange = try DemoCoin(value: reserve.value).amount.subtracting(DemoMerchant.fee)
            let session = try DemoMerchant.signedSession(approval: approval, slot: wallet.primarySlotID, height: height)
            let transfer = try CanonicalCashApprovalSession(approval: approval).sign(with: DemoMerchant.custody(), slotID: wallet.primarySlotID, minimumVersion: 1, minimumFinalizedHeight: 0)
            saved.purchase = DemoPurchase(request: approval.request, reference: approval.intentID, session: session, transfer: transfer, paymentChange: change, feeChange: feeChange)
            try save(saved, wallet: wallet)
            paidHeight = nil; pending = true; message = "Payment pending."
            let receipt = try await rpc.submitPayment(session: session, transfer: transfer)
            guard receipt.reference == approval.intentID else { throw DemoShopError("Payment submission mismatch.") }
        } catch { message = error.localizedDescription }
    }
}
