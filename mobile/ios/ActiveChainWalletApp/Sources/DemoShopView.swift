import SwiftUI

struct DemoShopView: View {
    @ObservedObject var liveState: WalletLiveState
    @StateObject private var shop = DemoMerchantState()
    @Environment(\.scenePhase) private var scenePhase
    var body: some View {
        ZStack {
            WalletBackground()
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    VStack(alignment: .leading, spacing: 12) {
                        Label("TESTNET DEMO", systemImage: "cup.and.saucer.fill")
                            .font(.caption.bold()).foregroundStyle(WalletPalette.mint)
                        Text("Kanalen Coffee").font(.largeTitle.bold())
                        Text("Try a purchase with your faucet coins.")
                            .foregroundStyle(WalletPalette.muted)
                        HStack {
                            Image(systemName: "cup.and.saucer.fill").font(.system(size: 44)).foregroundStyle(WalletPalette.mint)
                            VStack(alignment: .leading) {
                                Text("Demo coffee").font(.title3.bold())
                                Text("5 ACT").font(.title2.bold())
                                Text("Network fee: 0.001 ACT").font(.caption)
                            }
                            Spacer()
                        }.padding(.vertical, 12)
                        Text("A testnet purchase. No physical goods or real money.")
                            .font(.caption).foregroundStyle(WalletPalette.muted)
                    }.cardStyle()

                    VStack(alignment: .leading, spacing: 12) {
                        if let height = shop.enrolledHeight {
                            Label("Wallet key registered", systemImage: "checkmark.shield.fill")
                                .foregroundStyle(WalletPalette.mint).accessibilityIdentifier("shop.enrollment")
                            Text("Verified at block \(height)").font(.caption)
                        } else {
                            Text("Register your wallet key").font(.headline)
                            Text("Prove that you control this wallet. Identity credentials are optional.")
                                .font(.caption).foregroundStyle(WalletPalette.muted)
                            Button("Register wallet key") { Task { await shop.enroll(wallet: liveState) } }
                                .buttonStyle(.borderedProminent)
                                .disabled(shop.busy || shop.pending || liveState.verifiedOwnerPage?.records.isEmpty != false)
                                .accessibilityIdentifier("shop.enroll")
                        }
                        if shop.busy { ProgressView().accessibilityIdentifier("shop.progress") }
                        Text(shop.message).font(.callout).accessibilityIdentifier("shop.status")
                        if let height = shop.paidHeight {
                            Label("Payment verified", systemImage: "checkmark.seal.fill")
                                .foregroundStyle(WalletPalette.mint).accessibilityIdentifier("shop.paid")
                            Text("Merchant payment and your change verified at block \(height).")
                                .font(.caption).accessibilityIdentifier("shop.receipt")
                            if let reference = shop.reference {
                                Text(reference).font(.caption2.monospaced()).textSelection(.enabled)
                            }
                        }
                        Button(shop.paidHeight == nil ? "Buy demo coffee · 5 ACT" : "Buy another demo coffee · 5 ACT") {
                            Task { await shop.prepare(wallet: liveState) }
                        }.buttonStyle(.borderedProminent)
                            .disabled(shop.busy || shop.pending || !shop.canBuy)
                            .accessibilityIdentifier("shop.buy")
                        Button("Refresh payment status") { Task { await shop.refresh(wallet: liveState) } }
                            .disabled(shop.busy).accessibilityIdentifier("shop.refresh")
                    }.cardStyle()
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Merchant address").font(.caption.bold())
                        Text(DemoMerchant.owner.map { String(format: "%02x", $0) }.joined())
                            .font(.caption2.monospaced()).textSelection(.enabled)
                    }.cardStyle()
                }.padding(20)
            }
        }
        .navigationTitle("Demo shop")
        .walletNavigationBarBackground()
        .task {
            await liveState.refresh()
            while !Task.isCancelled {
                await shop.refresh(wallet: liveState, background: true)
                try? await Task.sleep(for: .seconds(3))
            }
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active { Task { await shop.refresh(wallet: liveState, background: true) } }
        }
        .sheet(isPresented: Binding(get: { shop.review != nil }, set: { if !$0 { shop.cancelReview() } })) {
            if let review = shop.review {
                NavigationStack {
                    VStack(alignment: .leading, spacing: 20) {
                        Text("Pay Kanalen Coffee").font(.title.bold())
                        Text("Demo coffee · 5 ACT").font(.title2)
                        Text("Network fee: 0.001 ACT\nTotal: 5.001 ACT\nNetwork: Kanalen testnet")
                        Text("Recipient").font(.caption.bold())
                        Text(review.recipient.map { String(format: "%02x", $0) }.joined()).font(.caption.monospaced()).textSelection(.enabled)
                        Text("Valid through block \(review.validUntil)").font(.caption)
                        Button("Confirm payment · 5.001 ACT") { Task { await shop.pay(wallet: liveState) } }
                            .buttonStyle(.borderedProminent).accessibilityIdentifier("shop.confirm")
                        Button("Cancel") { shop.cancelReview() }
                        Spacer()
                    }.padding(24).navigationTitle("Review payment")
                }.preferredColorScheme(.dark)
            }
        }
    }
}
