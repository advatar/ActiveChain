import SwiftUI

struct DemoShopView: View {
    @ObservedObject var liveState: WalletLiveState
    @StateObject private var shop = DemoMerchantState()
    @Environment(\.scenePhase) private var scenePhase
    @State private var showCreateRequest = false
    @State private var paymentLink = ""
    @State private var verifiedRequest: VerifiedWalletPaymentRequest?
    @State private var requestError: String?

    private var peerPaymentPending: Bool {
        WalletCashLaneGuard.peerPaymentPending(network: liveState.network)
    }

    var body: some View {
        ZStack {
            WalletBackground()
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    paymentRequests
                    demoShop
                }
                .padding(20)
            }
        }
        .navigationTitle("Payments")
        .walletNavigationBarBackground()
        .task {
            await liveState.refresh()
            while !Task.isCancelled {
                await shop.refresh(wallet: liveState)
                try? await Task.sleep(for: .seconds(3))
            }
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active { Task { await shop.refresh(wallet: liveState) } }
        }
        .onOpenURL { url in Task { await openPaymentRequest(url) } }
        .sheet(isPresented: $showCreateRequest) {
            CreatePaymentRequestSheet().preferredColorScheme(.dark)
        }
        .sheet(isPresented: Binding(
            get: { verifiedRequest != nil },
            set: { if !$0 { verifiedRequest = nil } }
        )) {
            if let verifiedRequest {
                PaymentRequestReviewSheet(verified: verifiedRequest, wallet: liveState)
                    .preferredColorScheme(.dark)
            }
        }
        .sheet(isPresented: Binding(
            get: { shop.review != nil },
            set: { if !$0 { shop.cancelReview() } }
        )) {
            if let review = shop.review {
                NavigationStack {
                    VStack(alignment: .leading, spacing: 20) {
                        Text("Pay Kanalen Coffee").font(.title.bold())
                        Text("Demo coffee · 5 ACT").font(.title2)
                        Text("Network fee: 0.001 ACT\nTotal: 5.001 ACT\nNetwork: Kanalen testnet")
                        Text("Recipient").font(.caption.bold())
                        Text(review.recipient.map { String(format: "%02x", $0) }.joined())
                            .font(.caption.monospaced()).textSelection(.enabled)
                        Text("Valid through block \(review.validUntil)").font(.caption)
                        Button("Confirm payment · 5.001 ACT") {
                            Task { await shop.pay(wallet: liveState) }
                        }
                        .buttonStyle(.borderedProminent)
                        .accessibilityIdentifier("shop.confirm")
                        Button("Cancel") { shop.cancelReview() }
                        Spacer()
                    }
                    .padding(24)
                    .navigationTitle("Review payment")
                }
                .preferredColorScheme(.dark)
            }
        }
    }

    private var paymentRequests: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Label("PAYMENTS", systemImage: "arrow.left.arrow.right.circle.fill")
                    .font(.caption.bold()).foregroundStyle(WalletPalette.mint)
                Spacer()
                Text("SIGNED REQUESTS")
                    .font(.caption2.bold()).foregroundStyle(WalletPalette.muted)
            }
            Text("Pay or get paid").font(.largeTitle.bold())
            Text("Requests are signed and network-bound, but they never authorize spending. The payer always reviews and approves the real transfer.")
                .font(.callout).foregroundStyle(WalletPalette.muted)

            Button { showCreateRequest = true } label: {
                Label("Request payment", systemImage: "qrcode")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(liveState.deviceProfile == nil || liveState.supersededProfile)
            .accessibilityIdentifier("payments.request")

            Divider()
            Text("Pay a request").font(.headline)
            TextField("Paste activechain://pay link", text: $paymentLink)
                .textFieldStyle(.roundedBorder)
                .autocorrectionDisabled()
                .accessibilityIdentifier("payments.link")
            HStack {
                Button("Paste") {
#if os(iOS)
                    paymentLink = UIPasteboard.general.string ?? ""
#elseif os(macOS)
                    paymentLink = NSPasteboard.general.string(forType: .string) ?? ""
#endif
                }
                .buttonStyle(.bordered)
                Button("Verify & review") {
                    guard let url = URL(string: paymentLink) else {
                        requestError = "That is not a valid ActiveChain payment link."
                        return
                    }
                    Task { await openPaymentRequest(url) }
                }
                .buttonStyle(.borderedProminent)
                .disabled(paymentLink.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                .accessibilityIdentifier("payments.verify")
            }
            if let requestError {
                Label(requestError, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(.orange)
            } else {
                Label(
                    "Signature, recipient, chain, genesis and expiry are verified before a Pay button is shown.",
                    systemImage: "checkmark.shield.fill"
                )
                .font(.caption).foregroundStyle(WalletPalette.mint)
            }
        }
        .cardStyle()
    }

    private var demoShop: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 12) {
                Label("TESTNET DEMO", systemImage: "cup.and.saucer.fill")
                    .font(.caption.bold()).foregroundStyle(WalletPalette.mint)
                Text("Kanalen Coffee").font(.title.bold())
                Text("Try a purchase with your faucet coins.")
                    .foregroundStyle(WalletPalette.muted)
                HStack {
                    Image(systemName: "cup.and.saucer.fill")
                        .font(.system(size: 44)).foregroundStyle(WalletPalette.mint)
                    VStack(alignment: .leading) {
                        Text("Demo coffee").font(.title3.bold())
                        Text("5 ACT").font(.title2.bold())
                        Text("Network fee: 0.001 ACT").font(.caption)
                    }
                    Spacer()
                }
                .padding(.vertical, 12)
                Text("A testnet purchase. No physical goods or real money.")
                    .font(.caption).foregroundStyle(WalletPalette.muted)
            }
            .cardStyle()

            VStack(alignment: .leading, spacing: 12) {
                if peerPaymentPending {
                    Label(
                        "A peer payment is pending. Demo checkout is paused until it finalizes.",
                        systemImage: "clock.arrow.circlepath"
                    )
                    .font(.caption)
                    .foregroundStyle(.orange)
                }
                if let height = shop.enrolledHeight {
                    Label("Wallet key registered", systemImage: "checkmark.shield.fill")
                        .foregroundStyle(WalletPalette.mint)
                        .accessibilityIdentifier("shop.enrollment")
                    Text("Verified at block \(height)").font(.caption)
                } else {
                    Text("Register your wallet key").font(.headline)
                    Text("Prove that you control this wallet. Identity credentials are optional.")
                        .font(.caption).foregroundStyle(WalletPalette.muted)
                    Button("Register wallet key") {
                        Task { await shop.enroll(wallet: liveState) }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(
                        shop.busy || shop.pending || peerPaymentPending
                            || liveState.verifiedOwnerPage?.records.isEmpty != false
                    )
                    .accessibilityIdentifier("shop.enroll")
                }
                if shop.busy { ProgressView() }
                Text(shop.message).font(.callout).accessibilityIdentifier("shop.status")
                if let height = shop.paidHeight {
                    Label("Payment verified", systemImage: "checkmark.seal.fill")
                        .foregroundStyle(WalletPalette.mint)
                        .accessibilityIdentifier("shop.paid")
                    Text("Merchant payment and your change verified at block \(height).")
                        .font(.caption).accessibilityIdentifier("shop.receipt")
                    if let reference = shop.reference {
                        Text(reference).font(.caption2.monospaced()).textSelection(.enabled)
                    }
                }
                Button(
                    shop.paidHeight == nil
                        ? "Buy demo coffee · 5 ACT"
                        : "Buy another demo coffee · 5 ACT"
                ) {
                    Task { await shop.prepare(wallet: liveState) }
                }
                .buttonStyle(.borderedProminent)
                .disabled(shop.busy || shop.pending || peerPaymentPending || !shop.canBuy)
                .accessibilityIdentifier("shop.buy")
                Button("Refresh payment status") {
                    Task { await shop.refresh(wallet: liveState) }
                }
                .disabled(shop.busy)
                .accessibilityIdentifier("shop.refresh")
            }
            .cardStyle()

            VStack(alignment: .leading, spacing: 6) {
                Text("Merchant address").font(.caption.bold())
                Text(DemoMerchant.owner.map { String(format: "%02x", $0) }.joined())
                    .font(.caption2.monospaced()).textSelection(.enabled)
            }
            .cardStyle()
        }
    }

    @MainActor
    private func openPaymentRequest(_ url: URL) async {
        requestError = nil
        await liveState.refresh()
        guard case let .healthy(height) = liveState.networkState else {
            requestError = "The selected network must be healthy before a payment request can be reviewed."
            return
        }
        do {
            verifiedRequest = try WalletPaymentRequestService.verify(
                url, network: liveState.network, finalizedHeight: height
            )
            paymentLink = url.absoluteString
        } catch WalletPaymentRequestError.invalidSignature {
            requestError = "The payment request signature is invalid."
        } catch WalletPaymentRequestError.recipientKeyMismatch {
            requestError = "The payment request recipient does not match its signing key."
        } catch WalletPaymentRequestError.wrongNetwork {
            requestError = "This payment request belongs to a different network or genesis."
        } catch WalletPaymentRequestError.expired {
            requestError = "This payment request has expired."
        } catch {
            requestError = "This payment request could not be verified."
        }
    }
}
