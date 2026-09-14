import SwiftUI

#if os(iOS)
import UIKit
#elseif os(macOS)
import AppKit
#endif

struct DemoShopView: View {
    @ObservedObject var liveState: WalletLiveState
    @StateObject private var shop = DemoMerchantState()
    @Environment(\.scenePhase) private var scenePhase
    @State private var showCreateRequest = false
    @State private var showTestnetDemo = false
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
                    testnetSandbox
                }
                .padding(20)
            }
        }
        .navigationTitle("Payments")
        .walletNavigationBarBackground()
        .task {
            await liveState.refresh()
            while !Task.isCancelled {
                if showTestnetDemo {
                    await shop.refresh(wallet: liveState)
                }
                try? await Task.sleep(for: .seconds(3))
            }
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active && showTestnetDemo {
                Task { await shop.refresh(wallet: liveState) }
            }
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
                        Label("TESTNET", systemImage: "flask.fill")
                            .font(.caption.bold())
                            .foregroundStyle(WalletPalette.mint)
                        Text("Pay Kanalen Coffee").font(.title.bold())
                        Text("5 ACT").font(.largeTitle.bold())
                        VStack(alignment: .leading, spacing: 8) {
                            LabeledContent("Network fee", value: "0.001 ACT")
                            LabeledContent("Total", value: "5.001 ACT")
                            LabeledContent("Network", value: "Kanalen testnet")
                        }
                        .cardStyle()
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Recipient").font(.caption.bold())
                            Text(review.recipient.map { String(format: "%02x", $0) }.joined())
                                .font(.caption2.monospaced())
                                .textSelection(.enabled)
                            Text("Valid through block \(review.validUntil)")
                                .font(.caption)
                                .foregroundStyle(WalletPalette.muted)
                        }
                        Button("Pay 5.001 ACT") {
                            Task { await shop.pay(wallet: liveState) }
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)
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
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 6) {
                Label("PAYMENTS", systemImage: "arrow.left.arrow.right.circle.fill")
                    .font(.caption.bold())
                    .foregroundStyle(WalletPalette.mint)
                Text("Pay or get paid")
                    .font(.largeTitle.bold())
                Text("Send ACT with a signed payment request. Nothing moves until the payer reviews and approves the transfer.")
                    .font(.callout)
                    .foregroundStyle(WalletPalette.muted)
            }

            HStack(spacing: 12) {
                Button { showCreateRequest = true } label: {
                    VStack(spacing: 8) {
                        Image(systemName: "qrcode")
                            .font(.title2)
                        Text("Request")
                            .font(.headline)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                }
                .buttonStyle(.borderedProminent)
                .disabled(liveState.deviceProfile == nil || liveState.supersededProfile)
                .accessibilityIdentifier("payments.request")

                Button {
#if os(iOS)
                    paymentLink = UIPasteboard.general.string ?? ""
#elseif os(macOS)
                    paymentLink = NSPasteboard.general.string(forType: .string) ?? ""
#endif
                    if let url = URL(string: paymentLink) {
                        Task { await openPaymentRequest(url) }
                    }
                } label: {
                    VStack(spacing: 8) {
                        Image(systemName: "arrow.down.left.circle.fill")
                            .font(.title2)
                        Text("Pay")
                            .font(.headline)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                }
                .buttonStyle(.bordered)
                .disabled(liveState.deviceProfile == nil || liveState.supersededProfile)
                .accessibilityIdentifier("payments.pay")
            }

            Divider()

            VStack(alignment: .leading, spacing: 10) {
                Text("Payment link").font(.headline)
                Text("Tap an ActiveChain payment link, scan its QR code, or paste it here.")
                    .font(.caption)
                    .foregroundStyle(WalletPalette.muted)
                TextField("activechain://pay…", text: $paymentLink)
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
                    Button("Review payment") {
                        guard let url = URL(string: paymentLink) else {
                            requestError = "That isn't a valid ActiveChain payment link."
                            return
                        }
                        Task { await openPaymentRequest(url) }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(paymentLink.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    .accessibilityIdentifier("payments.verify")
                }
            }

            if let requestError {
                Label(requestError, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
            } else {
                Label("Requests are verified before payment details are shown.", systemImage: "checkmark.shield.fill")
                    .font(.caption)
                    .foregroundStyle(WalletPalette.mint)
            }
        }
        .cardStyle()
    }

    private var testnetSandbox: some View {
        DisclosureGroup(isExpanded: $showTestnetDemo) {
            demoShop
                .padding(.top, 14)
        } label: {
            HStack(spacing: 12) {
                Image(systemName: "flask.fill")
                    .foregroundStyle(WalletPalette.violet)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Testnet sandbox")
                        .font(.headline)
                    Text("Kanalen Coffee demo")
                        .font(.caption)
                        .foregroundStyle(WalletPalette.muted)
                }
            }
        }
        .cardStyle()
        .onChange(of: showTestnetDemo) { _, expanded in
            if expanded { Task { await shop.refresh(wallet: liveState) } }
        }
    }

    private var demoShop: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 10) {
                Text("Buy a demo coffee")
                    .font(.title3.bold())
                Text("Exercise the same cash path with testnet ACT. No physical goods or real money.")
                    .font(.caption)
                    .foregroundStyle(WalletPalette.muted)
                HStack {
                    Image(systemName: "cup.and.saucer.fill")
                        .font(.system(size: 36))
                        .foregroundStyle(WalletPalette.mint)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Kanalen Coffee").font(.headline)
                        Text("5 ACT + 0.001 ACT network fee").font(.caption)
                    }
                    Spacer()
                }
            }

            Divider()

            VStack(alignment: .leading, spacing: 12) {
                if peerPaymentPending {
                    Label(
                        "A payment is still finalizing. Demo checkout will resume when it completes.",
                        systemImage: "clock.arrow.circlepath"
                    )
                    .font(.caption)
                    .foregroundStyle(.orange)
                }
                if let height = shop.enrolledHeight {
                    Label("Wallet ready", systemImage: "checkmark.shield.fill")
                        .foregroundStyle(WalletPalette.mint)
                        .accessibilityIdentifier("shop.enrollment")
                    Text("Signing key verified at block \(height)")
                        .font(.caption)
                        .foregroundStyle(WalletPalette.muted)
                } else {
                    Text("Prepare wallet for test payments").font(.headline)
                    Text("This one-time step registers the wallet's signing key on Kanalen.")
                        .font(.caption)
                        .foregroundStyle(WalletPalette.muted)
                    Button("Prepare wallet") {
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
                Text(shop.message)
                    .font(.callout)
                    .foregroundStyle(WalletPalette.muted)
                    .accessibilityIdentifier("shop.status")
                if let height = shop.paidHeight {
                    Label("Payment verified", systemImage: "checkmark.seal.fill")
                        .foregroundStyle(WalletPalette.mint)
                        .accessibilityIdentifier("shop.paid")
                    Text("Recipient and change outputs verified at block \(height).")
                        .font(.caption)
                        .accessibilityIdentifier("shop.receipt")
                    if let reference = shop.reference {
                        Text(reference)
                            .font(.caption2.monospaced())
                            .foregroundStyle(WalletPalette.muted)
                            .textSelection(.enabled)
                    }
                }
                Button(shop.paidHeight == nil ? "Buy coffee · 5 ACT" : "Buy another · 5 ACT") {
                    Task { await shop.prepare(wallet: liveState) }
                }
                .buttonStyle(.borderedProminent)
                .disabled(shop.busy || shop.pending || peerPaymentPending || !shop.canBuy)
                .accessibilityIdentifier("shop.buy")
                Button("Refresh") {
                    Task { await shop.refresh(wallet: liveState) }
                }
                .disabled(shop.busy)
                .accessibilityIdentifier("shop.refresh")
            }

            DisclosureGroup("Merchant details") {
                Text(DemoMerchant.owner.map { String(format: "%02x", $0) }.joined())
                    .font(.caption2.monospaced())
                    .foregroundStyle(WalletPalette.muted)
                    .textSelection(.enabled)
                    .padding(.top, 8)
            }
            .font(.caption.bold())
        }
    }

    @MainActor
    private func openPaymentRequest(_ url: URL) async {
        requestError = nil
        await liveState.refresh()
        guard case let .healthy(height) = liveState.networkState else {
            requestError = "The network isn't ready to review this payment yet."
            return
        }
        do {
            verifiedRequest = try WalletPaymentRequestService.verify(
                url, network: liveState.network, finalizedHeight: height
            )
            paymentLink = url.absoluteString
        } catch WalletPaymentRequestError.invalidSignature {
            requestError = "This payment request has an invalid signature."
        } catch WalletPaymentRequestError.recipientKeyMismatch {
            requestError = "The payment recipient doesn't match the request's signing key."
        } catch WalletPaymentRequestError.wrongNetwork {
            requestError = "This request is for a different ActiveChain network."
        } catch WalletPaymentRequestError.expired {
            requestError = "This payment request has expired."
        } catch {
            requestError = "This payment request couldn't be verified."
        }
    }
}
