import SwiftUI

struct PaymentRequestReviewSheet: View {
    @ObservedObject var wallet: WalletLiveState
    @StateObject private var state: PaymentRequestPayState
    @Environment(\.dismiss) private var dismiss

    init(verified: VerifiedWalletPaymentRequest, wallet: WalletLiveState) {
        self.wallet = wallet
        _state = StateObject(wrappedValue: PaymentRequestPayState(verified: verified))
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 18) {
                    VStack(spacing: 10) {
                        Image(systemName: "checkmark.shield.fill")
                            .font(.system(size: 42))
                            .foregroundStyle(WalletPalette.mint)
                        Text("Verified payment request").font(.title2.bold())
                        Text("The request signature, recipient and network match. You still approve the actual transfer separately.")
                            .font(.caption)
                            .foregroundStyle(WalletPalette.muted)
                            .multilineTextAlignment(.center)
                    }
                    .cardStyle()

                    VStack(alignment: .leading, spacing: 14) {
                        HStack {
                            Text("Amount").foregroundStyle(WalletPalette.muted)
                            Spacer()
                            Text(state.amountDisplay).font(.title3.bold())
                        }
                        if state.verified.amountAtomicUnits == nil {
                            TextField("Amount in ACT", text: $state.openAmountACT)
                                .textFieldStyle(.roundedBorder)
                                .walletNumberKeyboard()
                        }
                        if !state.verified.memo.isEmpty {
                            Divider()
                            Text(state.verified.memo)
                        }
                        Divider()
                        LabeledContent("Network", value: wallet.network.displayName)
                        LabeledContent("Network fee", value: "0.001 ACT")
                        LabeledContent("Recipient", value: WalletHex.short(state.verified.recipient))
                        LabeledContent("Reference", value: WalletHex.short(state.verified.reference))
                    }
                    .cardStyle()

                    status

                    Button(action: { Task { await state.pay(wallet: wallet) } }) {
                        Label(buttonTitle, systemImage: "faceid")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(!state.canPay)

                    Text("A payment request cannot spend funds. Only this wallet's biometric approval can authorize the canonical cash transfer.")
                        .font(.caption2)
                        .foregroundStyle(WalletPalette.muted)
                        .multilineTextAlignment(.center)
                }
                .padding(20)
            }
            .background(WalletBackground())
            .navigationTitle("Pay request")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } }
            }
            .task { await state.refresh(wallet: wallet) }
        }
    }

    @ViewBuilder private var status: some View {
        switch state.phase {
        case .review:
            Label("Ready for review", systemImage: "checkmark.circle")
                .foregroundStyle(WalletPalette.mint)
        case .preparing:
            progress("Preparing wallet…")
        case .authorizing:
            progress("Waiting for biometric approval…")
        case .submitting:
            progress("Submitting payment…")
        case .pending:
            progress("Payment submitted · verifying finality…")
        case let .paid(height):
            VStack(spacing: 8) {
                Label("Paid", systemImage: "checkmark.seal.fill")
                    .font(.title3.bold()).foregroundStyle(WalletPalette.mint)
                Text("Finalized and recipient output verified at block \(height).")
                    .font(.caption).foregroundStyle(WalletPalette.muted)
            }.cardStyle()
        case let .failed(message):
            VStack(alignment: .leading, spacing: 8) {
                Label("Payment not sent", systemImage: "exclamationmark.triangle.fill")
                    .font(.headline).foregroundStyle(.orange)
                Text(message).font(.caption).foregroundStyle(WalletPalette.muted)
            }.cardStyle()
        }
    }

    private func progress(_ text: String) -> some View {
        HStack(spacing: 12) { ProgressView(); Text(text).font(.subheadline.weight(.semibold)) }
            .frame(maxWidth: .infinity, alignment: .leading)
            .cardStyle()
    }

    private var buttonTitle: String {
        if case .failed = state.phase { return "Try again" }
        return "Review & Pay"
    }
}

struct CreatePaymentRequestSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var amount = ""
    @State private var memo = ""
    @State private var request: WalletPaymentRequestV1?
    @State private var error: String?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 18) {
                    if let request {
                        WalletPaymentRequestQRCode(request: request)
                            .frame(maxWidth: 280, maxHeight: 280)
                            .padding()
                            .background(.white, in: RoundedRectangle(cornerRadius: 24))
                        if let link = try? request.deepLink {
                            ShareLink(item: link) {
                                Label("Share payment request", systemImage: "square.and.arrow.up")
                                    .frame(maxWidth: .infinity)
                            }
                            .buttonStyle(.borderedProminent)
                            .controlSize(.large)
                            Text("Anyone can verify this request, but it cannot authorize a payment from their wallet.")
                                .font(.caption)
                                .foregroundStyle(WalletPalette.muted)
                                .multilineTextAlignment(.center)
                        }
                    } else {
                        VStack(alignment: .leading, spacing: 14) {
                            Text("Amount").font(.headline)
                            TextField("e.g. 10.50", text: $amount)
                                .textFieldStyle(.roundedBorder)
                                .walletNumberKeyboard()
                            Text("Leave blank for an open-amount request.")
                                .font(.caption).foregroundStyle(WalletPalette.muted)
                            Text("Memo").font(.headline)
                            TextField("What is this for?", text: $memo)
                                .textFieldStyle(.roundedBorder)
                        }.cardStyle()

                        Button("Create request") {
                            do {
                                let trimmed = amount.trimmingCharacters(in: .whitespacesAndNewlines)
                                request = try WalletPaymentRequestService().create(
                                    amountACT: trimmed.isEmpty ? nil : trimmed, memo: memo)
                                error = nil
                            } catch { self.error = error.localizedDescription }
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)
                    }
                    if let error { Text(error).font(.caption).foregroundStyle(.orange) }
                }
                .padding(20)
            }
            .background(WalletBackground())
            .navigationTitle("Request payment")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } }
            }
        }
    }
}

struct WalletPaymentActionsCard: View {
    let canRequest: Bool
    let requestPayment: () -> Void
    var body: some View {
        HStack(spacing: 12) {
            Button(action: requestPayment) {
                Label("Request", systemImage: "qrcode")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(!canRequest)
            ShareLink(item: URL(string: "https://activechain.dev")!) {
                Label("Receive", systemImage: "square.and.arrow.down")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .disabled(true)
        }
        .cardStyle()
    }
}
