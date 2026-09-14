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
                        Text("Verified request")
                            .font(.title2.bold())
                        Text("The request is signed, belongs to this network, and matches the recipient shown below.")
                            .font(.caption)
                            .foregroundStyle(WalletPalette.muted)
                            .multilineTextAlignment(.center)
                    }
                    .cardStyle()

                    VStack(alignment: .leading, spacing: 14) {
                        HStack(alignment: .firstTextBaseline) {
                            Text("Amount")
                                .foregroundStyle(WalletPalette.muted)
                            Spacer()
                            Text(state.amountDisplay)
                                .font(.title2.bold())
                        }
                        if state.verified.amountAtomicUnits == nil {
                            TextField("Amount in ACT", text: $state.openAmountACT)
                                .textFieldStyle(.roundedBorder)
                                .walletNumberKeyboard()
                        }
                        if !state.verified.memo.isEmpty {
                            Divider()
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Note")
                                    .font(.caption.bold())
                                    .foregroundStyle(WalletPalette.muted)
                                Text(state.verified.memo)
                            }
                        }
                        Divider()
                        LabeledContent("Network", value: wallet.network.displayName)
                        LabeledContent("Network fee", value: "0.001 ACT")
                        LabeledContent("Recipient", value: WalletHex.short(state.verified.recipient))
                        LabeledContent("Reference", value: WalletHex.short(state.verified.reference))
                    }
                    .cardStyle()

                    status

                    if !isPaid {
                        Button(action: { Task { await state.pay(wallet: wallet) } }) {
                            Label(buttonTitle, systemImage: "faceid")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)
                        .disabled(!state.canPay)
                    }

                    Text("This request cannot move money by itself. The transfer is created and authorized only after you approve it here.")
                        .font(.caption2)
                        .foregroundStyle(WalletPalette.muted)
                        .multilineTextAlignment(.center)
                }
                .padding(20)
            }
            .background(WalletBackground())
            .navigationTitle("Review payment")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(isPaid ? "Done" : "Close") { dismiss() }
                }
            }
            .task { await state.refresh(wallet: wallet) }
        }
    }

    private var isPaid: Bool {
        if case .paid = state.phase { return true }
        return false
    }

    @ViewBuilder private var status: some View {
        switch state.phase {
        case .review:
            Label("Ready to pay", systemImage: "checkmark.circle")
                .foregroundStyle(WalletPalette.mint)
        case .preparing:
            progress("Preparing payment…")
        case .authorizing:
            progress("Waiting for approval…")
        case .submitting:
            progress("Sending payment…")
        case .pending:
            progress("Sent · waiting for finality…")
        case let .paid(height):
            VStack(spacing: 10) {
                Image(systemName: "checkmark.circle.fill")
                    .font(.system(size: 42))
                    .foregroundStyle(WalletPalette.mint)
                Text("Payment complete")
                    .font(.title3.bold())
                Text("Verified on ActiveChain at block \(height).")
                    .font(.caption)
                    .foregroundStyle(WalletPalette.muted)
            }
            .frame(maxWidth: .infinity)
            .cardStyle()
        case let .failed(message):
            VStack(alignment: .leading, spacing: 8) {
                Label("Payment not sent", systemImage: "exclamationmark.triangle.fill")
                    .font(.headline)
                    .foregroundStyle(.orange)
                Text(message)
                    .font(.caption)
                    .foregroundStyle(WalletPalette.muted)
            }
            .cardStyle()
        }
    }

    private func progress(_ text: String) -> some View {
        HStack(spacing: 12) {
            ProgressView()
            Text(text).font(.subheadline.weight(.semibold))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .cardStyle()
    }

    private var buttonTitle: String {
        if case .failed = state.phase { return "Try again" }
        return "Pay"
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
                        VStack(spacing: 12) {
                            WalletPaymentRequestQRCode(request: request)
                                .frame(maxWidth: 280, maxHeight: 280)
                                .padding()
                                .background(.white, in: RoundedRectangle(cornerRadius: 24))
                            if let atomic = request.body.amountAtomicUnits {
                                Text(displayACT(atomic))
                                    .font(.title2.bold())
                            } else {
                                Text("Open amount")
                                    .font(.title2.bold())
                            }
                            if !request.body.memo.isEmpty {
                                Text(request.body.memo)
                                    .font(.callout)
                                    .foregroundStyle(WalletPalette.muted)
                                    .multilineTextAlignment(.center)
                            }
                        }
                        .cardStyle()

                        if let link = try? request.deepLink {
                            ShareLink(item: link) {
                                Label("Share request", systemImage: "square.and.arrow.up")
                                    .frame(maxWidth: .infinity)
                            }
                            .buttonStyle(.borderedProminent)
                            .controlSize(.large)
                            Text("The payer can verify this request before approving the transfer.")
                                .font(.caption)
                                .foregroundStyle(WalletPalette.muted)
                                .multilineTextAlignment(.center)
                        }
                    } else {
                        VStack(alignment: .leading, spacing: 14) {
                            Text("Amount")
                                .font(.headline)
                            TextField("0.00 ACT", text: $amount)
                                .textFieldStyle(.roundedBorder)
                                .walletNumberKeyboard()
                            Text("Leave this blank if the payer should choose the amount.")
                                .font(.caption)
                                .foregroundStyle(WalletPalette.muted)
                            Text("Note")
                                .font(.headline)
                            TextField("Dinner, tickets, rent…", text: $memo)
                                .textFieldStyle(.roundedBorder)
                        }
                        .cardStyle()

                        Button("Create request") {
                            do {
                                let trimmed = amount.trimmingCharacters(in: .whitespacesAndNewlines)
                                request = try WalletPaymentRequestService().create(
                                    amountACT: trimmed.isEmpty ? nil : trimmed,
                                    memo: memo
                                )
                                error = nil
                            } catch {
                                self.error = error.localizedDescription
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)
                    }
                    if let error {
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                }
                .padding(20)
            }
            .background(WalletBackground())
            .navigationTitle(request == nil ? "Request payment" : "Payment request")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(request == nil ? "Close" : "Done") { dismiss() }
                }
            }
        }
    }

    private func displayACT(_ atomic: String) -> String {
        let padded = String(repeating: "0", count: max(0, 19 - atomic.count)) + atomic
        let split = padded.index(padded.endIndex, offsetBy: -18)
        var fraction = String(padded[split...])
        while fraction.last == "0" { fraction.removeLast() }
        return String(padded[..<split]) + (fraction.isEmpty ? "" : "." + fraction) + " ACT"
    }
}
