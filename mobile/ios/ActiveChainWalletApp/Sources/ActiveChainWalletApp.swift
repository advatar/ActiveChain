import SwiftUI
import ActiveChainWallet

@main
struct ActiveChainWalletApp: App {
    var body: some Scene { WindowGroup { TransferPreviewView() } }
}

struct TransferPreviewView: View {
    private let bridge = LocalWalletBridge()
    @State private var recipient = "did:activechain:test"
    @State private var amount = "10"
    @State private var status = "Review transfer before approval"
    @State private var network = "kanalen"

    private let networks = ["kanalen", "roslagen", "tralhavet"]

    var body: some View {
        NavigationStack {
            Form {
                Section("Network") {
                    Picker("Testnet", selection: $network) { ForEach(networks, id: \.self) { Text($0) } }
                }
                Section("Recipient") { TextField("DID", text: $recipient).textInputAutocapitalization(.never) }
                Section("Amount") { TextField("ACT", text: $amount).keyboardType(.numberPad) }
                Button("Preview and approve") {
                    let preview = bridge.previewTransfer(recipient: recipient, amount: UInt64(amount) ?? 0,
                                                          feeReserve: 2, validUntil: 100, currentHeight: 1)
                    do { _ = try bridge.approveTransfer(preview); status = "Approved canonical intent" }
                    catch { status = "Rejected by wallet policy" }
                }
                Text(status).foregroundStyle(.secondary)
            }.navigationTitle("ActiveChain Wallet")
        }
    }
}
