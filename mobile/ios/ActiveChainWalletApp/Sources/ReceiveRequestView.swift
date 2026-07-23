import CoreImage
import CoreImage.CIFilterBuiltins
import SwiftUI

#if os(iOS)
import UIKit
#elseif os(macOS)
import AppKit
#endif

struct ReceiveRequestView: View {
    @Environment(\.dismiss) private var dismiss
    let request: ReceiveRequest
    @State private var copied = false

    var body: some View {
        ZStack {
            WalletBackground()
            ScrollView {
                VStack(spacing: 20) {
                    Text("Receive ACT")
                        .font(.title.bold())
                    Text("Share this request to receive on \(request.networkID.capitalized).")
                        .font(.callout)
                        .foregroundStyle(WalletPalette.muted)
                        .multilineTextAlignment(.center)

                    qrCode
                        .frame(width: 230, height: 230)
                        .padding(18)
                        .background(.white, in: RoundedRectangle(cornerRadius: 22))

                    VStack(alignment: .leading, spacing: 8) {
                        Text("Receiving identifier")
                            .font(.caption)
                            .foregroundStyle(WalletPalette.muted)
                        Text(request.address)
                            .font(.callout.monospaced())
                            .textSelection(.enabled)
                    }
                    .cardStyle()

                    HStack(spacing: 12) {
                        Button(copied ? "Copied" : "Copy request") {
                            copy(request.payload)
                            copied = true
                        }
                        .buttonStyle(PrimaryWalletButton())

                        ShareLink(item: request.payload) {
                            Label("Share", systemImage: "square.and.arrow.up")
                        }
                        .buttonStyle(SecondaryWalletButton())
                    }

                    Text("The network and genesis are included to prevent sending to the wrong ActiveChain network.")
                        .font(.caption)
                        .foregroundStyle(WalletPalette.muted)
                        .multilineTextAlignment(.center)
                }
                .padding(24)
                .frame(maxWidth: 520)
                .frame(maxWidth: .infinity)
            }
        }
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Close") { dismiss() }
            }
        }
    }

    @ViewBuilder
    private var qrCode: some View {
        if let image = QRCodeGenerator.image(for: request.payload) {
            Image(decorative: image, scale: 1)
                .interpolation(.none)
                .resizable()
                .scaledToFit()
        } else {
            Image(systemName: "qrcode")
                .resizable()
                .scaledToFit()
                .foregroundStyle(.black)
                .padding(30)
        }
    }

    private func copy(_ value: String) {
#if os(iOS)
        UIPasteboard.general.string = value
#elseif os(macOS)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value, forType: .string)
#endif
    }
}

enum QRCodeGenerator {
    static func image(for value: String) -> CGImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(value.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        return CIContext().createCGImage(output, from: output.extent)
    }
}
