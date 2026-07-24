import SwiftUI

struct AmberComposerView: View {
    let boards: [AmberBoard]
    let board: AmberBoard?
    let quote: AmberBondQuote
    @Environment(\.dismiss) private var dismiss
    @State private var selectedBoardID: AmberBoardID?
    @State private var subject = ""
    @State private var bodyText = ""
    @State private var understandsBond = false

    init(boards: [AmberBoard], board: AmberBoard?, quote: AmberBondQuote) {
        self.boards = boards
        self.board = board
        self.quote = quote
        _selectedBoardID = State(initialValue: board?.id)
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    header
                    boardPicker
                    contentFields
                    bondDisclosure
                }
                .padding(24)
                .frame(maxWidth: 680)
                .frame(maxWidth: .infinity)
            }
            .background(AmberStyle.paper)
            .navigationTitle("New bonded post")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Lock \(quote.amountLockedAtSubmission) and post") {}
                        .disabled(!canSubmit)
                }
            }
        }
        .tint(AmberStyle.rust)
        .frame(minWidth: 480, minHeight: 620)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(selectedBoard?.id.description ?? "Choose a board")
                .font(.system(.title, design: .monospaced, weight: .black))
                .foregroundStyle(AmberStyle.rust)
            Text("Posting is not free. The fee is spent; the bond stays locked until a final outcome.")
                .foregroundStyle(AmberStyle.mutedInk)
        }
    }

    private var boardPicker: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("BOARD")
                .font(.caption.monospaced().weight(.bold))
                .foregroundStyle(AmberStyle.rust)
            Picker("Board", selection: $selectedBoardID) {
                Text("Choose a board").tag(Optional<AmberBoardID>.none)
                ForEach(boards) { candidate in
                    Text("\(candidate.id.description) \(candidate.title)")
                        .tag(Optional(candidate.id))
                }
            }
            .pickerStyle(.menu)
            .accessibilityIdentifier("amber.composer.board")
        }
    }

    private var contentFields: some View {
        VStack(alignment: .leading, spacing: 12) {
            TextField("Subject", text: $subject)
                .textFieldStyle(.roundedBorder)
            TextEditor(text: $bodyText)
                .scrollContentBackground(.hidden)
                .padding(10)
                .frame(minHeight: 140)
                .background(AmberStyle.card)
                .overlay { Rectangle().stroke(AmberStyle.border) }
            Button {
                // Content selection and verified encoding arrive with the content-network slice.
            } label: {
                Label("Choose image", systemImage: "photo.badge.plus")
            }
        }
    }

    private var bondDisclosure: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("BOND QUOTE · POLICY \(quote.policyRevision)")
                .font(.caption.monospaced().weight(.bold))
                .foregroundStyle(AmberStyle.rust)

            QuoteRow(label: "Non-refundable posting fee", value: quote.postingFee)
            QuoteRow(label: "Refundable post bond", value: quote.postBond)
            QuoteRow(label: "Maximum moderation slash", value: quote.maximumSlash)
            Divider()
            QuoteRow(label: "Locked now", value: quote.amountLockedAtSubmission, emphasized: true)

            Text("An upheld, final report can delete the post and slash up to the stated maximum. A reporter reward may come from that penalty. Emergency hiding alone cannot settle the bond. Unpenalized pruning or expiry returns the bond through a private one-shot claim.")
                .font(.caption)
                .foregroundStyle(AmberStyle.mutedInk)

            Toggle(
                "I understand that a finalized rule violation can forfeit my bond.",
                isOn: $understandsBond
            )
            .font(.subheadline.weight(.semibold))

            Text(readiness.message)
                .font(.caption2.monospaced())
                .foregroundStyle(AmberStyle.rust)
        }
        .padding(18)
        .background(AmberStyle.card)
        .overlay(alignment: .leading) {
            Rectangle().fill(AmberStyle.rust).frame(width: 3)
        }
        .overlay { Rectangle().stroke(AmberStyle.border) }
    }

    private var canSubmit: Bool {
        readiness == .ready
    }

    private var selectedBoard: AmberBoard? {
        boards.first { $0.id == selectedBoardID }
    }

    private var readiness: AmberComposerReadiness {
        AmberComposerReadiness.evaluate(
            board: selectedBoardID,
            body: bodyText,
            understandsBond: understandsBond,
            liveSubmissionAvailable: false
        )
    }
}

private struct QuoteRow: View {
    let label: String
    let value: UInt64
    var emphasized = false

    var body: some View {
        HStack {
            Text(label)
            Spacer()
            Text("\(value) test units")
                .font(.body.monospacedDigit().weight(emphasized ? .bold : .regular))
        }
        .foregroundStyle(emphasized ? AmberStyle.ink : AmberStyle.mutedInk)
    }
}
