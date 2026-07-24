import SwiftUI

struct AmberRootView: View {
    private let boards = AmberSampleData.boards
    private let rpcClient = AmberRPCClient()
    @State private var selection: AmberBoardID?
    @State private var connection: AmberConnectionState = .checking
    @State private var refreshPresentation = AmberNetworkRefreshPresentation()
    @State private var isComposerPresented = false

    var body: some View {
        NavigationSplitView {
            boardIndex
                .navigationSplitViewColumnWidth(min: 240, ideal: 280, max: 340)
        } detail: {
            if let board = boards.first(where: { $0.id == selection }) {
                BoardView(board: board)
            } else {
                WelcomeView()
            }
        }
        .tint(AmberStyle.rust)
        .background(AmberStyle.paper)
        .sheet(isPresented: $isComposerPresented) {
            AmberComposerView(
                board: boards.first(where: { $0.id == selection }),
                quote: .kanalenPreview
            )
        }
        .toolbar {
            ToolbarItem {
                Button {
                    isComposerPresented = true
                } label: {
                    Label("New bonded post", systemImage: "square.and.pencil")
                }
            }
        }
        .task {
            await refreshNetworkStatus()
        }
    }

    private var boardIndex: some View {
        List(boards, selection: $selection) { board in
            VStack(alignment: .leading, spacing: 4) {
                HStack(alignment: .firstTextBaseline) {
                    Text(board.id.description)
                        .font(.system(.headline, design: .monospaced, weight: .bold))
                        .foregroundStyle(AmberStyle.ink)
                    Spacer()
                    Text("\(board.activeUsers)")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(AmberStyle.mutedInk)
                }
                Text(board.title)
                    .font(.subheadline.weight(.semibold))
                Text(board.summary)
                    .font(.caption)
                    .foregroundStyle(AmberStyle.mutedInk)
                    .lineLimit(2)
            }
            .padding(.vertical, 6)
            .tag(board.id)
            .listRowBackground(AmberStyle.paper)
        }
        .scrollContentBackground(.hidden)
        .background(AmberStyle.paper)
        .navigationTitle("AMBER")
        .safeAreaInset(edge: .bottom) {
            NetworkStrip(
                network: .kanalenTestnet,
                state: connection,
                refreshPresentation: refreshPresentation
            )
        }
        .toolbar {
            ToolbarItem {
                Button {
                    Task { await refreshNetworkStatus() }
                } label: {
                    if refreshPresentation.isRefreshing {
                        ProgressView()
                            .controlSize(.small)
                            .accessibilityLabel("Checking network")
                    } else {
                        Label(
                            "Refresh network status",
                            systemImage: "point.3.connected.trianglepath.dotted"
                        )
                    }
                }
                .disabled(refreshPresentation.isRefreshing)
                .help(
                    refreshPresentation.isRefreshing
                        ? "Checking Kanalen testnet"
                        : "Refresh Kanalen testnet status"
                )
            }
        }
    }

    @MainActor
    private func refreshNetworkStatus() async {
        guard refreshPresentation.begin() else {
            return
        }
        defer { refreshPresentation.complete() }
        connection = .checking
        do {
            connection = try await rpcClient.status(for: .kanalenTestnet).connectionState
        } catch {
            connection = .unavailable
        }
    }
}

private struct WelcomeView: View {
    var body: some View {
        ZStack {
            AmberStyle.paper.ignoresSafeArea()
            VStack(alignment: .leading, spacing: 18) {
                Text("AMBER")
                    .font(.system(size: 54, weight: .black, design: .serif))
                    .tracking(3)
                    .foregroundStyle(AmberStyle.rust)
                Text("A private imageboard on ActiveChain")
                    .font(.title2.weight(.semibold))
                    .foregroundStyle(AmberStyle.ink)
                Rectangle()
                    .fill(AmberStyle.rust)
                    .frame(width: 72, height: 4)
                Text("Pick a board from the index. This native preview uses local sample state while verified Kanalen RPC and content retrieval are being connected.")
                    .font(.body)
                    .foregroundStyle(AmberStyle.mutedInk)
                    .frame(maxWidth: 520, alignment: .leading)
                Text("PROTOTYPE · THIRD-PARTY AUDIT PENDING")
                    .font(.caption.monospaced().weight(.bold))
                    .foregroundStyle(AmberStyle.rust)
            }
            .padding(42)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

private struct BoardView: View {
    let board: AmberBoard

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                VStack(alignment: .leading, spacing: 7) {
                    Text(board.id.description)
                        .font(.system(size: 42, weight: .black, design: .monospaced))
                        .foregroundStyle(AmberStyle.rust)
                    Text(board.title)
                        .font(.title2.weight(.bold))
                    Text(board.summary)
                        .foregroundStyle(AmberStyle.mutedInk)
                }
                .padding(.bottom, 22)

                ForEach(board.threads) { thread in
                    ThreadCard(thread: thread)
                }
            }
            .padding(24)
            .frame(maxWidth: 920, alignment: .leading)
        }
        .background(AmberStyle.paper)
        .navigationTitle(board.title)
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
    }
}

private struct ThreadCard: View {
    let thread: AmberThread

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Text(thread.subject)
                    .font(.headline.weight(.bold))
                    .foregroundStyle(AmberStyle.ink)
                Spacer()
                Text("No.\(thread.number)")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(AmberStyle.mutedInk)
            }
            ForEach(thread.posts) { post in
                HStack(alignment: .top, spacing: 12) {
                    ImagePlaceholder()
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Text(post.authorLabel)
                                .font(.caption.weight(.bold))
                                .foregroundStyle(AmberStyle.olive)
                            Text("No.\(post.id.postNumber)")
                                .font(.caption.monospacedDigit())
                                .foregroundStyle(AmberStyle.mutedInk)
                        }
                        Text(post.body)
                            .font(.body)
                            .textSelection(.enabled)
                            .foregroundStyle(AmberStyle.ink)
                    }
                }
            }
        }
        .padding(16)
        .background(AmberStyle.card)
        .overlay(alignment: .leading) {
            Rectangle().fill(AmberStyle.rust).frame(width: 3)
        }
        .overlay {
            Rectangle().stroke(AmberStyle.border, lineWidth: 1)
        }
        .padding(.bottom, 12)
    }
}

private struct ImagePlaceholder: View {
    var body: some View {
        ZStack {
            AmberStyle.imagePaper
            Image(systemName: "photo")
                .font(.title2)
                .foregroundStyle(AmberStyle.rust.opacity(0.7))
        }
        .frame(width: 92, height: 72)
        .overlay { Rectangle().stroke(AmberStyle.border) }
        .accessibilityLabel("Image preview unavailable")
    }
}

private struct NetworkStrip: View {
    let network: AmberNetwork
    let state: AmberConnectionState
    let refreshPresentation: AmberNetworkRefreshPresentation

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack {
                Circle()
                    .fill(state.isAvailable ? AmberStyle.olive : AmberStyle.rust)
                    .frame(width: 7, height: 7)
                Text(state.label)
                    .font(.caption.weight(.semibold))
                Spacer()
                Text("TESTNET")
                    .font(.caption2.monospaced().weight(.bold))
            }
            HStack {
                Text(network.rpcURL.host() ?? network.name)
                Spacer()
                if let completionLabel = refreshPresentation.completionLabel {
                    Text(completionLabel)
                }
            }
            .font(.caption2.monospaced())
            .foregroundStyle(AmberStyle.mutedInk)
        }
        .padding(12)
        .background(AmberStyle.card)
        .overlay(alignment: .top) { Divider() }
    }
}

enum AmberStyle {
    static let paper = Color(red: 0.96, green: 0.91, blue: 0.78)
    static let card = Color(red: 0.99, green: 0.96, blue: 0.87)
    static let imagePaper = Color(red: 0.90, green: 0.83, blue: 0.67)
    static let ink = Color(red: 0.14, green: 0.11, blue: 0.08)
    static let mutedInk = Color(red: 0.36, green: 0.31, blue: 0.24)
    static let rust = Color(red: 0.60, green: 0.20, blue: 0.08)
    static let olive = Color(red: 0.24, green: 0.32, blue: 0.12)
    static let border = Color(red: 0.45, green: 0.32, blue: 0.20).opacity(0.45)
}
