import SwiftUI

@main
struct ActiveChainWalletApp: App {
    var body: some Scene {
        WindowGroup { WalletRootView() }
    }
}

private enum WalletTab: Hashable {
    case home, activity, approvals, identity
}

private struct WalletPalette {
    static let ink = Color(red: 0.035, green: 0.055, blue: 0.09)
    static let panel = Color(red: 0.075, green: 0.10, blue: 0.145)
    static let mint = Color(red: 0.45, green: 0.96, blue: 0.71)
    static let cyan = Color(red: 0.34, green: 0.80, blue: 0.94)
    static let violet = Color(red: 0.61, green: 0.54, blue: 0.98)
    static let muted = Color.white.opacity(0.62)
}

struct WalletRootView: View {
    @Environment(\.scenePhase) private var scenePhase
    @State private var selection: WalletTab = .home
    @State private var showingSend = false

    var body: some View {
        TabView(selection: $selection) {
            NavigationStack {
                HomeView(showingSend: $showingSend, selection: $selection)
            }
            .tag(WalletTab.home)
            .tabItem { Label("Wallet", systemImage: "wallet.bifold.fill") }

            NavigationStack { ActivityView() }
                .tag(WalletTab.activity)
                .tabItem { Label("Activity", systemImage: "clock.arrow.circlepath") }

            NavigationStack { ApprovalsView() }
                .tag(WalletTab.approvals)
                .tabItem { Label("Approvals", systemImage: "checkmark.shield.fill") }
                .badge(2)

            NavigationStack { IdentityView() }
                .tag(WalletTab.identity)
                .tabItem { Label("Identity", systemImage: "person.text.rectangle.fill") }
        }
        .tint(WalletPalette.mint)
        .preferredColorScheme(.dark)
        .sheet(isPresented: $showingSend) {
            NavigationStack { SendFlowView() }
                .presentationDetents([.large])
        }
        .onAppear(perform: consumeAgentIntentRoute)
        .onChange(of: scenePhase) { _, phase in
            if phase == .active { consumeAgentIntentRoute() }
        }
    }

    private func consumeAgentIntentRoute() {
        guard AgentIntentRouter.consume() != nil else { return }
        selection = .approvals
    }
}

private struct HomeView: View {
    @Binding var showingSend: Bool
    @Binding var selection: WalletTab

    var body: some View {
        ZStack {
            WalletBackground()
            ScrollView {
                LazyVStack(spacing: 18) {
                    Header()
                    BalanceCard(showingSend: $showingSend)
                    NetworkCard()
                    ApprovalBanner { selection = .approvals }
                    AssetSection()
                    SecurityFooter()
                }
                .padding(.horizontal, 20)
                .padding(.bottom, 32)
            }
            .scrollIndicators(.hidden)
        }
        .toolbar(.hidden, for: .navigationBar)
    }
}

private struct Header: View {
    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                Circle().fill(WalletPalette.mint.opacity(0.16))
                Image(systemName: "a.circle.fill")
                    .font(.system(size: 30, weight: .semibold))
                    .foregroundStyle(WalletPalette.mint)
            }
            .frame(width: 46, height: 46)
            VStack(alignment: .leading, spacing: 2) {
                Text("Good morning")
                    .font(.subheadline)
                    .foregroundStyle(WalletPalette.muted)
                Text("Johan")
                    .font(.title2.bold())
            }
            Spacer()
            Button(action: {}) {
                Image(systemName: "qrcode.viewfinder")
                    .font(.title3.weight(.semibold))
                    .frame(width: 44, height: 44)
                    .background(.white.opacity(0.08), in: Circle())
            }
            .accessibilityLabel("Scan QR code")
        }
        .padding(.top, 14)
    }
}

private struct BalanceCard: View {
    @Binding var showingSend: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack {
                Label("Total balance", systemImage: "sparkles")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.white.opacity(0.72))
                Spacer()
                Text("TESTNET")
                    .font(.caption2.bold())
                    .tracking(1.3)
                    .foregroundStyle(WalletPalette.ink)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(WalletPalette.mint, in: Capsule())
            }

            VStack(alignment: .leading, spacing: 4) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text("12,480.42")
                        .font(.system(size: 34, weight: .bold, design: .rounded))
                        .minimumScaleFactor(0.65)
                        .lineLimit(1)
                    Text("ACT")
                        .font(.title2.bold())
                        .foregroundStyle(.white.opacity(0.88))
                }
                Text("≈ 2,742.69 USD")
                    .font(.callout)
                    .foregroundStyle(.white.opacity(0.64))
            }

            HStack(spacing: 12) {
                PrimaryAction(title: "Send", icon: "arrow.up.right", emphasized: true) {
                    showingSend = true
                }
                PrimaryAction(title: "Receive", icon: "arrow.down.left", emphasized: false) {}
                PrimaryAction(title: "Fund", icon: "plus", emphasized: false) {}
            }
        }
        .padding(22)
        .background(
            LinearGradient(
                colors: [
                    Color(red: 0.12, green: 0.29, blue: 0.27),
                    Color(red: 0.08, green: 0.16, blue: 0.25),
                    Color(red: 0.16, green: 0.12, blue: 0.28)
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            ),
            in: RoundedRectangle(cornerRadius: 28, style: .continuous)
        )
        .overlay(alignment: .topTrailing) {
            Circle()
                .fill(WalletPalette.mint.opacity(0.16))
                .frame(width: 150, height: 150)
                .blur(radius: 4)
                .offset(x: 48, y: -62)
                .allowsHitTesting(false)
        }
        .overlay {
            RoundedRectangle(cornerRadius: 28, style: .continuous)
                .stroke(.white.opacity(0.1), lineWidth: 1)
        }
        .accessibilityElement(children: .contain)
    }
}

private struct PrimaryAction: View {
    let title: String
    let icon: String
    let emphasized: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(spacing: 8) {
                Image(systemName: icon).font(.headline)
                Text(title).font(.caption.weight(.semibold))
            }
            .frame(maxWidth: .infinity)
            .frame(height: 62)
            .foregroundStyle(emphasized ? WalletPalette.ink : .white)
            .background(
                emphasized ? WalletPalette.mint : .white.opacity(0.09),
                in: RoundedRectangle(cornerRadius: 17, style: .continuous)
            )
        }
        .buttonStyle(.plain)
    }
}

private struct NetworkCard: View {
    var body: some View {
        HStack(spacing: 14) {
            ZStack {
                Circle().fill(WalletPalette.cyan.opacity(0.15))
                Circle().fill(WalletPalette.cyan).frame(width: 9, height: 9)
            }
            .frame(width: 42, height: 42)
            VStack(alignment: .leading, spacing: 3) {
                Text("Kanalen")
                    .font(.headline)
                Text("Finalized block 184,291 · 3 validators")
                    .font(.caption)
                    .foregroundStyle(WalletPalette.muted)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 3) {
                Text("Healthy")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(WalletPalette.mint)
                Text("2s ago")
                    .font(.caption2)
                    .foregroundStyle(WalletPalette.muted)
            }
        }
        .cardStyle()
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Kanalen testnet healthy, finalized block 184291, three validators")
    }
}

private struct ApprovalBanner: View {
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 14) {
                ZStack {
                    RoundedRectangle(cornerRadius: 14)
                        .fill(WalletPalette.violet.opacity(0.2))
                    Image(systemName: "wand.and.stars")
                        .foregroundStyle(WalletPalette.violet)
                }
                .frame(width: 46, height: 46)
                VStack(alignment: .leading, spacing: 3) {
                    Text("2 agent actions need you")
                        .font(.headline)
                    Text("Review scope, recipient and exact fee")
                        .font(.caption)
                        .foregroundStyle(WalletPalette.muted)
                }
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.caption.bold())
                    .foregroundStyle(WalletPalette.muted)
            }
            .cardStyle()
        }
        .buttonStyle(.plain)
    }
}

private struct AssetSection: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Assets").font(.title3.bold())
                Spacer()
                Button("Manage") {}
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(WalletPalette.mint)
            }
            AssetRow(
                symbol: "ACT",
                name: "ActiveChain",
                amount: "12,480.42",
                value: "$2,742.69",
                color: WalletPalette.mint
            )
            AssetRow(
                symbol: "tEUR",
                name: "Test Euro",
                amount: "240.00",
                value: "$281.35",
                color: WalletPalette.cyan
            )
        }
    }
}

private struct AssetRow: View {
    let symbol: String
    let name: String
    let amount: String
    let value: String
    let color: Color

    var body: some View {
        HStack(spacing: 14) {
            Text(String(symbol.prefix(1)))
                .font(.headline)
                .foregroundStyle(WalletPalette.ink)
                .frame(width: 44, height: 44)
                .background(color, in: Circle())
            VStack(alignment: .leading, spacing: 3) {
                Text(name).font(.headline)
                Text(symbol).font(.caption).foregroundStyle(WalletPalette.muted)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 3) {
                Text(amount).font(.headline.monospacedDigit())
                Text(value).font(.caption).foregroundStyle(WalletPalette.muted)
            }
        }
        .cardStyle()
        .accessibilityElement(children: .combine)
    }
}

private struct SecurityFooter: View {
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "lock.shield.fill").foregroundStyle(WalletPalette.mint)
            Text("Keys protected on this device · Post-quantum signing")
                .font(.caption)
                .foregroundStyle(WalletPalette.muted)
        }
        .frame(maxWidth: .infinity)
        .padding(.top, 4)
    }
}

private struct ActivityView: View {
    private let entries = [
        ("arrow.down.left", "Received ACT", "Faucet · finalized", "+ 2,500.00 ACT", WalletPalette.mint),
        ("arrow.up.right", "Sent to did:…7f2c", "Block 184,102", "− 42.00 ACT", Color.white),
        ("checkmark.shield", "Agent settlement", "Research agent · verified", "− 1.20 ACT", WalletPalette.violet),
        ("person.crop.rectangle", "Credential received", "Kanalen Test ID", "OpenWallet", WalletPalette.cyan)
    ]

    var body: some View {
        ZStack {
            WalletBackground()
            ScrollView {
                LazyVStack(spacing: 12) {
                    ForEach(Array(entries.enumerated()), id: \.offset) { _, item in
                        HStack(spacing: 14) {
                            Image(systemName: item.0)
                                .foregroundStyle(item.4)
                                .frame(width: 42, height: 42)
                                .background(item.4.opacity(0.13), in: Circle())
                            VStack(alignment: .leading, spacing: 4) {
                                Text(item.1).font(.headline)
                                Text(item.2).font(.caption).foregroundStyle(WalletPalette.muted)
                            }
                            Spacer()
                            Text(item.3)
                                .font(.subheadline.weight(.semibold).monospacedDigit())
                                .foregroundStyle(item.4)
                        }
                        .cardStyle()
                    }
                }
                .padding(20)
            }
        }
        .navigationTitle("Activity")
        .toolbarBackground(WalletPalette.ink, for: .navigationBar)
    }
}

private struct ApprovalsView: View {
    @StateObject private var agents = AgentWalletStore()

    init() {
        let store = AgentWalletStore()
        _ = store.delegate(AgentDelegation(
            id: "did:active:agent-research", label: "Research agent",
            capabilities: ["Pay approved providers", "Read public artifacts"],
            dailyLimit: 50, expiresAt: 240_000, connection: .thirdParty, spentToday: 18
        ))
        _ = store.delegate(AgentDelegation(
            id: "did:active:agent-travel", label: "Travel planner",
            capabilities: ["Request selected credentials"], dailyLimit: 10,
            expiresAt: 210_000, connection: .remote, spentToday: 0
        ))
        _agents = StateObject(wrappedValue: store)
    }

    var body: some View {
        ZStack {
            WalletBackground()
            ScrollView {
                VStack(spacing: 16) {
                    NavigationLink {
                        AgentInventoryView(store: agents)
                    } label: {
                        HStack(spacing: 14) {
                            Image(systemName: "person.2.badge.gearshape.fill")
                                .foregroundStyle(WalletPalette.mint)
                                .frame(width: 42, height: 42)
                                .background(WalletPalette.mint.opacity(0.13), in: Circle())
                            VStack(alignment: .leading, spacing: 3) {
                                Text("Manage agents").font(.headline)
                                Text("2 active · capabilities, budgets and revocation")
                                    .font(.caption).foregroundStyle(WalletPalette.muted)
                            }
                            Spacer()
                            Image(systemName: "chevron.right")
                                .font(.caption.bold()).foregroundStyle(WalletPalette.muted)
                        }
                        .cardStyle()
                    }
                    .buttonStyle(.plain)
                    ApprovalCard(
                        agent: "Research agent",
                        action: "Pay data provider",
                        detail: "18.00 ACT + 0.08 fee",
                        risk: "Within daily limit",
                        color: WalletPalette.mint
                    )
                    ApprovalCard(
                        agent: "Travel planner",
                        action: "Share identity credential",
                        detail: "Name · age over 18 · nationality",
                        risk: "3 claims requested",
                        color: WalletPalette.violet
                    )
                    Text("Every approval is bound to the exact action, recipient, fee, claims and expiry.")
                        .font(.caption)
                        .foregroundStyle(WalletPalette.muted)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 24)
                }
                .padding(20)
            }
        }
        .navigationTitle("Approvals")
        .toolbarBackground(WalletPalette.ink, for: .navigationBar)
    }
}

private struct AgentInventoryView: View {
    @ObservedObject var store: AgentWalletStore

    var body: some View {
        ZStack {
            WalletBackground()
            ScrollView {
                VStack(spacing: 14) {
                    Text("Agents are authenticated principals, not apps the wallet can inspect. Controls below limit their ActiveChain authority.")
                        .font(.caption)
                        .foregroundStyle(WalletPalette.muted)
                        .padding(16)
                        .background(WalletPalette.violet.opacity(0.12),
                                    in: RoundedRectangle(cornerRadius: 18))
                    ForEach(store.agents) { agent in
                        NavigationLink {
                            AgentDetailView(store: store, agentID: agent.id)
                        } label: {
                            AgentRow(agent: agent)
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(20)
            }
        }
        .navigationTitle("Agents")
        .toolbarBackground(WalletPalette.ink, for: .navigationBar)
    }
}

private struct AgentRow: View {
    let agent: AgentDelegation

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: agent.connection == .remote ? "cloud.fill" : "app.connected.to.app.below.fill")
                .foregroundStyle(statusColor)
                .frame(width: 44, height: 44)
                .background(statusColor.opacity(0.14), in: Circle())
            VStack(alignment: .leading, spacing: 4) {
                Text(agent.label).font(.headline)
                Text("\(agent.connection.rawValue) · \(agent.capabilities.count) capabilities")
                    .font(.caption).foregroundStyle(WalletPalette.muted)
                ProgressView(value: Double(agent.spentToday), total: Double(agent.dailyLimit))
                    .tint(statusColor)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 4) {
                Text(statusLabel).font(.caption.bold()).foregroundStyle(statusColor)
                Text("\(agent.spentToday)/\(agent.dailyLimit) ACT")
                    .font(.caption2.monospacedDigit()).foregroundStyle(WalletPalette.muted)
            }
        }
        .cardStyle()
        .accessibilityElement(children: .combine)
    }

    private var statusLabel: String {
        switch agent.lifecycle {
        case .active: "Active"
        case .paused: "Paused"
        case .revocationPending: "Revoking"
        case .revoked: "Revoked"
        }
    }

    private var statusColor: Color {
        switch agent.lifecycle {
        case .active: WalletPalette.mint
        case .paused: .orange
        case .revocationPending: WalletPalette.violet
        case .revoked: .red
        }
    }
}

private struct AgentDetailView: View {
    @ObservedObject var store: AgentWalletStore
    let agentID: String

    private var agent: AgentDelegation? {
        store.agents.first(where: { $0.id == agentID })
    }

    var body: some View {
        ZStack {
            WalletBackground()
            if let agent {
                ScrollView {
                    VStack(alignment: .leading, spacing: 18) {
                        AgentRow(agent: agent)
                        DetailSection(title: "Verified principal", values: [agent.id])
                        DetailSection(title: "Granted capabilities", values: agent.capabilities)
                        DetailSection(title: "Enforcement", values: [
                            "Exact request and nonce binding",
                            "Wallet approval before secure signing",
                            "Validator capability and revocation checks"
                        ])
                        Text("This wallet can stop ActiveChain signing and revoke chain capabilities. It cannot monitor unrelated activity inside a third-party app.")
                            .font(.caption).foregroundStyle(WalletPalette.muted)
                        lifecycleControls(agent)
                    }
                    .padding(20)
                }
            }
        }
        .navigationTitle(agent?.label ?? "Agent")
        .toolbarBackground(WalletPalette.ink, for: .navigationBar)
    }

    @ViewBuilder
    private func lifecycleControls(_ agent: AgentDelegation) -> some View {
        switch agent.lifecycle {
        case .active:
            Button("Pause agent") { store.pause(agentID: agent.id) }
                .buttonStyle(SecondaryWalletButton())
            Button("Revoke capabilities") { store.revoke(agentID: agent.id) }
                .buttonStyle(PrimaryWalletButton())
                .tint(.red)
        case .paused:
            Button("Resume agent") { store.resume(agentID: agent.id) }
                .buttonStyle(PrimaryWalletButton())
            Button("Revoke capabilities") { store.revoke(agentID: agent.id) }
                .buttonStyle(SecondaryWalletButton())
        case .revocationPending:
            Label("Revocation submitted · awaiting finality", systemImage: "clock.badge.checkmark")
                .font(.subheadline.weight(.semibold)).foregroundStyle(WalletPalette.violet)
        case .revoked(let height):
            Label("Revoked at finalized block \(height)", systemImage: "xmark.shield.fill")
                .font(.subheadline.weight(.semibold)).foregroundStyle(.red)
        }
    }
}

private struct DetailSection: View {
    let title: String
    let values: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title).font(.subheadline.bold())
            ForEach(values, id: \.self) { value in
                Label(value, systemImage: "checkmark.circle.fill")
                    .font(.caption).foregroundStyle(WalletPalette.muted)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .cardStyle()
    }
}

private struct ApprovalCard: View {
    let agent: String
    let action: String
    let detail: String
    let risk: String
    let color: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                Label(agent, systemImage: "wand.and.stars")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(color)
                Spacer()
                Text("2 min")
                    .font(.caption)
                    .foregroundStyle(WalletPalette.muted)
            }
            VStack(alignment: .leading, spacing: 6) {
                Text(action).font(.title3.bold())
                Text(detail).font(.subheadline).foregroundStyle(WalletPalette.muted)
            }
            Label(risk, systemImage: "checkmark.circle.fill")
                .font(.caption.weight(.semibold))
                .foregroundStyle(WalletPalette.mint)
            HStack(spacing: 12) {
                Button("Decline") {}
                    .buttonStyle(SecondaryWalletButton())
                Button("Review") {}
                    .buttonStyle(PrimaryWalletButton())
            }
        }
        .padding(20)
        .background(WalletPalette.panel, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 24, style: .continuous)
                .stroke(color.opacity(0.22), lineWidth: 1)
        }
    }
}

private struct IdentityView: View {
    var body: some View {
        ZStack {
            WalletBackground()
            ScrollView {
                VStack(spacing: 18) {
                    VStack(spacing: 12) {
                        Image(systemName: "person.crop.circle.badge.checkmark")
                            .font(.system(size: 62))
                            .foregroundStyle(WalletPalette.mint)
                        Text("Johan’s wallet").font(.title2.bold())
                        Text("did:activechain:kanalen:8c7a…19ef")
                            .font(.caption.monospaced())
                            .foregroundStyle(WalletPalette.muted)
                            .textSelection(.enabled)
                        Label("Device protected", systemImage: "lock.fill")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(WalletPalette.mint)
                    }
                    .frame(maxWidth: .infinity)
                    .cardStyle()

                    VStack(alignment: .leading, spacing: 12) {
                        Text("Credentials").font(.title3.bold())
                        CredentialRow(
                            icon: "person.text.rectangle.fill",
                            title: "Kanalen Test ID",
                            issuer: "ActiveChain Foundation",
                            color: WalletPalette.cyan
                        )
                        CredentialRow(
                            icon: "calendar.badge.checkmark",
                            title: "Age over 18",
                            issuer: "Derived disclosure",
                            color: WalletPalette.violet
                        )
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    Button("Add credential") {}
                        .buttonStyle(PrimaryWalletButton())
                }
                .padding(20)
            }
        }
        .navigationTitle("Identity")
        .toolbarBackground(WalletPalette.ink, for: .navigationBar)
    }
}

private struct CredentialRow: View {
    let icon: String
    let title: String
    let issuer: String
    let color: Color

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: icon)
                .foregroundStyle(color)
                .frame(width: 42, height: 42)
                .background(color.opacity(0.14), in: RoundedRectangle(cornerRadius: 13))
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.headline)
                Text(issuer).font(.caption).foregroundStyle(WalletPalette.muted)
            }
            Spacer()
            Image(systemName: "chevron.right")
                .font(.caption.bold())
                .foregroundStyle(WalletPalette.muted)
        }
        .cardStyle()
    }
}

private struct SendFlowView: View {
    @Environment(\.dismiss) private var dismiss
    private let bridge = LocalWalletBridge()
    @State private var recipient = "did:activechain:kanalen:"
    @State private var amount = ""
    @State private var reviewed = false
    @State private var status = ""

    var body: some View {
        ZStack {
            WalletBackground()
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Amount").font(.subheadline).foregroundStyle(WalletPalette.muted)
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            TextField("0", text: $amount)
                                .font(.system(size: 42, weight: .bold, design: .rounded))
                                .keyboardType(.decimalPad)
                            Text("ACT").font(.title3.bold()).foregroundStyle(WalletPalette.mint)
                        }
                        Text("Available 12,480.42 ACT")
                            .font(.caption)
                            .foregroundStyle(WalletPalette.muted)
                    }
                    .cardStyle()

                    VStack(alignment: .leading, spacing: 8) {
                        Text("Recipient").font(.subheadline).foregroundStyle(WalletPalette.muted)
                        TextField("DID or address", text: $recipient)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .font(.callout.monospaced())
                        Divider().overlay(.white.opacity(0.1))
                        HStack {
                            Label("Fee reserve", systemImage: "gauge.with.dots.needle.33percent")
                            Spacer()
                            Text("0.08 ACT").monospacedDigit()
                        }
                        .font(.subheadline)
                    }
                    .cardStyle()

                    if reviewed {
                        Label(
                            "Policy allows this payment. You will approve the exact recipient, amount, fee and validity window.",
                            systemImage: "checkmark.shield.fill"
                        )
                        .font(.subheadline)
                        .foregroundStyle(WalletPalette.mint)
                        .cardStyle()
                    }

                    Button(reviewed ? "Approve with biometrics" : "Review transfer") {
                        let value = UInt64(Double(amount) ?? 0)
                        let preview = bridge.previewTransfer(
                            recipient: recipient,
                            amount: value,
                            feeReserve: 1,
                            validUntil: 184_391,
                            currentHeight: 184_291
                        )
                        if reviewed {
                            do {
                                _ = try bridge.approveTransfer(preview)
                                status = "Canonical intent approved"
                            } catch {
                                status = "Wallet policy rejected this transfer"
                            }
                        } else {
                            reviewed = preview.policyAllowed
                            status = preview.policyAllowed ? "" : "Enter a valid amount"
                        }
                    }
                    .buttonStyle(PrimaryWalletButton())
                    .disabled(amount.isEmpty)

                    if !status.isEmpty {
                        Text(status)
                            .font(.subheadline.weight(.semibold))
                            .foregroundStyle(status.contains("approved") ? WalletPalette.mint : .orange)
                            .frame(maxWidth: .infinity)
                    }
                }
                .padding(20)
            }
        }
        .navigationTitle("Send ACT")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Close") { dismiss() }
            }
        }
    }
}

private struct WalletBackground: View {
    var body: some View {
        WalletPalette.ink
            .overlay(alignment: .topTrailing) {
                RadialGradient(
                    colors: [WalletPalette.violet.opacity(0.12), .clear],
                    center: .topTrailing,
                    startRadius: 0,
                    endRadius: 280
                )
            }
            .ignoresSafeArea()
    }
}

private extension View {
    func cardStyle() -> some View {
        padding(16)
            .background(
                WalletPalette.panel.opacity(0.94),
                in: RoundedRectangle(cornerRadius: 20, style: .continuous)
            )
            .overlay {
                RoundedRectangle(cornerRadius: 20, style: .continuous)
                    .stroke(.white.opacity(0.07), lineWidth: 1)
            }
    }
}

private struct PrimaryWalletButton: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.headline)
            .foregroundStyle(WalletPalette.ink)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 15)
            .background(
                WalletPalette.mint.opacity(configuration.isPressed ? 0.72 : 1),
                in: RoundedRectangle(cornerRadius: 16, style: .continuous)
            )
            .scaleEffect(configuration.isPressed ? 0.98 : 1)
    }
}

private struct SecondaryWalletButton: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.headline)
            .foregroundStyle(.white)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 15)
            .background(
                .white.opacity(configuration.isPressed ? 0.05 : 0.09),
                in: RoundedRectangle(cornerRadius: 16, style: .continuous)
            )
    }
}
