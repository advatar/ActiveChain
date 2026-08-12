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

struct WalletPalette {
    static let ink = Color(red: 0.035, green: 0.055, blue: 0.09)
    static let panel = Color(red: 0.075, green: 0.10, blue: 0.145)
    static let mint = Color(red: 0.45, green: 0.96, blue: 0.71)
    static let cyan = Color(red: 0.34, green: 0.80, blue: 0.94)
    static let violet = Color(red: 0.61, green: 0.54, blue: 0.98)
    static let muted = Color.white.opacity(0.62)
}

struct WalletRootView: View {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var liveState = WalletLiveState()
    @State private var selection: WalletTab = .home

    var body: some View {
        TabView(selection: $selection) {
            NavigationStack {
                HomeView(liveState: liveState)
            }
            .tag(WalletTab.home)
            .tabItem { Label("Wallet", systemImage: "wallet.bifold.fill") }

            NavigationStack { ActivityView() }
                .tag(WalletTab.activity)
                .tabItem { Label("Activity", systemImage: "clock.arrow.circlepath") }

            NavigationStack { ApprovalsView() }
                .tag(WalletTab.approvals)
                .tabItem { Label("Approvals", systemImage: "checkmark.shield.fill") }

            NavigationStack { IdentityView() }
                .tag(WalletTab.identity)
                .tabItem { Label("Identity", systemImage: "person.text.rectangle.fill") }
        }
        .tint(WalletPalette.mint)
        .preferredColorScheme(.dark)
        .onAppear(perform: consumeAgentIntentRoute)
        .task { await liveState.refresh() }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active {
                consumeAgentIntentRoute()
                Task { await liveState.refresh() }
            }
        }
    }

    private func consumeAgentIntentRoute() {
        guard AgentIntentRouter.consume() != nil else { return }
        selection = .approvals
    }
}

private struct HomeView: View {
    @ObservedObject var liveState: WalletLiveState

    var body: some View {
        ZStack {
            WalletBackground()
            ScrollView {
                LazyVStack(spacing: 18) {
                    Header()
                    BalanceCard(networkState: liveState.networkState, verifiedPage: liveState.verifiedOwnerPage)
                    if let secret = liveState.recoverySecret {
                        RecoveryKeyCard(secret: secret) { liveState.acknowledgeRecoverySecret() }
                    }
                    if liveState.deviceProfile == nil {
                        OnboardingCard(
                            creating: liveState.creatingWallet,
                            error: liveState.onboardingError
                        ) {
                            Task { await liveState.createWallet() }
                        }
                    }
                    FundingCard(state: liveState.fundingState) {
                        Task { await liveState.requestTestnetFunding() }
                    }
                    NetworkCard(state: liveState.networkState) {
                        Task { await liveState.refresh() }
                    }
                    AssetSection()
                    SecurityFooter(
                        hasProfile: liveState.deviceProfile != nil,
                        hasVerifiedState: liveState.verifiedOwnerPage != nil
                    )
                }
                .padding(.horizontal, 20)
                .padding(.bottom, 32)
            }
            .scrollIndicators(.hidden)
        }
        .walletNavigationBarHidden()
    }
}

private struct FundingCard: View {
    let state: WalletFundingState
    let request: () -> Void

    private var detail: String {
        switch state {
        case let .unavailable(reason), let .rejected(_, reason): reason
        case .ready: "The faucet submits a real Coin Cell transition. Balance changes only after proof-backed finality."
        case .requesting: "The exact chain-bound request is being authorized and submitted."
        case let .pending(reference): "Reference \(reference) is awaiting finalized evidence. No balance has been credited."
        case let .finalized(reference, height): "Reference \(reference) finalized at block \(height). Refreshing owner proofs."
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label(state.title, systemImage: "drop.fill")
                    .font(.headline)
                    .accessibilityIdentifier("funding.title")
                Spacer()
                if case .requesting = state { ProgressView().controlSize(.small) }
            }
            Text(detail)
                .font(.caption)
                .foregroundStyle(WalletPalette.muted)
            Button("Request testnet funding", action: request)
                .buttonStyle(.borderedProminent)
                .disabled(state != .ready)
            if !state.creditsBalance {
                Label("Pending and rejected requests never change the displayed balance",
                      systemImage: "checkmark.shield.fill")
                    .font(.caption2)
                    .foregroundStyle(WalletPalette.mint)
            }
        }
        .cardStyle()
        .accessibilityElement(children: .contain)
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
                Text("ActiveChain")
                    .font(.subheadline)
                    .foregroundStyle(WalletPalette.muted)
                Text("Wallet")
                    .font(.title2.bold())
            }
            Spacer()
        }
        .padding(.top, 14)
    }
}

private struct BalanceCard: View {
    let networkState: WalletNetworkState
    let verifiedPage: WalletOwnerCoinPage?

    private var stateMessage: String {
        if let verifiedPage {
            return "\(verifiedPage.records.count) owner-scoped Coin Cell proof(s) verified at finalized state."
        }
        return switch networkState {
        case .healthy: "The network is finalized, but no owner-scoped Coin Cell proof is loaded for this wallet."
        case .checking: "Waiting for a finalized RPC checkpoint before loading wallet state."
        case .stale: "The RPC checkpoint is stale; balances remain hidden until finality catches up."
        case .unavailable: "Kanalen RPC is unavailable; no local or optimistic balance is shown."
        case .incompatible: "Kanalen RPC protocol is incompatible; update before loading wallet state."
        }
    }

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
                Text("Balance unavailable")
                    .accessibilityIdentifier("balance.headline")
                    .font(.system(size: 28, weight: .bold, design: .rounded))
                Text(stateMessage)
                    .font(.callout)
                    .foregroundStyle(.white.opacity(0.64))
            }

            Label("Transfers disabled until finalized wallet state is available",
                  systemImage: "exclamationmark.lock.fill")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.orange)
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

private struct NetworkCard: View {
    let state: WalletNetworkState
    let refresh: () -> Void

    var body: some View {
        Button(action: refresh) {
            HStack(spacing: 14) {
                ZStack {
                    Circle().fill(state.color.opacity(0.15))
                    Circle().fill(state.color).frame(width: 9, height: 9)
                }
                .frame(width: 42, height: 42)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Kanalen").font(.headline)
                    Text(state.detail)
                        .font(.caption)
                        .foregroundStyle(WalletPalette.muted)
                }
                Spacer()
                Text(state.label)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(state.color)
                    .accessibilityIdentifier("network.status")
            }
            .cardStyle()
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Kanalen testnet, \(state.label), \(state.detail)")
    }
}

private struct AssetSection: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Assets").font(.title3.bold())
            }
            ContentUnavailableView(
                "No verified assets",
                systemImage: "tray",
                description: Text("Asset balances require finalized owner-scoped Coin Cell proofs.")
            )
            .cardStyle()
        }
    }
}

private struct SecurityFooter: View {
    let hasProfile: Bool
    let hasVerifiedState: Bool

    private var message: String {
        if hasVerifiedState {
            return "Finalized owner proofs verified by the linked Rust verifier"
        }
        if hasProfile {
            return "Wallet profile loaded; no verified Coin Cell state is available"
        }
        return "No wallet profile or signing key is loaded"
    }

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "lock.shield.fill").foregroundStyle(WalletPalette.mint)
            Text(message)
                .font(.caption)
                .foregroundStyle(WalletPalette.muted)
        }
        .frame(maxWidth: .infinity)
        .padding(.top, 4)
    }
}

private struct ActivityView: View {
    var body: some View {
        ZStack {
            WalletBackground()
            ContentUnavailableView(
                "No verified activity",
                systemImage: "clock.badge.questionmark",
                description: Text("Activity will appear after finalized receipt queries are available.")
            )
        }
        .navigationTitle("Activity")
        .walletNavigationBarBackground()
    }
}

private struct ApprovalsView: View {
    @StateObject private var agents = RustAgentRegistryStore()

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
                                Text(agentSummary)
                                    .font(.caption).foregroundStyle(WalletPalette.muted)
                            }
                            Spacer()
                            Image(systemName: "chevron.right")
                                .font(.caption.bold()).foregroundStyle(WalletPalette.muted)
                        }
                        .cardStyle()
                    }
                    .buttonStyle(.plain)
                    ContentUnavailableView(
                        "No pending approvals",
                        systemImage: "checkmark.shield",
                        description: Text("Only persisted, approval-bound requests are shown here.")
                    )
                    .cardStyle()
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
        .walletNavigationBarBackground()
    }

    private var agentSummary: String {
        agents.agents.isEmpty
            ? "No registered agents"
            : "\(agents.agents.count) persisted agent\(agents.agents.count == 1 ? "" : "s")"
    }
}

private struct AgentInventoryView: View {
    @ObservedObject var store: RustAgentRegistryStore

    var body: some View {
        ZStack {
            WalletBackground()
            ScrollView {
                VStack(spacing: 14) {
                    Text("Agents are authenticated principals, not apps the wallet can inspect. Available controls affect only this wallet's local signing authority.")
                        .font(.caption)
                        .foregroundStyle(WalletPalette.muted)
                        .padding(16)
                        .background(WalletPalette.violet.opacity(0.12),
                                    in: RoundedRectangle(cornerRadius: 18))
                    if store.agents.isEmpty {
                        ContentUnavailableView {
                            Label("No agents yet", systemImage: "person.badge.key")
                        } description: {
                            Text("Agent enrollment requires validator-backed submission and finality, which are unavailable in this build.")
                        }
                        .cardStyle()
                    }
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
        .walletNavigationBarBackground()
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
        case .enrollmentPending: "Local draft"
        case .active: "Local active"
        case .paused: "Local paused"
        case .revocationPending: "Local revocation draft"
        case .revoked: "Revoked"
        }
    }

    private var statusColor: Color {
        switch agent.lifecycle {
        case .enrollmentPending: WalletPalette.violet
        case .active: WalletPalette.mint
        case .paused: .orange
        case .revocationPending: WalletPalette.violet
        case .revoked: .red
        }
    }
}

private struct AgentDetailView: View {
    @ObservedObject var store: RustAgentRegistryStore
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
        .walletNavigationBarBackground()
    }

    @ViewBuilder
    private func lifecycleControls(_ agent: AgentDelegation) -> some View {
        switch agent.lifecycle {
        case .enrollmentPending:
            Label("Prepared locally · testnet submission and finality unavailable",
                  systemImage: "clock.badge.exclamationmark")
                .font(.subheadline.weight(.semibold)).foregroundStyle(WalletPalette.violet)
        case .active:
            Button("Pause agent") { store.pause(agentID: agent.id) }
                .buttonStyle(SecondaryWalletButton())
            Label("Capability revocation requires unavailable testnet submission",
                  systemImage: "network.slash")
                .font(.caption).foregroundStyle(WalletPalette.muted)
        case .paused:
            Button("Resume agent") { store.resume(agentID: agent.id) }
                .buttonStyle(PrimaryWalletButton())
            Label("Capability revocation requires unavailable testnet submission",
                  systemImage: "network.slash")
                .font(.caption).foregroundStyle(WalletPalette.muted)
        case .revocationPending:
            Label("Revocation prepared locally · submission and finality unavailable",
                  systemImage: "clock.badge.exclamationmark")
                .font(.subheadline.weight(.semibold)).foregroundStyle(WalletPalette.violet)
        case .revoked(let height):
            Label("Revoked at finalized block \(height)", systemImage: "xmark.shield.fill")
                .font(.subheadline.weight(.semibold)).foregroundStyle(.red)
        }
    }
}

private struct AgentEnrollmentView: View {
    @ObservedObject var store: RustAgentRegistryStore
    @Environment(\.dismiss) private var dismiss
    @State private var draft = AgentEnrollmentDraft()
    @State private var errorMessage: String?
    @State private var authenticating = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Agent request") {
                    TextField("Agent name", text: $draft.label)
                    TextField("48-byte principal (hex)", text: $draft.principal, axis: .vertical)
                        .walletAddressInputBehavior()
                    TextField(
                        "Capability IDs (hex, one per line)",
                        text: $draft.capabilityIDs,
                        axis: .vertical
                    )
                    .lineLimit(3...6)
                    .walletAddressInputBehavior()
                }
                Section("Connection") {
                    Picker("Agent type", selection: $draft.connection) {
                        Text("Same-team app").tag(AgentConnection.walletOwned)
                        Text("Third-party app").tag(AgentConnection.thirdParty)
                        Text("Remote service").tag(AgentConnection.remote)
                        Text("Managed device").tag(AgentConnection.managedDevice)
                    }
                    Text(connectionExplanation)
                        .font(.caption)
                        .foregroundStyle(WalletPalette.muted)
                }
                Section("Authority") {
                    TextField("Spending limit (ACT base units)", value: $draft.budget, format: .number)
                        .walletNumberKeyboard()
                    TextField("Expiry block", value: $draft.expiresAt, format: .number)
                        .walletNumberKeyboard()
                    Text("The grant cannot add capabilities not present in the imported request. Pending enrollment cannot sign or spend.")
                        .font(.caption)
                        .foregroundStyle(WalletPalette.muted)
                }
                if let errorMessage {
                    Section {
                        Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                    }
                }
                Section {
                    Button(authenticating ? "Authenticating…" : "Review and prepare enrollment") {
                        prepare()
                    }
                    .disabled(authenticating)
                }
            }
            .navigationTitle("Add agent")
            .walletInlineNavigationTitle()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }

    private var connectionExplanation: String {
        switch draft.connection {
        case .walletOwned:
            "Only apps signed by the wallet team may use the shared app-group transport."
        case .thirdParty:
            "Third-party apps use authenticated protocol messages and receive no app-group access."
        case .remote:
            "Remote agents use an authenticated network session. Endpoint access is not wallet authority."
        case .managedDevice:
            "Managed-device controls require separately verified device-management provenance."
        }
    }

    private func prepare() {
        do {
            try draft.validate()
            authenticating = true
            BiometricAuthorizer().authorize(reason: "Approve this agent enrollment") { success, error in
                authenticating = false
                guard success else {
                    errorMessage = error?.localizedDescription ?? "Wallet authentication failed."
                    return
                }
                do {
                    try store.prepareEnrollment(draft)
                    dismiss()
                } catch {
                    errorMessage = error.localizedDescription
                }
            }
        } catch {
            errorMessage = error.localizedDescription
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

private struct IdentityView: View {
    var body: some View {
        ZStack {
            WalletBackground()
            ScrollView {
                VStack(spacing: 18) {
                    VStack(spacing: 12) {
                        Image(systemName: "person.crop.circle.badge.questionmark")
                            .font(.system(size: 62))
                            .foregroundStyle(WalletPalette.muted)
                        Text("No wallet identity").font(.title2.bold())
                        Text("Create or import a wallet profile before receiving credentials or funds.")
                            .font(.caption)
                            .foregroundStyle(WalletPalette.muted)
                            .multilineTextAlignment(.center)
                        Label("No signing key loaded", systemImage: "key.slash")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.orange)
                    }
                    .frame(maxWidth: .infinity)
                    .cardStyle()

                    ContentUnavailableView(
                        "No credentials",
                        systemImage: "person.text.rectangle",
                        description: Text("Only credentials persisted through the OpenWallet boundary will appear.")
                    )
                    .cardStyle()
                }
                .padding(20)
            }
        }
        .navigationTitle("Identity")
        .walletNavigationBarBackground()
    }
}

struct WalletBackground: View {
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

extension View {
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

/// Shown only until this device has a wallet. Provisioning is the one step the
/// app could never perform, so the absence of a wallet was previously visible
/// only as an unexplained empty balance.
struct OnboardingCard: View {
    let creating: Bool
    let error: String?
    let create: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("No wallet on this device", systemImage: "key.fill")
                    .font(.headline)
                    .accessibilityIdentifier("onboarding.title")
                Spacer()
                if creating { ProgressView().controlSize(.small) }
            }
            Text("Creates an ML-DSA-44 key whose seed is wrapped by the Secure Enclave and never leaves this device.")
                .font(.caption)
                .foregroundStyle(WalletPalette.muted)
            Button(creating ? "Creating…" : "Create wallet", action: create)
                .buttonStyle(.borderedProminent)
                .disabled(creating)
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption2)
                    .foregroundStyle(.orange)
            }
        }
        .padding(18)
        .background(WalletPalette.panel, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
    }
}

/// Shown once, immediately after provisioning.
///
/// This key seals the recovery envelope that lets a second device re-wrap the
/// same seed under its own Secure Enclave. It is never written to disk and
/// never logged, so if it is lost the wallet cannot move between devices.
private func copyToPasteboard(_ value: String) {
#if os(macOS)
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(value, forType: .string)
#else
    UIPasteboard.general.string = value
#endif
}

struct RecoveryKeyCard: View {
    let secret: String
    let acknowledge: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Save your recovery key", systemImage: "lock.rotation")
                .font(.headline)
                .accessibilityIdentifier("recovery.title")
            Text("Required to open this wallet on another device. It is shown once and is not stored anywhere.")
                .font(.caption)
                .foregroundStyle(WalletPalette.muted)
            Text(secret)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(WalletPalette.ink, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            HStack {
                Button("Copy") { copyToPasteboard(secret) }
                    .buttonStyle(SecondaryWalletButton())
                Button("I have saved it", action: acknowledge)
                    .buttonStyle(PrimaryWalletButton())
            }
        }
        .padding(18)
        .background(WalletPalette.panel, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
    }
}

struct PrimaryWalletButton: ButtonStyle {
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

struct SecondaryWalletButton: ButtonStyle {
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

private extension View {
    @ViewBuilder
    func walletNavigationBarHidden() -> some View {
#if os(iOS)
        toolbar(.hidden, for: .navigationBar)
#else
        self
#endif
    }

    @ViewBuilder
    func walletNavigationBarBackground() -> some View {
#if os(iOS)
        toolbarBackground(WalletPalette.ink, for: .navigationBar)
#else
        self
#endif
    }

    @ViewBuilder
    func walletDecimalKeyboard() -> some View {
#if os(iOS)
        keyboardType(.decimalPad)
#else
        self
#endif
    }

    @ViewBuilder
    func walletNumberKeyboard() -> some View {
#if os(iOS)
        keyboardType(.numberPad)
#else
        self
#endif
    }

    @ViewBuilder
    func walletAddressInputBehavior() -> some View {
#if os(iOS)
        textInputAutocapitalization(.never)
            .autocorrectionDisabled()
#else
        self
#endif
    }

    @ViewBuilder
    func walletInlineNavigationTitle() -> some View {
#if os(iOS)
        navigationBarTitleDisplayMode(.inline)
#else
        self
#endif
    }
}
