import AppIntents
import Foundation

enum AgentIntentDestination: String {
    case management
    case pendingApprovals
}

enum AgentIntentRouter {
    static let destinationKey = "activechain.wallet.intent.agent-destination"

    static func request(_ destination: AgentIntentDestination, defaults: UserDefaults = .standard) {
        defaults.set(destination.rawValue, forKey: destinationKey)
    }

    static func consume(defaults: UserDefaults = .standard) -> AgentIntentDestination? {
        guard let raw = defaults.string(forKey: destinationKey) else { return nil }
        defaults.removeObject(forKey: destinationKey)
        return AgentIntentDestination(rawValue: raw)
    }
}

struct OpenAgentManagementIntent: AppIntent {
    static var title: LocalizedStringResource = "Manage ActiveChain Agents"
    static var description = IntentDescription(
        "Opens the wallet’s authenticated agent inventory and capability controls."
    )
    static var openAppWhenRun = true
    static var authenticationPolicy: IntentAuthenticationPolicy = .requiresAuthentication

    func perform() async throws -> some IntentResult & ProvidesDialog {
        AgentIntentRouter.request(.management)
        return .result(dialog: "Opening agent management in ActiveChain Wallet.")
    }
}

struct ReviewAgentApprovalsIntent: AppIntent {
    static var title: LocalizedStringResource = "Review Agent Approvals"
    static var description = IntentDescription(
        "Opens ActiveChain Wallet to review exact, consent-bound agent requests."
    )
    static var openAppWhenRun = true
    static var authenticationPolicy: IntentAuthenticationPolicy = .requiresAuthentication

    func perform() async throws -> some IntentResult & ProvidesDialog {
        AgentIntentRouter.request(.pendingApprovals)
        return .result(dialog: "Opening pending agent approvals in ActiveChain Wallet.")
    }
}

struct ActiveChainWalletShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(
            intent: OpenAgentManagementIntent(),
            phrases: [
                "Manage my agents in \(.applicationName)",
                "Open agent controls in \(.applicationName)"
            ],
            shortTitle: "Manage Agents",
            systemImageName: "person.2.badge.gearshape"
        )
        AppShortcut(
            intent: ReviewAgentApprovalsIntent(),
            phrases: [
                "Review agent approvals in \(.applicationName)",
                "Show agent requests in \(.applicationName)"
            ],
            shortTitle: "Agent Approvals",
            systemImageName: "checkmark.shield"
        )
    }
}
