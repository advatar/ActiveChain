import Foundation
import LocalAuthentication
import Combine

public enum AgentConnection: String, Equatable {
    case walletOwned = "Wallet-owned"
    case thirdParty = "Third-party"
    case remote = "Remote"
    case managedDevice = "Managed device"
}

public enum AgentLifecycle: Equatable {
    case active
    case paused
    case revocationPending
    case revoked(finalizedHeight: UInt64)
}

public struct AgentDelegation: Identifiable, Equatable {
    public let id: String
    public let label: String
    public let capabilities: [String]
    public let dailyLimit: UInt64
    public let expiresAt: UInt64
    public let connection: AgentConnection
    public var spentToday: UInt64
    public var lifecycle: AgentLifecycle

    public init(id: String, label: String, capabilities: [String], dailyLimit: UInt64,
                expiresAt: UInt64, revoked: Bool = false,
                connection: AgentConnection = .thirdParty, spentToday: UInt64 = 0,
                lifecycle: AgentLifecycle? = nil) {
        self.id = id
        self.label = label
        self.capabilities = capabilities
        self.dailyLimit = dailyLimit
        self.expiresAt = expiresAt
        self.connection = connection
        self.spentToday = spentToday
        self.lifecycle = lifecycle ?? (revoked ? .revoked(finalizedHeight: 1) : .active)
    }

    public var revoked: Bool {
        if case .revoked = lifecycle { return true }
        return false
    }
}

public struct PendingApproval: Identifiable, Equatable {
    public let id: String
    public let agentID: String
    public let recipient: String
    public let amount: UInt64
    public let feeReserve: UInt64
    public let networkID: String
}

public final class AgentWalletStore: ObservableObject {
    @Published public private(set) var agents: [AgentDelegation] = []
    @Published public private(set) var pending: [PendingApproval] = []

    public init() {}

    public func delegate(_ agent: AgentDelegation) -> Bool {
        guard !agents.contains(where: { $0.id == agent.id }) else { return false }
        agents.append(agent)
        return true
    }

    public func enqueue(_ approval: PendingApproval) { pending.append(approval) }

    public func revoke(agentID: String) {
        guard let index = agents.firstIndex(where: { $0.id == agentID }) else { return }
        agents[index].lifecycle = .revocationPending
    }

    public func finalizeRevocation(agentID: String, height: UInt64) {
        guard height > 0, let index = agents.firstIndex(where: { $0.id == agentID }),
              agents[index].lifecycle == .revocationPending else { return }
        agents[index].lifecycle = .revoked(finalizedHeight: height)
    }

    public func pause(agentID: String) {
        guard let index = agents.firstIndex(where: { $0.id == agentID }),
              agents[index].lifecycle == .active else { return }
        agents[index].lifecycle = .paused
    }

    public func resume(agentID: String) {
        guard let index = agents.firstIndex(where: { $0.id == agentID }),
              agents[index].lifecycle == .paused else { return }
        agents[index].lifecycle = .active
    }
}

public final class BiometricAuthorizer {
    public init() {}

    /// Requests biometrics only; callers must fail closed on any error and never invoke
    /// `deviceOwnerAuthentication` as a passcode fallback for high-value actions.
    public func authorize(reason: String, completion: @escaping (Bool, Error?) -> Void) {
        let context = LAContext()
        context.localizedFallbackTitle = ""
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, error in
            DispatchQueue.main.async { completion(success, error) }
        }
    }
}
