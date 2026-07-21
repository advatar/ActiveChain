import Foundation
import LocalAuthentication
import Combine

public struct AgentDelegation: Identifiable, Equatable {
    public let id: String
    public let label: String
    public let capabilities: [String]
    public let dailyLimit: UInt64
    public let expiresAt: UInt64
    public var revoked: Bool
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
        agents[index].revoked = true
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
