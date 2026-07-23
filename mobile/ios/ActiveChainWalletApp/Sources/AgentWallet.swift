import Foundation
import LocalAuthentication

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
