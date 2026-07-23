import ActiveChainWallet
import Foundation
import Combine

enum RustAgentRegistryError: Error {
    case ffi(UInt32)
    case malformedSummary
}

final class RustAgentRegistryStore: ObservableObject {
    @Published private(set) var agents: [AgentDelegation] = []

    private var registry = Data()
    private let snapshotURL: URL?

    init(snapshotURL: URL? = RustAgentRegistryStore.defaultSnapshotURL()) {
        self.snapshotURL = snapshotURL
        if let snapshotURL, let stored = try? Data(contentsOf: snapshotURL) {
            registry = stored
        } else {
            try? seedDevelopmentAgents()
        }
        try? refresh()
    }

    func pause(agentID: String) {
        try? setPaused(agentID: agentID, paused: true)
    }

    func resume(agentID: String) {
        try? setPaused(agentID: agentID, paused: false)
    }

    func revoke(agentID: String) {
        guard let principal = principal(for: agentID) else { return }
        let transaction = Data(principal.map { $0 ^ 0x5a })
        try? transition { registryPointer, registryLength, output, capacity, required in
            principal.withUnsafeBytes { principalBytes in
                transaction.withUnsafeBytes { transactionBytes in
                    activechain_wallet_agent_revoke(
                        registryPointer,
                        registryLength,
                        principalBytes.bindMemory(to: UInt8.self).baseAddress,
                        transactionBytes.bindMemory(to: UInt8.self).baseAddress,
                        0,
                        output,
                        capacity,
                        required
                    )
                }
            }
        }
    }

    func finalizeRevocation(agentID: String, height: UInt64) {
        guard let principal = principal(for: agentID), height > 0 else { return }
        let transaction = Data(principal.map { $0 ^ 0x5a })
        try? transition { registryPointer, registryLength, output, capacity, required in
            principal.withUnsafeBytes { principalBytes in
                transaction.withUnsafeBytes { transactionBytes in
                    activechain_wallet_agent_revoke(
                        registryPointer,
                        registryLength,
                        principalBytes.bindMemory(to: UInt8.self).baseAddress,
                        transactionBytes.bindMemory(to: UInt8.self).baseAddress,
                        height,
                        output,
                        capacity,
                        required
                    )
                }
            }
        }
    }

    private func seedDevelopmentAgents() throws {
        try register(
            principalByte: 0x31,
            capabilityByte: 0x41,
            label: "Research agent",
            connection: 1,
            budget: 50,
            expiresAt: 240_000
        )
        try register(
            principalByte: 0x32,
            capabilityByte: 0x42,
            label: "Travel planner",
            connection: 2,
            budget: 10,
            expiresAt: 210_000
        )
    }

    private func register(
        principalByte: UInt8,
        capabilityByte: UInt8,
        label: String,
        connection: UInt32,
        budget: UInt64,
        expiresAt: UInt64
    ) throws {
        let principal = Data(repeating: principalByte, count: 48)
        let capability = Data(repeating: capabilityByte, count: 48)
        let label = Data(label.utf8)
        try transition { registryPointer, registryLength, output, capacity, required in
            principal.withUnsafeBytes { principalBytes in
                label.withUnsafeBytes { labelBytes in
                    capability.withUnsafeBytes { capabilityBytes in
                        activechain_wallet_agent_register(
                            registryPointer,
                            registryLength,
                            principalBytes.bindMemory(to: UInt8.self).baseAddress,
                            labelBytes.bindMemory(to: UInt8.self).baseAddress,
                            UInt32(label.count),
                            connection,
                            capabilityBytes.bindMemory(to: UInt8.self).baseAddress,
                            1,
                            0,
                            budget,
                            expiresAt,
                            output,
                            capacity,
                            required
                        )
                    }
                }
            }
        }
    }

    private func setPaused(agentID: String, paused: Bool) throws {
        guard let principal = principal(for: agentID) else { return }
        try transition { registryPointer, registryLength, output, capacity, required in
            principal.withUnsafeBytes { principalBytes in
                activechain_wallet_agent_set_paused(
                    registryPointer,
                    registryLength,
                    principalBytes.bindMemory(to: UInt8.self).baseAddress,
                    paused ? 1 : 0,
                    output,
                    capacity,
                    required
                )
            }
        }
    }

    private typealias Transition = (
        UnsafePointer<UInt8>?, UInt32, UnsafeMutablePointer<UInt8>?, UInt32,
        UnsafeMutablePointer<UInt32>?
    ) -> UInt32

    private func transition(_ operation: Transition) throws {
        var required: UInt32 = 0
        let queryCode = registry.withUnsafeBytes { registryBytes in
            operation(
                registryBytes.bindMemory(to: UInt8.self).baseAddress,
                UInt32(registry.count),
                nil,
                0,
                &required
            )
        }
        guard queryCode == ACTIVECHAIN_WALLET_BUFFER_TOO_SMALL, required > 0 else {
            throw RustAgentRegistryError.ffi(queryCode)
        }
        var next = Data(repeating: 0, count: Int(required))
        let nextCapacity = UInt32(next.count)
        let applyCode = registry.withUnsafeBytes { registryBytes in
            next.withUnsafeMutableBytes { outputBytes in
                operation(
                    registryBytes.bindMemory(to: UInt8.self).baseAddress,
                    UInt32(registry.count),
                    outputBytes.bindMemory(to: UInt8.self).baseAddress,
                    nextCapacity,
                    &required
                )
            }
        }
        guard applyCode == ACTIVECHAIN_WALLET_OK else {
            throw RustAgentRegistryError.ffi(applyCode)
        }
        registry = next
        try persist()
        try refresh()
    }

    private func refresh() throws {
        guard !registry.isEmpty else {
            agents = []
            return
        }
        var count: UInt32 = 0
        let countCode = registry.withUnsafeBytes {
            activechain_wallet_agent_count(
                $0.bindMemory(to: UInt8.self).baseAddress,
                UInt32(registry.count),
                &count
            )
        }
        guard countCode == ACTIVECHAIN_WALLET_OK else {
            throw RustAgentRegistryError.ffi(countCode)
        }
        agents = try (0..<count).map(summary)
    }

    private func summary(index: UInt32) throws -> AgentDelegation {
        var summary = ActivechainWalletAgentSummary(
            principal: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            connection: 0, lifecycle: 0, capability_count: 0,
            budget_limit_high: 0, budget_limit_low: 0,
            budget_spent_high: 0, budget_spent_low: 0,
            expires_at: 0, revocation_finalized_height: 0
        )
        var required: UInt32 = 0
        let query = registry.withUnsafeBytes {
            activechain_wallet_agent_summary(
                $0.bindMemory(to: UInt8.self).baseAddress,
                UInt32(registry.count),
                index,
                &summary,
                nil,
                0,
                &required
            )
        }
        guard query == ACTIVECHAIN_WALLET_BUFFER_TOO_SMALL, required > 0 else {
            throw RustAgentRegistryError.ffi(query)
        }
        var label = Data(repeating: 0, count: Int(required))
        let labelCapacity = UInt32(label.count)
        let code = registry.withUnsafeBytes { registryBytes in
            label.withUnsafeMutableBytes { labelBytes in
                activechain_wallet_agent_summary(
                    registryBytes.bindMemory(to: UInt8.self).baseAddress,
                    UInt32(registry.count),
                    index,
                    &summary,
                    labelBytes.bindMemory(to: UInt8.self).baseAddress,
                    labelCapacity,
                    &required
                )
            }
        }
        guard code == ACTIVECHAIN_WALLET_OK, let label = String(data: label, encoding: .utf8) else {
            throw RustAgentRegistryError.malformedSummary
        }
        let principal = withUnsafeBytes(of: summary.principal) { Data($0) }
        let lifecycle: AgentLifecycle = switch summary.lifecycle {
        case 0: .active
        case 1: .paused
        case 2: .revocationPending
        case 3: .revoked(finalizedHeight: summary.revocation_finalized_height)
        default: throw RustAgentRegistryError.malformedSummary
        }
        let connection: AgentConnection = switch summary.connection {
        case 0: .walletOwned
        case 1: .thirdParty
        case 2: .remote
        case 3: .managedDevice
        default: throw RustAgentRegistryError.malformedSummary
        }
        return AgentDelegation(
            id: principal.map { String(format: "%02x", $0) }.joined(),
            label: label,
            capabilities: ["\(summary.capability_count) scoped capability"],
            dailyLimit: summary.budget_limit_low,
            expiresAt: summary.expires_at,
            connection: connection,
            spentToday: summary.budget_spent_low,
            lifecycle: lifecycle
        )
    }

    private func principal(for id: String) -> Data? {
        guard id.count == 96 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(48)
        var index = id.startIndex
        for _ in 0..<48 {
            let next = id.index(index, offsetBy: 2)
            guard let byte = UInt8(id[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        return Data(bytes)
    }

    private func persist() throws {
        guard let snapshotURL else { return }
        try FileManager.default.createDirectory(
            at: snapshotURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try registry.write(to: snapshotURL, options: .atomic)
    }

    private static func defaultSnapshotURL() -> URL? {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first?
            .appendingPathComponent("ActiveChainWallet", isDirectory: true)
            .appendingPathComponent("agents-v1.bin")
    }
}
