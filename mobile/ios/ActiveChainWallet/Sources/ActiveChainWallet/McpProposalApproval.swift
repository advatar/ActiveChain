import Foundation

public enum McpAction: UInt32, Codable, Equatable, Sendable {
    case transfer = 0
    case submitAnchor = 1
}

public struct CanonicalMcpProposalApproval: Equatable, Sendable {
    public let intent: Data
    public let requestID: String
    public let chainID: String
    public let walletID: String
    public let requestNonce: String
    public let agentPrincipal: Data
    public let capabilityID: Data
    public let resource: Data
    public let recipient: Data
    public let replayDomain: Data
    public let intentCommitment: Data
    public let proposalID: Data
    public let action: McpAction
    public let amount: Unsigned128Words
    public let maximumFee: Unsigned128Words
    public let expiresAtHeight: UInt64

    public init(
        intent: Data, requestID: String, chainID: String, walletID: String, requestNonce: String,
        agentPrincipal: Data, capabilityID: Data, resource: Data, recipient: Data,
        replayDomain: Data, intentCommitment: Data, proposalID: Data, action: McpAction,
        amount: Unsigned128Words, maximumFee: Unsigned128Words, expiresAtHeight: UInt64
    ) {
        precondition(!intent.isEmpty)
        precondition([requestID, chainID, walletID, requestNonce].allSatisfy {
            !$0.isEmpty && $0.utf8.count <= 128
        })
        precondition([agentPrincipal, capabilityID, resource, recipient, replayDomain,
                      intentCommitment, proposalID].allSatisfy { $0.count == 48 })
        precondition(expiresAtHeight > 0)
        self.intent = intent
        self.requestID = requestID
        self.chainID = chainID
        self.walletID = walletID
        self.requestNonce = requestNonce
        self.agentPrincipal = agentPrincipal
        self.capabilityID = capabilityID
        self.resource = resource
        self.recipient = recipient
        self.replayDomain = replayDomain
        self.intentCommitment = intentCommitment
        self.proposalID = proposalID
        self.action = action
        self.amount = amount
        self.maximumFee = maximumFee
        self.expiresAtHeight = expiresAtHeight
    }
}

public enum McpProposalLifecycle: String, Codable, Equatable, Sendable {
    case pending, approved, rejected, expired, submitted, finalized, failed
}

public struct McpProposalLifecycleRecord: Codable, Equatable, Sendable {
    public let proposalID: Data
    public let intent: Data
    public internal(set) var state: McpProposalLifecycle
    public internal(set) var revision: UInt64
    public internal(set) var evidence: Data?
    public let expiresAtHeight: UInt64
}

public enum McpProposalLifecycleError: Error, Equatable {
    case malformed
    case expired
    case concurrentReview
    case invalidTransition
    case persistence
}

public actor McpProposalLifecycleStore {
    private let file: URL
    private var records: [Data: McpProposalLifecycleRecord]

    public init(file: URL) throws {
        self.file = file
        guard FileManager.default.fileExists(atPath: file.path) else {
            records = [:]
            return
        }
        do {
            let decoded = try JSONDecoder().decode([McpProposalLifecycleRecord].self,
                                                   from: Data(contentsOf: file))
            guard decoded.count <= 4_096,
                  Set(decoded.map(\.proposalID)).count == decoded.count else {
                throw McpProposalLifecycleError.malformed
            }
            records = Dictionary(uniqueKeysWithValues: decoded.map { ($0.proposalID, $0) })
        } catch let error as McpProposalLifecycleError {
            throw error
        } catch {
            throw McpProposalLifecycleError.persistence
        }
    }

    public func admit(_ approval: CanonicalMcpProposalApproval,
                      finalizedHeight: UInt64) throws -> McpProposalLifecycleRecord {
        guard finalizedHeight < approval.expiresAtHeight else { throw McpProposalLifecycleError.expired }
        if let existing = records[approval.proposalID] {
            guard existing.intent == approval.intent else { throw McpProposalLifecycleError.malformed }
            return existing
        }
        guard records.count < 4_096 else { throw McpProposalLifecycleError.persistence }
        let record = McpProposalLifecycleRecord(
            proposalID: approval.proposalID, intent: approval.intent, state: .pending,
            revision: 1, evidence: nil, expiresAtHeight: approval.expiresAtHeight
        )
        records[approval.proposalID] = record
        try persist()
        return record
    }

    public func transition(
        proposalID: Data, expectedRevision: UInt64, to next: McpProposalLifecycle,
        evidence: Data, finalizedHeight: UInt64
    ) throws -> McpProposalLifecycleRecord {
        guard evidence.count == 48, var record = records[proposalID] else {
            throw McpProposalLifecycleError.malformed
        }
        guard record.revision == expectedRevision else { throw McpProposalLifecycleError.concurrentReview }
        guard next == .expired || finalizedHeight < record.expiresAtHeight else {
            throw McpProposalLifecycleError.expired
        }
        let allowed = switch (record.state, next) {
        case (.pending, .approved), (.pending, .rejected), (.pending, .expired),
             (.approved, .submitted), (.approved, .failed), (.approved, .expired),
             (.submitted, .finalized), (.submitted, .failed): true
        default: false
        }
        guard allowed, record.revision < UInt64.max else {
            throw McpProposalLifecycleError.invalidTransition
        }
        record.state = next
        record.revision += 1
        record.evidence = evidence
        records[proposalID] = record
        try persist()
        return record
    }

    public func record(proposalID: Data) -> McpProposalLifecycleRecord? { records[proposalID] }

    private func persist() throws {
        do {
            try FileManager.default.createDirectory(
                at: file.deletingLastPathComponent(), withIntermediateDirectories: true
            )
            let ordered = records.values.sorted { $0.proposalID.lexicographicallyPrecedes($1.proposalID) }
            try JSONEncoder().encode(ordered).write(to: file, options: [.atomic])
        } catch {
            throw McpProposalLifecycleError.persistence
        }
    }
}
