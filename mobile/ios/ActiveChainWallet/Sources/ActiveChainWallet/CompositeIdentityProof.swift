import Foundation
import Security
import Darwin
import AnyIdentity

/// Public identity state and issuer evidence. Roots and policy come from trusted configuration,
/// never from this holder-provided profile. No identity seed or native custody key is stored here.
public struct CompositeIdentityProfile: Codable, Equatable, Sendable {
    public let authority: AuthorityState
    public let evidence: [Signed<Evidence>]

    public init(authority: AuthorityState, evidence: [Signed<Evidence>]) {
        self.authority = authority
        self.evidence = evidence
    }

    public func assess(roots: [TrustedRoot], policy: AssurancePolicy,
                       revocations: RevocationSnapshot, now: UInt64) throws -> Assurance {
        guard policy.minimumIndependentRoots >= 2 else { throw CompositeIdentityError.configuration }
        return try AnyIdentity.assess(state: authority, evidence: evidence, roots: roots,
                                      policy: policy, revocations: revocations, now: now)
    }
}

public enum CompositeIdentityError: Error, Equatable {
    case configuration, malformed, expired, unknownChallenge, substitutedProposal, replay, persistence, clock, capacity
}

public struct CompositeIdentityProof: Codable, Equatable, Sendable {
    public let action: Signed<Action>
    public let evidence: [Signed<Evidence>]
    public let delegation: [Signed<Delegation>]

    public init(action: Signed<Action>, evidence: [Signed<Evidence>], delegation: [Signed<Delegation>] = []) {
        self.action = action
        self.evidence = evidence
        self.delegation = delegation
    }

    public func encoded() throws -> Data {
        let bytes = try AnyIdentity.encode(self)
        guard bytes.count <= 1_048_576 else { throw CompositeIdentityError.malformed }
        return bytes
    }
}

public struct CompositeIdentityChallenge: Codable, Equatable, Sendable {
    public let expected: Action
    public let proposalID: Data
    public let nativeExpiresAtHeight: UInt64
    public var nonce: String { expected.nonce }
}

/// Optional application identity gate. The caller supplies authenticated authority, roots, policy,
/// revocation input and time, and a Rust-reviewed native proposal. Successful verification consumes
/// a durable challenge before native signing. Native ML-DSA custody and admission remain required.
public actor CompositeIdentityApprovalVerifier {
    private let authority: AuthorityState
    private let verifier: AuthorityVerifier
    private let journal: IdentityChallengeJournal

    public init(authority: AuthorityState, roots: [TrustedRoot], policy: AssurancePolicy,
                revocations: RevocationSnapshot, journalURL: URL) throws {
        guard policy.minimumIndependentRoots >= 2, !roots.isEmpty else {
            throw CompositeIdentityError.configuration
        }
        self.authority = authority
        let binding = IdentityJournalBinding(authority: authority, roots: roots, policy: policy)
        journal = IdentityChallengeJournal(file: journalURL, binding: binding, checkedAt: revocations.checkedAt)
        try journal.update { _ in () }
        verifier = AuthorityVerifier(state: authority, roots: roots, policy: policy, revocations: revocations)
    }

    public func issue(for approval: CanonicalMcpProposalApproval, audience: String,
                      finalizedHeight: UInt64, now: UInt64, lifetime: UInt64 = 120) throws -> CompositeIdentityChallenge {
        let (expires, overflow) = now.addingReportingOverflow(lifetime)
        guard !overflow, lifetime > 0, lifetime <= 120, !audience.isEmpty,
              audience.utf8.count <= 128 else { throw CompositeIdentityError.malformed }
        guard finalizedHeight < approval.expiresAtHeight else { throw CompositeIdentityError.expired }
        var random = Data(count: 32)
        let status = random.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard status == errSecSuccess else { throw CompositeIdentityError.persistence }
        let nonce = random.map { String(format: "%02x", $0) }.joined()
        let operation: String
        switch approval.action {
        case .transfer: operation = "activechain.mcp.v1.transfer"
        case .submitAnchor: operation = "activechain.mcp.v1.submitAnchor"
        }
        let proposalHex = approval.proposalID.map { String(format: "%02x", $0) }.joined()
        let expected = Action(authorityId: authority.authorityId, epoch: authority.epoch,
                              audience: audience, nonce: nonce, operation: operation,
                              resource: "activechain:proposal:" + proposalHex,
                              payloadDigest: try AnyIdentity.sha256(approval.intent), issuedAt: now, expiresAt: expires)
        let challenge = CompositeIdentityChallenge(expected: expected, proposalID: approval.proposalID,
                                                    nativeExpiresAtHeight: approval.expiresAtHeight)
        try journal.update { state in
            try state.advanceClock(now)
            state.records.removeAll { $0.challenge.expected.expiresAt <= now }
            guard state.records.count < 4_096 else { throw CompositeIdentityError.capacity }
            guard !state.records.contains(where: { $0.challenge.nonce == nonce }) else {
                throw CompositeIdentityError.replay
            }
            state.records.append(IdentityChallengeRecord(challenge: challenge, consumedAt: nil, actionDigest: nil))
        }
        return challenge
    }

    public func verifyAndConsume(_ bytes: Data, challenge nonce: String,
                                 approval: CanonicalMcpProposalApproval,
                                 finalizedHeight: UInt64, now: UInt64) async throws -> AuthorizedAction {
        guard !bytes.isEmpty, bytes.count <= 1_048_576 else { throw CompositeIdentityError.malformed }
        let challenge = try journal.update { state in
            try state.advanceClock(now)
            guard let record = state.records.first(where: { $0.challenge.nonce == nonce }) else {
                throw CompositeIdentityError.unknownChallenge
            }
            guard record.consumedAt == nil else { throw CompositeIdentityError.replay }
            let challenge = record.challenge
            guard now < challenge.expected.expiresAt, finalizedHeight < challenge.nativeExpiresAtHeight else {
                throw CompositeIdentityError.expired
            }
            guard approval.proposalID == challenge.proposalID,
                  approval.expiresAtHeight == challenge.nativeExpiresAtHeight,
                  try AnyIdentity.sha256(approval.intent) == challenge.expected.payloadDigest else {
                throw CompositeIdentityError.substitutedProposal
            }
            return challenge
        }
        let proof = try AnyIdentity.decode(CompositeIdentityProof.self, from: bytes)
        let authorization = try await verifier.verifyAndConsume(action: proof.action, expected: challenge.expected,
                                                                chain: proof.delegation, evidence: proof.evidence, now: now)
        try journal.update { state in
            try state.advanceClock(now)
            guard let index = state.records.firstIndex(where: { $0.challenge.nonce == nonce }),
                  state.records[index].challenge == challenge else { throw CompositeIdentityError.unknownChallenge }
            guard state.records[index].consumedAt == nil else { throw CompositeIdentityError.replay }
            state.records[index].consumedAt = now
            // This is identity audit metadata, never native 48-byte lifecycle evidence.
            state.records[index].actionDigest = authorization.verification.actionDigest
        }
        return authorization
    }
}

private struct IdentityJournalBinding: Codable, Equatable {
    let authority: AuthorityState
    let roots: [TrustedRoot]
    let policy: AssurancePolicy
}

private struct IdentityChallengeRecord: Codable {
    let challenge: CompositeIdentityChallenge
    var consumedAt: UInt64?
    var actionDigest: String?
}

private struct IdentityJournalState: Codable {
    var version = 1
    let binding: IdentityJournalBinding
    var checkedAt: UInt64
    var lastTime: UInt64 = 0
    var records: [IdentityChallengeRecord] = []

    mutating func advanceClock(_ now: UInt64) throws {
        guard now >= lastTime else { throw CompositeIdentityError.clock }
        lastTime = now
    }
}

/// OS locking and reload-under-lock also protect independent app/process views of one journal.
/// Only challenge metadata is retained; personal evidence and identity seeds are not written here.
private struct IdentityChallengeJournal {
    let file: URL
    let binding: IdentityJournalBinding
    let checkedAt: UInt64

    func update<T>(_ operation: (inout IdentityJournalState) throws -> T) throws -> T {
        let directory = file.deletingLastPathComponent()
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                     attributes: [.posixPermissions: 0o700])
        } catch { throw CompositeIdentityError.persistence }
        let lock = open(file.path + ".lock", O_CREAT | O_RDWR | O_NOFOLLOW, 0o600)
        guard lock >= 0 else { throw CompositeIdentityError.persistence }
        defer { close(lock) }
        guard flock(lock, LOCK_EX) == 0 else { throw CompositeIdentityError.persistence }
        defer { flock(lock, LOCK_UN) }
        var state: IdentityJournalState
        do {
            if FileManager.default.fileExists(atPath: file.path) {
                guard (try? FileManager.default.destinationOfSymbolicLink(atPath: file.path)) == nil else {
                    throw CompositeIdentityError.persistence
                }
                let bytes = try Data(contentsOf: file)
                guard bytes.count <= 4_194_304 else { throw CompositeIdentityError.persistence }
                state = try JSONDecoder().decode(IdentityJournalState.self, from: bytes)
                guard state.version == 1, state.records.count <= 4_096,
                      Set(state.records.map { $0.challenge.nonce }).count == state.records.count else {
                    throw CompositeIdentityError.persistence
                }
            } else { state = IdentityJournalState(binding: binding, checkedAt: checkedAt) }
        } catch { throw CompositeIdentityError.persistence }
        guard state.binding == binding, checkedAt >= state.checkedAt else {
            throw CompositeIdentityError.configuration
        }
        state.checkedAt = checkedAt
        let result = try operation(&state)
        do {
            try JSONEncoder().encode(state).write(to: file, options: [.atomic])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
            let handle = open(file.path, O_RDONLY | O_NOFOLLOW)
            guard handle >= 0 else { throw CompositeIdentityError.persistence }
            defer { close(handle) }
            guard fsync(handle) == 0 else { throw CompositeIdentityError.persistence }
            let parent = open(directory.path, O_RDONLY)
            guard parent >= 0 else { throw CompositeIdentityError.persistence }
            defer { close(parent) }
            guard fsync(parent) == 0 else { throw CompositeIdentityError.persistence }
        } catch { throw CompositeIdentityError.persistence }
        return result
    }
}
