import Foundation
import CAnyIdentity

public enum AnyIdentity {
    public static func createAuthority(key: IdentityKey, recoveryKeys: [String] = [], recoveryThreshold: Int = 0) throws -> AuthorityState {
        try Bridge.call("create_authority", ["recoveryKeys": recoveryKeys, "recoveryThreshold": recoveryThreshold], key: key)
    }
    public static func enroll(_ enrollment: Enrollment, key: IdentityKey) throws -> Signed<Enrollment> {
        try Bridge.call("enroll", ["enrollment": enrollment], key: key)
    }
    /// Trusted attestor boundary: verify the source credential and same-person binding before calling.
    /// expectedNonce must come from the attestor's one-use challenge store, never from the submitted proof.
    public static func attest(enrollment: Signed<Enrollment>, evidence: Evidence, expectedAudience: String, expectedNonce: String, now: UInt64, issuerKey: IdentityKey) throws -> Signed<Evidence> {
        try Bridge.call("attest", ["enrollment": enrollment, "evidence": evidence,
            "expectedAudience": expectedAudience, "expectedNonce": expectedNonce, "now": now], key: issuerKey)
    }
    public static func assess(state: AuthorityState, evidence: [Signed<Evidence>], roots: [TrustedRoot], policy: AssurancePolicy, revocations: RevocationSnapshot, now: UInt64) throws -> Assurance {
        try Bridge.call("assess", ["state": state, "evidence": evidence, "roots": roots,
            "policy": policy, "revocations": revocations, "now": now])
    }
    public static func approveTransition(_ transition: Transition, key: IdentityKey) throws -> Signed<Transition> {
        try Bridge.call("approve_transition", ["transition": transition], key: key)
    }
    /// Apply to a pinned current state and atomically persist the result to prevent rollback/forks.
    public static func applyTransition(state: AuthorityState, approvals: [Signed<Transition>], revocations: RevocationSnapshot, now: UInt64) throws -> AuthorityState {
        try Bridge.call("apply_transition", ["state": state, "approvals": approvals, "revocations": revocations, "now": now])
    }
    public static func delegate(_ delegation: Delegation, key: IdentityKey) throws -> Signed<Delegation> {
        try Bridge.call("delegate", ["delegation": delegation], key: key)
    }
    public static func sign(_ action: Action, key: IdentityKey) throws -> Signed<Action> {
        try Bridge.call("sign_action", ["action": action], key: key)
    }
    /// Stateless cryptographic check. Use AuthorityVerifier for identity assurance and in-process replay protection.
    /// Expected must be the verifier's intended request, including its unpredictable challenge and payload digest.
    public static func verifyAction(state: AuthorityState, chain: [Signed<Delegation>] = [], action: Signed<Action>, expected: Action, revocations: RevocationSnapshot, now: UInt64) throws -> Verification {
        try Bridge.call("verify_action", ["state": state, "chain": chain, "action": action,
            "expected": expected, "revocations": revocations, "now": now])
    }
    public static func digest<T>(_ envelope: Signed<T>) throws -> String {
        try Bridge.call("envelope_digest", ["envelope": envelope])
    }
    public static func evidenceReference(issuer: String, id: String) throws -> String {
        try Bridge.call("evidence_reference", ["issuer": issuer, "id": id])
    }
    public static func sha256(_ data: Data) throws -> String {
        var output = [CChar](repeating: 0, count: 65)
        let success = data.withUnsafeBytes { bytes in
            anyidentity_sha256(bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count, &output)
        }
        guard success else { throw AnyIdentityError(code: "ffi", message: "Hashing failed") }
        return String(decoding: output.prefix(64).map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder(); encoder.keyEncodingStrategy = .convertToSnakeCase
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }
    public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        let decoder = JSONDecoder(); decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(type, from: data)
    }
}

/// Adapter implementations validate issuer signatures, trust chains, holder binding, freshness,
/// status and same-person evidence in their native credential ecosystem. No unverified raw
/// credential can enter the core as trusted evidence automatically.
public protocol IdentityEvidenceAdapter: Sendable {
    var credentialKind: String { get }
    func verifyAndAttest(credential: Data, enrollment: Signed<Enrollment>) async throws -> Signed<Evidence>
}

/// A verifier scoped to one pinned authority. Trusted inputs must come from authenticated local
/// configuration. Replay state is process-local; services must persist nonces and transitions
/// atomically with side effects across restarts and replicas.
public actor AuthorityVerifier {
    private var state: AuthorityState
    private let roots: [TrustedRoot]
    private let policy: AssurancePolicy
    private var revocations: RevocationSnapshot
    private struct Nonce: Hashable { let audience: String; let value: String }
    private var consumed: [Nonce: UInt64] = [:]
    private var lastTime: UInt64 = 0
    private let maximumReplayEntries: Int

    public init(state: AuthorityState, roots: [TrustedRoot], policy: AssurancePolicy,
                revocations: RevocationSnapshot, maximumReplayEntries: Int = 100_000) {
        self.state = state; self.roots = roots; self.policy = policy
        self.revocations = revocations; self.maximumReplayEntries = maximumReplayEntries
    }
    public func currentState() -> AuthorityState { state }
    public func updateRevocations(_ snapshot: RevocationSnapshot) throws {
        guard snapshot.checkedAt >= revocations.checkedAt else {
            throw AnyIdentityError(code: "rollback", message: "Revocation snapshot moved backwards")
        }
        revocations = snapshot
    }
    public func transition(approvals: [Signed<Transition>], now: UInt64) throws -> AuthorityState {
        try checkClock(now)
        state = try AnyIdentity.applyTransition(state: state, approvals: approvals, revocations: revocations, now: now)
        return state
    }
    public func verifyAndConsume(action: Signed<Action>, expected: Action, chain: [Signed<Delegation>] = [],
                                 evidence: [Signed<Evidence>], now: UInt64) throws -> AuthorizedAction {
        try checkClock(now)
        consumed = consumed.filter { $0.value > now }
        let nonce = Nonce(audience: expected.audience, value: expected.nonce)
        guard consumed[nonce] == nil else { throw AnyIdentityError(code: "replay", message: "Challenge already consumed") }
        guard consumed.count < maximumReplayEntries else {
            throw AnyIdentityError(code: "capacity", message: "Replay cache full; no unexpired challenges evicted")
        }
        let assurance = try AnyIdentity.assess(state: state, evidence: evidence, roots: roots,
                                             policy: policy, revocations: revocations, now: now)
        let verified = try AnyIdentity.verifyAction(state: state, chain: chain, action: action,
                                                   expected: expected, revocations: revocations, now: now)
        consumed[nonce] = expected.expiresAt
        return AuthorizedAction(verification: verified, assurance: assurance)
    }
    private func checkClock(_ now: UInt64) throws {
        guard now >= lastTime else { throw AnyIdentityError(code: "clock", message: "Verifier time moved backwards") }
        lastTime = now
    }
}
