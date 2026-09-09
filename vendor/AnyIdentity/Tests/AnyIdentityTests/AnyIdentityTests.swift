import Foundation
import CryptoKit
import Testing
@testable import AnyIdentity

private struct Fixture {
    let person: IdentityKey
    let agent: IdentityKey
    let issuer: IdentityKey
    let state: AuthorityState
    let evidence: Signed<Evidence>
    let root: TrustedRoot
    let revocations = RevocationSnapshot(checkedAt: 100, validUntil: 1000)
    init() throws {
        person = try IdentityKey(seed: Data(repeating: 1, count: 32))
        agent = try IdentityKey(seed: Data(repeating: 2, count: 32))
        issuer = try IdentityKey(seed: Data(repeating: 3, count: 32))
        state = try AnyIdentity.createAuthority(key: person)
        let enrollment = try AnyIdentity.enroll(Enrollment(authorityId: state.authorityId,
            subjectKey: state.currentKey, audience: "issuer", nonce: "enrollment-nonce",
            issuedAt: 100, expiresAt: 200), key: person)
        evidence = try AnyIdentity.attest(enrollment: enrollment,
            evidence: Evidence(id: "e1", authorityId: state.authorityId, subjectKey: state.currentKey,
                issuer: "issuer", credentialKind: "test", claims: ["adult"], assuranceLevel: 2,
                liveness: true, hardwareBound: false, issuedAt: 100, expiresAt: 1000),
            expectedAudience: "issuer", expectedNonce: "enrollment-nonce", now: 150, issuerKey: issuer)
        root = TrustedRoot(issuer: "issuer", publicKey: try issuer.publicKey,
            independenceGroup: "independent", credentialKinds: ["test"], maximumAssuranceLevel: 2)
    }
    func action(nonce: String = "action-nonce") throws -> Action {
        Action(authorityId: state.authorityId, epoch: state.epoch, audience: "travel.example",
            nonce: nonce, operation: "book", resource: "flight",
            payloadDigest: try AnyIdentity.sha256(Data("flight data".utf8)), amountMinor: 12345,
            currency: "GBP", merchantCategory: "travel", issuedAt: 150, expiresAt: 200)
    }
    func delegation() throws -> Signed<Delegation> {
        try AnyIdentity.delegate(Delegation(authorityId: state.authorityId, epoch: 0,
            delegateKey: try agent.publicKey, audience: "travel.example",
            scope: Scope(operations: ["book"], resources: ["flight"], maximumAmountMinor: 20000,
                         currency: "GBP", merchantCategory: "travel"),
            notBefore: 100, expiresAt: 300, remainingDepth: 0), key: person)
    }
    func verifier(capacity: Int = 100_000) -> AuthorityVerifier {
        AuthorityVerifier(state: state, roots: [root], policy: AssurancePolicy(requiredClaims: ["adult"]),
                          revocations: revocations, maximumReplayEntries: capacity)
    }
}

@Test func keysHashingAndNativeOwnership() throws {
    let key = try IdentityKey(seed: Data(repeating: 42, count: 32))
    let restored = try IdentityKey(seed: key.exportSeed())
    #expect(try restored.publicKey == key.publicKey)
    #expect(throws: AnyIdentityError.self) { try IdentityKey(seed: Data(count: 31)) }
    #expect(try AnyIdentity.sha256(Data("abc".utf8)) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    #expect(try AnyIdentity.sha256(Data()) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    for _ in 0..<100 { let transient = try IdentityKey(); #expect(try transient.publicKey.count == 64) }
}
@Test func pairwiseKeysAreStableAcrossRestorationAndSeparated() throws {
    let key = try IdentityKey()
    let restored = try IdentityKey(seed: key.exportSeed())
    let bank = try key.pairwiseKey(for: "bank.example")
    #expect(try bank.publicKey == restored.pairwiseKey(for: "bank.example").publicKey)
    #expect(try bank.publicKey != key.pairwiseKey(for: "hospital.example").publicKey)
    #expect(throws: AnyIdentityError.self) { try key.pairwiseKey(for: "") }
}
@Test func nativeSignatureIndependentlyVerifiesWithCryptoKit() throws {
    let f = try Fixture(); let action = try f.action()
    let signed = try AnyIdentity.sign(action, key: f.person)
    let encoded = try AnyIdentity.encode(signed)
    var transcript = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
    transcript.removeValue(forKey: "signature"); transcript["protocol"] = "AnyIdentity"
    let bytes = try JSONSerialization.data(withJSONObject: transcript, options: [.sortedKeys, .withoutEscapingSlashes])
    func unhex(_ s: String) -> Data { Data(stride(from: 0, to: s.count, by: 2).map { i in
        let start = s.index(s.startIndex, offsetBy: i); let end = s.index(start, offsetBy: 2)
        return UInt8(s[start..<end], radix: 16)!
    }) }
    let key = try Curve25519.Signing.PublicKey(rawRepresentation: unhex(signed.signer))
    #expect(key.isValidSignature(unhex(signed.signature), for: bytes))
    let decoded = try AnyIdentity.decode(Signed<Action>.self, from: encoded)
    #expect(decoded == signed)
    #expect(try AnyIdentity.digest(decoded) == AnyIdentity.digest(signed))
}
@Test func evidencePolicyAndWrongHolderAreEnforced() throws {
    let f = try Fixture()
    let assurance = try AnyIdentity.assess(state: f.state, evidence: [f.evidence], roots: [f.root],
        policy: AssurancePolicy(requiredClaims: ["adult"]), revocations: f.revocations, now: 150)
    #expect(assurance.independentRoots == 1)
    #expect(throws: AnyIdentityError.self) { try AnyIdentity.assess(state: f.state, evidence: [f.evidence], roots: [f.root],
        policy: AssurancePolicy(minimumIndependentRoots: 2), revocations: f.revocations, now: 150) }
    let other = try AnyIdentity.createAuthority(key: f.agent)
    #expect(throws: AnyIdentityError.self) { try AnyIdentity.assess(state: other, evidence: [f.evidence], roots: [f.root],
        policy: AssurancePolicy(), revocations: f.revocations, now: 150) }
}
@Test func delegatedAuthorizationAndReplayProtection() async throws {
    let f = try Fixture(); let action = try f.action(); let d = try f.delegation()
    let signed = try AnyIdentity.sign(action, key: f.agent); let verifier = f.verifier()
    let result = try await verifier.verifyAndConsume(action: signed, expected: action, chain: [d], evidence: [f.evidence], now: 150)
    #expect(result.verification.delegationDepth == 1)
    #expect(result.validUntil == 200)
    await #expect(throws: AnyIdentityError(code: "replay", message: "Challenge already consumed")) {
        try await verifier.verifyAndConsume(action: signed, expected: action, chain: [d], evidence: [f.evidence], now: 150)
    }
}
@Test func concurrentReplayHasOnlyOneWinner() async throws {
    let f = try Fixture(); let action = try f.action(); let signed = try AnyIdentity.sign(action, key: f.person)
    let verifier = f.verifier()
    let successes = await withTaskGroup(of: Bool.self) { group in
        for _ in 0..<20 { group.addTask {
            do { _ = try await verifier.verifyAndConsume(action: signed, expected: action, evidence: [f.evidence], now: 150); return true }
            catch { return false }
        } }
        var count = 0; for await success in group { if success { count += 1 } }; return count
    }
    #expect(successes == 1)
}
@Test func invalidRequestDoesNotConsumeChallenge() async throws {
    let f = try Fixture(); let action = try f.action(); let verifier = f.verifier()
    var tampered = try AnyIdentity.sign(action, key: f.person); tampered.payload.resource = "wrong"
    await #expect(throws: AnyIdentityError.self) {
        try await verifier.verifyAndConsume(action: tampered, expected: action, evidence: [f.evidence], now: 150)
    }
    _ = try await verifier.verifyAndConsume(action: AnyIdentity.sign(action, key: f.person), expected: action,
                                           evidence: [f.evidence], now: 150)
}
@Test func scopeAmountAudienceExpiryAndRevocationsFailClosed() throws {
    let f = try Fixture(); let chain = [try f.delegation()]
    for i in 0..<5 {
        var a = try f.action()
        switch i { case 0: a.amountMinor = 20001; case 1: a.audience = "evil.example"
        case 2: a.currency = "USD"; case 3: a.operation = "delete"; default: a.expiresAt = 301 }
        let signed = try AnyIdentity.sign(a, key: f.agent)
        #expect(throws: AnyIdentityError.self) { try AnyIdentity.verifyAction(state: f.state, chain: chain,
            action: signed, expected: a, revocations: f.revocations, now: 150) }
    }
    let a = try f.action(); let signed = try AnyIdentity.sign(a, key: f.agent)
    var r = f.revocations; r.revokedDelegations = [try AnyIdentity.digest(chain[0])]
    #expect(throws: AnyIdentityError.self) { try AnyIdentity.verifyAction(state: f.state, chain: chain,
        action: signed, expected: a, revocations: r, now: 150) }
    r = f.revocations; r.validUntil = 150
    #expect(throws: AnyIdentityError.self) { try AnyIdentity.verifyAction(state: f.state, chain: chain,
        action: signed, expected: a, revocations: r, now: 150) }
}
@Test func rotationAndRecoveryCrossTheFFI() throws {
    let person = try IdentityKey(); let replacement = try IdentityKey(); let guardian = try IdentityKey()
    let initial = try AnyIdentity.createAuthority(key: person, recoveryKeys: [guardian.publicKey], recoveryThreshold: 1)
    let revocations = RevocationSnapshot(checkedAt: 100, validUntil: 1000)
    for recovery in [false, true] {
        let t = Transition(authorityId: initial.authorityId, previousKey: initial.currentKey,
            newKey: try replacement.publicKey, epoch: 1, issuedAt: 100, expiresAt: 200, recovery: recovery)
        let approval = try AnyIdentity.approveTransition(t, key: recovery ? guardian : person)
        #expect(throws: AnyIdentityError.self) { try AnyIdentity.applyTransition(state: initial, approvals: [approval], revocations: revocations, now: 150) }
        let approvals = [approval, try AnyIdentity.approveTransition(t, key: replacement)]
        let result = try AnyIdentity.applyTransition(state: initial, approvals: approvals, revocations: revocations, now: 150)
        #expect(result.authorityId == initial.authorityId); #expect(result.epoch == 1)
        #expect(throws: AnyIdentityError.self) { try AnyIdentity.applyTransition(state: result, approvals: approvals, revocations: revocations, now: 150) }
    }
}
@Test func replayCacheCapacityAndClockRollbackFailClosed() async throws {
    let f = try Fixture(); let verifier = f.verifier(capacity: 1); let first = try f.action()
    _ = try await verifier.verifyAndConsume(action: AnyIdentity.sign(first, key: f.person), expected: first, evidence: [f.evidence], now: 150)
    let next = try f.action(nonce: "next")
    await #expect(throws: AnyIdentityError.self) { try await verifier.verifyAndConsume(action: AnyIdentity.sign(next, key: f.person), expected: next, evidence: [f.evidence], now: 150) }
    await #expect(throws: AnyIdentityError.self) { try await verifier.verifyAndConsume(action: AnyIdentity.sign(next, key: f.person), expected: next, evidence: [f.evidence], now: 149) }
    await #expect(throws: AnyIdentityError.self) { try await verifier.updateRevocations(RevocationSnapshot(checkedAt: 99, validUntil: 1000)) }
}

@Test func childDelegationUsesNormalizedParentDigestAcrossFFI() throws {
    let f = try Fixture(); let childAgent = try IdentityKey()
    var rootPayload = try f.delegation().payload; rootPayload.remainingDepth = 1
    // Exercise optional-field normalization in the parent hash as well as attenuation.
    rootPayload.scope.merchantCategory = nil
    let root = try AnyIdentity.delegate(rootPayload, key: f.person)
    var childPayload = rootPayload
    childPayload.parentDigest = try AnyIdentity.digest(root)
    childPayload.delegateKey = try childAgent.publicKey
    childPayload.remainingDepth = 0
    childPayload.scope.maximumAmountMinor = 15000
    let child = try AnyIdentity.delegate(childPayload, key: f.agent)
    let action = try f.action(); let signed = try AnyIdentity.sign(action, key: childAgent)
    let result = try AnyIdentity.verifyAction(state: f.state, chain: [root, child], action: signed,
        expected: action, revocations: f.revocations, now: 150)
    #expect(result.delegationDepth == 2)
    childPayload.scope.maximumAmountMinor = 30000
    let expanded = try AnyIdentity.delegate(childPayload, key: f.agent)
    #expect(throws: AnyIdentityError.self) {
        try AnyIdentity.verifyAction(state: f.state, chain: [root, expanded], action: signed,
            expected: action, revocations: f.revocations, now: 150)
    }
}
