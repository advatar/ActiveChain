import AnyIdentity
import Foundation

// Synthetic attestors demonstrate the protocol. These are not government credentials.
@main
struct Demo {
    static func main() async throws {
        let person = try IdentityKey()
        let agent = try IdentityKey()
        let state = try AnyIdentity.createAuthority(key: person)
        let now = UInt64(Date().timeIntervalSince1970)
        let enrollment = try AnyIdentity.enroll(Enrollment(
            authorityId: state.authorityId, subjectKey: state.currentKey,
            audience: "demo-enrollment", nonce: UUID().uuidString,
            issuedAt: now, expiresAt: now + 300), key: person)
        var roots: [TrustedRoot] = []
        var bindings: [Signed<Evidence>] = []
        for (issuer, kind) in [("demo-dmv", "mdl"), ("demo-passport", "passport")] {
            let key = try IdentityKey()
            roots.append(TrustedRoot(issuer: issuer, publicKey: try key.publicKey,
                independenceGroup: issuer, credentialKinds: [kind], maximumAssuranceLevel: 2))
            let facts = Evidence(id: UUID().uuidString, authorityId: state.authorityId,
                subjectKey: state.currentKey, issuer: issuer, credentialKind: kind,
                claims: ["adult", "government_identity"], assuranceLevel: 2,
                liveness: true, hardwareBound: false, issuedAt: now, expiresAt: now + 3600)
            bindings.append(try AnyIdentity.attest(enrollment: enrollment, evidence: facts,
                expectedAudience: "demo-enrollment", expectedNonce: enrollment.payload.nonce,
                now: now, issuerKey: key))
        }
        let delegation = try AnyIdentity.delegate(Delegation(
            authorityId: state.authorityId, epoch: 0, delegateKey: try agent.publicKey,
            audience: "travel.example", scope: Scope(operations: ["book"], resources: ["flight"],
                maximumAmountMinor: 200_000, currency: "GBP", merchantCategory: "travel"),
            notBefore: now, expiresAt: now + 600, remainingDepth: 0), key: person)
        let request = Action(authorityId: state.authorityId, epoch: 0,
            audience: "travel.example", nonce: UUID().uuidString, operation: "book", resource: "flight",
            payloadDigest: try AnyIdentity.sha256(Data("LHR to ARN, flight example".utf8)),
            amountMinor: 95_000, currency: "GBP", merchantCategory: "travel",
            issuedAt: now, expiresAt: now + 60)
        let verifier = AuthorityVerifier(state: state, roots: roots,
            policy: AssurancePolicy(minimumIndependentRoots: 2, minimumAssuranceLevel: 2,
                requiredClaims: ["government_identity"], requireLiveness: true),
            revocations: RevocationSnapshot(checkedAt: now, validUntil: now + 300))
        let signed = try AnyIdentity.sign(request, key: agent)
        let result = try await verifier.verifyAndConsume(action: signed, expected: request,
            chain: [delegation], evidence: bindings, now: now)
        print("Authorized booking: \(result.assurance.independentRoots) independent roots; \(result.verification.delegationDepth) delegation")
        do {
            _ = try await verifier.verifyAndConsume(action: signed, expected: request,
                chain: [delegation], evidence: bindings, now: now)
            fatalError("Replay should have been rejected")
        } catch let error as AnyIdentityError {
            guard error.code == "replay" else { throw error }
            print("Replay rejected")
        }
        let bank = try person.pairwiseKey(for: "bank.example")
        let hospital = try person.pairwiseKey(for: "hospital.example")
        print("Separate pairwise keys: \(try bank.publicKey != hospital.publicKey)")
    }
}
