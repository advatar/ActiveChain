import ActiveChainWallet
import AnyIdentity
import Foundation
import XCTest

final class CompositeIdentityProofTests: XCTestCase {
    private struct Fixture {
        let person = try! IdentityKey(seed: Data(repeating: 1, count: 32))
        let authority: AuthorityState
        var roots: [TrustedRoot] = []
        var evidence: [Signed<Evidence>] = []
        var policy = AssurancePolicy(minimumIndependentRoots: 2, minimumAssuranceLevel: 2,
                                     requiredClaims: ["adult"], requireLiveness: true)
        var revocations = RevocationSnapshot(checkedAt: 100, validUntil: 1_000)
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        var journal: URL { directory.appendingPathComponent("challenges.json") }

        init() throws {
            authority = try AnyIdentity.createAuthority(key: person)
            for index in 0..<2 {
                let issuer = try IdentityKey(seed: Data(repeating: UInt8(index + 2), count: 32))
                let name = "issuer-\(index)"
                let enrollment = try AnyIdentity.enroll(Enrollment(authorityId: authority.authorityId,
                    subjectKey: authority.currentKey, audience: name, nonce: "enroll-\(index)",
                    issuedAt: 100, expiresAt: 200), key: person)
                evidence.append(try AnyIdentity.attest(enrollment: enrollment,
                    evidence: Evidence(id: "evidence-\(index)", authorityId: authority.authorityId,
                        subjectKey: authority.currentKey, issuer: name, credentialKind: "test",
                        claims: ["adult"], assuranceLevel: 2, liveness: true, hardwareBound: false,
                        issuedAt: 100, expiresAt: 1_000), expectedAudience: name,
                    expectedNonce: "enroll-\(index)", now: 150, issuerKey: issuer))
                roots.append(TrustedRoot(issuer: name, publicKey: try issuer.publicKey,
                    independenceGroup: name, credentialKinds: ["test"], maximumAssuranceLevel: 2))
            }
        }
        func verifier() throws -> CompositeIdentityApprovalVerifier {
            try CompositeIdentityApprovalVerifier(authority: authority, roots: roots, policy: policy,
                                                   revocations: revocations, journalURL: journal)
        }
        func proof(_ challenge: CompositeIdentityChallenge) throws -> Data {
            try CompositeIdentityProof(action: AnyIdentity.sign(challenge.expected, key: person),
                                       evidence: evidence).encoded()
        }
        func cleanup() { try? FileManager.default.removeItem(at: directory) }
    }

    private func approval(intent: Data = Data([1, 2, 3]), proposalByte: UInt8 = 7) -> CanonicalMcpProposalApproval {
        // Library contract fixture; the application factory separately obtains these fields from Rust.
        CanonicalMcpProposalApproval(intent: intent, requestID: "request", chainID: "testnet", walletID: "wallet",
            requestNonce: "nonce", agentPrincipal: Data(repeating: 1, count: 48),
            capabilityID: Data(repeating: 2, count: 48), resource: Data(repeating: 3, count: 48),
            recipient: Data(repeating: 4, count: 48), replayDomain: Data(repeating: 5, count: 48),
            intentCommitment: Data(repeating: 6, count: 48), proposalID: Data(repeating: proposalByte, count: 48),
            action: .transfer, amount: Unsigned128Words(high: 0, low: 50),
            maximumFee: Unsigned128Words(high: 0, low: 2), expiresAtHeight: 500)
    }

    private func rejects(_ body: () async throws -> Void, file: StaticString = #filePath, line: UInt = #line) async {
        do { try await body(); XCTFail("Authorization unexpectedly accepted", file: file, line: line) }
        catch { }
    }

    func testIndependentEvidenceAndProfilePolicies() throws {
        var f = try Fixture(); defer { f.cleanup() }
        let profile = CompositeIdentityProfile(authority: f.authority, evidence: f.evidence)
        XCTAssertEqual(try profile.assess(roots: f.roots, policy: f.policy,
                                          revocations: f.revocations, now: 150).independentRoots, 2)
        XCTAssertEqual(try JSONDecoder().decode(CompositeIdentityProfile.self,
                        from: JSONEncoder().encode(profile)), profile)
        f.roots[1].independenceGroup = f.roots[0].independenceGroup
        XCTAssertThrowsError(try profile.assess(roots: f.roots, policy: f.policy, revocations: f.revocations, now: 150))
        f.policy.minimumIndependentRoots = 1
        XCTAssertThrowsError(try profile.assess(roots: f.roots, policy: f.policy, revocations: f.revocations, now: 150))
    }

    func testSuccessfulProofConsumesBeforeNativeWorkAndSurvivesRestart() async throws {
        let f = try Fixture(); defer { f.cleanup() }
        let verifier = try f.verifier(), native = approval()
        let challenge = try await verifier.issue(for: native, audience: "wallet.example", finalizedHeight: 100, now: 150)
        XCTAssertEqual(challenge.expected.payloadDigest, try AnyIdentity.sha256(native.intent))
        XCTAssertEqual(challenge.expected.resource, "activechain:proposal:" + String(repeating: "07", count: 48))
        XCTAssertEqual(challenge.nonce.count, 64)
        let bytes = try f.proof(challenge)
        let authorization = try await verifier.verifyAndConsume(bytes, challenge: challenge.nonce,
                                                                approval: native, finalizedHeight: 100, now: 151)
        XCTAssertEqual(authorization.assurance.independentRoots, 2)
        // Simulate failed/cancelled native custody after identity success: no retry after restart.
        let restarted = try f.verifier()
        await rejects { _ = try await restarted.verifyAndConsume(bytes, challenge: challenge.nonce,
                                                                 approval: native, finalizedHeight: 100, now: 152) }
        let journal = try String(contentsOf: f.journal, encoding: .utf8)
        XCTAssertFalse(journal.contains("evidence-0"))
        XCTAssertFalse(journal.contains("signature"))
    }

    func testSubstitutionsAndInvalidEvidenceDoNotAuthorizeOrConsume() async throws {
        let f = try Fixture(); defer { f.cleanup() }
        let verifier = try f.verifier(), native = approval()
        let challenge = try await verifier.issue(for: native, audience: "wallet.example", finalizedHeight: 100, now: 150)
        let bytes = try f.proof(challenge)
        for replacement in [approval(intent: Data([1, 2, 4])), approval(proposalByte: 8)] {
            await rejects { _ = try await verifier.verifyAndConsume(bytes, challenge: challenge.nonce,
                                                                    approval: replacement, finalizedHeight: 100, now: 150) }
        }
        for index in 0..<6 {
            var action = challenge.expected
            var evidence = f.evidence
            var key = f.person
            switch index {
            case 0: evidence.removeLast()
            case 1: action.audience = "attacker.example"
            case 2: action.payloadDigest = String(repeating: "0", count: 64)
            case 3: action.nonce = "holder-chosen-nonce"
            case 4: key = try IdentityKey(seed: Data(repeating: 99, count: 32))
            default: evidence[0].payload.claims = ["adult", "forged"]
            }
            let invalid = try CompositeIdentityProof(action: AnyIdentity.sign(action, key: key), evidence: evidence).encoded()
            await rejects { _ = try await verifier.verifyAndConsume(invalid, challenge: challenge.nonce,
                                                                    approval: native, finalizedHeight: 100, now: 150) }
        }
        _ = try await verifier.verifyAndConsume(bytes, challenge: challenge.nonce,
                                                approval: native, finalizedHeight: 100, now: 150)
    }

    func testExpiryRevocationClaimsAndBoundsFailClosed() async throws {
        for index in 0..<9 {
            var f = try Fixture(); defer { f.cleanup() }
            switch index {
            case 0: f.revocations.revokedKeys = [f.authority.currentKey]
            case 1: f.revocations.revokedEvidence = [try AnyIdentity.evidenceReference(issuer: "issuer-0", id: "evidence-0")]
            case 2: f.revocations.validUntil = 150
            case 3: f.policy.requiredClaims = ["unattested"]
            case 4: f.roots[1].independenceGroup = f.roots[0].independenceGroup
            default: break
            }
            let verifier = try f.verifier(), native = approval()
            let challenge = try await verifier.issue(for: native, audience: "wallet.example", finalizedHeight: 100, now: 150)
            let bytes = index == 8 ? Data(repeating: 1, count: 1_048_577) : try f.proof(challenge)
            await rejects { _ = try await verifier.verifyAndConsume(bytes, challenge: index == 7 ? "unknown" : challenge.nonce,
                approval: native, finalizedHeight: index == 5 ? 500 : 100, now: index == 6 ? 270 : 150) }
        }
    }

    func testIndependentVerifierInstancesRaceForOneDurableConsumption() async throws {
        let f = try Fixture(); defer { f.cleanup() }
        let first = try f.verifier(), second = try f.verifier(), native = approval()
        let challenge = try await first.issue(for: native, audience: "wallet.example", finalizedHeight: 100, now: 150)
        let bytes = try f.proof(challenge)
        let count = await withTaskGroup(of: Bool.self) { group in
            for verifier in [first, second] { group.addTask {
                do { _ = try await verifier.verifyAndConsume(bytes, challenge: challenge.nonce,
                    approval: native, finalizedHeight: 100, now: 150); return true } catch { return false }
            } }
            var successes = 0
            for await success in group { if success { successes += 1 } }
            return successes
        }
        XCTAssertEqual(count, 1)
    }

    func testRestartClockRevocationRollbackAndCorruptionFailClosed() async throws {
        var f = try Fixture(); defer { f.cleanup() }
        let initial = try f.verifier(), native = approval()
        let challenge = try await initial.issue(for: native, audience: "wallet.example", finalizedHeight: 100, now: 150)
        let restarted = try f.verifier()
        await rejects { _ = try await restarted.issue(for: native, audience: "wallet.example", finalizedHeight: 100, now: 149) }
        f.revocations.checkedAt = 101
        _ = try f.verifier()
        await rejects { _ = try await initial.verifyAndConsume(f.proof(challenge), challenge: challenge.nonce,
                                                               approval: native, finalizedHeight: 100, now: 150) }
        try Data("corrupt".utf8).write(to: f.journal)
        XCTAssertThrowsError(try f.verifier())
    }

    func testDelegatedProofRetainsScopeAndRequiresBothIssuers() async throws {
        let f = try Fixture(); defer { f.cleanup() }
        let verifier = try f.verifier(), native = approval()
        let challenge = try await verifier.issue(for: native, audience: "wallet.example", finalizedHeight: 100, now: 150)
        let agent = try IdentityKey(seed: Data(repeating: 9, count: 32))
        var scope = Scope(operations: ["wrong"], resources: [challenge.expected.resource])
        for accepted in [false, true] {
            if accepted { scope.operations = [challenge.expected.operation] }
            let delegation = try AnyIdentity.delegate(Delegation(authorityId: f.authority.authorityId,
                epoch: f.authority.epoch, delegateKey: agent.publicKey, audience: challenge.expected.audience,
                scope: scope, notBefore: 100, expiresAt: 300, remainingDepth: 0), key: f.person)
            let bytes = try CompositeIdentityProof(action: AnyIdentity.sign(challenge.expected, key: agent),
                                                   evidence: f.evidence, delegation: [delegation]).encoded()
            if accepted {
                let result = try await verifier.verifyAndConsume(bytes, challenge: challenge.nonce,
                                                                 approval: native, finalizedHeight: 100, now: 150)
                XCTAssertEqual(result.verification.delegationDepth, 1)
            } else {
                await rejects { _ = try await verifier.verifyAndConsume(bytes, challenge: challenge.nonce,
                                                                        approval: native, finalizedHeight: 100, now: 150) }
            }
        }
    }
}
