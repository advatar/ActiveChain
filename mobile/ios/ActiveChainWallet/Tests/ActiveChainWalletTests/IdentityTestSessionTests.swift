import XCTest
@testable import ActiveChainWallet

final class IdentityTestSessionTests: XCTestCase {
    private func session() throws -> IdentityTestSession {
        let id = String(repeating: "a", count: 43)
        let raw: [String: Any] = ["id": id, "token": String(repeating: "b", count: 43), "expires": Date().timeIntervalSince1970 + 120,
            "invocation": "eudi-openid4vp://?client_id=rp.example&request_uri=https%3A%2F%2Fkanalen.actum.network%2Fidentity-test%2Frequest%2F" + id]
        return try JSONDecoder().decode(IdentityTestSession.self, from: JSONSerialization.data(withJSONObject: raw))
    }
    func testCallbackCannotGrantCredentialOrSubstituteSession() throws {
        let session = try session()
        try session.validate()
        XCTAssertTrue(session.matchesReturn(URL(string: "activechain-wallet://identity-return?session=" + session.id)!))
        XCTAssertFalse(session.matchesReturn(URL(string: "activechain-wallet://identity-return?session=other")!))
        XCTAssertFalse(session.matchesReturn(URL(string: "activechain-wallet://identity-return?session=" + session.id + "&verified=true")!))
        XCTAssertFalse(session.matchesReturn(URL(string: "activechain-wallet://identity-return?session=" + session.id + "#fragment")!))
    }
    func testReceiptIsTestOnlyAndBoundToExactWalletAndChain() throws {
        let session = try session()
        var raw = ["id": session.id, "owner": "owner", "chain": "chain", "status": "test_verified", "proof": String(repeating: "a", count: 64), "assurance": "test_only"]
        func receipt() throws -> IdentityTestReceipt {
            try JSONDecoder().decode(IdentityTestReceipt.self, from: JSONSerialization.data(withJSONObject: raw))
        }
        try receipt().validate(session: session, owner: "owner", chain: "chain")
        XCTAssertThrowsError(try receipt().validate(session: session, owner: "other", chain: "chain"))
        XCTAssertThrowsError(try receipt().validate(session: session, owner: "owner", chain: "other"))
        raw["assurance"] = "government_verified"
        XCTAssertThrowsError(try receipt().validate(session: session, owner: "owner", chain: "chain"))
        raw["assurance"] = "test_only"; raw["proof"] = ""
        XCTAssertThrowsError(try receipt().validate(session: session, owner: "owner", chain: "chain"))
    }
}
