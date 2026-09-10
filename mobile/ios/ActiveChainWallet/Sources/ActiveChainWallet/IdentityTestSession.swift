import Foundation

/// Protocol-test records carry no government-identity or native-chain admission authority.
public struct IdentityTestSession: Codable, Equatable, Sendable {
    public let id: String
    public let token: String
    public let expires: TimeInterval
    public let invocation: URL

    public func validate() throws {
        guard Self.isToken(id), Self.isToken(token), expires > Date().timeIntervalSince1970,
              let parts = URLComponents(url: invocation, resolvingAgainstBaseURL: false),
              parts.scheme == "eudi-openid4vp", parts.host == nil || parts.host == "",
              let items = parts.queryItems, items.count == 2,
              items.filter({ $0.name == "client_id" && $0.value == "rp.example" }).count == 1,
              items.filter({ $0.name == "request_uri" && $0.value == Self.base + "/request/" + id }).count == 1
        else { throw IdentityTestError.invalidResponse }
    }
    public static let base = "https://kanalen.actum.network/identity-test"
    public static func isToken(_ value: String) -> Bool {
        value.count == 43 && value.utf8.allSatisfy {
            (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95
        }
    }
    public func matchesReturn(_ url: URL) -> Bool {
        guard let parts = URLComponents(url: url, resolvingAgainstBaseURL: false),
              parts.scheme == "activechain-wallet", parts.host == "identity-return",
              parts.path.isEmpty, parts.fragment == nil, parts.user == nil, parts.port == nil,
              let items = parts.queryItems, items.count == 1 else { return false }
        return items[0].name == "session" && items[0].value == id
    }
}

public enum IdentityTestError: Error { case invalidResponse }

public struct IdentityTestReceipt: Codable, Equatable, Sendable {
    public let id: String
    public let owner: String
    public let chain: String
    public let status: String
    public let proof: String
    public let assurance: String

    public func validate(session: IdentityTestSession, owner: String, chain: String) throws {
        guard id == session.id, self.owner == owner, self.chain == chain, assurance == "test_only",
              ["pending", "expired", "declined", "rejected", "test_verified"].contains(status),
              status == "test_verified" ? (proof.count == 64 && proof.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }) : proof.isEmpty
        else { throw IdentityTestError.invalidResponse }
    }
}
