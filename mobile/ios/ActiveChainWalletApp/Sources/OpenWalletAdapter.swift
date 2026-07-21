import Foundation

public struct OpenWalletCredentialReference: Equatable {
    public let credentialID: String
    public let schemaID: String
    public let issuer: String
}

public struct OpenWalletApplicationSession: Equatable {
    public let sessionID: String
    public let relyingParty: String
    public let expiresAt: UInt64
}

public final class OpenWalletAdapter {
    private(set) public var credentials: [OpenWalletCredentialReference] = []
    private(set) public var sessions: [OpenWalletApplicationSession] = []

    public init() {}

    public func register(_ credential: OpenWalletCredentialReference) -> Bool {
        guard !credentials.contains(where: { $0.credentialID == credential.credentialID }) else { return false }
        credentials.append(credential)
        credentials.sort { $0.credentialID < $1.credentialID }
        return true
    }

    public func open(_ session: OpenWalletApplicationSession, at height: UInt64) -> Bool {
        guard session.expiresAt >= height,
              !sessions.contains(where: { $0.sessionID == session.sessionID }) else { return false }
        sessions.append(session)
        sessions.sort { $0.sessionID < $1.sessionID }
        return true
    }
}
