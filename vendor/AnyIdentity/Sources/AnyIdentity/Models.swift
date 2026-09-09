// Wire models shared with rust/src/model.rs. Times are Unix seconds; amounts are integer minor units.
import Foundation

public struct Signed<Payload: Codable & Sendable & Equatable>: Codable, Sendable, Equatable {
    public var version: UInt8
    public var kind: String
    public var signer: String
    public var payload: Payload
    public var signature: String
}

public struct Enrollment: Codable, Sendable, Equatable {
    public var authorityId: String
    public var subjectKey: String
    public var audience: String
    public var nonce: String
    public var issuedAt: UInt64
    public var expiresAt: UInt64

    public init(
        authorityId: String,
        subjectKey: String,
        audience: String,
        nonce: String,
        issuedAt: UInt64,
        expiresAt: UInt64
    ) {
        self.authorityId = authorityId
        self.subjectKey = subjectKey
        self.audience = audience
        self.nonce = nonce
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
    }
}

public struct Evidence: Codable, Sendable, Equatable {
    public var id: String
    public var authorityId: String
    public var subjectKey: String
    public var issuer: String
    public var credentialKind: String
    public var claims: [String]
    public var assuranceLevel: UInt8
    public var liveness: Bool
    public var hardwareBound: Bool
    public var issuedAt: UInt64
    public var expiresAt: UInt64

    public init(
        id: String,
        authorityId: String,
        subjectKey: String,
        issuer: String,
        credentialKind: String,
        claims: [String],
        assuranceLevel: UInt8,
        liveness: Bool,
        hardwareBound: Bool,
        issuedAt: UInt64,
        expiresAt: UInt64
    ) {
        self.id = id
        self.authorityId = authorityId
        self.subjectKey = subjectKey
        self.issuer = issuer
        self.credentialKind = credentialKind
        self.claims = claims
        self.assuranceLevel = assuranceLevel
        self.liveness = liveness
        self.hardwareBound = hardwareBound
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
    }
}

public struct TrustedRoot: Codable, Sendable, Equatable {
    public var issuer: String
    public var publicKey: String
    public var independenceGroup: String
    public var credentialKinds: [String]
    public var maximumAssuranceLevel: UInt8

    public init(
        issuer: String,
        publicKey: String,
        independenceGroup: String,
        credentialKinds: [String],
        maximumAssuranceLevel: UInt8
    ) {
        self.issuer = issuer
        self.publicKey = publicKey
        self.independenceGroup = independenceGroup
        self.credentialKinds = credentialKinds
        self.maximumAssuranceLevel = maximumAssuranceLevel
    }
}

public struct AssurancePolicy: Codable, Sendable, Equatable {
    public var minimumIndependentRoots: Int
    public var minimumAssuranceLevel: UInt8
    public var maximumAgeSeconds: UInt64
    public var requiredClaims: [String]
    public var requireLiveness: Bool
    public var requireHardware: Bool

    public init(
        minimumIndependentRoots: Int = 1,
        minimumAssuranceLevel: UInt8 = 1,
        maximumAgeSeconds: UInt64 = 86400,
        requiredClaims: [String] = [],
        requireLiveness: Bool = false,
        requireHardware: Bool = false
    ) {
        self.minimumIndependentRoots = minimumIndependentRoots
        self.minimumAssuranceLevel = minimumAssuranceLevel
        self.maximumAgeSeconds = maximumAgeSeconds
        self.requiredClaims = requiredClaims
        self.requireLiveness = requireLiveness
        self.requireHardware = requireHardware
    }
}

public struct Assurance: Codable, Sendable, Equatable {
    public var authorityId: String
    public var subjectKey: String
    public var independentRoots: Int
    public var acceptedEvidence: [String]
    public var claims: [String]
    public var validUntil: UInt64

    public init(
        authorityId: String,
        subjectKey: String,
        independentRoots: Int,
        acceptedEvidence: [String],
        claims: [String],
        validUntil: UInt64
    ) {
        self.authorityId = authorityId
        self.subjectKey = subjectKey
        self.independentRoots = independentRoots
        self.acceptedEvidence = acceptedEvidence
        self.claims = claims
        self.validUntil = validUntil
    }
}

public struct AuthorityState: Codable, Sendable, Equatable {
    public var authorityId: String
    public var currentKey: String
    public var epoch: UInt64
    public var recoveryKeys: [String]
    public var recoveryThreshold: Int

    public init(
        authorityId: String,
        currentKey: String,
        epoch: UInt64,
        recoveryKeys: [String],
        recoveryThreshold: Int
    ) {
        self.authorityId = authorityId
        self.currentKey = currentKey
        self.epoch = epoch
        self.recoveryKeys = recoveryKeys
        self.recoveryThreshold = recoveryThreshold
    }
}

public struct Transition: Codable, Sendable, Equatable {
    public var authorityId: String
    public var previousKey: String
    public var newKey: String
    public var epoch: UInt64
    public var issuedAt: UInt64
    public var expiresAt: UInt64
    public var recovery: Bool

    public init(
        authorityId: String,
        previousKey: String,
        newKey: String,
        epoch: UInt64,
        issuedAt: UInt64,
        expiresAt: UInt64,
        recovery: Bool
    ) {
        self.authorityId = authorityId
        self.previousKey = previousKey
        self.newKey = newKey
        self.epoch = epoch
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.recovery = recovery
    }
}

public struct RevocationSnapshot: Codable, Sendable, Equatable {
    public var checkedAt: UInt64
    public var validUntil: UInt64
    public var revokedKeys: [String]
    public var revokedEvidence: [String]
    public var revokedDelegations: [String]
    public var revokedAuthorities: [String]

    public init(
        checkedAt: UInt64,
        validUntil: UInt64,
        revokedKeys: [String] = [],
        revokedEvidence: [String] = [],
        revokedDelegations: [String] = [],
        revokedAuthorities: [String] = []
    ) {
        self.checkedAt = checkedAt
        self.validUntil = validUntil
        self.revokedKeys = revokedKeys
        self.revokedEvidence = revokedEvidence
        self.revokedDelegations = revokedDelegations
        self.revokedAuthorities = revokedAuthorities
    }
}

public struct Scope: Codable, Sendable, Equatable {
    public var operations: [String]
    public var resources: [String]
    public var maximumAmountMinor: UInt64?
    public var currency: String?
    public var merchantCategory: String?

    public init(
        operations: [String],
        resources: [String],
        maximumAmountMinor: UInt64? = nil,
        currency: String? = nil,
        merchantCategory: String? = nil
    ) {
        self.operations = operations
        self.resources = resources
        self.maximumAmountMinor = maximumAmountMinor
        self.currency = currency
        self.merchantCategory = merchantCategory
    }
}

public struct Delegation: Codable, Sendable, Equatable {
    public var authorityId: String
    public var epoch: UInt64
    public var parentDigest: String?
    public var delegateKey: String
    public var audience: String
    public var scope: Scope
    public var notBefore: UInt64
    public var expiresAt: UInt64
    public var remainingDepth: UInt8

    public init(
        authorityId: String,
        epoch: UInt64,
        parentDigest: String? = nil,
        delegateKey: String,
        audience: String,
        scope: Scope,
        notBefore: UInt64,
        expiresAt: UInt64,
        remainingDepth: UInt8
    ) {
        self.authorityId = authorityId
        self.epoch = epoch
        self.parentDigest = parentDigest
        self.delegateKey = delegateKey
        self.audience = audience
        self.scope = scope
        self.notBefore = notBefore
        self.expiresAt = expiresAt
        self.remainingDepth = remainingDepth
    }
}

public struct Action: Codable, Sendable, Equatable {
    public var authorityId: String
    public var epoch: UInt64
    public var audience: String
    public var nonce: String
    public var operation: String
    public var resource: String
    public var payloadDigest: String
    public var amountMinor: UInt64?
    public var currency: String?
    public var merchantCategory: String?
    public var issuedAt: UInt64
    public var expiresAt: UInt64

    public init(
        authorityId: String,
        epoch: UInt64,
        audience: String,
        nonce: String,
        operation: String,
        resource: String,
        payloadDigest: String,
        amountMinor: UInt64? = nil,
        currency: String? = nil,
        merchantCategory: String? = nil,
        issuedAt: UInt64,
        expiresAt: UInt64
    ) {
        self.authorityId = authorityId
        self.epoch = epoch
        self.audience = audience
        self.nonce = nonce
        self.operation = operation
        self.resource = resource
        self.payloadDigest = payloadDigest
        self.amountMinor = amountMinor
        self.currency = currency
        self.merchantCategory = merchantCategory
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
    }
}

public struct Verification: Codable, Sendable, Equatable {
    public var authorityId: String
    public var signer: String
    public var delegationDepth: Int
    public var actionDigest: String
    public var validUntil: UInt64

    public init(
        authorityId: String,
        signer: String,
        delegationDepth: Int,
        actionDigest: String,
        validUntil: UInt64
    ) {
        self.authorityId = authorityId
        self.signer = signer
        self.delegationDepth = delegationDepth
        self.actionDigest = actionDigest
        self.validUntil = validUntil
    }
}

public struct AuthorizedAction: Sendable, Equatable {
    public let verification: Verification
    public let assurance: Assurance
    public var validUntil: UInt64 { min(verification.validUntil, assurance.validUntil) }
}
