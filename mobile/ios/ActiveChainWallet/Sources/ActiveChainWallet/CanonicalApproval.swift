import Foundation

public struct Unsigned128Words: Equatable, Sendable {
    public let high: UInt64
    public let low: UInt64

    public init(high: UInt64, low: UInt64) {
        self.high = high
        self.low = low
    }
}

public struct CanonicalCashApproval: Equatable, Sendable {
    public let request: Data
    public let chainID: Data
    public let signer: Data
    public let recipient: Data
    public let feeReserve: Data
    public let sessionID: Data
    public let intentID: Data
    public let nonce: UInt64
    public let sessionExpiresAt: UInt64
    public let amount: Unsigned128Words
    public let fee: Unsigned128Words
    public let validUntil: UInt64
    public let inputCount: UInt32

    public init(
        request: Data, chainID: Data, signer: Data, recipient: Data, feeReserve: Data,
        sessionID: Data, intentID: Data, nonce: UInt64, sessionExpiresAt: UInt64,
        amount: Unsigned128Words, fee: Unsigned128Words, validUntil: UInt64, inputCount: UInt32
    ) {
        precondition(!request.isEmpty && chainID.count == 48 && signer.count == 48)
        precondition(recipient.count == 48 && feeReserve.count == 48 && sessionID.count == 48)
        precondition(intentID.count == 48 && inputCount > 0)
        self.request = request
        self.chainID = chainID
        self.signer = signer
        self.recipient = recipient
        self.feeReserve = feeReserve
        self.sessionID = sessionID
        self.intentID = intentID
        self.nonce = nonce
        self.sessionExpiresAt = sessionExpiresAt
        self.amount = amount
        self.fee = fee
        self.validUntil = validUntil
        self.inputCount = inputCount
    }
}

public protocol CanonicalApprovalReviewing {
    func review(_ canonicalRequest: Data) throws -> CanonicalCashApproval
}
