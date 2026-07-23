import Foundation

struct AmberBondQuote: Equatable, Sendable {
    let postingFee: UInt64
    let postBond: UInt64
    let maximumSlash: UInt64
    let reportBond: UInt64
    let policyRevision: UInt64

    init(
        postingFee: UInt64,
        postBond: UInt64,
        maximumSlash: UInt64,
        reportBond: UInt64,
        policyRevision: UInt64
    ) throws {
        guard postingFee > 0,
              postBond > 0,
              maximumSlash > 0,
              maximumSlash <= postBond,
              reportBond > 0,
              policyRevision > 0
        else {
            throw AmberBondError.invalidQuote
        }
        self.postingFee = postingFee
        self.postBond = postBond
        self.maximumSlash = maximumSlash
        self.reportBond = reportBond
        self.policyRevision = policyRevision
    }

    var amountLockedAtSubmission: UInt64 {
        postingFee + postBond
    }

    func upheldSettlement(
        penalty: UInt64,
        reporterReward: UInt64
    ) throws -> AmberUpheldSettlement {
        guard penalty > 0,
              penalty <= maximumSlash,
              reporterReward <= penalty
        else {
            throw AmberBondError.invalidSettlement
        }
        return AmberUpheldSettlement(
            posterResidual: postBond - penalty,
            reporterBondReturned: reportBond,
            reporterReward: reporterReward,
            slashedToBoardTreasury: penalty - reporterReward
        )
    }
}

struct AmberUpheldSettlement: Equatable, Sendable {
    let posterResidual: UInt64
    let reporterBondReturned: UInt64
    let reporterReward: UInt64
    let slashedToBoardTreasury: UInt64

    var totalOutputs: UInt64 {
        posterResidual + reporterBondReturned + reporterReward + slashedToBoardTreasury
    }
}

enum AmberBondError: Error, Equatable {
    case invalidQuote
    case invalidSettlement
}

extension AmberBondQuote {
    static let kanalenPreview = try! AmberBondQuote(
        postingFee: 1,
        postBond: 25,
        maximumSlash: 25,
        reportBond: 25,
        policyRevision: 1
    )
}
