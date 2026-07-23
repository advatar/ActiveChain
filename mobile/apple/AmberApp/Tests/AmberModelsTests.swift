import XCTest
@testable import AmberApp

final class AmberModelsTests: XCTestCase {
    func testBoardIdentifierUsesBoundedCanonicalSlug() throws {
        XCTAssertEqual(try AmberBoardID("ac").description, "/ac/")
        XCTAssertThrowsError(try AmberBoardID("Uppercase"))
        XCTAssertThrowsError(try AmberBoardID("thisslugistoolong"))
    }

    func testThreadSortsPostsAndRejectsDuplicates() throws {
        let board = try AmberBoardID("test")
        let later = try AmberPost(
            id: AmberPostID(board: board, threadNumber: 7, postNumber: 2),
            body: "second",
            createdAt: Date()
        )
        let first = try AmberPost(
            id: AmberPostID(board: board, threadNumber: 7, postNumber: 1),
            body: "first",
            createdAt: Date()
        )
        let thread = try AmberThread(
            board: board,
            number: 7,
            generation: 3,
            subject: "Ordering",
            posts: [later, first]
        )

        XCTAssertEqual(thread.posts.map(\.id.postNumber), [1, 2])
        XCTAssertThrowsError(
            try AmberThread(
                board: board,
                number: 7,
                generation: 3,
                subject: "Duplicate",
                posts: [first, first]
            )
        )
    }

    func testPostAndImageBoundsFailClosed() throws {
        let board = try AmberBoardID("test")
        let id = AmberPostID(board: board, threadNumber: 1, postNumber: 1)

        XCTAssertThrowsError(
            try AmberPost(
                id: id,
                body: String(repeating: "a", count: AmberLimits.maximumPostBytes + 1),
                createdAt: Date()
            )
        )
        XCTAssertThrowsError(
            try AmberImage(
                digest: String(repeating: "f", count: 64),
                width: 100,
                height: 100,
                byteCount: AmberLimits.maximumImageBytes + 1
            )
        )
    }

    func testKanalenEndpointIsExplicitHttpsConfiguration() {
        XCTAssertEqual(AmberNetwork.kanalenTestnet.rpcURL.scheme, "https")
        XCTAssertEqual(
            AmberNetwork.kanalenTestnet.rpcURL.host(),
            "rpc.kanalen.activechain.dev"
        )
        XCTAssertEqual(AmberConnectionState.verified(finalizedHeight: 42).label, "Finalized #42")
    }

    func testBondQuoteRejectsFreeOrOverSlashablePosting() {
        XCTAssertThrowsError(
            try AmberBondQuote(
                postingFee: 0,
                postBond: 25,
                maximumSlash: 25,
                reportBond: 25,
                policyRevision: 1
            )
        )
        XCTAssertThrowsError(
            try AmberBondQuote(
                postingFee: 1,
                postBond: 25,
                maximumSlash: 26,
                reportBond: 25,
                policyRevision: 1
            )
        )
    }

    func testUpheldSettlementConservesBothBonds() throws {
        let quote = try AmberBondQuote(
            postingFee: 1,
            postBond: 25,
            maximumSlash: 20,
            reportBond: 25,
            policyRevision: 7
        )
        let settlement = try quote.upheldSettlement(penalty: 20, reporterReward: 8)

        XCTAssertEqual(settlement.posterResidual, 5)
        XCTAssertEqual(settlement.reporterBondReturned, 25)
        XCTAssertEqual(settlement.reporterReward, 8)
        XCTAssertEqual(settlement.slashedToBoardTreasury, 12)
        XCTAssertEqual(settlement.totalOutputs, quote.postBond + quote.reportBond)
    }

    func testSettlementCannotExceedQuote() throws {
        let quote = AmberBondQuote.kanalenPreview
        XCTAssertThrowsError(try quote.upheldSettlement(penalty: 26, reporterReward: 1))
        XCTAssertThrowsError(try quote.upheldSettlement(penalty: 10, reporterReward: 11))
    }
}
