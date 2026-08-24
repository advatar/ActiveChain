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
            "rpc.kanalen.actum.network"
        )
        XCTAssertEqual(AmberConnectionState.verified(finalizedHeight: 42).label, "Finalized #42")
        XCTAssertEqual(AmberConnectionState.stale(finalizedHeight: 0).label, "Stale at #0")
        XCTAssertTrue(AmberConnectionState.degraded(finalizedHeight: 7).isAvailable)
        XCTAssertFalse(AmberConnectionState.incompatible.isAvailable)
    }

    func testComposerReadinessRequiresBoardContentBondAndLiveSubmission() throws {
        let board = try AmberBoardID("ac")
        XCTAssertEqual(
            AmberComposerReadiness.evaluate(
                board: nil,
                body: "post",
                understandsBond: true,
                liveSubmissionAvailable: true
            ),
            .chooseBoard
        )
        XCTAssertEqual(
            AmberComposerReadiness.evaluate(
                board: board,
                body: " ",
                understandsBond: true,
                liveSubmissionAvailable: true
            ),
            .enterPost
        )
        XCTAssertEqual(
            AmberComposerReadiness.evaluate(
                board: board,
                body: "post",
                understandsBond: false,
                liveSubmissionAvailable: true
            ),
            .acknowledgeBond
        )
        XCTAssertEqual(
            AmberComposerReadiness.evaluate(
                board: board,
                body: "post",
                understandsBond: true,
                liveSubmissionAvailable: false
            ),
            .liveSubmissionUnavailable
        )
        XCTAssertEqual(
            AmberComposerReadiness.evaluate(
                board: board,
                body: "post",
                understandsBond: true,
                liveSubmissionAvailable: true
            ),
            .ready
        )
    }

    func testStatusRequestUsesCanonicalFraming() {
        XCTAssertEqual(
            Array(AmberRPCCodec.framedStatusRequest),
            [0, 0, 0, 6, 0x01, 0x07, 0, 3, 1, 0]
        )
    }

    func testStatusDecoderMapsStaleAndRejectsMalformedEnvelope() throws {
        let response = makeStatusResponse(
            protocolRevision: 1,
            schemaRevision: 4,
            finalizedHeight: 0,
            finalizedAt: 10,
            servedAt: 100,
            maximumStaleness: 30,
            health: 1
        )
        let status = try AmberRPCCodec.decodeStatus(response)
        XCTAssertEqual(status.connectionState, .stale(finalizedHeight: 0))
        XCTAssertThrowsError(try AmberRPCCodec.decodeStatus(Data(response.dropLast())))
    }

    func testStatusDecoderReportsIncompatibleRevision() throws {
        let response = makeStatusResponse(
            protocolRevision: 2,
            schemaRevision: 4,
            finalizedHeight: 12,
            finalizedAt: 90,
            servedAt: 100,
            maximumStaleness: 30,
            health: 0
        )
        XCTAssertEqual(try AmberRPCCodec.decodeStatus(response).connectionState, .incompatible)
    }

    func testStatusDecoderPinsKanalenChainAndGenesis() throws {
        let live = makeStatusResponse(
            protocolRevision: 1, schemaRevision: 4, finalizedHeight: 12,
            finalizedAt: 90, servedAt: 100, maximumStaleness: 30, health: 0
        )
        XCTAssertEqual(try AmberRPCCodec.decodeStatus(live).connectionState, .verified(finalizedHeight: 12))
        XCTAssertEqual(
            try AmberRPCCodec.decodeStatus(
                makeStatusResponse(
                    chainID: Data(repeating: 0x44, count: 48), protocolRevision: 1,
                    schemaRevision: 4, finalizedHeight: 12, finalizedAt: 90,
                    servedAt: 100, maximumStaleness: 30, health: 0
                )
            ).connectionState,
            .incompatible
        )
        XCTAssertEqual(
            try AmberRPCCodec.decodeStatus(
                makeStatusResponse(
                    genesis: Data(repeating: 0x55, count: 48), protocolRevision: 1,
                    schemaRevision: 4, finalizedHeight: 12, finalizedAt: 90,
                    servedAt: 100, maximumStaleness: 30, health: 0
                )
            ).connectionState,
            .incompatible
        )
    }

    func testLiveKanalenStatusWhenEnabled() async throws {
        guard ProcessInfo.processInfo.environment["ACTIVECHAIN_LIVE_KANALEN"] == "1" else {
            throw XCTSkip("set ACTIVECHAIN_LIVE_KANALEN=1 for the bounded live RPC test")
        }
        let status = try await AmberRPCClient().status(for: .kanalenTestnet)
        XCTAssertEqual(status.chainID, AmberRPCCodec.kanalenChainID)
        XCTAssertEqual(status.genesis, AmberRPCCodec.kanalenGenesis)
        guard case let .verified(finalizedHeight) = status.connectionState else {
            return XCTFail("live Kanalen status is not healthy and identity-compatible")
        }
        XCTAssertGreaterThan(finalizedHeight, 0)
    }

    private func makeStatusResponse(
        chainID: Data = AmberRPCCodec.kanalenChainID,
        genesis: Data = AmberRPCCodec.kanalenGenesis,
        protocolRevision: UInt64,
        schemaRevision: UInt32,
        finalizedHeight: UInt64,
        finalizedAt: UInt64,
        servedAt: UInt64,
        maximumStaleness: UInt64,
        health: UInt8
    ) -> Data {
        var body = Data([0])
        body.append(chainID)
        body.append(genesis)
        body.append(contentsOf: protocolRevision.bigEndianBytes)
        body.append(contentsOf: schemaRevision.bigEndianBytes)
        body.append(contentsOf: finalizedHeight.bigEndianBytes)
        body.append(contentsOf: finalizedAt.bigEndianBytes)
        body.append(contentsOf: servedAt.bigEndianBytes)
        body.append(contentsOf: maximumStaleness.bigEndianBytes)
        body.append(health)
        body.append(contentsOf: [2, 0, 1])
        XCTAssertEqual(body.count, 145)
        var envelope = Data([0x01, 0x0a, 0, 4, 0x91, 0x01])
        envelope.append(body)
        return envelope
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

    func testNetworkRefreshPresentationShowsActivityAndCompletion() {
        var presentation = AmberNetworkRefreshPresentation()

        XCTAssertNil(presentation.completionLabel)
        XCTAssertTrue(presentation.begin())
        XCTAssertTrue(presentation.isRefreshing)
        XCTAssertFalse(presentation.begin())

        presentation.complete()
        XCTAssertFalse(presentation.isRefreshing)
        XCTAssertEqual(presentation.completedChecks, 1)
        XCTAssertEqual(presentation.completionLabel, "Checked now")

        presentation.complete()
        XCTAssertEqual(presentation.completedChecks, 1)
    }
}

private extension FixedWidthInteger {
    var bigEndianBytes: [UInt8] {
        withUnsafeBytes(of: bigEndian) { Array($0) }
    }
}
