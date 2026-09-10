import XCTest

/// Live acceptance test: run on the fresh simulator created by
/// scripts/test-ios-wallet-e2e.sh. No reset hook or pre-funded profile is used.
final class FreshWalletFaucetUITests: XCTestCase {
    private var app: XCUIApplication!

    override func setUpWithError() throws {
        continueAfterFailure = false
        app = XCUIApplication()
        app.launch()
    }

    override func tearDownWithError() throws {
        app?.terminate()
        app = nil
    }

    private func reveal(_ element: XCUIElement, upwards: Bool = true) {
        let scroll = app.scrollViews.firstMatch
        for _ in 0..<10 {
            if element.exists && element.isHittable { return }
            guard scroll.exists else { return }
            if upwards { scroll.swipeUp() } else { scroll.swipeDown() }
        }
    }

    private func waitForLabel(_ element: XCUIElement, pattern: String, timeout: TimeInterval) {
        let expectation = XCTNSPredicateExpectation(
            predicate: NSPredicate(format: "exists == true AND label MATCHES %@", pattern),
            object: element
        )
        XCTAssertEqual(XCTWaiter.wait(for: [expectation], timeout: timeout), .completed,
                       "Expected \(pattern); last label: \(element.exists ? element.label : "absent")")
    }

    private func healthyHeight() throws -> UInt64 {
        let refresh = app.buttons["network.refresh"]
        reveal(refresh)
        waitForLabel(refresh, pattern: "Kanalen testnet, Healthy, Finalized block [1-9][0-9]*", timeout: 30)
        return try XCTUnwrap(UInt64(try XCTUnwrap(refresh.label.split(separator: " ").last)))
    }

    func testFreshWalletReceivesFinalizedFaucetCoinsAndPersistsAfterRelaunch() throws {
        let initialHeight = try healthyHeight()
        let create = app.buttons["Create wallet"]
        reveal(create, upwards: false)
        XCTAssertTrue(create.exists && create.isEnabled,
                      "This test requires a fresh wallet. Use the isolated simulator runner.")
        create.tap()

        let recovery = app.staticTexts["recovery.title"]
        XCTAssertTrue(recovery.waitForExistence(timeout: 45), "Wallet creation must produce recovery material")
        let acknowledge = app.buttons["I have saved it"]
        reveal(acknowledge)
        XCTAssertTrue(acknowledge.exists && acknowledge.isHittable)
        // This is a disposable test identity. Never copy or attach the recovery key.
        acknowledge.tap()
        XCTAssertTrue(recovery.waitForNonExistence(timeout: 10))
        XCTAssertFalse(create.exists)

        let balance = app.staticTexts["balance.headline"]
        reveal(balance, upwards: false)
        waitForLabel(balance, pattern: "0 ACT", timeout: 45)

        let request = app.buttons["Request testnet funding"]
        reveal(request)
        XCTAssertTrue(request.exists && request.isEnabled,
                      "A disabled faucet is a failed live acceptance prerequisite, never a skip")
        request.tap()
        let funding = app.staticTexts["funding.title"]
        waitForLabel(funding, pattern: "Funding (pending|finalized|rejected)|Funding unavailable", timeout: 30)

        // Finality is resolved by the app's ordinary refresh action. Waiting
        // without refreshing leaves an accepted grant pending indefinitely.
        let deadline = Date().addingTimeInterval(240)
        while Date() < deadline && funding.label == "Funding pending" {
            let refresh = app.buttons["network.refresh"]
            reveal(refresh)
            XCTAssertTrue(refresh.isHittable)
            refresh.tap()
            Thread.sleep(forTimeInterval: 3)
            reveal(funding, upwards: false)
        }
        XCTAssertEqual(funding.label, "Funding finalized",
                       "Faucet did not finalize: \(app.staticTexts["funding.detail"].label)")
        let receipt = app.staticTexts["funding.detail"].label
        let finalHeight = try XCTUnwrap(UInt64(try XCTUnwrap(
            receipt.components(separatedBy: "block ").last?.components(separatedBy: ".").first)))
        XCTAssertGreaterThan(finalHeight, initialHeight, "The grant must finalize in a new block")

        reveal(balance, upwards: false)
        // Kanalen grants two cells so payment and fee inputs can be distinct.
        // One finalized half of the grant must not pass acceptance.
        waitForLabel(balance, pattern: "100 ACT", timeout: 60)
        let fundedBalance = balance.label
        let proof = app.staticTexts["balance.detail"].label
        XCTAssertTrue(proof.contains("proof(s) verified at finalized height"))
        let proofHeight = try XCTUnwrap(UInt64(try XCTUnwrap(
            proof.split(separator: " ").last).trimmingCharacters(in: CharacterSet(charactersIn: "."))))
        XCTAssertGreaterThanOrEqual(proofHeight, finalHeight)
        let evidence = XCTAttachment(string: "\(receipt)\n\(fundedBalance)\n\(proof)")
        evidence.name = "Finalized faucet receipt and verified holdings"
        evidence.lifetime = .keepAlways
        add(evidence)

        app.terminate()
        app.launch()
        XCTAssertTrue(balance.waitForExistence(timeout: 30))
        waitForLabel(balance, pattern: "100 ACT", timeout: 60)
        XCTAssertEqual(balance.label, fundedBalance)
        XCTAssertGreaterThanOrEqual(try healthyHeight(), finalHeight)
        reveal(app.staticTexts["funding.title"], upwards: false)
        XCTAssertFalse(create.exists, "Relaunch must load the original wallet from keychain")
        XCTAssertFalse(recovery.exists, "Acknowledged recovery material must not reappear")
        reveal(balance, upwards: false)
        app.tabBars.buttons["Shop"].tap()
        let enroll = app.buttons["shop.enroll"]
        XCTAssertTrue(enroll.waitForExistence(timeout: 30))
        XCTAssertTrue(enroll.isEnabled)
        enroll.tap()
        XCTAssertTrue(app.staticTexts["shop.enrollment"].waitForExistence(timeout: 180),
                      "Wallet enrollment must finalize: \(app.staticTexts["shop.status"].label)")
        let buy = app.buttons["shop.buy"]
        reveal(buy)
        let readyToBuy = XCTNSPredicateExpectation(predicate: NSPredicate(format: "enabled == true"), object: buy)
        XCTAssertEqual(XCTWaiter.wait(for: [readyToBuy], timeout: 90), .completed)
        buy.tap()
        let confirm = app.buttons["shop.confirm"]
        XCTAssertTrue(confirm.waitForExistence(timeout: 30))
        confirm.tap()
        let paid = app.staticTexts["shop.paid"]
        XCTAssertTrue(paid.waitForExistence(timeout: 180),
                      "Payment must have native finality and output proofs: \(app.staticTexts["shop.status"].label)")
        let paymentReceipt = app.staticTexts["shop.receipt"].label
        let purchaseEvidence = XCTAttachment(string: paymentReceipt + "\n" + app.staticTexts["shop.status"].label)
        purchaseEvidence.name = "Verified demo merchant payment"
        purchaseEvidence.lifetime = .keepAlways
        add(purchaseEvidence)
        app.terminate()
        app.launch()
        app.tabBars.buttons["Shop"].tap()
        XCTAssertTrue(paid.waitForExistence(timeout: 45), "The verified purchase must survive relaunch")
        XCTAssertEqual(app.staticTexts["shop.receipt"].label, paymentReceipt)
        app.tabBars.buttons["Wallet"].tap()
        reveal(balance, upwards: false)
        waitForLabel(balance, pattern: "94.999 ACT", timeout: 60)
        let assetBalance = app.staticTexts["assets.act.balance"]
        reveal(assetBalance)
        XCTAssertEqual(assetBalance.label, "94.999 ACT")
        app.tabBars.buttons["Shop"].tap()
        let screenshot = XCTAttachment(screenshot: app.screenshot())
        screenshot.name = "Verified demo coffee purchase after relaunch"
        screenshot.lifetime = .keepAlways
        add(screenshot)
    }
}
