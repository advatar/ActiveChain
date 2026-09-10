import XCTest

/// Requires the Debug EUWallet build installed on the selected simulator. Uses EUWallet's actual
/// sample issuance, consent machine and HTTPS transport; never creates government identity evidence.
final class EUWalletConnectionUITests: XCTestCase {
    private func approveAppHandoff(from source: String, to destination: String) {
        let system = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let alert = system.alerts["“\(source)” wants to open “\(destination)”"]
        if alert.waitForExistence(timeout: 5) { alert.buttons["Open"].tap() }
    }

    func testFinalizedPaymentDoesNotRestartAutomaticVerification() throws {
        continueAfterFailure = false
        let wallet = XCUIApplication()
        wallet.launch()
        wallet.tabBars.buttons["Shop"].tap()
        let paid = wallet.descendants(matching: .any)["shop.paid"].firstMatch
        XCTAssertTrue(paid.waitForExistence(timeout: 20), wallet.debugDescription)
        let receipt = wallet.staticTexts["shop.receipt"].label
        for _ in 0..<4 {
            let stable = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in
                paid.exists && !wallet.progressIndicators["shop.progress"].exists
                    && wallet.staticTexts["shop.receipt"].label == receipt
            }, object: nil)
            XCTAssertEqual(XCTWaiter.wait(for: [stable], timeout: 3), .completed)
            Thread.sleep(forTimeInterval: 2)
        }
    }

    func testEUWalletConsentAttachesOnlyTestReceiptAndSurvivesRelaunch() throws {
        continueAfterFailure = false
        let eu = XCUIApplication(bundleIdentifier: "eu.advatar.wallet")
        eu.launchArguments = ["-ActiveChainTestConnection", "YES", "-autostart", "add"]
        eu.launch()
        let add = eu.buttons["issuance.add"]
        XCTAssertTrue(add.waitForExistence(timeout: 30), eu.debugDescription)
        add.tap()
        XCTAssertTrue(eu.buttons["Go to Wallet"].waitForExistence(timeout: 20), eu.debugDescription)
        eu.buttons["Go to Wallet"].tap()
        XCTAssertTrue(eu.staticTexts["Your documents"].waitForExistence(timeout: 30), eu.debugDescription)
        let wallet = XCUIApplication()
        wallet.launch()
        wallet.tabBars.buttons["Identity"].tap()
        let connect = wallet.buttons["identity.connect.euwallet"]
        for _ in 0..<5 {
            if connect.exists && connect.isHittable { break }
            wallet.scrollViews.firstMatch.swipeUp()
        }
        XCTAssertTrue(connect.waitForExistence(timeout: 15), wallet.debugDescription)
        connect.tap()
        approveAppHandoff(from: "ActiveChain Wallet", to: "EU Wallet")
        XCTAssertTrue(eu.wait(for: .runningForeground, timeout: 25), wallet.debugDescription + eu.debugDescription + XCUIApplication(bundleIdentifier: "com.apple.springboard").debugDescription)
        let approve = eu.buttons["consent.approve"]
        XCTAssertTrue(approve.waitForExistence(timeout: 30), eu.debugDescription)
        approve.tap()
        approveAppHandoff(from: "EU Wallet", to: "ActiveChain Wallet")
        XCTAssertTrue(wallet.wait(for: .runningForeground, timeout: 30), eu.debugDescription)
        let status = wallet.staticTexts["identity.connection.status"]
        let attached = XCTNSPredicateExpectation(predicate: NSPredicate(format: "label BEGINSWITH %@", "Test credential attached."), object: status)
        XCTAssertEqual(XCTWaiter.wait(for: [attached], timeout: 30), .completed, wallet.debugDescription)
        wallet.terminate()
        wallet.launch()
        wallet.tabBars.buttons["Identity"].tap()
        for _ in 0..<5 {
            if status.exists && status.isHittable { break }
            wallet.scrollViews.firstMatch.swipeUp()
        }
        XCTAssertTrue(status.label.hasPrefix("Test credential attached."), wallet.debugDescription)
        XCTAssertTrue(wallet.staticTexts["TEST ONLY · No government verification"].exists)
    }
}
