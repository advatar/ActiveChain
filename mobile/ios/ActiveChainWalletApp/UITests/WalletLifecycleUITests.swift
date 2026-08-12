import XCTest

/// Drives the macOS wallet through its real lifecycle.
///
/// Everything below runs against the live Kanalen RPC, the real Secure Enclave,
/// and the real keychain. That is deliberate: the enclave and the sandbox are
/// exactly the parts a unit test has to substitute, and they are where every
/// provisioning defect in this app has actually lived.
///
/// The wallet persists in the keychain, so a second run starts with one already
/// present. Each test therefore states which branch it is in rather than
/// assuming a clean device, and the shared assertions hold either way.
final class WalletLifecycleUITests: XCTestCase {
    private var app: XCUIApplication!

    override func setUp() {
        continueAfterFailure = false
        app = XCUIApplication()
        // A macOS app outlives its test unless terminated, and the next test
        // then attaches to a stale instance whose state it did not establish.
        app.terminate()
        app.launch()
    }

    override func tearDown() {
        app?.terminate()
        app = nil
    }

    /// The first refresh has to complete a real round trip to Kanalen, so give
    /// it room rather than racing the network.
    private func awaitNetworkSettled() {
        let healthy = app.staticTexts["Healthy"]
        let unavailable = app.staticTexts["Unavailable"]
        let deadline = Date().addingTimeInterval(60)
        while Date() < deadline {
            if healthy.exists || unavailable.exists { return }
            _ = healthy.waitForExistence(timeout: 2)
        }
    }

    /// Network health is the precondition for everything else, so failing here
    /// separates "the chain is unreachable" from "onboarding is broken".
    func testReportsKanalenHealthBeforeAnythingElse() {
        awaitNetworkSettled()
        let healthy = app.staticTexts["Healthy"]
        XCTAssertTrue(
            healthy.exists,
            "Kanalen never reported healthy; the wallet cannot be exercised without a reachable chain"
        )
    }

    func testProvisionsAWalletAndOffersFunding() throws {
        let createButton = app.buttons["Create wallet"]
        let hasWallet = !createButton.waitForExistence(timeout: 15)

        if hasWallet {
            // A previous run already provisioned this machine. The onboarding
            // branch cannot be re-exercised without clearing the keychain, so
            // assert the state it should have left behind.
            XCTAssertTrue(
                app.staticTexts["Request testnet ACT"].waitForExistence(timeout: 20),
                "a provisioned wallet must offer funding"
            )
            throw XCTSkip("wallet already provisioned on this machine; onboarding branch not re-run")
        }

        createButton.click()

        // Provisioning must produce recovery material, because a wallet that
        // cannot be recovered cannot be moved to another device.
        let recoveryHeading = app.staticTexts["Save your recovery key"]
        XCTAssertTrue(
            recoveryHeading.waitForExistence(timeout: 30),
            "provisioning did not surface a recovery key"
        )

        let acknowledge = app.buttons["I have saved it"]
        XCTAssertTrue(acknowledge.exists, "recovery material must be acknowledged explicitly")
        acknowledge.click()

        XCTAssertFalse(
            recoveryHeading.waitForExistence(timeout: 3),
            "the recovery key must be shown once and then dismissed"
        )
        XCTAssertTrue(
            app.staticTexts["Request testnet ACT"].waitForExistence(timeout: 20),
            "funding must become available once a wallet exists"
        )
        XCTAssertFalse(
            app.buttons["Create wallet"].exists,
            "the onboarding card must disappear once a wallet exists"
        )
    }

    /// The balance claim is the one the user acts on, so it must never read as
    /// a figure while the wallet holds no verified Coin Cell proof.
    func testNeverShowsABalanceWithoutVerifiedState() {
        XCTAssertTrue(
            app.staticTexts["Balance unavailable"].waitForExistence(timeout: 30),
            "a wallet with no verified owner-scoped proof must say so rather than show a number"
        )
    }
}
