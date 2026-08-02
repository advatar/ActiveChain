import XCTest
@testable import AmberApp

final class OpenId4VpDeepLinkTests: XCTestCase {
    func testValidLinkCreatesReviewOnly() throws {
        let url = URL(string: "openid4vp://authorize?request_uri=https%3A%2F%2Fverifier.example%2Frequest.jwt&client_id=verifier.example&nonce=n&state=s")!
        XCTAssertEqual(try OpenId4VpDeepLink.parse(url).requestURI.absoluteString, "https://verifier.example/request.jwt")
    }
    func testRedirectDowngradeAndHTTPAreRejected() {
        XCTAssertThrowsError(try OpenId4VpDeepLink.parse(URL(string: "openid4vp://authorize?request_uri=http%3A%2F%2Fevil.example&client_id=x&nonce=n&state=s")!))
        XCTAssertThrowsError(try OpenId4VpDeepLink.parse(URL(string: "openid4vp://authorize?request_uri=https%3A%2F%2Fv.example&redirect_uri=https%3A%2F%2Fevil.example&client_id=x&nonce=n&state=s")!))
    }
}
