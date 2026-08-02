package dev.activechain.wallet

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class OpenId4VpDeepLinkTest {
    @Test fun validLinkCreatesReviewOnly() {
        val review = OpenId4VpDeepLink.parse("openid4vp://authorize?request_uri=https%3A%2F%2Fverifier.example%2Frequest.jwt&client_id=verifier.example&nonce=n&state=s")
        assertEquals("https://verifier.example/request.jwt", review.requestUri.toString())
    }
    @Test fun redirectDowngradeAndHttpAreRejected() {
        assertThrows(IllegalArgumentException::class.java) { OpenId4VpDeepLink.parse("openid4vp://authorize?request_uri=http%3A%2F%2Fevil.example&client_id=x&nonce=n&state=s") }
        assertThrows(IllegalArgumentException::class.java) { OpenId4VpDeepLink.parse("openid4vp://authorize?request_uri=https%3A%2F%2Fv.example&redirect_uri=https%3A%2F%2Fevil.example&client_id=x&nonce=n&state=s") }
    }
}
