package dev.activechain.wallet

import java.net.URI

data class OpenId4VpReviewIntent(
    val requestUri: URI,
    val clientId: String,
    val nonce: String,
    val state: String,
)

/** Deep links can only create a wallet-owned review intent; they cannot approve or post. */
object OpenId4VpDeepLink {
    fun parse(raw: String): OpenId4VpReviewIntent {
        val uri = URI(raw)
        require(uri.scheme == "openid4vp" && uri.host == "authorize" && uri.fragment == null)
        val query = mutableMapOf<String, String>()
        uri.rawQuery.orEmpty().split('&').filter { it.isNotEmpty() }.forEach { part ->
            val pair = part.split('=', limit = 2)
            require(pair.size == 2 && pair[0] !in setOf("redirect_uri", "response_uri"))
            val key = java.net.URLDecoder.decode(pair[0], Charsets.UTF_8)
            require(key !in query)
            query[key] = java.net.URLDecoder.decode(pair[1], Charsets.UTF_8)
        }
        val request = URI(query.getValue("request_uri"))
        require(request.scheme == "https" && request.userInfo == null && request.fragment == null)
        return OpenId4VpReviewIntent(request, query.getValue("client_id"), query.getValue("nonce"), query.getValue("state"))
    }
}
