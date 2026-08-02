import Foundation

struct OpenId4VpReviewIntent: Equatable {
    let requestURI: URL
    let clientID: String
    let nonce: String
    let state: String
}

enum OpenId4VpDeepLink {
    static func parse(_ url: URL) throws -> OpenId4VpReviewIntent {
        guard url.scheme == "openid4vp", url.host == "authorize", url.fragment == nil,
              let parts = URLComponents(url: url, resolvingAgainstBaseURL: false) else { throw ParseError.invalid }
        var query: [String: String] = [:]
        for item in parts.queryItems ?? [] {
            guard let value = item.value, query[item.name] == nil,
                  item.name != "redirect_uri", item.name != "response_uri" else { throw ParseError.invalid }
            query[item.name] = value
        }
        guard let raw = query["request_uri"], let request = URL(string: raw),
              request.scheme == "https", request.user == nil, request.fragment == nil,
              let client = query["client_id"], let nonce = query["nonce"], let state = query["state"]
        else { throw ParseError.invalid }
        return OpenId4VpReviewIntent(requestURI: request, clientID: client, nonce: nonce, state: state)
    }
    enum ParseError: Error { case invalid }
}
