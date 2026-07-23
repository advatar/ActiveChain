import Foundation

struct ReceiveRequest: Equatable {
    let networkID: String
    let genesis: String
    let address: String

    var payload: String {
        var components = URLComponents()
        components.scheme = "activechain"
        components.host = "receive"
        components.queryItems = [
            URLQueryItem(name: "network", value: networkID),
            URLQueryItem(name: "genesis", value: genesis),
            URLQueryItem(name: "address", value: address)
        ]
        return components.string ?? address
    }

    static let kanalen = ReceiveRequest(
        networkID: "kanalen",
        genesis: "activechain-kanalen-testnet-v1",
        address: "did:activechain:kanalen:8c7a4ec141451793c8d2d6edfd0b3a34203f321cb313f120538e3287ea7d19ef"
    )
}
