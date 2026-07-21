import Foundation
import Combine

public struct NetworkProfile: Identifiable, Equatable {
    public let id: String
    public let displayName: String
    public let genesis: String
    public let rpcURL: URL
    public let faucetURL: URL?
    public let assets: [String]
}

public final class NetworkSelection: ObservableObject {
    @Published public private(set) var selected: NetworkProfile
    @Published public private(set) var visibleAssets: [String]
    private let profiles: [NetworkProfile]

    public init(profiles: [NetworkProfile], selectedID: String? = nil) {
        precondition(!profiles.isEmpty)
        self.profiles = profiles
        let initial = profiles.first { $0.id == selectedID } ?? profiles[0]
        self.selected = initial
        self.visibleAssets = initial.assets
    }

    public func switchTo(_ id: String) -> Bool {
        guard let next = profiles.first(where: { $0.id == id }) else { return false }
        selected = next
        visibleAssets = next.assets
        return true
    }
}
