import Foundation
import Network
import os

/// One network this wallet knows how to talk to.
///
/// The chain id and genesis are a **pin**, not a discovery result. The wallet
/// refuses a node that reports anything else, so choosing a network is an act
/// by the person holding the phone and never by the peer they are talking to.
/// That distinction is the whole security value of the pin, and it survives
/// making the pin selectable.
struct WalletNetwork: Equatable, Sendable, Codable {
    /// Stable, lowercase, and safe in a keychain account and a slot id.
    let id: String
    let displayName: String
    let hostName: String
    let port: UInt16
    let protocolRevision: UInt64
    let schemaRevision: UInt32
    let chainID: Data
    let genesis: Data

    var host: NWEndpoint.Host { NWEndpoint.Host(hostName) }
    var endpointPort: NWEndpoint.Port { NWEndpoint.Port(rawValue: port) ?? 443 }
    var hostDescription: String { "\(hostName):\(port)" }

    /// Keys and profiles are scoped by network, because a key provisioned
    /// against one genesis has no meaning on another and a balance from one
    /// chain must never be shown while another is selected.
    var custodySlotID: String { "primary.\(id)" }
    var profileAccount: String { "owner-and-genesis.\(id)" }

    var isWellFormed: Bool {
        !id.isEmpty
            && id.count <= 32
            && id.allSatisfy { $0.isLowercase && $0.isASCII || $0.isNumber || $0 == "-" }
            && !hostName.isEmpty
            && port > 0
            && chainID.count == 48
            && genesis.count == 48
            && chainID.contains(where: { $0 != 0 })
            && genesis.contains(where: { $0 != 0 })
    }
}

extension WalletNetwork {
    /// The network this build ships pinned to.
    ///
    /// Kept as a constant rather than a default entry in storage so a wallet
    /// with no configuration still refuses an unknown chain rather than
    /// accepting the first one it meets.
    static let kanalen = WalletNetwork(
        id: "kanalen",
        displayName: "Kanalen",
        hostName: "rpc.kanalen.activechain.dev",
        port: 443,
        protocolRevision: 1,
        schemaRevision: 3,
        chainID: Data([
            0xb1, 0x2c, 0x1c, 0x31, 0x67, 0x17, 0xe9, 0x66,
            0x9c, 0xec, 0x36, 0xf7, 0x63, 0x2a, 0x90, 0x80,
            0x70, 0x2c, 0x57, 0xa3, 0x12, 0x5d, 0x90, 0xc7,
            0x21, 0x54, 0xf8, 0xa7, 0x29, 0x8e, 0x4f, 0x0b,
            0x09, 0x5e, 0x6c, 0xfe, 0x94, 0x4b, 0xd2, 0xc9,
            0xf6, 0x53, 0x5b, 0x4c, 0x92, 0x77, 0x82, 0xf1,
        ]),
        genesis: Data([
            0xa8, 0x36, 0xc4, 0xd2, 0x01, 0xcd, 0xa6, 0xba,
            0x33, 0xa0, 0x1a, 0xa4, 0x80, 0x11, 0xcf, 0x5f,
            0x4d, 0x6a, 0xcd, 0xfd, 0x1e, 0xc4, 0x09, 0xd3,
            0x22, 0xdc, 0x1b, 0x56, 0xed, 0x35, 0x52, 0xa2,
            0x5d, 0xcb, 0x15, 0x8e, 0x0b, 0x1e, 0xc0, 0x35,
            0x27, 0x28, 0x65, 0x3d, 0x31, 0x5d, 0x47, 0x7c,
        ])
    )
}

enum WalletNetworkError: Error, Equatable {
    case malformed
    case duplicateIdentifier
    case unknownNetwork
    case cannotRemoveSelected
    case cannotRemoveBuiltIn
}

/// The networks this wallet knows, and which one is selected.
///
/// Only the *selection* and any networks the user added are stored; the
/// built-in network is compiled in, so a wallet whose storage is empty or
/// tampered with falls back to a known pin rather than to none.
///
/// Nothing here is secret — a chain id, a genesis commitment and a hostname
/// are all public — so this is ordinary preferences storage, not the keychain.
/// The keychain holds the keys these networks are used with.
final class WalletNetworkRegistry {
    private static let selectionKey = "dev.activechain.wallet.network.selected.v1"
    private static let customKey = "dev.activechain.wallet.network.custom.v1"

    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    var known: [WalletNetwork] {
        [WalletNetwork.kanalen] + custom
    }

    var custom: [WalletNetwork] {
        guard let data = defaults.data(forKey: Self.customKey),
              let decoded = try? JSONDecoder().decode([WalletNetwork].self, from: data)
        else { return [] }
        // A malformed stored entry is dropped rather than trusted: it would
        // otherwise be a pin nobody chose.
        return decoded.filter(\.isWellFormed).filter { $0.id != WalletNetwork.kanalen.id }
    }

    var selected: WalletNetwork {
        guard let id = defaults.string(forKey: Self.selectionKey),
              let network = known.first(where: { $0.id == id })
        else { return .kanalen }
        return network
    }

    func select(_ id: String) throws {
        guard known.contains(where: { $0.id == id }) else { throw WalletNetworkError.unknownNetwork }
        defaults.set(id, forKey: Self.selectionKey)
    }

    func add(_ network: WalletNetwork) throws {
        guard network.isWellFormed else { throw WalletNetworkError.malformed }
        guard !known.contains(where: { $0.id == network.id }) else {
            throw WalletNetworkError.duplicateIdentifier
        }
        try persist(custom + [network])
    }

    /// Removing a network does not remove its wallet. The key stays in the
    /// keychain under that network's slot, so re-adding the network restores
    /// access rather than silently destroying funds.
    func remove(_ id: String) throws {
        guard id != WalletNetwork.kanalen.id else { throw WalletNetworkError.cannotRemoveBuiltIn }
        guard id != selected.id else { throw WalletNetworkError.cannotRemoveSelected }
        let remaining = custom.filter { $0.id != id }
        guard remaining.count != custom.count else { throw WalletNetworkError.unknownNetwork }
        try persist(remaining)
    }

    private func persist(_ networks: [WalletNetwork]) throws {
        let encoded = try JSONEncoder().encode(networks)
        defaults.set(encoded, forKey: Self.customKey)
    }
}
