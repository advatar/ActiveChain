import ActiveChainWallet
import Foundation
import Network
import Security
import SwiftUI
import os

/// Diagnostics for the Kanalen transport.
///
/// Every failure below collapses into `WalletRPCError.transport`, which keeps
/// the UI honest but throws away the reason. A refused port, an unfinished TLS
/// handshake, and a peer that closes mid-frame are indistinguishable on screen,
/// so record the underlying cause here.
///
/// Only network identifiers and byte counts are logged. Chain and genesis
/// commitments are public and are what a pin mismatch turns on, so they are
/// logged in the clear; wallet owners, keys, and payload bytes never are.
enum WalletLog {
    /// Notice level, not debug: debug records are memory-only and are dropped
    /// unless a debug-level stream is already attached, so they are invisible
    /// in Console and in a plain `log stream`.
    static let rpc = Logger(subsystem: "dev.activechain.wallet", category: "rpc")
}

enum WalletHex {
    /// First eight bytes are enough to tell two commitments apart in a log line.
    static func short(_ value: Data) -> String {
        value.prefix(8).map { String(format: "%02x", $0) }.joined() + "…"
    }
}

enum WalletKanalen {
    static let host = NWEndpoint.Host("rpc.kanalen.activechain.dev")
    static let port = NWEndpoint.Port(rawValue: 443)!
    static var hostDescription: String { "\(host):\(port.rawValue)" }
    static let protocolRevision: UInt64 = 1
    static let schemaRevision: UInt32 = 2
    static let chainID = Data([
        0xb1, 0x2c, 0x1c, 0x31, 0x67, 0x17, 0xe9, 0x66,
        0x9c, 0xec, 0x36, 0xf7, 0x63, 0x2a, 0x90, 0x80,
        0x70, 0x2c, 0x57, 0xa3, 0x12, 0x5d, 0x90, 0xc7,
        0x21, 0x54, 0xf8, 0xa7, 0x29, 0x8e, 0x4f, 0x0b,
        0x09, 0x5e, 0x6c, 0xfe, 0x94, 0x4b, 0xd2, 0xc9,
        0xf6, 0x53, 0x5b, 0x4c, 0x92, 0x77, 0x82, 0xf1,
    ])
    static let genesis = Data([
        0xf6, 0x00, 0xeb, 0x4a, 0x56, 0x2a, 0x3a, 0xcd,
        0x2b, 0xd8, 0x2e, 0x46, 0xfa, 0x8e, 0xe0, 0x63,
        0x21, 0x71, 0x53, 0xf8, 0x27, 0xaf, 0x12, 0x30,
        0x0c, 0x35, 0xfc, 0xb1, 0xb7, 0x5f, 0xc9, 0x6a,
        0xb5, 0x65, 0x04, 0x77, 0x69, 0x1a, 0x6c, 0xe1,
        0xb4, 0x35, 0x0a, 0x31, 0x4e, 0x5d, 0xbc, 0xa4,
    ])
}

enum WalletNetworkState: Equatable, Sendable {
    case checking
    case healthy(finalizedHeight: UInt64)
    case stale(finalizedHeight: UInt64)
    case unavailable
    case incompatible

    var label: String {
        switch self {
        case .checking: "Checking"
        case .healthy: "Healthy"
        case .stale: "Stale"
        case .unavailable: "Unavailable"
        case .incompatible: "Incompatible"
        }
    }

    var detail: String {
        switch self {
        case .checking: "Querying finalized RPC status"
        case let .healthy(height): "Finalized block \(height)"
        case let .stale(height): "Finalized block \(height) has not advanced recently"
        case .unavailable: "RPC status request failed"
        case .incompatible: "Unexpected chain, genesis, protocol, or RPC schema"
        }
    }

    var color: Color {
        switch self {
        case .healthy: WalletPalette.mint
        case .stale, .checking: .orange
        case .unavailable, .incompatible: .red
        }
    }
}

enum WalletFundingState: Equatable, Sendable {
    case unavailable(reason: String)
    case ready
    case requesting
    case pending(reference: String)
    case finalized(reference: String, height: UInt64)
    case rejected(reference: String?, reason: String)

    var title: String {
        switch self {
        case .unavailable: "Funding unavailable"
        case .ready: "Request testnet ACT"
        case .requesting: "Submitting signed request"
        case .pending: "Funding pending"
        case .finalized: "Funding finalized"
        case .rejected: "Funding rejected"
        }
    }

    var creditsBalance: Bool {
        if case .finalized = self { return true }
        return false
    }
}

@MainActor
final class WalletLiveState: ObservableObject {
    @Published private(set) var networkState: WalletNetworkState = .checking
    @Published private(set) var deviceProfile: WalletDeviceProfile?
    @Published private(set) var verifiedOwnerPage: WalletOwnerCoinPage?
    @Published private(set) var fundingState: WalletFundingState = .unavailable(
        reason: "Load a finalized wallet profile and secure cash key first."
    )
    private let rpc = WalletRPCClient()
    private let verifier: any WalletOwnerCoinProofVerifier = RustWalletOwnerCoinProofVerifier()

    init() {
        deviceProfile = WalletDeviceProfileStore().load()
    }

    func refresh() async {
        networkState = .checking
        verifiedOwnerPage = nil
        let status: WalletRPCStatus
        do {
            status = try await rpc.status()
            networkState = status.networkState
        } catch {
            WalletLog.rpc.error(
                "status refresh failed against \(WalletKanalen.hostDescription, privacy: .public): \(String(describing: error), privacy: .public)")
            networkState = .unavailable
            return
        }
        guard case let .healthy(height) = networkState,
              let profile = deviceProfile,
              profile.chainGenesis == status.genesis,
              status.supports(1)
        else {
            // A healthy network with no balance is the most confusing state the
            // wallet can show, and this guard was the silent cause: a profile
            // bound to a superseded genesis is skipped without a word.
            if case .healthy = networkState {
                if deviceProfile == nil {
                    WalletLog.rpc.notice("no device profile stored; balances and funding stay unavailable")
                } else if let profile = deviceProfile, profile.chainGenesis != status.genesis {
                    WalletLog.rpc.error(
                        "device profile is bound to genesis \(WalletHex.short(profile.chainGenesis), privacy: .public) but the chain reports \(WalletHex.short(status.genesis), privacy: .public); recreate the profile for this chain")
                } else if !status.supports(1) {
                    WalletLog.rpc.error("node does not advertise the owner coin-cell capability")
                }
            }
            updateFundingAvailability()
            return
        }
        do {
            verifiedOwnerPage = try await rpc.verifiedOwnerCoinCells(
                profile: profile,
                finalizedHeight: height,
                verifier: verifier
            )
        } catch {
            verifiedOwnerPage = nil
        }
        updateFundingAvailability()
    }

    func requestTestnetFunding() async {
        guard case .healthy = networkState else {
            fundingState = .unavailable(reason: "A healthy finalized Kanalen checkpoint is required.")
            return
        }
        guard deviceProfile != nil else {
            fundingState = .unavailable(reason: "Create or restore the wallet profile first.")
            return
        }
        guard let profile = deviceProfile else { return }
        fundingState = .requesting
        do {
            let terms = try await rpc.faucetTerms()
            guard terms.chainID == WalletKanalen.chainID,
                  terms.genesis == WalletKanalen.genesis,
                  terms.challengeKind == 0 else {
                fundingState = .unavailable(reason: "The faucet policy is incompatible with this wallet build.")
                return
            }
            let receipt = try await rpc.requestFaucet(owner: profile.owner)
            let reference = receipt.reference.map { String(format: "%02x", $0) }.joined()
            switch receipt.state {
            case 0: fundingState = .pending(reference: reference)
            case 1:
                guard let height = receipt.finalizedHeight else {
                    throw WalletRPCError.malformedResponse
                }
                let finalized = WalletFundingState.finalized(reference: reference, height: height)
                fundingState = finalized
                await refresh()
                fundingState = finalized
            case 2: fundingState = .rejected(reference: reference, reason: "The faucet rejected this request.")
            default: throw WalletRPCError.malformedResponse
            }
        } catch {
            fundingState = .rejected(reference: nil, reason: "Funding request failed without changing balance.")
        }
    }

    private func updateFundingAvailability() {
        guard case .healthy = networkState else {
            fundingState = .unavailable(reason: "A healthy finalized Kanalen checkpoint is required.")
            return
        }
        guard deviceProfile != nil else {
            fundingState = .unavailable(reason: "Create or restore the wallet profile first.")
            return
        }
        if case .pending = fundingState { return }
        if case .finalized = fundingState { return }
        fundingState = .ready
    }

    func refreshVerifiedOwnerPage(verifier: any WalletOwnerCoinProofVerifier) async {
        guard let profile = deviceProfile,
              profile.chainGenesis == WalletKanalen.genesis,
              case let .healthy(height) = networkState else {
            verifiedOwnerPage = nil
            return
        }
        do {
            verifiedOwnerPage = try await rpc.verifiedOwnerCoinCells(
                profile: profile, finalizedHeight: height, verifier: verifier
            )
        } catch {
            verifiedOwnerPage = nil
        }
    }
}

struct WalletDeviceProfile: Equatable, Sendable {
    let owner: Data
    let chainGenesis: Data
}

struct WalletDeviceProfileStore {
    private let service = "dev.activechain.wallet.profile.v1"
    private let account = "owner-and-genesis"

    func load() -> WalletDeviceProfile? {
        guard let keychain = try? SharedKeychain(),
              let data = try? keychain.load(service: service, account: account),
              data.count == 96 else { return nil }
        let owner = Data(data.prefix(48))
        let genesis = Data(data.suffix(48))
        guard owner.contains(where: { $0 != 0 }), genesis.contains(where: { $0 != 0 }) else { return nil }
        return WalletDeviceProfile(owner: owner, chainGenesis: genesis)
    }

    func save(_ profile: WalletDeviceProfile) throws {
        guard profile.owner.count == 48, profile.chainGenesis.count == 48,
              profile.owner.contains(where: { $0 != 0 }), profile.chainGenesis.contains(where: { $0 != 0 })
        else { throw WalletRPCError.malformedResponse }
        let keychain = try SharedKeychain()
        try keychain.save(profile.owner + profile.chainGenesis, service: service, account: account)
    }
}

struct WalletRPCStatus: Equatable, Sendable {
    let supportedProofs: Set<UInt8>
    enum Health: UInt8, Equatable, Sendable {
        case healthy = 0
        case stale = 1
        case degraded = 2
    }

    let chainID: Data
    let genesis: Data
    let protocolRevision: UInt64
    let schemaRevision: UInt32
    let finalizedHeight: UInt64
    let health: Health

    func supports(_ proof: UInt8) -> Bool { supportedProofs.contains(proof) }

    var networkState: WalletNetworkState {
        guard chainID == WalletKanalen.chainID,
              genesis == WalletKanalen.genesis,
              protocolRevision == WalletRPCCodec.supportedProtocolRevision,
              schemaRevision == WalletRPCCodec.supportedSchemaRevision
        else {
            // "Incompatible" on its own cannot distinguish a rebuilt chain from
            // a stale client, so name the field that actually diverged. A
            // genesis mismatch is the expected result after a chain rebuild.
            if chainID != WalletKanalen.chainID {
                WalletLog.rpc.error(
                    "chain mismatch: node \(WalletHex.short(chainID), privacy: .public) pinned \(WalletHex.short(WalletKanalen.chainID), privacy: .public)")
            }
            if genesis != WalletKanalen.genesis {
                WalletLog.rpc.error(
                    "genesis mismatch: node \(WalletHex.short(genesis), privacy: .public) pinned \(WalletHex.short(WalletKanalen.genesis), privacy: .public)")
            }
            if protocolRevision != WalletRPCCodec.supportedProtocolRevision {
                WalletLog.rpc.error(
                    "protocol revision mismatch: node \(protocolRevision, privacy: .public) supported \(WalletRPCCodec.supportedProtocolRevision, privacy: .public)")
            }
            if schemaRevision != WalletRPCCodec.supportedSchemaRevision {
                WalletLog.rpc.error(
                    "RPC schema mismatch: node \(schemaRevision, privacy: .public) supported \(WalletRPCCodec.supportedSchemaRevision, privacy: .public)")
            }
            return .incompatible
        }
        WalletLog.rpc.notice(
            "status accepted: height \(finalizedHeight, privacy: .public) health \(String(describing: health), privacy: .public)")
        switch health {
        case .healthy: return .healthy(finalizedHeight: finalizedHeight)
        case .stale, .degraded: return .stale(finalizedHeight: finalizedHeight)
        }
    }
}

struct WalletFaucetTerms: Equatable, Sendable {
    let chainID: Data
    let genesis: Data
    let challengeKind: UInt8
}

struct WalletFaucetReceipt: Equatable, Sendable {
    let reference: Data
    let state: UInt8
    let finalizedHeight: UInt64?
}

struct WalletOwnerCoinRecord: Equatable, Sendable {
    let key: Data
    let finalizedHeight: UInt64
    let value: Data
    let proof: Data
    let finality: Data
}

struct WalletOwnerCoinPage: Equatable, Sendable {
    let records: [WalletOwnerCoinRecord]
    let next: Data?

    func validated(
        owner: Data,
        chainGenesis: Data,
        finalizedHeight: UInt64,
        verifier: any WalletOwnerCoinProofVerifier
    ) throws -> WalletOwnerCoinPage {
        guard owner.count == 48,
              owner.contains(where: { $0 != 0 }),
              chainGenesis == WalletKanalen.genesis,
              !records.isEmpty
        else { throw WalletRPCError.malformedResponse }
        for record in records {
            guard record.finalizedHeight == finalizedHeight,
                  verifier.verify(record: record, owner: owner, chainGenesis: chainGenesis)
            else { throw WalletRPCError.unexpectedResponse }
        }
        return self
    }
}

/// Cryptographic verification is deliberately injected so the Swift UI cannot
/// accidentally treat transport decoding as proof verification. The production
/// implementation is supplied by the linked ActiveChain verifier artifact.
protocol WalletOwnerCoinProofVerifier: Sendable {
    func verify(record: WalletOwnerCoinRecord, owner: Data, chainGenesis: Data) -> Bool
}

struct RustWalletOwnerCoinProofVerifier: WalletOwnerCoinProofVerifier {
    func verify(record: WalletOwnerCoinRecord, owner: Data, chainGenesis: Data) -> Bool {
        guard record.key.count == 48,
              owner.count == 48,
              chainGenesis.count == 48,
              !record.value.isEmpty,
              !record.proof.isEmpty,
              !record.finality.isEmpty,
              record.value.count <= Int(UInt32.max),
              record.proof.count <= Int(UInt32.max),
              record.finality.count <= Int(UInt32.max)
        else { return false }
        return record.key.withUnsafeBytes { key in
            record.value.withUnsafeBytes { value in
                record.proof.withUnsafeBytes { proof in
                    record.finality.withUnsafeBytes { finality in
                        owner.withUnsafeBytes { owner in
                            chainGenesis.withUnsafeBytes { genesis in
                                activechain_wallet_verify_owner_coin_cell_record(
                                    key.bindMemory(to: UInt8.self).baseAddress!,
                                    record.finalizedHeight,
                                    value.bindMemory(to: UInt8.self).baseAddress!,
                                    UInt32(record.value.count),
                                    proof.bindMemory(to: UInt8.self).baseAddress!,
                                    UInt32(record.proof.count),
                                    finality.bindMemory(to: UInt8.self).baseAddress!,
                                    UInt32(record.finality.count),
                                    owner.bindMemory(to: UInt8.self).baseAddress!,
                                    genesis.bindMemory(to: UInt8.self).baseAddress!
                                ) == 0
                            }
                        }
                    }
                }
            }
        }
    }
}

enum WalletRPCError: Error, Equatable {
    case transport
    case malformedResponse
    case responseTooLarge
    case unexpectedResponse
}

enum WalletRPCCodec {
    static let supportedProtocolRevision = WalletKanalen.protocolRevision
    static let supportedSchemaRevision = WalletKanalen.schemaRevision
    static let maximumFrameLength = 4 * 1_024 * 1_024
    private static let maximumBlobLength = 256 * 1_024
    private static let maximumStatusBodyLength = 151

    /// Canonical (type tag, schema revision) pairs for the RPC envelopes.
    ///
    /// These were previously inlined as literals at five call sites pinned to
    /// revision 1. When RpcRequest and RpcResponse moved to revision 2 the node
    /// began rejecting every request as undecodable and closing the connection,
    /// which reached the UI only as an unexplained transport failure.
    static let requestSchemaRevision: UInt16 = 2
    static let responseTypeTag: UInt16 = 0x010a
    static let responseSchemaRevision: UInt16 = 2
    private static let requestEnvelopeHeader = Data([0x01, 0x07, 0x00, 0x02])

    static let framedStatusRequest = framedRequest(body: Data([0]))

    static let framedFaucetTermsRequest = framedRequest(body: Data([7]))

    static func framedFaucetRequest(
        owner: Data,
        idempotencyKey: Data,
        sourceCommitment: Data
    ) throws -> Data {
        guard owner.count == 48,
              idempotencyKey.count == 48,
              sourceCommitment.count == 48,
              owner.contains(where: { $0 != 0 }),
              idempotencyKey.contains(where: { $0 != 0 }),
              sourceCommitment.contains(where: { $0 != 0 }) else {
            throw WalletRPCError.unexpectedResponse
        }
        var body = Data([5])
        body.append(WalletKanalen.chainID)
        body.append(WalletKanalen.genesis)
        body.append(owner)
        body.append(idempotencyKey)
        body.append(sourceCommitment)
        body.append(contentsOf: UInt64.zero.bigEndianBytes)
        body.append(0) // empty bounded challenge evidence
        return framedRequest(body: body)
    }

    static func decodeFaucetTerms(_ envelope: Data) throws -> WalletFaucetTerms {
        var decoder = try responseBody(envelope, variant: 7)
        let chain = try decoder.read(count: 48)
        let genesis = try decoder.read(count: 48)
        _ = try decoder.readUInt64() // policy revision
        _ = try decoder.readUInt64() // valid until
        _ = try decoder.read(count: 16) // grant amount
        _ = try decoder.readUInt64() // recipient cooldown
        _ = try decoder.readUInt16() // recipient lifetime
        _ = try decoder.readUInt64() // source window
        _ = try decoder.readUInt16() // source limit
        _ = try decoder.readUInt64() // global window
        _ = try decoder.readUInt32() // global limit
        let challenge = try decoder.readUInt8()
        let difficulty = try decoder.readUInt8()
        guard decoder.remaining == 0,
              chain.contains(where: { $0 != 0 }),
              genesis.contains(where: { $0 != 0 }),
              challenge <= 1,
              (challenge == 0) == (difficulty == 0) else {
            throw WalletRPCError.malformedResponse
        }
        return WalletFaucetTerms(chainID: chain, genesis: genesis, challengeKind: challenge)
    }

    static func decodeFaucetReceipt(_ envelope: Data) throws -> WalletFaucetReceipt {
        var decoder = try responseBody(envelope, variant: 6)
        let reference = try decoder.read(count: 48)
        _ = try decoder.read(count: 48) // recipient
        _ = try decoder.read(count: 16) // amount
        let state = try decoder.readUInt8()
        let hasTransaction = try decoder.readUInt8()
        guard hasTransaction <= 1 else { throw WalletRPCError.malformedResponse }
        if hasTransaction == 1 { _ = try decoder.read(count: 48) }
        let hasHeight = try decoder.readUInt8()
        guard hasHeight <= 1 else { throw WalletRPCError.malformedResponse }
        let height = hasHeight == 1 ? try decoder.readUInt64() : nil
        let hasBlock = try decoder.readUInt8()
        guard hasBlock <= 1 else { throw WalletRPCError.malformedResponse }
        if hasBlock == 1 { _ = try decoder.read(count: 48) }
        let proof = try decoder.readBlob(maximum: maximumBlobLength)
        guard reference.contains(where: { $0 != 0 }),
              state <= 2,
              decoder.remaining == 0,
              (state == 1) == (hasTransaction == 1 && height != nil && hasBlock == 1 && !proof.isEmpty),
              state == 1 || (height == nil && hasBlock == 0 && proof.isEmpty) else {
            throw WalletRPCError.malformedResponse
        }
        return WalletFaucetReceipt(reference: reference, state: state, finalizedHeight: height)
    }

    private static func responseBody(
        _ envelope: Data,
        variant: UInt8
    ) throws -> WalletBinaryDecoder {
        var decoder = WalletBinaryDecoder(data: envelope)
        guard try decoder.readUInt16() == responseTypeTag,
              try decoder.readUInt16() == responseSchemaRevision
        else { throw WalletRPCError.unexpectedResponse }
        let length = try decoder.readULEB128(maximum: maximumFrameLength)
        guard length == decoder.remaining,
              try decoder.readUInt8() == variant else { throw WalletRPCError.unexpectedResponse }
        return decoder
    }

    private static func framedRequest(body: Data) -> Data {
        var envelope = requestEnvelopeHeader
        envelope.append(contentsOf: uleb128(body.count))
        envelope.append(body)
        var frame = Data()
        frame.append(contentsOf: UInt32(envelope.count).bigEndianBytes)
        frame.append(envelope)
        return frame
    }

    private static func uleb128(_ input: Int) -> [UInt8] {
        var value = input
        var bytes: [UInt8] = []
        repeat {
            var byte = UInt8(value & 0x7f)
            value >>= 7
            if value != 0 { byte |= 0x80 }
            bytes.append(byte)
        } while value != 0
        return bytes
    }

    /// Canonical envelope for RpcRequest::ListOwnerCoinCells. The owner is a
    /// 48-byte PrincipalId digest; pagination is deliberately bounded by the
    /// protocol maximum and no local balance is inferred from the request.
    static func framedOwnerCoinCellRequest(owner: Data, limit: UInt16 = 4) throws -> Data {
        guard owner.count == 48, limit > 0, limit <= 4 else { throw WalletRPCError.unexpectedResponse }
        var body = Data([8])
        body.append(owner)
        body.append(0) // Option<Digest384>::None
        body.append(UInt8(limit >> 8))
        body.append(UInt8(limit & 0xff))
        var envelope = requestEnvelopeHeader
        envelope.append(UInt8(body.count))
        envelope.append(body)
        var framed = Data()
        framed.append(UInt8(envelope.count >> 24))
        framed.append(UInt8(envelope.count >> 16))
        framed.append(UInt8(envelope.count >> 8))
        framed.append(UInt8(envelope.count & 0xff))
        framed.append(envelope)
        return framed
    }

    static func decodeStatus(_ envelope: Data) throws -> WalletRPCStatus {
        var decoder = WalletBinaryDecoder(data: envelope)
        guard try decoder.readUInt16() == responseTypeTag,
              try decoder.readUInt16() == responseSchemaRevision
        else {
            throw WalletRPCError.unexpectedResponse
        }
        let bodyLength = try decoder.readULEB128(maximum: maximumStatusBodyLength)
        guard bodyLength == decoder.remaining, try decoder.readUInt8() == 0 else {
            throw WalletRPCError.unexpectedResponse
        }
        let chainID = try decoder.read(count: 48)
        let genesis = try decoder.read(count: 48)
        guard chainID.contains(where: { $0 != 0 }),
              genesis.contains(where: { $0 != 0 }) else {
            throw WalletRPCError.malformedResponse
        }
        let protocolRevision = try decoder.readUInt64()
        let schemaRevision = try decoder.readUInt32()
        let finalizedHeight = try decoder.readUInt64()
        let finalizedAt = try decoder.readUInt64()
        let servedAt = try decoder.readUInt64()
        let maximumStaleness = try decoder.readUInt64()
        guard protocolRevision > 0,
              maximumStaleness > 0,
              finalizedAt <= servedAt,
              let health = WalletRPCStatus.Health(rawValue: try decoder.readUInt8())
        else {
            throw WalletRPCError.malformedResponse
        }
        let expected: WalletRPCStatus.Health =
            servedAt - finalizedAt > maximumStaleness ? .stale : .healthy
        guard health == expected else {
            throw WalletRPCError.malformedResponse
        }
        let proofCount = try decoder.readULEB128(maximum: 8)
        guard proofCount > 0 else { throw WalletRPCError.malformedResponse }
        let proofs = try decoder.read(count: proofCount)
        guard proofs.allSatisfy({ $0 <= 3 }),
              zip(proofs, proofs.dropFirst()).allSatisfy({ $0 < $1 }),
              decoder.remaining == 0
        else {
            throw WalletRPCError.malformedResponse
        }
        return WalletRPCStatus(
            supportedProofs: Set(proofs),
            chainID: chainID,
            genesis: genesis,
            protocolRevision: protocolRevision,
            schemaRevision: schemaRevision,
            finalizedHeight: finalizedHeight,
            health: health
        )
    }

    static func decodeOwnerCoinPage(_ envelope: Data) throws -> WalletOwnerCoinPage {
        var decoder = WalletBinaryDecoder(data: envelope)
        guard try decoder.readUInt16() == responseTypeTag,
              try decoder.readUInt16() == responseSchemaRevision
        else { throw WalletRPCError.unexpectedResponse }
        let bodyLength = try decoder.readULEB128(maximum: maximumFrameLength)
        guard bodyLength == decoder.remaining else { throw WalletRPCError.unexpectedResponse }
        guard try decoder.readUInt8() == 2 else { throw WalletRPCError.unexpectedResponse }
        let count = try decoder.readULEB128(maximum: 4)
        var records: [WalletOwnerCoinRecord] = []
        records.reserveCapacity(count)
        var previous = Data()
        for _ in 0..<count {
            guard try decoder.readUInt8() == 4 else { throw WalletRPCError.unexpectedResponse }
            let key = try decoder.read(count: 48)
            guard key.contains(where: { $0 != 0 }), previous.isEmpty || previous.lexicographicallyPrecedes(key)
            else { throw WalletRPCError.malformedResponse }
            let height = try decoder.readUInt64()
            let value = try decoder.readBlob(maximum: maximumBlobLength)
            let proof = try decoder.readBlob(maximum: maximumBlobLength)
            let finality = try decoder.readBlob(maximum: maximumBlobLength)
            guard !value.isEmpty, !proof.isEmpty, !finality.isEmpty else { throw WalletRPCError.malformedResponse }
            records.append(WalletOwnerCoinRecord(key: key, finalizedHeight: height, value: value, proof: proof, finality: finality))
            previous = key
        }
        let hasNext = try decoder.readUInt8()
        let next: Data?
        switch hasNext {
        case 0: next = nil
        case 1:
            let cursor = try decoder.read(count: 48)
            guard cursor.contains(where: { $0 != 0 }),
                  records.last.map({ cursor.lexicographicallyPrecedes($0.key) }) != true
            else { throw WalletRPCError.malformedResponse }
            next = cursor
        default: throw WalletRPCError.malformedResponse
        }
        guard decoder.remaining == 0 else { throw WalletRPCError.malformedResponse }
        return WalletOwnerCoinPage(records: records, next: next)
    }
}

private struct WalletBinaryDecoder {
    let data: Data
    private(set) var offset = 0
    var remaining: Int { data.count - offset }

    mutating func read(count: Int) throws -> Data {
        guard count >= 0, remaining >= count else { throw WalletRPCError.malformedResponse }
        defer { offset += count }
        return data.subdata(in: offset..<(offset + count))
    }

    mutating func readUInt8() throws -> UInt8 { try read(count: 1)[0] }
    mutating func readUInt16() throws -> UInt16 { try readInteger() }
    mutating func readUInt32() throws -> UInt32 { try readInteger() }
    mutating func readUInt64() throws -> UInt64 { try readInteger() }

    mutating func readBlob(maximum: Int) throws -> Data {
        let length = try readULEB128(maximum: maximum)
        return try read(count: length)
    }

    mutating func readULEB128(maximum: Int) throws -> Int {
        var value: UInt32 = 0
        var shift: UInt32 = 0
        var count = 0
        while count < 5 {
            let byte = try readUInt8()
            let payload = UInt32(byte & 0x7f)
            if shift == 28, payload > 0x0f { throw WalletRPCError.malformedResponse }
            value |= payload << shift
            count += 1
            if byte & 0x80 == 0 {
                if count > 1, payload == 0 { throw WalletRPCError.malformedResponse }
                guard value <= maximum else { throw WalletRPCError.malformedResponse }
                return Int(value)
            }
            shift += 7
        }
        throw WalletRPCError.malformedResponse
    }

    private mutating func readInteger<T: FixedWidthInteger>() throws -> T {
        try read(count: MemoryLayout<T>.size).reduce(T.zero) { ($0 << 8) | T($1) }
    }
}

final class WalletRPCClient: @unchecked Sendable {
    private let queue = DispatchQueue(label: "dev.activechain.wallet.rpc")

    func status() async throws -> WalletRPCStatus {
        try WalletRPCCodec.decodeStatus(await roundTrip(WalletRPCCodec.framedStatusRequest))
    }

    func faucetTerms() async throws -> WalletFaucetTerms {
        try WalletRPCCodec.decodeFaucetTerms(await roundTrip(WalletRPCCodec.framedFaucetTermsRequest))
    }

    func requestFaucet(owner: Data) async throws -> WalletFaucetReceipt {
        try WalletRPCCodec.decodeFaucetReceipt(
            await roundTrip(
                try WalletRPCCodec.framedFaucetRequest(
                    owner: owner,
                    idempotencyKey: try randomDigest(),
                    sourceCommitment: try randomDigest()
                )
            )
        )
    }

    func ownerCoinCells(owner: Data, limit: UInt16 = 4) async throws -> WalletOwnerCoinPage {
        let connection = NWConnection(host: WalletKanalen.host, port: WalletKanalen.port, using: .tls)
        let timeout = DispatchSource.makeTimerSource(queue: queue)
        timeout.schedule(deadline: .now() + 8)
        timeout.setEventHandler { connection.cancel() }
        timeout.resume()
        defer { timeout.cancel(); connection.cancel() }
        try await waitUntilReady(connection)
        try await send(try WalletRPCCodec.framedOwnerCoinCellRequest(owner: owner, limit: limit), over: connection)
        let prefix = try await receiveExactly(4, over: connection)
        let length = prefix.reduce(0) { ($0 << 8) | Int($1) }
        guard length > 0, length <= WalletRPCCodec.maximumFrameLength else {
            throw length > WalletRPCCodec.maximumFrameLength ? WalletRPCError.responseTooLarge : WalletRPCError.malformedResponse
        }
        return try WalletRPCCodec.decodeOwnerCoinPage(try await receiveExactly(length, over: connection))
    }

    func ownerCoinCells(profile: WalletDeviceProfile, limit: UInt16 = 4) async throws -> WalletOwnerCoinPage {
        let page = try await ownerCoinCells(owner: profile.owner, limit: limit)
        // The finality bytes are retained for the linked verifier, which must
        // bind each record to this exact trusted genesis before UI use.
        guard page.records.allSatisfy({ !$0.finality.isEmpty }) else {
            throw WalletRPCError.malformedResponse
        }
        return page
    }

    func verifiedOwnerCoinCells(
        profile: WalletDeviceProfile,
        finalizedHeight: UInt64,
        verifier: any WalletOwnerCoinProofVerifier,
        limit: UInt16 = 4
    ) async throws -> WalletOwnerCoinPage {
        let page = try await ownerCoinCells(profile: profile, limit: limit)
        return try page.validated(
            owner: profile.owner,
            chainGenesis: profile.chainGenesis,
            finalizedHeight: finalizedHeight,
            verifier: verifier
        )
    }

    private func waitUntilReady(_ connection: NWConnection) async throws {
        let readiness = WalletReadinessFlag()
        try await withCheckedThrowingContinuation { continuation in
            let gate = WalletContinuationGate()
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    readiness.markReady()
                    WalletLog.rpc.notice("connection ready to \(WalletKanalen.hostDescription, privacy: .public)")
                    gate.resumeOnce { continuation.resume() }
                case let .failed(error):
                    WalletLog.rpc.error("connection failed: \(String(describing: error), privacy: .public)")
                    gate.resumeOnce { continuation.resume(throwing: WalletRPCError.transport) }
                case .cancelled:
                    // Every round trip cancels in a defer, so a cancel after the
                    // connection went ready is ordinary teardown. Only a cancel
                    // that beats readiness means the watchdog fired.
                    if readiness.isReady {
                        WalletLog.rpc.notice("connection closed after exchange")
                    } else {
                        WalletLog.rpc.error("connection cancelled before ready (timeout or teardown)")
                    }
                    gate.resumeOnce { continuation.resume(throwing: WalletRPCError.transport) }
                case let .waiting(error):
                    // NWConnection stays here on a refused port or an
                    // unreachable path; without this the app simply hangs to
                    // the watchdog with nothing to show for it.
                    WalletLog.rpc.error("connection waiting: \(String(describing: error), privacy: .public)")
                case .preparing:
                    WalletLog.rpc.notice("connection preparing (DNS and TLS)")
                default:
                    break
                }
            }
            WalletLog.rpc.notice("dialing \(WalletKanalen.hostDescription, privacy: .public)")
            connection.start(queue: queue)
        }
    }

    private func roundTrip(_ request: Data) async throws -> Data {
        let connection = NWConnection(host: WalletKanalen.host, port: WalletKanalen.port, using: .tls)
        let timeout = DispatchSource.makeTimerSource(queue: queue)
        timeout.schedule(deadline: .now() + 8)
        timeout.setEventHandler { connection.cancel() }
        timeout.resume()
        defer { timeout.cancel(); connection.cancel() }
        try await waitUntilReady(connection)
        try await send(request, over: connection)
        let prefix = try await receiveExactly(4, over: connection)
        let length = prefix.reduce(0) { ($0 << 8) | Int($1) }
        guard length > 0, length <= WalletRPCCodec.maximumFrameLength else {
            throw length > WalletRPCCodec.maximumFrameLength
                ? WalletRPCError.responseTooLarge : WalletRPCError.malformedResponse
        }
        return try await receiveExactly(length, over: connection)
    }

    private func randomDigest() throws -> Data {
        var bytes = Data(count: 48)
        let status = bytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 48, $0.baseAddress!)
        }
        guard status == errSecSuccess, bytes.contains(where: { $0 != 0 }) else {
            throw WalletRPCError.transport
        }
        return bytes
    }

    private func send(_ data: Data, over connection: NWConnection) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    WalletLog.rpc.error("send of \(data.count) bytes failed: \(String(describing: error), privacy: .public)")
                    continuation.resume(throwing: WalletRPCError.transport)
                } else {
                    WalletLog.rpc.notice("sent \(data.count) request bytes")
                    continuation.resume()
                }
            })
        }
    }

    private func receiveExactly(_ count: Int, over connection: NWConnection) async throws -> Data {
        var result = Data()
        while result.count < count {
            let needed = count - result.count
            let chunk: Data = try await withCheckedThrowingContinuation { continuation in
                connection.receive(minimumIncompleteLength: 1, maximumLength: needed) {
                    data, _, complete, error in
                    if let data, !data.isEmpty {
                        continuation.resume(returning: data)
                    } else {
                        // A clean EOF here means the peer accepted the request
                        // and then closed, which is what a terminating proxy
                        // does when its backend is gone.
                        WalletLog.rpc.error(
                            "receive stalled after \(result.count)/\(count) bytes; complete=\(complete, privacy: .public) error=\(String(describing: error), privacy: .public)")
                        continuation.resume(throwing: WalletRPCError.transport)
                    }
                }
            }
            result.append(chunk)
        }
        return result
    }
}

/// Records whether a connection ever reached `.ready`, so ordinary teardown is
/// not reported as a failure. The state handler runs on the connection queue
/// while the flag is read from it too, so a lock keeps it well defined.
private final class WalletReadinessFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var ready = false

    var isReady: Bool {
        lock.lock()
        defer { lock.unlock() }
        return ready
    }

    func markReady() {
        lock.lock()
        ready = true
        lock.unlock()
    }
}

private final class WalletContinuationGate: @unchecked Sendable {
    private let lock = NSLock()
    private var resumed = false

    func resumeOnce(_ action: () -> Void) {
        lock.lock()
        defer { lock.unlock() }
        guard !resumed else { return }
        resumed = true
        action()
    }
}

private extension FixedWidthInteger {
    var bigEndianBytes: [UInt8] {
        withUnsafeBytes(of: bigEndian) { Array($0) }
    }
}
