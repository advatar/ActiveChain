import Foundation
import Network
import SwiftUI

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
        case .incompatible: "Unsupported protocol or RPC schema"
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

@MainActor
final class WalletLiveState: ObservableObject {
    @Published private(set) var networkState: WalletNetworkState = .checking
    private let rpc = WalletRPCClient()

    func refresh() async {
        networkState = .checking
        do {
            networkState = try await rpc.status().networkState
        } catch {
            networkState = .unavailable
        }
    }
}

struct WalletRPCStatus: Equatable, Sendable {
    let supportedProofs: Set<UInt8>
    enum Health: UInt8, Equatable, Sendable {
        case healthy = 0
        case stale = 1
        case degraded = 2
    }

    let protocolRevision: UInt64
    let schemaRevision: UInt32
    let finalizedHeight: UInt64
    let health: Health

    func supports(_ proof: UInt8) -> Bool { supportedProofs.contains(proof) }

    var networkState: WalletNetworkState {
        guard protocolRevision == WalletRPCCodec.supportedProtocolRevision,
              schemaRevision == WalletRPCCodec.supportedSchemaRevision
        else {
            return .incompatible
        }
        switch health {
        case .healthy: return .healthy(finalizedHeight: finalizedHeight)
        case .stale, .degraded: return .stale(finalizedHeight: finalizedHeight)
        }
    }
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
        guard owner.count == 48, chainGenesis.count == 48 else { throw WalletRPCError.malformedResponse }
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

enum WalletRPCError: Error, Equatable {
    case transport
    case malformedResponse
    case responseTooLarge
    case unexpectedResponse
}

enum WalletRPCCodec {
    static let supportedProtocolRevision: UInt64 = 1
    static let supportedSchemaRevision: UInt32 = 1
    static let maximumFrameLength = 4 * 1_024 * 1_024
    private static let maximumStatusBodyLength = 151

    static let framedStatusRequest = Data([
        0x00, 0x00, 0x00, 0x06,
        0x00, 0xa0, 0x00, 0x01, 0x01, 0x00
    ])

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
        var envelope = Data([0x00, 0xa0, 0x00, 0x01])
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
        guard try decoder.readUInt16() == 0x00a1,
              try decoder.readUInt16() == 1
        else {
            throw WalletRPCError.unexpectedResponse
        }
        let bodyLength = try decoder.readULEB128(maximum: maximumStatusBodyLength)
        guard bodyLength == decoder.remaining, try decoder.readUInt8() == 0 else {
            throw WalletRPCError.unexpectedResponse
        }
        _ = try decoder.read(count: 48)
        let genesis = try decoder.read(count: 48)
        guard genesis.contains(where: { $0 != 0 }) else {
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
            protocolRevision: protocolRevision,
            schemaRevision: schemaRevision,
            finalizedHeight: finalizedHeight,
            health: health,
            supportedProofs: Set(proofs)
        )
    }

    static func decodeOwnerCoinPage(_ envelope: Data) throws -> WalletOwnerCoinPage {
        var decoder = WalletBinaryDecoder(data: envelope)
        guard try decoder.readUInt16() == 0x00a1,
              try decoder.readUInt16() == 1 else { throw WalletRPCError.unexpectedResponse }
        let bodyLength = try decoder.readULEB128(maximum: maximumStatusBodyLength)
        guard bodyLength == decoder.remaining else { throw WalletRPCError.unexpectedResponse }
        guard try decoder.readUInt8() == 2 else { throw WalletRPCError.unexpectedResponse }
        let count = try decoder.readULEB128(maximum: 4)
        var records: [WalletOwnerCoinRecord] = []
        records.reserveCapacity(count)
        var previous = Data()
        for _ in 0..<count {
            guard try decoder.readUInt8() == 0 else { throw WalletRPCError.unexpectedResponse }
            let key = try decoder.read(count: 48)
            guard key.contains(where: { $0 != 0 }), previous.isEmpty || previous.lexicographicallyPrecedes(key)
            else { throw WalletRPCError.malformedResponse }
            let height = try decoder.readUInt64()
            let value = try decoder.readBlob(maximum: maximumFrameLength)
            let proof = try decoder.readBlob(maximum: maximumFrameLength)
            let finality = try decoder.readBlob(maximum: maximumFrameLength)
            guard !value.isEmpty, !proof.isEmpty, !finality.isEmpty else { throw WalletRPCError.malformedResponse }
            records.append(WalletOwnerCoinRecord(key: key, finalizedHeight: height, value: value, proof: proof, finality: finality))
            previous = key
        }
        let hasNext = try decoder.readUInt8()
        let next: Data?
        switch hasNext {
        case 0: next = nil
        case 1: next = try decoder.read(count: 48)
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
        let connection = NWConnection(
            host: "rpc.kanalen.activechain.dev",
            port: 443,
            using: .tls
        )
        let timeout = DispatchSource.makeTimerSource(queue: queue)
        timeout.schedule(deadline: .now() + 8)
        timeout.setEventHandler { connection.cancel() }
        timeout.resume()
        defer {
            timeout.cancel()
            connection.cancel()
        }
        try await waitUntilReady(connection)
        try await send(WalletRPCCodec.framedStatusRequest, over: connection)
        let prefix = try await receiveExactly(4, over: connection)
        let length = prefix.reduce(0) { ($0 << 8) | Int($1) }
        guard length > 0 else { throw WalletRPCError.malformedResponse }
        guard length <= WalletRPCCodec.maximumFrameLength else {
            throw WalletRPCError.responseTooLarge
        }
        return try WalletRPCCodec.decodeStatus(try await receiveExactly(length, over: connection))
    }

    private func waitUntilReady(_ connection: NWConnection) async throws {
        try await withCheckedThrowingContinuation { continuation in
            let gate = WalletContinuationGate()
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    gate.resumeOnce { continuation.resume() }
                case .failed, .cancelled:
                    gate.resumeOnce { continuation.resume(throwing: WalletRPCError.transport) }
                default:
                    break
                }
            }
            connection.start(queue: queue)
        }
    }

    private func send(_ data: Data, over connection: NWConnection) async throws {
        try await withCheckedThrowingContinuation { continuation in
            connection.send(content: data, completion: .contentProcessed { error in
                if error == nil {
                    continuation.resume()
                } else {
                    continuation.resume(throwing: WalletRPCError.transport)
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
                    } else if complete || error != nil {
                        continuation.resume(throwing: WalletRPCError.transport)
                    } else {
                        continuation.resume(throwing: WalletRPCError.transport)
                    }
                }
            }
            result.append(chunk)
        }
        return result
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
