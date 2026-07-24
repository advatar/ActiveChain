import Foundation
import Network

struct AmberRPCStatus: Equatable, Sendable {
    enum Health: UInt8, Equatable, Sendable {
        case healthy = 0
        case stale = 1
        case degraded = 2
    }

    let protocolRevision: UInt64
    let schemaRevision: UInt32
    let finalizedHeight: UInt64
    let health: Health

    var connectionState: AmberConnectionState {
        guard protocolRevision == AmberRPCCodec.supportedProtocolRevision,
              schemaRevision == AmberRPCCodec.supportedSchemaRevision
        else {
            return .incompatible
        }
        switch health {
        case .healthy: return .verified(finalizedHeight: finalizedHeight)
        case .stale: return .stale(finalizedHeight: finalizedHeight)
        case .degraded: return .degraded(finalizedHeight: finalizedHeight)
        }
    }
}

enum AmberRPCError: Error, Equatable {
    case invalidEndpoint
    case transport
    case malformedResponse
    case responseTooLarge
    case unexpectedResponse
}

enum AmberRPCCodec {
    static let supportedProtocolRevision: UInt64 = 1
    static let supportedSchemaRevision: UInt32 = 1
    static let maximumFrameLength = 4 * 1_024 * 1_024
    private static let responseTypeTag: UInt16 = 0x00a1
    private static let envelopeSchema: UInt16 = 1

    static let framedStatusRequest = Data([
        0x00, 0x00, 0x00, 0x06,
        0x00, 0xa0, 0x00, 0x01, 0x01, 0x00
    ])

    static func decodeStatus(_ envelope: Data) throws -> AmberRPCStatus {
        var decoder = AmberBinaryDecoder(data: envelope)
        guard try decoder.readUInt16() == responseTypeTag,
              try decoder.readUInt16() == envelopeSchema
        else {
            throw AmberRPCError.unexpectedResponse
        }
        let bodyLength = try decoder.readULEB128(maximum: 151)
        guard bodyLength == decoder.remaining else {
            throw AmberRPCError.malformedResponse
        }
        guard try decoder.readUInt8() == 0 else {
            throw AmberRPCError.unexpectedResponse
        }
        _ = try decoder.read(count: 48)
        let genesis = try decoder.read(count: 48)
        guard genesis.contains(where: { $0 != 0 }) else {
            throw AmberRPCError.malformedResponse
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
              let health = AmberRPCStatus.Health(rawValue: try decoder.readUInt8())
        else {
            throw AmberRPCError.malformedResponse
        }
        let expectedHealth: AmberRPCStatus.Health =
            servedAt - finalizedAt > maximumStaleness ? .stale : .healthy
        guard health == expectedHealth else {
            throw AmberRPCError.malformedResponse
        }
        let proofCount = try decoder.readULEB128(maximum: 8)
        guard proofCount > 0 else {
            throw AmberRPCError.malformedResponse
        }
        let proofs = try decoder.read(count: proofCount)
        guard proofs.allSatisfy({ $0 <= 3 }),
              zip(proofs, proofs.dropFirst()).allSatisfy({ $0 < $1 }),
              decoder.remaining == 0
        else {
            throw AmberRPCError.malformedResponse
        }
        return AmberRPCStatus(
            protocolRevision: protocolRevision,
            schemaRevision: schemaRevision,
            finalizedHeight: finalizedHeight,
            health: health
        )
    }
}

private struct AmberBinaryDecoder {
    let data: Data
    private(set) var offset = 0
    var remaining: Int { data.count - offset }

    mutating func read(count: Int) throws -> Data {
        guard count >= 0, remaining >= count else { throw AmberRPCError.malformedResponse }
        defer { offset += count }
        return data.subdata(in: offset..<(offset + count))
    }

    mutating func readUInt8() throws -> UInt8 {
        try read(count: 1)[0]
    }

    mutating func readUInt16() throws -> UInt16 { try readInteger() }
    mutating func readUInt32() throws -> UInt32 { try readInteger() }
    mutating func readUInt64() throws -> UInt64 { try readInteger() }

    mutating func readULEB128(maximum: Int) throws -> Int {
        var value: UInt32 = 0
        var shift: UInt32 = 0
        var bytes = 0
        while bytes < 5 {
            let byte = try readUInt8()
            let payload = UInt32(byte & 0x7f)
            if shift == 28, payload > 0x0f { throw AmberRPCError.malformedResponse }
            value |= payload << shift
            bytes += 1
            if byte & 0x80 == 0 {
                if bytes > 1, payload == 0 { throw AmberRPCError.malformedResponse }
                guard value <= maximum else { throw AmberRPCError.malformedResponse }
                return Int(value)
            }
            shift += 7
        }
        throw AmberRPCError.malformedResponse
    }

    private mutating func readInteger<T: FixedWidthInteger>() throws -> T {
        try read(count: MemoryLayout<T>.size).reduce(T.zero) { ($0 << 8) | T($1) }
    }
}

final class AmberRPCClient: @unchecked Sendable {
    private let queue = DispatchQueue(label: "dev.activechain.amber.rpc")

    func status(for network: AmberNetwork) async throws -> AmberRPCStatus {
        guard let host = network.rpcURL.host() else {
            throw AmberRPCError.invalidEndpoint
        }
        let portValue = network.rpcURL.port ?? 443
        guard let port = NWEndpoint.Port(rawValue: UInt16(portValue)) else {
            throw AmberRPCError.invalidEndpoint
        }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: port, using: .tls)
        let timeout = DispatchSource.makeTimerSource(queue: queue)
        timeout.schedule(deadline: .now() + 5)
        timeout.setEventHandler { connection.cancel() }
        timeout.resume()
        defer {
            timeout.cancel()
            connection.cancel()
        }
        try await waitUntilReady(connection)
        try await send(AmberRPCCodec.framedStatusRequest, over: connection)
        let prefix = try await receiveExactly(4, over: connection)
        let length = prefix.reduce(0) { ($0 << 8) | Int($1) }
        guard length > 0 else { throw AmberRPCError.malformedResponse }
        guard length <= AmberRPCCodec.maximumFrameLength else { throw AmberRPCError.responseTooLarge }
        return try AmberRPCCodec.decodeStatus(try await receiveExactly(length, over: connection))
    }

    private func waitUntilReady(_ connection: NWConnection) async throws {
        try await withCheckedThrowingContinuation { continuation in
            let gate = AmberContinuationGate()
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    gate.resumeOnce { continuation.resume() }
                case .failed, .cancelled:
                    gate.resumeOnce {
                        continuation.resume(throwing: AmberRPCError.transport)
                    }
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
                    continuation.resume(throwing: AmberRPCError.transport)
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
                        continuation.resume(throwing: AmberRPCError.transport)
                    } else {
                        continuation.resume(throwing: AmberRPCError.transport)
                    }
                }
            }
            result.append(chunk)
        }
        return result
    }
}

private final class AmberContinuationGate: @unchecked Sendable {
    private let lock = NSLock()
    private var didResume = false

    func resumeOnce(_ action: () -> Void) {
        lock.lock()
        defer { lock.unlock() }
        guard !didResume else { return }
        didResume = true
        action()
    }
}
