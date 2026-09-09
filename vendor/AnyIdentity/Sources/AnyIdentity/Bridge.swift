import Foundation
import CAnyIdentity

public struct AnyIdentityError: Error, Codable, Sendable, Equatable, LocalizedError {
    public let code: String
    public let message: String
    public var errorDescription: String? { "\(code): \(message)" }
    public init(code: String, message: String) { self.code = code; self.message = message }
}

struct DynamicKey: CodingKey {
    let stringValue: String
    let intValue: Int? = nil
    init(_ value: String) { stringValue = value }
    init?(stringValue: String) { self.init(stringValue) }
    init?(intValue: Int) { return nil }
}
private struct Request: Encodable {
    let operation: String
    let fields: [String: any Encodable]
    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: DynamicKey.self)
        try container.encode(operation, forKey: DynamicKey("op"))
        for (key, value) in fields { try container.encode(value, forKey: DynamicKey(key)) }
    }
}
private struct Response<T: Decodable>: Decodable {
    let ok: Bool
    let value: T?
    let error: AnyIdentityError?
}

enum Bridge {
    static func call<T: Decodable>(_ operation: String, _ fields: [String: any Encodable] = [:], key: IdentityKey? = nil) throws -> T {
        guard anyidentity_abi_version() == 1 else {
            throw AnyIdentityError(code: "abi", message: "Unsupported Rust ABI version")
        }
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let input = try encoder.encode(Request(operation: operation, fields: fields))
        let pointer = input.withUnsafeBytes { bytes in
            anyidentity_call(key?.handle, bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count)
        }
        withExtendedLifetime(key) {}
        guard let pointer else { throw AnyIdentityError(code: "ffi", message: "Rust returned no response") }
        defer { anyidentity_string_free(pointer) }
        let data = Data(bytes: pointer, count: strlen(pointer))
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        let response = try decoder.decode(Response<T>.self, from: data)
        guard response.ok, let value = response.value else {
            throw response.error ?? AnyIdentityError(code: "ffi", message: "Malformed Rust response")
        }
        return value
    }
}

/// An immutable, reference-counted Rust Ed25519 key. Concurrent reads/signatures are safe.
/// This software key is not a Secure Enclave key. Exported seeds require protected storage.
public final class IdentityKey: @unchecked Sendable {
    let handle: OpaquePointer
    private init(handle: OpaquePointer) { self.handle = handle }
    public convenience init() throws {
        guard let key = anyidentity_key_generate() else {
            throw AnyIdentityError(code: "entropy", message: "Could not generate an Ed25519 key")
        }
        self.init(handle: key)
    }
    public convenience init(seed: Data) throws {
        let key = seed.withUnsafeBytes { bytes in
            anyidentity_key_import(bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count)
        }
        guard let key else { throw AnyIdentityError(code: "invalid_input", message: "Expected a 32-byte seed") }
        self.init(handle: key)
    }
    deinit { anyidentity_key_free(handle) }
    public var publicKey: String { get throws { try Bridge.call("public_key", key: self) } }

    /// Derives a key for an exact, case-sensitive application audience. Keep the master secret.
    /// Publishing a master-signed link destroys unlinkability. This is not an anonymous credential proof.
    public func pairwiseKey(for audience: String) throws -> IdentityKey {
        let data = Data(audience.utf8)
        let key = data.withUnsafeBytes { bytes in
            anyidentity_key_derive(handle, bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count)
        }
        withExtendedLifetime(self) {}
        guard let key else { throw AnyIdentityError(code: "invalid_input", message: "Invalid pairwise audience") }
        return IdentityKey(handle: key)
    }
    /// Caller owns the returned plaintext seed. Store in Keychain or another protected secret store.
    public func exportSeed() throws -> Data {
        var data = Data(count: 32)
        let success = data.withUnsafeMutableBytes { bytes in
            anyidentity_key_export(handle, bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count)
        }
        withExtendedLifetime(self) {}
        guard success else { throw AnyIdentityError(code: "ffi", message: "Key export failed") }
        return data
    }
}
