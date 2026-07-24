import Foundation

enum AgentEnrollmentError: LocalizedError {
    case invalidLabel
    case invalidPrincipal
    case invalidCapabilities
    case invalidBudget
    case invalidExpiry

    var errorDescription: String? {
        switch self {
        case .invalidLabel: "Enter a name for this agent."
        case .invalidPrincipal: "The agent principal must be exactly 48 bytes of hexadecimal."
        case .invalidCapabilities: "Add one or more distinct 48-byte capability identifiers."
        case .invalidBudget: "The spending limit must be greater than zero."
        case .invalidExpiry: "The expiry block must be greater than zero."
        }
    }
}

struct AgentEnrollmentDraft: Equatable {
    var label = ""
    var principal = ""
    var capabilityIDs = ""
    var connection: AgentConnection = .thirdParty
    var budget: UInt64 = 0
    var expiresAt: UInt64 = 0

    func validate() throws {
        guard !label.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              label.utf8.count <= 96
        else { throw AgentEnrollmentError.invalidLabel }
        _ = try principalBytes()
        _ = try capabilityBytes()
        guard budget > 0 else { throw AgentEnrollmentError.invalidBudget }
        guard expiresAt > 0 else { throw AgentEnrollmentError.invalidExpiry }
    }

    func principalBytes() throws -> Data {
        guard let value = Self.decodeHex(principal), value.count == 48 else {
            throw AgentEnrollmentError.invalidPrincipal
        }
        return value
    }

    func capabilityBytes() throws -> Data {
        let values = capabilityIDs
            .split(whereSeparator: { $0 == "," || $0 == "\n" || $0 == " " })
            .map(String.init)
        let decoded = try values.map { value -> Data in
            guard let bytes = Self.decodeHex(value), bytes.count == 48 else {
                throw AgentEnrollmentError.invalidCapabilities
            }
            return bytes
        }
        guard !decoded.isEmpty,
              zip(decoded, decoded.dropFirst()).allSatisfy({ $0.lexicographicallyPrecedes($1) })
        else { throw AgentEnrollmentError.invalidCapabilities }
        return decoded.reduce(into: Data()) { $0.append($1) }
    }

    private static func decodeHex(_ input: String) -> Data? {
        let input = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard input.count.isMultiple(of: 2), input.allSatisfy(\.isHexDigit) else { return nil }
        var output = Data()
        var index = input.startIndex
        while index < input.endIndex {
            let next = input.index(index, offsetBy: 2)
            guard let byte = UInt8(input[index..<next], radix: 16) else { return nil }
            output.append(byte)
            index = next
        }
        return output
    }
}

extension AgentConnection {
    var abiValue: UInt32 {
        switch self {
        case .walletOwned: 0
        case .thirdParty: 1
        case .remote: 2
        case .managedDevice: 3
        }
    }
}
