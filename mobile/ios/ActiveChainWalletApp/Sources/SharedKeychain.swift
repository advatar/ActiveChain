import ActiveChainWallet
import Foundation
import os
import Security
import CryptoKit
import LocalAuthentication

enum SharedKeychainError: Error, Equatable {
    case unexpectedStatus(OSStatus)
}

enum WalletCustodyLog {
    /// Custody failures collapse into a handful of cases that discard the
    /// underlying OSStatus and CFError, so "no signing key" cannot be told
    /// apart from a missing entitlement, a locked keychain, or an enclave that
    /// declined the request. Record the real cause; no key material is logged.
    static let custody = Logger(subsystem: "dev.activechain.wallet", category: "custody")
}

/// Keychain scoping for the wallet.
///
/// There is deliberately no access group. A group shares items only between
/// apps on one device that carry the same team prefix, so it cannot open the
/// same wallet on iOS and macOS — that is the recovery envelope's job, which
/// re-wraps the seed under each device's own Secure Enclave key. Keeping a
/// group bought nothing and cost provisioning entirely: the prefix is empty in
/// an unsigned build, and the repository builds unsigned for local work and for
/// the Apple stage of the deterministic gate.
struct SharedKeychainConfiguration {
    static func application(bundle: Bundle = .main) throws -> Self {
        Self()
    }

    func query(
        service: String,
        account: String,
        synchronizeAcrossDevices: Bool
    ) -> [CFString: Any] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrSynchronizable: synchronizeAcrossDevices ? kCFBooleanTrue! : kCFBooleanFalse!
        ]
#if os(macOS)
        query[kSecUseDataProtectionKeychain] = kCFBooleanTrue
#endif
        return query
    }
}

final class SharedKeychain {
    private let configuration: SharedKeychainConfiguration

    init(configuration: SharedKeychainConfiguration) {
        self.configuration = configuration
    }

    convenience init(bundle: Bundle = .main) throws {
        try self.init(configuration: .application(bundle: bundle))
    }

    func save(
        _ data: Data,
        service: String,
        account: String,
        synchronizeAcrossDevices: Bool = false,
        accessibility: CFString? = nil
    ) throws {
        let query = configuration.query(
            service: service,
            account: account,
            synchronizeAcrossDevices: synchronizeAcrossDevices
        )
        let attributes: [CFString: Any] = [
            kSecValueData: data,
            kSecAttrAccessible: accessibility ?? (synchronizeAcrossDevices
                ? kSecAttrAccessibleAfterFirstUnlock
                : kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
        ]
        let update = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if update == errSecSuccess {
            return
        }
        guard update == errSecItemNotFound else {
            throw SharedKeychainError.unexpectedStatus(update)
        }
        var insertion = query
        attributes.forEach { insertion[$0.key] = $0.value }
        let add = SecItemAdd(insertion as CFDictionary, nil)
        guard add == errSecSuccess else {
            // -34018 is errSecMissingEntitlement: the binary was not signed
            // with the declared keychain access group.
            WalletCustodyLog.custody.error("keychain add failed: OSStatus \(add, privacy: .public)")
            throw SharedKeychainError.unexpectedStatus(add)
        }
    }

    func load(
        service: String,
        account: String,
        synchronizeAcrossDevices: Bool = false
    ) throws -> Data? {
        var query = configuration.query(
            service: service,
            account: account,
            synchronizeAcrossDevices: synchronizeAcrossDevices
        )
        query[kSecMatchLimit] = kSecMatchLimitOne
        query[kSecReturnData] = kCFBooleanTrue
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = result as? Data else {
            WalletCustodyLog.custody.error("keychain read failed: OSStatus \(status, privacy: .public)")
            throw SharedKeychainError.unexpectedStatus(status)
        }
        return data
    }

    func delete(
        service: String,
        account: String,
        synchronizeAcrossDevices: Bool = false
    ) throws {
        let status = SecItemDelete(
            configuration.query(
                service: service,
                account: account,
                synchronizeAcrossDevices: synchronizeAcrossDevices
            ) as CFDictionary
        )
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SharedKeychainError.unexpectedStatus(status)
        }
    }
}

enum AppleCustodyCapability: String, Codable, Equatable {
    case secureEnclaveWrappedMLDSA44
}

enum AppleCustodyError: Error, Equatable {
    case invalidSlot
    case invalidRecoveryKey
    case unsupportedRecord
    case missingSlot
    case revoked
    case rollback
    case userPresenceRequired
    case authenticationCancelled
    case deviceLocked
    case hardwareUnavailable
    case wrongKey
    case invalidKeyMaterial
    case invalidSignature
    case storageFailure
    case cryptographicFailure
}

protocol AppleMLDSA44Engine {
    /// Generates a fresh ML-DSA-44 seed entirely inside the native custody provider.
    func generateSeed() throws -> Data
    func publicKey(seed: inout Data) throws -> Data
    func sign(payload: Data, seed: inout Data) throws -> Data
}

/// Wire-compatible ML-DSA-44 implementation supplied by the same audited Rust library that
/// verifies wallet authorization envelopes. Seeds remain transient and caller-owned.
final class RustAppleMLDSA44Engine: AppleMLDSA44Engine {
    func generateSeed() throws -> Data {
        var seed = Data(count: AppleNativeCustodyProvider.seedLength)
        let status = seed.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(
                kSecRandomDefault,
                bytes.count,
                bytes.bindMemory(to: UInt8.self).baseAddress!
            )
        }
        guard status == errSecSuccess else { throw AppleCustodyError.cryptographicFailure }
        return seed
    }

    func publicKey(seed: inout Data) throws -> Data {
        guard seed.count == AppleNativeCustodyProvider.seedLength else {
            throw AppleCustodyError.invalidKeyMaterial
        }
        var publicKey = Data(count: AppleNativeCustodyProvider.publicKeyLength)
        let code = seed.withUnsafeBytes { seedBytes in
            publicKey.withUnsafeMutableBytes { outputBytes in
                activechain_wallet_mldsa44_public_key(
                    seedBytes.bindMemory(to: UInt8.self).baseAddress,
                    UInt32(seedBytes.count),
                    outputBytes.bindMemory(to: UInt8.self).baseAddress,
                    UInt32(outputBytes.count)
                )
            }
        }
        guard code == ACTIVECHAIN_WALLET_OK else { throw Self.map(code) }
        return publicKey
    }

    func sign(payload: Data, seed: inout Data) throws -> Data {
        guard seed.count == AppleNativeCustodyProvider.seedLength else {
            throw AppleCustodyError.invalidKeyMaterial
        }
        var signature = Data(count: AppleNativeCustodyProvider.signatureLength)
        let code = seed.withUnsafeBytes { seedBytes in
            payload.withUnsafeBytes { payloadBytes in
                signature.withUnsafeMutableBytes { outputBytes in
                    activechain_wallet_mldsa44_sign(
                        seedBytes.bindMemory(to: UInt8.self).baseAddress,
                        UInt32(seedBytes.count),
                        payloadBytes.bindMemory(to: UInt8.self).baseAddress,
                        UInt32(payloadBytes.count),
                        outputBytes.bindMemory(to: UInt8.self).baseAddress,
                        UInt32(outputBytes.count)
                    )
                }
            }
        }
        guard code == ACTIVECHAIN_WALLET_OK else { throw Self.map(code) }
        return signature
    }

    private static func map(_ code: UInt32) -> AppleCustodyError {
        if code == UInt32(ACTIVECHAIN_WALLET_INVALID_SIGNATURE) {
            return .invalidSignature
        }
        if code == UInt32(ACTIVECHAIN_WALLET_MALFORMED)
            || code == UInt32(ACTIVECHAIN_WALLET_NULL_POINTER) {
            return .invalidKeyMaterial
        }
        return .cryptographicFailure
    }
}

protocol AppleCustodyRecordStore {
    func loadCustodyRecord(slotID: String) throws -> Data?
    func saveCustodyRecord(_ data: Data, slotID: String) throws
    func deleteCustodyRecord(slotID: String) throws
}

extension SharedKeychain: AppleCustodyRecordStore {
    private static let custodyService = "dev.activechain.wallet.custody.v1"

    func loadCustodyRecord(slotID: String) throws -> Data? {
        try load(service: Self.custodyService, account: slotID)
    }

    func saveCustodyRecord(_ data: Data, slotID: String) throws {
        try save(
            data,
            service: Self.custodyService,
            account: slotID,
            accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        )
    }

    func deleteCustodyRecord(slotID: String) throws {
        try delete(service: Self.custodyService, account: slotID)
    }
}

protocol AppleHardwareWrapping {
    var capability: AppleCustodyCapability { get }
    func createAndWrap(secret: Data, tag: Data) throws -> Data
    func unwrap(ciphertext: Data, tag: Data, reason: String) throws -> Data
    func deleteWrappingKey(tag: Data) throws
}

/// Uses a user-presence-gated P-256 Secure Enclave key only to wrap the protocol's ML-DSA-44
/// seed. The P-256 key never authorizes an ActiveChain transaction.
final class SecureEnclaveWrappingBackend: AppleHardwareWrapping {
    let capability = AppleCustodyCapability.secureEnclaveWrappedMLDSA44

    func createAndWrap(secret: Data, tag: Data) throws -> Data {
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .userPresence],
            &accessError
        ) else {
            let reason = accessError?.takeRetainedValue().localizedDescription ?? "unspecified"
            WalletCustodyLog.custody.error("access control rejected: \(reason, privacy: .public)")
            throw AppleCustodyError.hardwareUnavailable
        }
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: tag,
                kSecAttrAccessControl: access
            ]
        ]
        var creationError: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &creationError),
              let publicKey = SecKeyCopyPublicKey(privateKey) else {
            let reason = creationError?.takeRetainedValue().localizedDescription ?? "unspecified"
            WalletCustodyLog.custody.error("secure enclave key creation failed: \(reason, privacy: .public)")
            throw AppleCustodyError.hardwareUnavailable
        }
        WalletCustodyLog.custody.notice("secure enclave wrapping key created")
        var encryptionError: Unmanaged<CFError>?
        guard let ciphertext = SecKeyCreateEncryptedData(
            publicKey,
            .eciesEncryptionCofactorVariableIVX963SHA256AESGCM,
            secret as CFData,
            &encryptionError
        ) else {
            try? deleteWrappingKey(tag: tag)
            throw AppleCustodyError.cryptographicFailure
        }
        return ciphertext as Data
    }

    func unwrap(ciphertext: Data, tag: Data, reason: String) throws -> Data {
        let authentication = LAContext()
        authentication.localizedReason = reason
        var query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag: tag,
            kSecReturnRef: kCFBooleanTrue!,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecUseAuthenticationContext: authentication
        ]
#if os(macOS)
        query[kSecUseDataProtectionKeychain] = kCFBooleanTrue
#endif
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let privateKey = item as! SecKey? else {
            throw Self.map(status)
        }
        var decryptionError: Unmanaged<CFError>?
        guard let plaintext = SecKeyCreateDecryptedData(
            privateKey,
            .eciesEncryptionCofactorVariableIVX963SHA256AESGCM,
            ciphertext as CFData,
            &decryptionError
        ) else {
            let code = (decryptionError?.takeRetainedValue() as Error?) as NSError?
            throw Self.map(OSStatus(code?.code ?? Int(errSecAuthFailed)))
        }
        return plaintext as Data
    }

    func deleteWrappingKey(tag: Data) throws {
        var query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag: tag
        ]
#if os(macOS)
        query[kSecUseDataProtectionKeychain] = kCFBooleanTrue
#endif
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Self.map(status)
        }
    }

    private static func map(_ status: OSStatus) -> AppleCustodyError {
        switch status {
        case errSecInteractionNotAllowed: return .deviceLocked
        case errSecUserCanceled: return .authenticationCancelled
        case errSecAuthFailed: return .userPresenceRequired
        case errSecItemNotFound: return .missingSlot
        default: return .cryptographicFailure
        }
    }
}

private struct AppleCustodyRecord: Codable, Equatable {
    static let schemaVersion: UInt16 = 1

    let schema: UInt16
    let slotID: String
    let keyVersion: UInt32
    let finalizedHeight: UInt64
    let publicKey: Data
    let wrappedSeed: Data
    let wrappingTag: Data
    let recoveryEnvelope: Data
    let capability: AppleCustodyCapability
    var revoked: Bool
}

private struct AppleRecoveryEnvelope: Codable, Equatable {
    static let schemaVersion: UInt16 = 1

    let schema: UInt16
    let slotID: String
    let keyVersion: UInt32
    let finalizedHeight: UInt64
    let publicKey: Data
    let sealedSeed: Data

    func authenticatedMetadata() -> Data {
        var bytes = Data("ACTIVECHAIN-APPLE-MLDSA44-RECOVERY-V1".utf8)
        bytes.append(Data(slotID.utf8))
        bytes.append(keyVersion.bigEndianBytes)
        bytes.append(finalizedHeight.bigEndianBytes)
        bytes.append(publicKey)
        return bytes
    }
}

final class AppleNativeCustodyProvider {
    static let publicKeyLength = 1_312
    static let signatureLength = 2_420
    static let seedLength = 32

    private let store: AppleCustodyRecordStore
    private let hardware: AppleHardwareWrapping
    private let engine: AppleMLDSA44Engine
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    init(
        store: AppleCustodyRecordStore,
        hardware: AppleHardwareWrapping,
        engine: AppleMLDSA44Engine
    ) {
        self.store = store
        self.hardware = hardware
        self.engine = engine
    }

    convenience init(store: AppleCustodyRecordStore, hardware: AppleHardwareWrapping) {
        self.init(store: store, hardware: hardware, engine: RustAppleMLDSA44Engine())
    }

    func provision(
        slotID: String,
        keyVersion: UInt32,
        finalizedHeight: UInt64,
        recoveryKey: inout Data
    ) throws -> Data {
        try validate(slotID: slotID)
        guard try store.loadCustodyRecord(slotID: slotID) == nil else {
            throw AppleCustodyError.rollback
        }
        var seed = try engine.generateSeed()
        defer { seed.zeroize() }
        return try install(
            seed: &seed,
            slotID: slotID,
            keyVersion: keyVersion,
            finalizedHeight: finalizedHeight,
            recoveryKey: &recoveryKey,
            replacing: nil
        )
    }

    func sign(
        slotID: String,
        payload: Data,
        minimumVersion: UInt32,
        minimumFinalizedHeight: UInt64,
        reason: String
    ) throws -> Data {
        let record = try load(slotID: slotID)
        guard !record.revoked else { throw AppleCustodyError.revoked }
        guard record.keyVersion >= minimumVersion,
              record.finalizedHeight >= minimumFinalizedHeight else {
            throw AppleCustodyError.rollback
        }
        var seed = try hardware.unwrap(
            ciphertext: record.wrappedSeed,
            tag: record.wrappingTag,
            reason: reason
        )
        defer { seed.zeroize() }
        try validate(seed: &seed, publicKey: record.publicKey)
        let signature = try engine.sign(payload: payload, seed: &seed)
        guard signature.count == Self.signatureLength else {
            throw AppleCustodyError.invalidSignature
        }
        return signature
    }

    func publicKey(slotID: String) throws -> Data {
        let record = try load(slotID: slotID)
        guard !record.revoked else { throw AppleCustodyError.revoked }
        return record.publicKey
    }

    func rotate(
        slotID: String,
        newVersion: UInt32,
        finalizedHeight: UInt64,
        recoveryKey: inout Data
    ) throws -> Data {
        let current = try load(slotID: slotID)
        guard !current.revoked,
              newVersion > current.keyVersion,
              finalizedHeight >= current.finalizedHeight else {
            throw AppleCustodyError.rollback
        }
        var seed = try engine.generateSeed()
        defer { seed.zeroize() }
        return try install(
            seed: &seed,
            slotID: slotID,
            keyVersion: newVersion,
            finalizedHeight: finalizedHeight,
            recoveryKey: &recoveryKey,
            replacing: current
        )
    }

    func revoke(slotID: String) throws {
        var record = try load(slotID: slotID)
        guard !record.revoked else { return }
        record.revoked = true
        do {
            try store.saveCustodyRecord(try encoder.encode(record), slotID: slotID)
        } catch {
            throw AppleCustodyError.storageFailure
        }
        try hardware.deleteWrappingKey(tag: record.wrappingTag)
    }

    func exportRecoveryEnvelope(slotID: String) throws -> Data {
        let record = try load(slotID: slotID)
        guard !record.revoked else { throw AppleCustodyError.revoked }
        return record.recoveryEnvelope
    }

    func recover(
        envelopeBytes: Data,
        expectedPublicKey: Data,
        newVersion: UInt32,
        finalizedHeight: UInt64,
        recoveryKey: inout Data
    ) throws -> Data {
        guard recoveryKey.count == 32 else { throw AppleCustodyError.invalidRecoveryKey }
        let envelope: AppleRecoveryEnvelope
        do {
            envelope = try decoder.decode(AppleRecoveryEnvelope.self, from: envelopeBytes)
        } catch {
            throw AppleCustodyError.unsupportedRecord
        }
        guard envelope.schema == AppleRecoveryEnvelope.schemaVersion else {
            throw AppleCustodyError.unsupportedRecord
        }
        try validate(slotID: envelope.slotID)
        guard envelope.publicKey.constantTimeEquals(expectedPublicKey) else {
            throw AppleCustodyError.wrongKey
        }
        guard newVersion > envelope.keyVersion,
              finalizedHeight >= envelope.finalizedHeight else {
            throw AppleCustodyError.rollback
        }
        let key = SymmetricKey(data: recoveryKey)
        let box: AES.GCM.SealedBox
        do {
            box = try AES.GCM.SealedBox(combined: envelope.sealedSeed)
        } catch {
            throw AppleCustodyError.cryptographicFailure
        }
        var seed: Data
        do {
            seed = try AES.GCM.open(
                box,
                using: key,
                authenticating: envelope.authenticatedMetadata()
            )
        } catch {
            throw AppleCustodyError.cryptographicFailure
        }
        defer { seed.zeroize() }
        try validate(seed: &seed, publicKey: expectedPublicKey)
        let current = try? load(slotID: envelope.slotID)
        if let current, newVersion <= current.keyVersion {
            throw AppleCustodyError.rollback
        }
        return try install(
            seed: &seed,
            slotID: envelope.slotID,
            keyVersion: newVersion,
            finalizedHeight: finalizedHeight,
            recoveryKey: &recoveryKey,
            replacing: current
        )
    }

    private func install(
        seed: inout Data,
        slotID: String,
        keyVersion: UInt32,
        finalizedHeight: UInt64,
        recoveryKey: inout Data,
        replacing current: AppleCustodyRecord?
    ) throws -> Data {
        guard seed.count == Self.seedLength, recoveryKey.count == 32 else {
            throw AppleCustodyError.invalidKeyMaterial
        }
        let publicKey = try engine.publicKey(seed: &seed)
        guard publicKey.count == Self.publicKeyLength else {
            throw AppleCustodyError.invalidKeyMaterial
        }
        let wrappingTag = Data(
            "dev.activechain.wallet.custody.\(slotID).\(keyVersion).\(UUID().uuidString)".utf8
        )
        let wrappedSeed = try hardware.createAndWrap(secret: seed, tag: wrappingTag)
        do {
            let recoveryEnvelope = try sealRecovery(
                seed: seed,
                slotID: slotID,
                keyVersion: keyVersion,
                finalizedHeight: finalizedHeight,
                publicKey: publicKey,
                recoveryKey: recoveryKey
            )
            let record = AppleCustodyRecord(
                schema: AppleCustodyRecord.schemaVersion,
                slotID: slotID,
                keyVersion: keyVersion,
                finalizedHeight: finalizedHeight,
                publicKey: publicKey,
                wrappedSeed: wrappedSeed,
                wrappingTag: wrappingTag,
                recoveryEnvelope: recoveryEnvelope,
                capability: hardware.capability,
                revoked: false
            )
            try store.saveCustodyRecord(try encoder.encode(record), slotID: slotID)
        } catch {
            try? hardware.deleteWrappingKey(tag: wrappingTag)
            if error is AppleCustodyError { throw error }
            throw AppleCustodyError.storageFailure
        }
        if let current {
            try? hardware.deleteWrappingKey(tag: current.wrappingTag)
        }
        return publicKey
    }

    private func load(slotID: String) throws -> AppleCustodyRecord {
        try validate(slotID: slotID)
        let bytes: Data
        do {
            guard let stored = try store.loadCustodyRecord(slotID: slotID) else {
                throw AppleCustodyError.missingSlot
            }
            bytes = stored
        } catch let error as AppleCustodyError {
            throw error
        } catch {
            throw AppleCustodyError.storageFailure
        }
        let record: AppleCustodyRecord
        do {
            record = try decoder.decode(AppleCustodyRecord.self, from: bytes)
        } catch {
            throw AppleCustodyError.unsupportedRecord
        }
        guard record.schema == AppleCustodyRecord.schemaVersion,
              record.slotID == slotID,
              record.capability == hardware.capability else {
            throw AppleCustodyError.unsupportedRecord
        }
        return record
    }

    private func validate(slotID: String) throws {
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
        guard !slotID.isEmpty, slotID.utf8.count <= 64,
              slotID.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
            throw AppleCustodyError.invalidSlot
        }
    }

    private func validate(seed: inout Data, publicKey: Data) throws {
        guard seed.count == Self.seedLength,
              publicKey.count == Self.publicKeyLength,
              try engine.publicKey(seed: &seed).constantTimeEquals(publicKey) else {
            throw AppleCustodyError.wrongKey
        }
    }

    private func sealRecovery(
        seed: Data,
        slotID: String,
        keyVersion: UInt32,
        finalizedHeight: UInt64,
        publicKey: Data,
        recoveryKey: Data
    ) throws -> Data {
        guard recoveryKey.count == 32 else { throw AppleCustodyError.invalidRecoveryKey }
        let envelope = AppleRecoveryEnvelope(
            schema: AppleRecoveryEnvelope.schemaVersion,
            slotID: slotID,
            keyVersion: keyVersion,
            finalizedHeight: finalizedHeight,
            publicKey: publicKey,
            sealedSeed: Data()
        )
        let sealed = try AES.GCM.seal(
            seed,
            using: SymmetricKey(data: recoveryKey),
            authenticating: envelope.authenticatedMetadata()
        )
        guard let combined = sealed.combined else {
            throw AppleCustodyError.cryptographicFailure
        }
        return try encoder.encode(
            AppleRecoveryEnvelope(
                schema: envelope.schema,
                slotID: envelope.slotID,
                keyVersion: envelope.keyVersion,
                finalizedHeight: envelope.finalizedHeight,
                publicKey: envelope.publicKey,
                sealedSeed: combined
            )
        )
    }
}

/// Module visible: any code holding key material should be able to wipe it,
/// not only this file.
extension Data {
    mutating func zeroize() {
        guard !isEmpty else { return }
        resetBytes(in: startIndex..<endIndex)
        removeAll(keepingCapacity: false)
    }

    func constantTimeEquals(_ other: Data) -> Bool {
        guard count == other.count else { return false }
        var difference: UInt8 = 0
        for index in indices {
            difference |= self[index] ^ other[index]
        }
        return difference == 0
    }
}

private extension FixedWidthInteger {
    var bigEndianBytes: Data {
        withUnsafeBytes(of: bigEndian) { Data($0) }
    }
}
