import Foundation
import Security

enum SharedKeychainError: Error, Equatable {
    case invalidAccessGroup
    case unexpectedStatus(OSStatus)
}

struct SharedKeychainConfiguration {
    static let infoKey = "ActiveChainKeychainAccessGroup"
    static let expectedSuffix = ".dev.activechain.wallet.shared"

    let accessGroup: String

    init(accessGroup: String) throws {
        guard accessGroup.hasSuffix(Self.expectedSuffix),
              accessGroup.count > Self.expectedSuffix.count else {
            throw SharedKeychainError.invalidAccessGroup
        }
        self.accessGroup = accessGroup
    }

    static func application(bundle: Bundle = .main) throws -> Self {
        guard let group = bundle.object(forInfoDictionaryKey: infoKey) as? String else {
            throw SharedKeychainError.invalidAccessGroup
        }
        return try Self(accessGroup: group)
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
            kSecAttrAccessGroup: accessGroup,
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
        synchronizeAcrossDevices: Bool = false
    ) throws {
        let query = configuration.query(
            service: service,
            account: account,
            synchronizeAcrossDevices: synchronizeAcrossDevices
        )
        let attributes: [CFString: Any] = [
            kSecValueData: data,
            kSecAttrAccessible: synchronizeAcrossDevices
                ? kSecAttrAccessibleAfterFirstUnlock
                : kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
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
