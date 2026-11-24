import Foundation
import Security
import X509

public protocol CredentialStore {
    func read(_ account: String) throws -> Data?
    func write(_ account: String, _ data: Data) throws
}

/// Login keychain; the data-protection keychain needs an entitlement an ad-hoc build lacks (-34018).
public struct KeychainCredentialStore: CredentialStore {
    public static let service = "enclave-ca credential-process"

    public struct Failure: Error, CustomStringConvertible {
        public let status: OSStatus
        public var description: String {
            "keychain: \(SecCopyErrorMessageString(status, nil).map { $0 as String } ?? "OSStatus \(status)")"
        }
    }

    public init() {}

    func query(_ account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: account,
        ]
    }

    public func read(_ account: String) throws -> Data? {
        var q = query(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw Failure(status: status) }
        return out as? Data
    }

    public func write(_ account: String, _ data: Data) throws {
        let q = query(account)
        var status = SecItemUpdate(q as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var add = q
            add[kSecValueData as String] = data
            add[kSecAttrLabel as String] = Self.service
            status = SecItemAdd(add as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw Failure(status: status) }
    }
}

/// Process-credentials JSON, reused until `refreshMargin` before its Expiration.
public struct CredentialCache {
    /// botocore's mandatory refresh window.
    public static let refreshMargin: TimeInterval = 10 * 60

    public var store: any CredentialStore
    public var now: () -> Date

    public init(store: any CredentialStore = KeychainCredentialStore(), now: @escaping () -> Date = Date.init) {
        self.store = store
        self.now = now
    }

    public static func account(keyBlob: Data, certificate: Certificate, params: RolesAnywhere.SessionParams) throws -> String {
        let inputs: [String: Any] = [
            "v": 1,
            "key": hexSHA256(keyBlob),
            "certificate": hexSHA256(Data(try derBytes(certificate))),
            "trustAnchorArn": params.trustAnchorArn,
            "profileArn": params.profileArn,
            "roleArn": params.roleArn,
            "durationSeconds": params.durationSeconds,
            "roleSessionName": params.roleSessionName ?? NSNull(),
        ]
        return hexSHA256(try JSONSerialization.data(withJSONObject: inputs, options: [.sortedKeys]))
    }

    public static func expiration(_ credentials: Data) -> Date? {
        guard let obj = try? JSONSerialization.jsonObject(with: credentials) as? [String: Any],
              let s = obj["Expiration"] as? String
        else { return nil }
        let f = ISO8601DateFormatter()
        if let d = f.date(from: s) { return d }
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f.date(from: s)
    }

    public func isFresh(_ credentials: Data) -> Bool {
        guard let exp = Self.expiration(credentials) else { return false }
        return exp.timeIntervalSince(now()) > Self.refreshMargin
    }

    public func lookup(_ account: String) throws -> Data? {
        guard let data = try store.read(account), isFresh(data) else { return nil }
        return data
    }

    /// Returns false when the credentials are too close to expiry to be worth keeping.
    @discardableResult
    public func save(_ account: String, _ credentials: Data) throws -> Bool {
        guard isFresh(credentials) else { return false }
        try store.write(account, credentials)
        return true
    }
}
