import Crypto
import Foundation
import LocalAuthentication
import Security
import X509

public enum EnclaveKeyError: Error, CustomStringConvertible {
    case secureEnclaveUnavailable
    case accessControl(String)

    public var description: String {
        switch self {
        case .secureEnclaveUnavailable:
            return "this Mac has no Secure Enclave"
        case let .accessControl(msg):
            return "could not build access control: \(msg)"
        }
    }
}

/// What a client key needs on each use.
public enum ClientKeyAccess: String, CaseIterable, Sendable {
    case none
    case userPresence = "user-presence"
    case passcode

    public init(flag: String) throws {
        guard let mode = Self(rawValue: flag) else {
            let modes = Self.allCases.map(\.rawValue).joined(separator: ", ")
            throw UsageError(description: "--access must be one of \(modes), got \"\(flag)\"")
        }
        self = mode
    }

    public var flags: SecAccessControlCreateFlags {
        switch self {
        case .none: return [.privateKeyUsage]
        case .userPresence: return [.privateKeyUsage, .userPresence]
        case .passcode: return [.privateKeyUsage, .devicePasscode]
        }
    }

    public var protection: CFString {
        self == .none ? kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly : kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    }
}

/// A P-256 key that lives in this Mac's Secure Enclave.
///
/// The private key never leaves the enclave. What we store on disk is `dataRepresentation`:
/// a blob wrapped by this device's enclave, useless on any other machine.
///
/// Every signature requires user presence (Touch ID, or the login password as a fallback).
/// `.userPresence` is deliberate: unlike `.biometryCurrentSet`, it survives adding or removing
/// a fingerprint, so enrolling a finger does not destroy the CA. Each signature uses a fresh
/// LAContext, so one approval never covers a second signature.
public enum EnclaveKey {
    public static func create() throws -> SecureEnclave.P256.Signing.PrivateKey {
        guard SecureEnclave.isAvailable else { throw EnclaveKeyError.secureEnclaveUnavailable }
        var err: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .userPresence],
            &err
        ) else {
            throw EnclaveKeyError.accessControl(String(describing: err?.takeRetainedValue()))
        }
        return try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
    }

    public static func createClient(access mode: ClientKeyAccess) throws -> SecureEnclave.P256.Signing.PrivateKey {
        guard SecureEnclave.isAvailable else { throw EnclaveKeyError.secureEnclaveUnavailable }
        var err: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, mode.protection, mode.flags, &err) else {
            throw EnclaveKeyError.accessControl(String(describing: err?.takeRetainedValue()))
        }
        return try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
    }

    /// `reason` is shown only if the key requires user presence.
    public static func loadClient(_ blob: Data, reason: String) throws -> SecureEnclave.P256.Signing.PrivateKey {
        let ctx = LAContext()
        ctx.localizedReason = reason
        return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: ctx)
    }

    /// Loads the wrapped key. `reason` is shown in the Touch ID prompt, so it should say what is being signed.
    public static func load(_ blob: Data, reason: String) throws -> Certificate.PrivateKey {
        let ctx = LAContext()
        ctx.localizedReason = reason
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: ctx)
        return Certificate.PrivateKey(key)
    }
}
