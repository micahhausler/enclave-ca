import Crypto
import Foundation

// Just enough TPM 2.0 wire format (TPM 2.0 Library Part 2) to check a TPM2_Certify attestation
// and build a TPM2_MakeCredential challenge. Only P-256 ECC keys with SHA-256 names are accepted.

public enum TPMError: Error, CustomStringConvertible {
    case malformed(String)
    case unsupported(String)
    case rejected(String)
    case failed(String)

    public var description: String {
        switch self {
        case let .malformed(m): return "malformed TPM structure: \(m)"
        case let .unsupported(m): return "unsupported TPM structure: \(m)"
        case let .rejected(m): return "TPM attestation rejected: \(m)"
        case let .failed(m): return "TPM operation failed: \(m)"
        }
    }
}

struct TPMReader {
    let bytes: [UInt8]
    var pos = 0

    init(_ bytes: [UInt8]) { self.bytes = bytes }

    var atEnd: Bool { pos == bytes.count }

    mutating func take(_ n: Int, _ what: String) throws -> [UInt8] {
        guard n >= 0, bytes.count - pos >= n else { throw TPMError.malformed("truncated \(what)") }
        defer { pos += n }
        return Array(bytes[pos..<pos + n])
    }

    mutating func uint(_ size: Int, _ what: String) throws -> UInt64 {
        try take(size, what).reduce(0) { $0 << 8 | UInt64($1) }
    }

    mutating func u16(_ what: String) throws -> UInt16 { UInt16(try uint(2, what)) }
    mutating func u32(_ what: String) throws -> UInt32 { UInt32(try uint(4, what)) }

    /// A TPM2B: a 16-bit big-endian size, then that many bytes.
    mutating func sized(_ what: String) throws -> [UInt8] {
        try take(Int(try u16(what + " size")), what)
    }

    func expectEnd(_ what: String) throws {
        guard atEnd else { throw TPMError.malformed("\(bytes.count - pos) trailing bytes after \(what)") }
    }
}

func be16(_ v: Int) -> [UInt8] { [UInt8(v >> 8 & 0xFF), UInt8(v & 0xFF)] }
func be32(_ v: UInt32) -> [UInt8] { (0..<4).map { UInt8(v >> (24 - 8 * $0) & 0xFF) } }
func sized(_ b: [UInt8]) -> [UInt8] { be16(b.count) + b }

enum TPMAlg {
    static let null: UInt16 = 0x0010
    static let sha256: UInt16 = 0x000B
    static let ecc: UInt16 = 0x0023
    static let ecdsa: UInt16 = 0x0018
    static let ecdaa: UInt16 = 0x001A
    static let eccNistP256: UInt16 = 0x0003
}

/// TPMA_OBJECT (Part 2 §8.3).
public struct TPMObjectAttributes: OptionSet, Sendable, CustomStringConvertible {
    public let rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }

    public static let fixedTPM = Self(rawValue: 1 << 1)
    public static let fixedParent = Self(rawValue: 1 << 4)
    public static let sensitiveDataOrigin = Self(rawValue: 1 << 5)
    public static let userWithAuth = Self(rawValue: 1 << 6)
    public static let restricted = Self(rawValue: 1 << 16)
    public static let decrypt = Self(rawValue: 1 << 17)
    public static let sign = Self(rawValue: 1 << 18)

    static let names: [(Self, String)] = [
        (.fixedTPM, "fixedTPM"), (.fixedParent, "fixedParent"), (.sensitiveDataOrigin, "sensitiveDataOrigin"),
        (.userWithAuth, "userWithAuth"), (.restricted, "restricted"), (.decrypt, "decrypt"), (.sign, "sign"),
    ]

    public var description: String {
        Self.names.filter { contains($0.0) }.map(\.1).joined(separator: "|")
    }
}

/// A TPMT_PUBLIC for a P-256 ECC key with a SHA-256 name algorithm.
public struct TPMECCPublic: Sendable {
    /// The marshaled TPMT_PUBLIC, exactly as received. The TPM name is computed over these bytes.
    public let encoded: [UInt8]
    public let attributes: TPMObjectAttributes
    /// The signing scheme as (scheme, hash), or nil for TPM_ALG_NULL.
    let scheme: (UInt16, UInt16)?
    public let publicKey: P256.Signing.PublicKey

    /// Parses a TPM2B_PUBLIC (what `tpm2_readpublic -o` and `tpm2_createak -u` write).
    public init(tpm2bPublic bytes: [UInt8]) throws {
        var r = TPMReader(bytes)
        let inner = try r.sized("TPM2B_PUBLIC")
        try r.expectEnd("TPM2B_PUBLIC")
        try self.init(tpmtPublic: inner)
    }

    public init(tpmtPublic bytes: [UInt8]) throws {
        var r = TPMReader(bytes)
        guard try r.u16("type") == TPMAlg.ecc else { throw TPMError.unsupported("key type is not ECC") }
        guard try r.u16("nameAlg") == TPMAlg.sha256 else { throw TPMError.unsupported("name algorithm is not SHA-256") }
        attributes = TPMObjectAttributes(rawValue: try r.u32("objectAttributes"))
        _ = try r.sized("authPolicy")
        // TPMS_ECC_PARMS
        if try r.u16("symmetric.algorithm") != TPMAlg.null {
            _ = try r.take(4, "symmetric keyBits and mode")
        }
        let schemeAlg = try r.u16("scheme")
        if schemeAlg == TPMAlg.ecdaa { throw TPMError.unsupported("ECDAA scheme") }
        scheme = schemeAlg == TPMAlg.null ? nil : (schemeAlg, try r.u16("scheme hash"))
        guard try r.u16("curveID") == TPMAlg.eccNistP256 else { throw TPMError.unsupported("curve is not NIST P-256") }
        if try r.u16("kdf") != TPMAlg.null {
            _ = try r.u16("kdf hash")
        }
        // TPMS_ECC_POINT
        let x = try r.sized("unique.x")
        let y = try r.sized("unique.y")
        try r.expectEnd("TPMT_PUBLIC")
        guard x.count <= 32, y.count <= 32 else { throw TPMError.malformed("ECC point coordinate longer than 32 bytes") }
        let pad = { (c: [UInt8]) in [UInt8](repeating: 0, count: 32 - c.count) + c }
        publicKey = try P256.Signing.PublicKey(x963Representation: [0x04] + pad(x) + pad(y))
        encoded = bytes
    }

    /// The TPM name: nameAlg followed by the SHA-256 of the TPMT_PUBLIC.
    public var name: [UInt8] { be16(Int(TPMAlg.sha256)) + Array(SHA256.hash(data: encoded)) }
}

/// A TPMS_ATTEST of type TPM_ST_ATTEST_CERTIFY (what `tpm2_certify -o` writes).
struct TPMCertifyInfo {
    static let generatedValue: UInt32 = 0xFF54_4347 // "\xffTCG"
    static let attestCertify: UInt16 = 0x8017

    let extraData: [UInt8]
    /// The name of the certified object.
    let name: [UInt8]

    init(_ bytes: [UInt8]) throws {
        var r = TPMReader(bytes)
        guard try r.u32("magic") == Self.generatedValue else { throw TPMError.rejected("attestation magic is not TPM_GENERATED_VALUE") }
        guard try r.u16("type") == Self.attestCertify else { throw TPMError.rejected("attestation is not TPM_ST_ATTEST_CERTIFY") }
        _ = try r.sized("qualifiedSigner")
        extraData = try r.sized("extraData")
        _ = try r.take(8 + 4 + 4 + 1, "clockInfo")
        _ = try r.take(8, "firmwareVersion")
        name = try r.sized("certify.name")
        _ = try r.sized("certify.qualifiedName")
        try r.expectEnd("TPMS_ATTEST")
    }
}
