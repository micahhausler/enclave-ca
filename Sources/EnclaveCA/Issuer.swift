import Crypto
import Foundation
import SwiftASN1
import X509

public enum IssuerError: Error, CustomStringConvertible {
    case csrSignatureInvalid
    case csrSubjectMismatch(expected: String, got: String)
    case caKeyMismatch
    case caMissingSubjectKeyIdentifier
    case leafOutlivesCA(leafNotAfter: Date, caNotAfter: Date)
    case nonPositiveDays(Int)

    public var description: String {
        switch self {
        case .csrSignatureInvalid:
            return "CSR signature does not verify against its own public key"
        case let .csrSubjectMismatch(expected, got):
            return "CSR subject is \"\(got)\", expected \"\(expected)\"; refusing to sign a CSR for a different name"
        case .caKeyMismatch:
            return "CA key does not match the CA certificate's public key"
        case .caMissingSubjectKeyIdentifier:
            return "CA certificate has no Subject Key Identifier"
        case let .leafOutlivesCA(leaf, ca):
            return "leaf would expire \(leaf) but the CA expires \(ca); shorten --days or rotate the CA"
        case let .nonPositiveDays(d):
            return "--days must be positive, got \(d)"
        }
    }
}

/// Backdate notBefore slightly so a client clock that runs a little behind still accepts a fresh cert.
let clockSkew: TimeInterval = 60

func validity(now: Date, days: Int) throws -> (Date, Date) {
    guard days > 0 else { throw IssuerError.nonPositiveDays(days) }
    return (now.addingTimeInterval(-clockSkew), now.addingTimeInterval(TimeInterval(days) * 86400))
}

/// Builds a self-signed root: CA:TRUE with pathlen 0 (it can sign leaves, not intermediates),
/// keyCertSign + cRLSign only.
public func makeRoot(
    key: Certificate.PrivateKey,
    commonName: String,
    days: Int,
    now: Date = Date()
) throws -> Certificate {
    let (notBefore, notAfter) = try validity(now: now, days: days)
    let name = try DistinguishedName { CommonName(commonName) }
    let extensions = try Certificate.Extensions {
        Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0))
        Critical(KeyUsage(keyCertSign: true, cRLSign: true))
        SubjectKeyIdentifier(hash: key.publicKey)
    }
    return try Certificate(
        version: .v3,
        serialNumber: Certificate.SerialNumber(),
        publicKey: key.publicKey,
        notValidBefore: notBefore,
        notValidAfter: notAfter,
        issuer: name,
        subject: name,
        signatureAlgorithm: .ecdsaWithSHA256,
        extensions: extensions,
        issuerPrivateKey: key
    )
}

/// Signs a client-auth leaf for `commonName`.
///
/// The CA sets every field. From the CSR it takes only the public key, after checking that the
/// CSR's self-signature verifies and its subject is exactly `CN=<commonName>`. Requested
/// extensions in the CSR are ignored.
///
/// `organizationalUnit` is added to the leaf's subject (never taken from the CSR). Pass
/// `tpmAttestedOU` only after `verifyTPMAttestation` succeeded for this CSR.
public func signLeaf(
    csr: CertificateSigningRequest,
    caCert: Certificate,
    caKey: Certificate.PrivateKey,
    commonName: String,
    days: Int,
    organizationalUnit: String? = nil,
    now: Date = Date()
) throws -> Certificate {
    guard csr.publicKey.isValidSignature(csr.signature, for: csr) else {
        throw IssuerError.csrSignatureInvalid
    }
    let expected = "CN=\(commonName)"
    guard csr.subject.description == expected else {
        throw IssuerError.csrSubjectMismatch(expected: expected, got: csr.subject.description)
    }
    guard caCert.publicKey == caKey.publicKey else { throw IssuerError.caKeyMismatch }
    guard let caSKI = try caCert.extensions.subjectKeyIdentifier else {
        throw IssuerError.caMissingSubjectKeyIdentifier
    }

    let (notBefore, notAfter) = try validity(now: now, days: days)
    guard notAfter <= caCert.notValidAfter else {
        throw IssuerError.leafOutlivesCA(leafNotAfter: notAfter, caNotAfter: caCert.notValidAfter)
    }

    let subject = try DistinguishedName {
        if let organizationalUnit { OrganizationalUnitName(organizationalUnit) }
        CommonName(commonName)
    }
    let extensions = try Certificate.Extensions {
        Critical(BasicConstraints.notCertificateAuthority)
        Critical(KeyUsage(digitalSignature: true))
        try ExtendedKeyUsage([.clientAuth])
        SubjectKeyIdentifier(hash: csr.publicKey)
        AuthorityKeyIdentifier(keyIdentifier: caSKI.keyIdentifier)
    }
    return try Certificate(
        version: .v3,
        serialNumber: Certificate.SerialNumber(),
        publicKey: csr.publicKey,
        notValidBefore: notBefore,
        notValidAfter: notAfter,
        issuer: caCert.subject,
        subject: subject,
        signatureAlgorithm: .ecdsaWithSHA256,
        extensions: extensions,
        issuerPrivateKey: caKey
    )
}

/// A CSR for `CN=<commonName>`, self-signed by `key`.
public func makeCSR(key: Certificate.PrivateKey, commonName: String) throws -> CertificateSigningRequest {
    try CertificateSigningRequest(
        version: .v1,
        subject: DistinguishedName { CommonName(commonName) },
        privateKey: key,
        attributes: CertificateSigningRequest.Attributes(),
        signatureAlgorithm: .ecdsaWithSHA256
    )
}

/// SHA-256 over the DER encoding, as colon-separated uppercase hex (the format `openssl x509 -fingerprint -sha256` prints).
public func fingerprint(_ cert: Certificate) throws -> String {
    var serializer = DER.Serializer()
    try serializer.serialize(cert)
    return SHA256.hash(data: serializer.serializedBytes)
        .map { String(format: "%02X", $0) }
        .joined(separator: ":")
}
