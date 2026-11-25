import Crypto
import Foundation
import SwiftASN1
import Testing
import X509

@testable import EnclaveCA

// These use software P-256 keys so they run without a Secure Enclave or Touch ID.
// The signing code path is the same: both are Certificate.PrivateKey.

let now = Date(timeIntervalSince1970: 1_800_000_000)

func softwareKey() -> Certificate.PrivateKey {
    Certificate.PrivateKey(P256.Signing.PrivateKey())
}

func makeCSR(cn: String, key: Certificate.PrivateKey = softwareKey()) throws -> CertificateSigningRequest {
    try CertificateSigningRequest(
        version: .v1,
        subject: DistinguishedName { CommonName(cn) },
        privateKey: key,
        attributes: CertificateSigningRequest.Attributes(),
        signatureAlgorithm: .ecdsaWithSHA256
    )
}

@Test func rootIsPathLenZeroCA() throws {
    let key = softwareKey()
    let root = try makeRoot(key: key, commonName: "Test Root", days: 3650, now: now)

    #expect(root.subject.description == "CN=Test Root")
    #expect(root.issuer == root.subject)
    #expect(root.publicKey.isValidSignature(root.signature, for: root))

    let bc = try #require(try root.extensions.basicConstraints)
    #expect(bc == .isCertificateAuthority(maxPathLength: 0))
    #expect(root.extensions[oid: .X509ExtensionID.basicConstraints]?.critical == true)

    let ku = try #require(try root.extensions.keyUsage)
    #expect(ku == KeyUsage(keyCertSign: true, cRLSign: true))
    #expect(root.extensions[oid: .X509ExtensionID.keyUsage]?.critical == true)

    #expect(try root.extensions.subjectKeyIdentifier != nil)
    #expect(root.notValidAfter == now.addingTimeInterval(3650 * 86400))
}

@Test func leafHasClientAuthProfile() throws {
    let caKey = softwareKey()
    let root = try makeRoot(key: caKey, commonName: "Test Root", days: 3650, now: now)
    let leafKey = softwareKey()
    let csr = try makeCSR(cn: "some-host", key: leafKey)

    let leaf = try signLeaf(csr: csr, caCert: root, caKey: caKey, commonName: "some-host", days: 365, now: now)

    #expect(leaf.subject.description == "CN=some-host")
    #expect(leaf.issuer == root.subject)
    #expect(leaf.publicKey == leafKey.publicKey)
    #expect(root.publicKey.isValidSignature(leaf.signature, for: leaf))
    #expect(leaf.notValidAfter == now.addingTimeInterval(365 * 86400))
    #expect(leaf.notValidBefore < now)

    #expect(try leaf.extensions.basicConstraints == .notCertificateAuthority)
    #expect(leaf.extensions[oid: .X509ExtensionID.basicConstraints]?.critical == true)
    #expect(try leaf.extensions.keyUsage == KeyUsage(digitalSignature: true))
    #expect(leaf.extensions[oid: .X509ExtensionID.keyUsage]?.critical == true)
    #expect(try leaf.extensions.extendedKeyUsage == ExtendedKeyUsage([.clientAuth]))

    let aki = try #require(try leaf.extensions.authorityKeyIdentifier)
    let caSKI = try #require(try root.extensions.subjectKeyIdentifier)
    #expect(aki.keyIdentifier == caSKI.keyIdentifier)

    // Exactly these five extensions, nothing carried over from the CSR.
    #expect(Array(leaf.extensions).count == 5)
}

@Test func serialsAreUnique() throws {
    let caKey = softwareKey()
    let root = try makeRoot(key: caKey, commonName: "Test Root", days: 3650, now: now)
    let csr = try makeCSR(cn: "some-host")
    let a = try signLeaf(csr: csr, caCert: root, caKey: caKey, commonName: "some-host", days: 365, now: now)
    let b = try signLeaf(csr: csr, caCert: root, caKey: caKey, commonName: "some-host", days: 365, now: now)
    #expect(a.serialNumber != b.serialNumber)
}

@Test func rejectsCSRForDifferentName() throws {
    let caKey = softwareKey()
    let root = try makeRoot(key: caKey, commonName: "Test Root", days: 3650, now: now)
    let csr = try makeCSR(cn: "other-host")
    #expect(throws: IssuerError.self) {
        try signLeaf(csr: csr, caCert: root, caKey: caKey, commonName: "some-host", days: 365, now: now)
    }
}

func makeCSR(subject: DistinguishedName, key: Certificate.PrivateKey = softwareKey()) throws -> CertificateSigningRequest {
    try CertificateSigningRequest(
        version: .v1,
        subject: subject,
        privateKey: key,
        attributes: CertificateSigningRequest.Attributes(),
        signatureAlgorithm: .ecdsaWithSHA256
    )
}

func expectSubjectRefused(_ subject: DistinguishedName, commonName: String) throws {
    let caKey = softwareKey()
    let root = try makeRoot(key: caKey, commonName: "Test Root", days: 3650, now: now)
    let csr = try makeCSR(subject: subject)
    #expect {
        try signLeaf(csr: csr, caCert: root, caKey: caKey, commonName: commonName, days: 365, now: now)
    } throws: { error in
        if case IssuerError.csrSubjectMismatch = error { return true }
        return false
    }
}

@Test func rejectsCSRWithExtraRDN() throws {
    let subject = try DistinguishedName {
        OrganizationalUnitName("x")
        CommonName("a")
    }
    #expect(subject.description == "CN=a,OU=x")
    try expectSubjectRefused(subject, commonName: "a,OU=x")
    try expectSubjectRefused(subject, commonName: "a")
}

@Test func rejectsCSRWithMultiValuedRDN() throws {
    let rdn = RelativeDistinguishedName([
        .init(type: .RDNAttributeType.commonName, utf8String: "a"),
        .init(type: .RDNAttributeType.organizationalUnitName, utf8String: "x"),
    ])
    let subject = DistinguishedName([rdn])
    #expect(subject.description == "CN=a+OU=x")
    try expectSubjectRefused(subject, commonName: "a+OU=x")
    try expectSubjectRefused(subject, commonName: "a")
}

@Test func rejectsCSRWithEmptySubject() throws {
    try expectSubjectRefused(DistinguishedName(), commonName: "")
}

@Test func rejectsCSRWithNonCommonNameAttribute() throws {
    let subject = DistinguishedName([
        RelativeDistinguishedName(.init(type: .RDNAttributeType.organizationalUnitName, utf8String: "a")),
    ])
    try expectSubjectRefused(subject, commonName: "a")
}

@Test func acceptsPrintableStringCommonName() throws {
    let caKey = softwareKey()
    let root = try makeRoot(key: caKey, commonName: "Test Root", days: 3650, now: now)
    let subject = DistinguishedName([
        RelativeDistinguishedName(try .init(type: .RDNAttributeType.commonName, printableString: "some-host")),
    ])
    let csr = try makeCSR(subject: subject)
    var s = DER.Serializer()
    try s.serialize(csr)
    let parsed = try CertificateSigningRequest(derEncoded: s.serializedBytes)
    let value = try #require(parsed.subject.first?.first?.value)
    #expect(value == (try RelativeDistinguishedName.Attribute.Value(printableString: "some-host")))
    #expect(value != RelativeDistinguishedName.Attribute.Value(utf8String: "some-host"))
    let leaf = try signLeaf(csr: parsed, caCert: root, caKey: caKey, commonName: "some-host", days: 365, now: now)
    #expect(leaf.subject.description == "CN=some-host")
}

@Test func rejectsWrongCAKey() throws {
    let root = try makeRoot(key: softwareKey(), commonName: "Test Root", days: 3650, now: now)
    let csr = try makeCSR(cn: "some-host")
    #expect(throws: IssuerError.self) {
        try signLeaf(csr: csr, caCert: root, caKey: softwareKey(), commonName: "some-host", days: 365, now: now)
    }
}

@Test func rejectsLeafOutlivingCA() throws {
    let caKey = softwareKey()
    let root = try makeRoot(key: caKey, commonName: "Test Root", days: 30, now: now)
    let csr = try makeCSR(cn: "some-host")
    #expect(throws: IssuerError.self) {
        try signLeaf(csr: csr, caCert: root, caKey: caKey, commonName: "some-host", days: 365, now: now)
    }
}

@Test func rejectsNonPositiveDays() throws {
    #expect(throws: IssuerError.self) {
        try makeRoot(key: softwareKey(), commonName: "Test Root", days: 0, now: now)
    }
}

@Test func rejectsTamperedCSR() throws {
    let caKey = softwareKey()
    let root = try makeRoot(key: caKey, commonName: "Test Root", days: 3650, now: now)
    // Signed by one key, claiming another: the self-signature cannot verify.
    let signed = try makeCSR(cn: "some-host")
    let forged = try CertificateSigningRequest(
        version: signed.version,
        subject: signed.subject,
        publicKey: softwareKey().publicKey,
        attributes: signed.attributes,
        signatureAlgorithm: signed.signatureAlgorithm,
        signature: signed.signature
    )
    #expect(throws: IssuerError.self) {
        try signLeaf(csr: forged, caCert: root, caKey: caKey, commonName: "some-host", days: 365, now: now)
    }
}

// A CSR as tpm2-openssl 1.3.0 writes it: ecdsa-with-SHA256 followed by an explicit NULL.
func withNullParameters(_ csr: CertificateSigningRequest) throws -> [UInt8] {
    var s = DER.Serializer()
    try s.serialize(csr)
    let root = try DER.parse(s.serializedBytes)
    guard case let .constructed(top) = root.content else { fatalError() }
    let parts = Array(top)
    guard case let .constructed(algParts) = parts[1].content else { fatalError() }
    let oidNode = Array(algParts)[0]
    var out = DER.Serializer()
    try out.appendConstructedNode(identifier: .sequence) { o in
        o.serialize(parts[0])
        try o.appendConstructedNode(identifier: .sequence) { o in
            o.serialize(oidNode)
            try o.serialize(ASN1Null())
        }
        o.serialize(parts[2])
    }
    return out.serializedBytes
}

func pem(_ der: [UInt8]) -> String {
    PEMDocument(type: "CERTIFICATE REQUEST", derBytes: der).pemString
}

@Test func acceptsECDSANullParameters() throws {
    let caKey = softwareKey()
    let root = try makeRoot(key: caKey, commonName: "Test Root", days: 3650, now: now)
    let leafKey = softwareKey()
    let der = try withNullParameters(makeCSR(cn: "some-host", key: leafKey))

    #expect(throws: (any Error).self) { try CertificateSigningRequest(derEncoded: der) }
    let csr = try parseCSR(pem: pem(der))
    let leaf = try signLeaf(csr: csr, caCert: root, caKey: caKey, commonName: "some-host", days: 365, now: now)
    #expect(leaf.publicKey == leafKey.publicKey)
}

@Test func nullParameterRewriteStillVerifiesSignature() throws {
    let caKey = softwareKey()
    let root = try makeRoot(key: caKey, commonName: "Test Root", days: 3650, now: now)
    let signed = try makeCSR(cn: "some-host")
    let forged = try CertificateSigningRequest(
        version: signed.version, subject: signed.subject, publicKey: softwareKey().publicKey,
        attributes: signed.attributes, signatureAlgorithm: signed.signatureAlgorithm, signature: signed.signature
    )
    let csr = try parseCSR(pem: pem(withNullParameters(forged)))
    #expect(throws: IssuerError.self) {
        try signLeaf(csr: csr, caCert: root, caKey: caKey, commonName: "some-host", days: 365, now: now)
    }
}

@Test func wellFormedCSRPassesThroughUnchanged() throws {
    let csr = try makeCSR(cn: "some-host")
    var s = DER.Serializer()
    try s.serialize(csr)
    #expect(try stripECDSANullParameters(s.serializedBytes) == s.serializedBytes)
}
