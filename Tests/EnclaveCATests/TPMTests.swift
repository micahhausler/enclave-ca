import Crypto
import Foundation
import Testing
import X509

@testable import EnclaveCA

// Fixtures/some-host was captured from a swtpm software TPM (Fedora 42, tpm2-tools 5.7, tpm2-openssl)
// with scripts/tpm-attest.sh and `enclave-ca tpm-challenge` / `tpm-enroll`:
//   ek.crt.der             ECC P-256 EK certificate from NV 0x1c0000a, signed by a throwaway CA
//   some-host.tpm.json     completed enrollment (EK cert + AK)
//   some-host.attest.pem   `tpm-attest.sh certify` of some-host's client key
//   some-host.csr          that key's CSR (from tpm2-openssl)
//   other-ak.pub           a second AK from the same TPM

func fixture(_ name: String) throws -> Data {
    let dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Fixtures/some-host")
    return try Data(contentsOf: dir.appendingPathComponent(name))
}

func someHostEnrollment() throws -> TPMEnrollment {
    try JSONDecoder().decode(TPMEnrollment.self, from: fixture("some-host.tpm.json"))
}

func someHostBundle() throws -> TPMAttestationBundle {
    try TPMAttestationBundle(pem: String(decoding: fixture("some-host.attest.pem"), as: UTF8.self))
}

func someHostCSR() throws -> CertificateSigningRequest {
    try parseCSR(pem: String(decoding: fixture("some-host.csr"), as: UTF8.self))
}

/// Marshals a TPMT_PUBLIC for a P-256 key, the way a TPM would.
func tpmtPublic(_ key: P256.Signing.PublicKey, attributes: TPMObjectAttributes, ecdsaScheme: Bool) -> [UInt8] {
    let point = Array(key.x963Representation.dropFirst())
    var b = be16(Int(TPMAlg.ecc)) + be16(Int(TPMAlg.sha256)) + be32(attributes.rawValue) + sized([])
    b += be16(Int(TPMAlg.null)) // symmetric
    b += ecdsaScheme ? be16(Int(TPMAlg.ecdsa)) + be16(Int(TPMAlg.sha256)) : be16(Int(TPMAlg.null))
    b += be16(Int(TPMAlg.eccNistP256)) + be16(Int(TPMAlg.null)) // curve, kdf
    return b + sized(Array(point.prefix(32))) + sized(Array(point.suffix(32)))
}

/// Marshals a TPMS_ATTEST certifying `name`.
func certifyAttest(name: [UInt8]) -> [UInt8] {
    be32(TPMCertifyInfo.generatedValue) + be16(Int(TPMCertifyInfo.attestCertify))
        + sized([0x00, 0x0B] + [UInt8](repeating: 1, count: 32)) // qualifiedSigner
        + sized([0x00, 0xFF, 0x55, 0xAA]) // extraData
        + [UInt8](repeating: 0, count: 17) // clockInfo
        + [UInt8](repeating: 0, count: 8) // firmwareVersion
        + sized(name) + sized(name)
}

func pemBlock(_ label: String, _ bytes: [UInt8]) -> String {
    "-----BEGIN \(label)-----\n\(Data(bytes).base64EncodedString(options: .lineLength64Characters))\n-----END \(label)-----\n"
}

/// A software stand-in for a TPM: an AK and a client key with chosen attributes.
struct FakeTPM {
    let ak = P256.Signing.PrivateKey()
    let key = P256.Signing.PrivateKey()
    var keyAttributes: TPMObjectAttributes = [.fixedTPM, .fixedParent, .sensitiveDataOrigin, .userWithAuth, .sign]

    var enrollment: TPMEnrollment {
        let akPub = tpmtPublic(ak.publicKey, attributes: requiredAKAttributes.union(.userWithAuth), ecdsaScheme: true)
        return TPMEnrollment(commonName: "host", ekCertificate: Data(), attestationKey: Data(sized(akPub)), pendingChallengeSHA256: nil)
    }

    func bundle() throws -> TPMAttestationBundle {
        let keyPub = tpmtPublic(key.publicKey, attributes: keyAttributes, ecdsaScheme: false)
        let attest = certifyAttest(name: try TPMECCPublic(tpmtPublic: keyPub).name)
        let sig = try ak.signature(for: attest).derRepresentation
        return try TPMAttestationBundle(pem: pemBlock("TPM2B PUBLIC", sized(keyPub)) + pemBlock("TPMS ATTEST", attest) + pemBlock("TPM ECDSA SIGNATURE", Array(sig)))
    }

    func csr() throws -> CertificateSigningRequest {
        try makeCSR(key: Certificate.PrivateKey(key), commonName: "host")
    }
}

// MARK: - Software TPM fixtures

@Test func ekCertificatePublicKey() throws {
    // `openssl x509 -pubkey | openssl pkey -pubin -outform DER` on the same certificate.
    let spki = "3059301306072a8648ce3d020106082a8648ce3d03010703420004f906f637a1d7a9adeaf7fd59f90841c888d95356d344970a407d374d7666e5df457c0f9cdb28832c67901332c0de9404aea8c9c1875ac29a14ae65d2c8f16819"
    let key = try ekPublicKey(certificateDER: Array(fixture("ek.crt.der")))
    #expect(hex(key.derRepresentation) == spki)
    _ = try Certificate(derEncoded: Array(fixture("ek.crt.der"))) // strict DER, unlike the explicit-defaults case below
}

/// Minimal DER TLV, with the one-byte and two-byte length forms.
func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
    let n = content.count
    return [tag] + (n < 128 ? [UInt8(n)] : [0x81, UInt8(n)]) + content
}

@Test func ekCertificateWithExplicitDefaultsPublicKey() throws {
    // Intel PTT EK certificates encode `critical FALSE` and `cA FALSE` explicitly, which DER forbids.
    // Built by hand around a synthetic key; the signature is never checked.
    let ek = P256.KeyAgreement.PrivateKey().publicKey
    let ecdsaSHA256 = tlv(0x30, tlv(0x06, [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]))
    let emptyName = tlv(0x30, [])
    let time = tlv(0x17, Array("250101000000Z".utf8)) + tlv(0x17, Array("491231235959Z".utf8))
    let basicConstraints = tlv(0x30,
        tlv(0x06, [0x55, 0x1D, 0x13]) + tlv(0x01, [0x00]) + tlv(0x04, tlv(0x30, tlv(0x01, [0x00]))))
    let tbs = tlv(0x30,
        tlv(0xA0, tlv(0x02, [0x02])) + tlv(0x02, [0x01, 0x02, 0x03]) + ecdsaSHA256 + emptyName
        + tlv(0x30, time) + emptyName + Array(ek.derRepresentation)
        + tlv(0xA3, tlv(0x30, basicConstraints)))
    let der = tlv(0x30, tbs + ecdsaSHA256 + tlv(0x03, [0x00, 0x30, 0x00]))

    #expect(throws: (any Error).self) { try Certificate(derEncoded: der) }
    #expect(hex(try ekPublicKey(certificateDER: der).derRepresentation) == hex(ek.derRepresentation))
}

@Test func someHostAttestationVerifies() throws {
    try verifyTPMAttestation(someHostBundle(), enrollment: someHostEnrollment(), csr: someHostCSR(), commonName: "some-host")
}

@Test func someHostKeyAttributes() throws {
    let key = try TPMECCPublic(tpm2bPublic: someHostBundle().keyPublic)
    #expect(key.attributes.isSuperset(of: [.fixedTPM, .fixedParent, .sensitiveDataOrigin, .sign]))
    #expect(Certificate.PublicKey(key.publicKey) == (try someHostCSR()).publicKey)
}

@Test func tamperedAttestationRejected() throws {
    let b = try someHostBundle()
    for i in [0, 8, b.attest.count - 1] {
        var attest = b.attest
        attest[i] ^= 0x01
        let tampered = try TPMAttestationBundle(pem: pemBlock("TPM2B PUBLIC", b.keyPublic) + pemBlock("TPMS ATTEST", attest) + pemBlock("TPM ECDSA SIGNATURE", b.signature))
        #expect(throws: TPMError.self) { try verifyTPMAttestation(tampered, enrollment: someHostEnrollment(), csr: someHostCSR(), commonName: "some-host") }
    }
}

@Test func otherAKRejected() throws {
    var e = try someHostEnrollment()
    e.attestationKey = try fixture("other-ak.pub")
    #expect(throws: TPMError.self) { try verifyTPMAttestation(someHostBundle(), enrollment: e, csr: someHostCSR(), commonName: "some-host") }
}

@Test func differentCSRKeyRejected() throws {
    let csr = try makeCSR(key: softwareKey(), commonName: "some-host")
    #expect(throws: TPMError.self) { try verifyTPMAttestation(someHostBundle(), enrollment: someHostEnrollment(), csr: csr, commonName: "some-host") }
}

@Test func wrongNameOrPendingEnrollmentRejected() throws {
    #expect(throws: TPMError.self) { try verifyTPMAttestation(someHostBundle(), enrollment: someHostEnrollment(), csr: someHostCSR(), commonName: "other-host") }
    var pending = try someHostEnrollment()
    pending.pendingChallengeSHA256 = String(repeating: "0", count: 64)
    #expect(throws: TPMError.self) { try verifyTPMAttestation(someHostBundle(), enrollment: pending, csr: someHostCSR(), commonName: "some-host") }
}

// MARK: - Synthetic

@Test func fakeTPMPassesWithRequiredAttributes() throws {
    let t = FakeTPM()
    var e = t.enrollment
    e.commonName = "host"
    try verifyTPMAttestation(t.bundle(), enrollment: e, csr: t.csr(), commonName: "host")
}

@Test func exportableKeyRejected() throws {
    for missing: TPMObjectAttributes in [.fixedTPM, .fixedParent, .sensitiveDataOrigin, .sign] {
        var t = FakeTPM()
        t.keyAttributes.remove(missing)
        #expect(throws: TPMError.self) { try verifyTPMAttestation(t.bundle(), enrollment: t.enrollment, csr: t.csr(), commonName: "host") }
    }
}

@Test func unrestrictedAKRejected() throws {
    let ak = P256.Signing.PrivateKey()
    for attrs: TPMObjectAttributes in [[.fixedTPM, .fixedParent, .sensitiveDataOrigin, .sign], requiredAKAttributes.union(.decrypt)] {
        let pub = sized(tpmtPublic(ak.publicKey, attributes: attrs, ecdsaScheme: true))
        #expect(throws: TPMError.self) { try checkAttestationKey(TPMECCPublic(tpm2bPublic: pub)) }
    }
}

@Test func bundleRejectsExtraOrMissingBlocks() throws {
    let pem = String(decoding: try fixture("some-host.attest.pem"), as: UTF8.self)
    #expect(throws: TPMError.self) { try TPMAttestationBundle(pem: pem + pemBlock("CERTIFICATE", [1])) }
    #expect(throws: TPMError.self) { try TPMAttestationBundle(pem: pem + pemBlock("TPMS ATTEST", [1])) }
    #expect(throws: TPMError.self) { try TPMAttestationBundle(pem: pemBlock("TPMS ATTEST", [1])) }
}

// MARK: - MakeCredential

/// TPM2_ActivateCredential in software, to round-trip makeCredential.
func activateCredential(ek: P256.KeyAgreement.PrivateKey, objectName: [UInt8], blob: [UInt8]) throws -> [UInt8] {
    var r = TPMReader(blob)
    guard try r.u32("magic") == credentialFileMagic, try r.u32("version") == credentialFileVersion else { throw TPMError.malformed("header") }
    var id = TPMReader(try r.sized("idObject"))
    let outerHMAC = try id.sized("hmac")
    let encIdentity = try id.take(id.bytes.count - id.pos, "encIdentity")
    var point = TPMReader(try r.sized("encSecret"))
    let (ephX, ephY) = (try point.sized("x"), try point.sized("y"))
    try r.expectEnd("blob")

    let eph = try P256.KeyAgreement.PublicKey(x963Representation: [0x04] + ephX + ephY)
    let z = try ek.sharedSecretFromKeyAgreement(with: eph).withUnsafeBytes { Array($0) }
    let ekX = Array(ek.publicKey.x963Representation.dropFirst().prefix(32))
    let seed = kdfe(z: z, label: "IDENTITY", partyU: ephX, partyV: ekX, bits: 256)
    let hmacKey = kdfa(key: seed, label: "INTEGRITY", contextU: [], contextV: [], bits: 256)
    var mac = HMAC<SHA256>(key: SymmetricKey(data: hmacKey))
    mac.update(data: encIdentity)
    mac.update(data: objectName)
    guard Array(mac.finalize()) == outerHMAC else { throw TPMError.rejected("integrity check failed") }
    let symKey = kdfa(key: seed, label: "STORAGE", contextU: objectName, contextV: [], bits: 128)
    var plain = TPMReader(try aes128CFB(encrypt: false, key: symKey, encIdentity))
    let secret = try plain.sized("credential")
    try plain.expectEnd("credential")
    return secret
}

@Test func makeCredentialRoundTrip() throws {
    let ek = P256.KeyAgreement.PrivateKey()
    let name = [0x00, 0x0B] + [UInt8](repeating: 7, count: 32)
    let secret = (0..<32).map { UInt8($0) }
    let blob = try makeCredential(ek: ek.publicKey, objectName: name, secret: secret)
    #expect(blob.count == 148) // same size tpm2_makecredential produced for a P-256 EK
    #expect(try activateCredential(ek: ek, objectName: name, blob: blob) == secret)

    var otherName = name
    otherName[5] ^= 1
    #expect(throws: TPMError.self) { try activateCredential(ek: ek, objectName: otherName, blob: blob) }
    #expect(throws: TPMError.self) { try activateCredential(ek: P256.KeyAgreement.PrivateKey(), objectName: name, blob: blob) }
}

@Test func enrollmentChallengeAndComplete() throws {
    // The challenge path with the real EK certificate and AK; completion is checked by hash only.
    let e = try someHostEnrollment()
    let (pending, blob) = try TPMEnrollment.challenge(
        commonName: "some-host", ekCertificateDER: Array(e.ekCertificate), attestationKeyTPM2BPublic: Array(e.attestationKey)
    )
    #expect(!pending.isEnrolled && blob.count == 148)
    #expect(throws: TPMError.self) { try pending.completing(withActivatedSecret: [UInt8](repeating: 0, count: 32)) }
    #expect(throws: TPMError.self) { try e.completing(withActivatedSecret: []) }
}

// MARK: - Issuance

@Test func leafCarriesAttestedOU() throws {
    let caKey = softwareKey()
    let root = try makeRoot(key: caKey, commonName: "Test Root", days: 3650, now: now)
    let leaf = try signLeaf(csr: someHostCSR(), caCert: root, caKey: caKey, commonName: "some-host", days: 365, organizationalUnit: tpmAttestedOU, now: now)
    let rdns = leaf.subject.map { $0.description }
    #expect(rdns == ["OU=tpm-ek-pinned", "CN=some-host"])
    let plain = try signLeaf(csr: someHostCSR(), caCert: root, caKey: caKey, commonName: "some-host", days: 365, now: now)
    #expect(plain.subject.description == "CN=some-host")
}

@Test func publicAreaMustMatchCertifiedName() throws {
    // some-host's attestation, with the public area swapped for a software key that has the right
    // attributes and a matching CSR. Only the certified-name check stands between this and an OU.
    let b = try someHostBundle()
    let impostor = P256.Signing.PrivateKey()
    let pub = tpmtPublic(impostor.publicKey, attributes: [.fixedTPM, .fixedParent, .sensitiveDataOrigin, .userWithAuth, .sign], ecdsaScheme: false)
    let swapped = try TPMAttestationBundle(pem: pemBlock("TPM2B PUBLIC", sized(pub)) + pemBlock("TPMS ATTEST", b.attest) + pemBlock("TPM ECDSA SIGNATURE", b.signature))
    let csr = try makeCSR(key: Certificate.PrivateKey(impostor), commonName: "some-host")
    #expect(throws: TPMError.self) { try verifyTPMAttestation(swapped, enrollment: someHostEnrollment(), csr: csr, commonName: "some-host") }
}
