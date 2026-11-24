import Crypto
import Foundation
import SwiftASN1
import X509

/// The subject OU a leaf gets when its key passed TPM attestation. IAM Roles Anywhere maps it to the
/// session tag `x509Subject/OU`, so a trust policy can require it.
///
/// The name says what was checked: the key is non-exportable and lives in the TPM whose endorsement
/// key was pinned at enrollment. It does not claim the TPM is genuine hardware; the EK certificate's
/// chain to the manufacturer is not verified.
public let tpmAttestedOU = "tpm-ek-pinned"

/// A host's pinned TPM identity: its endorsement key certificate and an attestation key (AK) that
/// was proven, by credential activation, to live in the same TPM.
public struct TPMEnrollment: Codable, Sendable {
    public var commonName: String
    /// DER. The EK public key is taken from here; the certificate chain is not checked.
    public var ekCertificate: Data
    /// TPM2B_PUBLIC of the attestation key.
    public var attestationKey: Data
    /// SHA-256 (hex) of the credential-activation secret while enrollment is pending; nil once enrolled.
    public var pendingChallengeSHA256: String?

    public var isEnrolled: Bool { pendingChallengeSHA256 == nil }
}

/// AK requirements: created in the TPM and restricted signing. Self-declared bits; they hold only
/// if the enrolled EK is a real TPM's.
let requiredAKAttributes: TPMObjectAttributes = [.fixedTPM, .fixedParent, .sensitiveDataOrigin, .restricted, .sign]

/// Client key requirements: generated inside the TPM and never exportable.
let requiredKeyAttributes: TPMObjectAttributes = [.fixedTPM, .fixedParent, .sensitiveDataOrigin, .sign]

func checkAttestationKey(_ ak: TPMECCPublic) throws {
    guard ak.attributes.isSuperset(of: requiredAKAttributes), !ak.attributes.contains(.decrypt) else {
        throw TPMError.rejected("attestation key attributes are \(ak.attributes), need \(requiredAKAttributes) and not decrypt")
    }
    guard let scheme = ak.scheme, scheme == (TPMAlg.ecdsa, TPMAlg.sha256) else {
        throw TPMError.rejected("attestation key scheme is not ECDSA with SHA-256")
    }
}

/// The EK public key from its certificate.
///
/// Intel PTT EK certificates are not valid DER: they encode `critical FALSE` and `cA FALSE`
/// explicitly, which DER forbids for DEFAULT values, and swift-certificates rejects them. Nothing
/// here relies on the certificate's signature or extensions, so this walks the generic DER tree to
/// tbsCertificate.subjectPublicKeyInfo and parses only that.
func ekPublicKey(certificateDER: [UInt8]) throws -> P256.KeyAgreement.PublicKey {
    func children(_ node: ASN1Node, _ what: String) throws -> [ASN1Node] {
        guard node.identifier == .sequence, case let .constructed(c) = node.content else {
            throw TPMError.malformed("EK certificate \(what) is not a SEQUENCE")
        }
        return Array(c)
    }
    let cert = try children(DER.parse(certificateDER), "Certificate")
    guard let tbsNode = cert.first else { throw TPMError.malformed("empty EK certificate") }
    var tbs = try children(tbsNode, "tbsCertificate")
    // version [0] EXPLICIT is optional; after it: serial, signature, issuer, validity, subject, SPKI.
    if tbs.first?.identifier == ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific) { tbs.removeFirst() }
    guard tbs.count >= 6 else { throw TPMError.malformed("EK tbsCertificate is too short") }
    let spki = tbs[5]
    guard let key = try? P256.KeyAgreement.PublicKey(derRepresentation: Array(spki.encodedBytes)) else {
        throw TPMError.unsupported("EK certificate key is not P-256; use the ECC EK certificate (NV index 0x1c0000a)")
    }
    return key
}

extension TPMEnrollment {
    /// Starts enrollment: returns the pending record and a credential blob for
    /// `tpm2_activatecredential`. Only the TPM holding this EK, with this exact AK loaded, can recover
    /// the secret inside.
    public static func challenge(
        commonName: String,
        ekCertificateDER: [UInt8],
        attestationKeyTPM2BPublic: [UInt8]
    ) throws -> (TPMEnrollment, credentialBlob: [UInt8]) {
        let ek = try ekPublicKey(certificateDER: ekCertificateDER)
        let ak = try TPMECCPublic(tpm2bPublic: attestationKeyTPM2BPublic)
        try checkAttestationKey(ak)

        var secret = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, secret.count, &secret) == errSecSuccess else {
            throw TPMError.malformed("could not generate a random challenge")
        }
        let blob = try makeCredential(ek: ek, objectName: ak.name, secret: secret)
        let pending = TPMEnrollment(
            commonName: commonName,
            ekCertificate: Data(ekCertificateDER),
            attestationKey: Data(attestationKeyTPM2BPublic),
            pendingChallengeSHA256: hexSHA256(Data(secret))
        )
        return (pending, blob)
    }

    /// Finishes enrollment with the secret `tpm2_activatecredential` recovered.
    public func completing(withActivatedSecret response: [UInt8]) throws -> TPMEnrollment {
        guard let want = pendingChallengeSHA256 else { throw TPMError.rejected("enrollment is already complete") }
        guard hexSHA256(Data(response)) == want else {
            throw TPMError.rejected("activated secret does not match the challenge; the AK is not in the TPM holding this EK")
        }
        var done = self
        done.pendingChallengeSHA256 = nil
        return done
    }
}

/// What a host sends with its CSR: the client key's public area, a TPM2_Certify of it by the AK,
/// and the AK's signature over that attestation.
public struct TPMAttestationBundle: Sendable {
    static let keyLabel = "TPM2B PUBLIC"
    static let attestLabel = "TPMS ATTEST"
    static let signatureLabel = "TPM ECDSA SIGNATURE"

    /// TPM2B_PUBLIC of the client key.
    public let keyPublic: [UInt8]
    /// TPMS_ATTEST, as signed.
    public let attest: [UInt8]
    /// DER ECDSA signature by the AK over `attest` (`tpm2_certify -f plain`).
    public let signature: [UInt8]

    public init(pem: String) throws {
        var blocks: [String: [UInt8]] = [:]
        for doc in try PEMDocument.parseMultiple(pemString: pem) {
            guard [Self.keyLabel, Self.attestLabel, Self.signatureLabel].contains(doc.discriminator) else {
                throw TPMError.malformed("unexpected PEM block \"\(doc.discriminator)\" in attestation bundle")
            }
            guard blocks[doc.discriminator] == nil else {
                throw TPMError.malformed("PEM block \"\(doc.discriminator)\" appears twice in attestation bundle")
            }
            blocks[doc.discriminator] = doc.derBytes
        }
        guard let k = blocks[Self.keyLabel], let a = blocks[Self.attestLabel], let s = blocks[Self.signatureLabel] else {
            throw TPMError.malformed("attestation bundle needs \(Self.keyLabel), \(Self.attestLabel), and \(Self.signatureLabel) blocks")
        }
        (keyPublic, attest, signature) = (k, a, s)
    }
}

/// Checks that `csr`'s key is a non-exportable key in the TPM enrolled for `commonName`.
public func verifyTPMAttestation(
    _ bundle: TPMAttestationBundle,
    enrollment: TPMEnrollment,
    csr: CertificateSigningRequest,
    commonName: String
) throws {
    guard enrollment.isEnrolled else { throw TPMError.rejected("enrollment for \(enrollment.commonName) is still pending") }
    guard enrollment.commonName == commonName else {
        throw TPMError.rejected("enrollment is for CN=\(enrollment.commonName), not CN=\(commonName)")
    }
    let ak = try TPMECCPublic(tpm2bPublic: Array(enrollment.attestationKey))
    try checkAttestationKey(ak)

    let signature = try P256.Signing.ECDSASignature(derRepresentation: bundle.signature)
    guard ak.publicKey.isValidSignature(signature, for: bundle.attest) else {
        throw TPMError.rejected("attestation signature does not verify with the enrolled AK")
    }
    // The AK is restricted, so a valid signature over data starting with TPM_GENERATED_VALUE means
    // the TPM produced this attestation; TPMCertifyInfo checks that magic.
    let info = try TPMCertifyInfo(bundle.attest)

    let key = try TPMECCPublic(tpm2bPublic: bundle.keyPublic)
    guard info.name == key.name else {
        throw TPMError.rejected("attestation certifies a different object than the supplied public area")
    }
    guard key.attributes.isSuperset(of: requiredKeyAttributes) else {
        throw TPMError.rejected("client key attributes are \(key.attributes), need \(requiredKeyAttributes)")
    }
    guard Certificate.PublicKey(key.publicKey) == csr.publicKey else {
        throw TPMError.rejected("attested TPM key is not the CSR's public key")
    }
}
