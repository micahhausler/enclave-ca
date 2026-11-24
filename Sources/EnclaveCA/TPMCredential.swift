import CommonCrypto
import Crypto
import Foundation

// TPM2_MakeCredential done in software (TPM 2.0 Library Part 1 §24 "Credential Protection",
// Part 1 §11.4.10 KDFa/KDFe), for an ECC P-256 endorsement key with the default EK template
// (SHA-256 name algorithm, AES-128-CFB symmetric). The output is the file format that
// `tpm2_makecredential -o` writes and `tpm2_activatecredential -i` reads.

/// SP 800-108 counter-mode KDF with HMAC-SHA-256. The label is NUL-terminated, as the TPM spec requires.
func kdfa(key: [UInt8], label: String, contextU: [UInt8], contextV: [UInt8], bits: Int) -> [UInt8] {
    var out: [UInt8] = []
    var counter: UInt32 = 1
    while out.count * 8 < bits {
        var h = HMAC<SHA256>(key: SymmetricKey(data: key))
        h.update(data: be32(counter))
        h.update(data: Array(label.utf8) + [0])
        h.update(data: contextU)
        h.update(data: contextV)
        h.update(data: be32(UInt32(bits)))
        out += h.finalize()
        counter += 1
    }
    return Array(out.prefix(bits / 8))
}

/// SP 800-56A concatenation KDF with SHA-256, as the TPM uses for ECC secret sharing.
func kdfe(z: [UInt8], label: String, partyU: [UInt8], partyV: [UInt8], bits: Int) -> [UInt8] {
    var out: [UInt8] = []
    var counter: UInt32 = 1
    while out.count * 8 < bits {
        var h = SHA256()
        h.update(data: be32(counter))
        h.update(data: z)
        h.update(data: Array(label.utf8) + [0])
        h.update(data: partyU)
        h.update(data: partyV)
        out += h.finalize()
        counter += 1
    }
    return Array(out.prefix(bits / 8))
}

/// AES-128 in CFB-128 mode with a zero IV, the TPM's parameter/credential encryption.
func aes128CFB(encrypt: Bool, key: [UInt8], _ input: [UInt8]) throws -> [UInt8] {
    precondition(key.count == 16)
    let iv = [UInt8](repeating: 0, count: 16)
    var ref: CCCryptorRef?
    var status = CCCryptorCreateWithMode(
        CCOperation(encrypt ? kCCEncrypt : kCCDecrypt), CCMode(kCCModeCFB), CCAlgorithm(kCCAlgorithmAES),
        CCPadding(ccNoPadding), iv, key, key.count, nil, 0, 0, 0, &ref
    )
    guard status == kCCSuccess, let ref else { throw TPMError.malformed("AES-CFB setup failed (\(status))") }
    defer { CCCryptorRelease(ref) }
    var out = [UInt8](repeating: 0, count: input.count)
    var moved = 0
    status = CCCryptorUpdate(ref, input, input.count, &out, out.count, &moved)
    guard status == kCCSuccess, moved == input.count else { throw TPMError.malformed("AES-CFB failed (\(status))") }
    return out
}

/// The file header tpm2-tools puts on a credential blob.
let credentialFileMagic: UInt32 = 0xBADC_C0DE
let credentialFileVersion: UInt32 = 1

/// Wraps `secret` so that only the TPM holding the endorsement key `ek` can recover it, and only
/// by naming an object loaded in that same TPM whose name is `objectName` (the attestation key).
func makeCredential(
    ek: P256.KeyAgreement.PublicKey,
    objectName: [UInt8],
    secret: [UInt8],
    ephemeral: P256.KeyAgreement.PrivateKey = P256.KeyAgreement.PrivateKey()
) throws -> [UInt8] {
    precondition(secret.count <= 32, "credential larger than the SHA-256 digest size")
    let z = try ephemeral.sharedSecretFromKeyAgreement(with: ek).withUnsafeBytes { Array($0) }
    let ephPoint = Array(ephemeral.publicKey.x963Representation.dropFirst())
    let (ephX, ephY) = (Array(ephPoint.prefix(32)), Array(ephPoint.suffix(32)))
    let ekX = Array(ek.x963Representation.dropFirst().prefix(32))

    let seed = kdfe(z: z, label: "IDENTITY", partyU: ephX, partyV: ekX, bits: 256)
    let symKey = kdfa(key: seed, label: "STORAGE", contextU: objectName, contextV: [], bits: 128)
    let encIdentity = try aes128CFB(encrypt: true, key: symKey, sized(secret))
    let hmacKey = kdfa(key: seed, label: "INTEGRITY", contextU: [], contextV: [], bits: 256)
    var mac = HMAC<SHA256>(key: SymmetricKey(data: hmacKey))
    mac.update(data: encIdentity)
    mac.update(data: objectName)
    let outerHMAC = Array(mac.finalize())

    let idObject = sized(sized(outerHMAC) + encIdentity) // TPM2B_ID_OBJECT
    let encSecret = sized(sized(ephX) + sized(ephY)) // TPM2B_ENCRYPTED_SECRET holding a TPMS_ECC_POINT
    return be32(credentialFileMagic) + be32(credentialFileVersion) + idObject + encSecret
}
