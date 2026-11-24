import SwiftASN1
import X509

/// ECDSA signature algorithm OIDs (RFC 5758 §3.2): ecdsa-with-SHA256/384/512.
let ecdsaSignatureOIDs: Set<ASN1ObjectIdentifier> = [
    [1, 2, 840, 10045, 4, 3, 2],
    [1, 2, 840, 10045, 4, 3, 3],
    [1, 2, 840, 10045, 4, 3, 4],
]

/// Parses a PEM CSR, tolerating one known encoding defect.
///
/// tpm2-openssl (seen with 1.3.0) writes the CSR's outer signatureAlgorithm as
/// `SEQUENCE { ecdsa-with-SHA256, NULL }`. RFC 5758 §3.2 says the parameters MUST be absent for
/// ECDSA, and swift-certificates rejects the NULL. That AlgorithmIdentifier sits outside
/// certificationRequestInfo, so it is not covered by the CSR's signature; dropping the NULL
/// changes nothing that was signed. The signature is still verified afterwards by `signLeaf`.
///
/// Only that exact shape is rewritten. Anything else is passed to swift-certificates unchanged.
public func parseCSR(pem: String) throws -> CertificateSigningRequest {
    let doc = try PEMDocument(pemString: pem)
    return try CertificateSigningRequest(derEncoded: stripECDSANullParameters(doc.derBytes))
}

func stripECDSANullParameters(_ der: [UInt8]) throws -> [UInt8] {
    let root = try DER.parse(der)
    guard root.identifier == .sequence, case let .constructed(top) = root.content else { return der }
    let parts = Array(top)
    guard parts.count == 3 else { return der }
    let (info, alg, sig) = (parts[0], parts[1], parts[2])

    guard alg.identifier == .sequence, case let .constructed(algParts) = alg.content else { return der }
    let fields = Array(algParts)
    guard fields.count == 2, fields[1].identifier == .null,
          case let .primitive(nullBody) = fields[1].content, nullBody.isEmpty
    else { return der }
    let oid = try ASN1ObjectIdentifier(derEncoded: fields[0])
    guard ecdsaSignatureOIDs.contains(oid) else { return der }

    var out = DER.Serializer()
    try out.appendConstructedNode(identifier: .sequence) { s in
        s.serialize(info)
        try s.appendConstructedNode(identifier: .sequence) { s in
            try s.serialize(oid)
        }
        s.serialize(sig)
    }
    return out.serializedBytes
}
