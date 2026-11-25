import Crypto
import Foundation
import Testing
import X509

@testable import EnclaveCA

@Test func decimalSerialMatchesSigningHelper() throws {
    // aws_signing_helper read-certificate-data printed this serial for a cert whose hex serial is below.
    let hexSerial = "c4e6f0a94f446044d86e9bbb384dad96920f9287"
    var bytes: [UInt8] = []
    var i = hexSerial.startIndex
    while i < hexSerial.endIndex {
        let j = hexSerial.index(i, offsetBy: 2)
        bytes.append(UInt8(hexSerial[i..<j], radix: 16)!)
        i = j
    }
    let serial = Certificate.SerialNumber(bytes: bytes)
    #expect(decimalSerial(serial) == "1124112327038842262589253133447750281021837251207")
    #expect(decimalSerial(Certificate.SerialNumber(bytes: [0x00, 0x01, 0x00])) == "256")
}

@Test func regionFromTrustAnchorArn() throws {
    let arn = "arn:aws:rolesanywhere:us-west-2:111122223333:trust-anchor/00000000-0000-0000-0000-000000000000"
    #expect(try RolesAnywhere.region(fromTrustAnchorArn: arn) == "us-west-2")
    #expect(throws: RolesAnywhere.Failure.self) { try RolesAnywhere.region(fromTrustAnchorArn: "arn:aws:iam::1:role/x") }
}

@Test func regionFromTrustAnchorArnAcceptsGovCloud() throws {
    let arn = "arn:aws-us-gov:rolesanywhere:us-gov-west-1:111122223333:trust-anchor/00000000-0000-0000-0000-000000000000"
    #expect(try RolesAnywhere.region(fromTrustAnchorArn: arn) == "us-gov-west-1")
}

@Test(arguments: [
    "arn:aws-cn:rolesanywhere:cn-north-1:111122223333:trust-anchor/x",
    "arn:aws:rolesanywhere:us-west-2.example.com:111122223333:trust-anchor/x",
    "arn:aws:rolesanywhere:us-west-2/x:111122223333:trust-anchor/x",
    "arn:aws:rolesanywhere::111122223333:trust-anchor/x",
    "arn:aws:rolesanywhere:US-WEST-2:111122223333:trust-anchor/x",
])
func regionFromTrustAnchorArnRefusesUnsupported(_ arn: String) throws {
    #expect(throws: RolesAnywhere.Failure.self) { try RolesAnywhere.region(fromTrustAnchorArn: arn) }
}

@Test func signedRequestShapeAndSignature() throws {
    let caKey = softwareKey()
    let root = try makeRoot(key: caKey, commonName: "Test Root", days: 3650, now: now)
    let leafKey = P256.Signing.PrivateKey()
    let leaf = try signLeaf(
        csr: makeCSR(key: Certificate.PrivateKey(leafKey), commonName: "mac"),
        caCert: root, caKey: caKey, commonName: "mac", days: 365, now: now
    )
    let params = RolesAnywhere.SessionParams(trustAnchorArn: "ta", profileArn: "p", roleArn: "r")
    let req = try RolesAnywhere.signedRequest(params: params, certificate: leaf, region: "us-west-2", now: now) {
        try leafKey.signature(for: $0).derRepresentation
    }

    #expect(req.url.absoluteString == "https://rolesanywhere.us-west-2.amazonaws.com/sessions")
    #expect(String(decoding: req.body, as: UTF8.self) == #"{"durationSeconds":3600,"profileArn":"p","roleArn":"r","trustAnchorArn":"ta"}"#)

    let lines = req.canonicalRequest.split(separator: "\n", omittingEmptySubsequences: false)
    #expect(lines[0] == "POST" && lines[1] == "/sessions" && lines[2] == "")
    #expect(lines[3] == "content-type:application/json")
    #expect(lines[4] == "host:rolesanywhere.us-west-2.amazonaws.com")
    #expect(lines[5] == "x-amz-date:20270115T080000Z")
    #expect(lines[6].hasPrefix("x-amz-x509:MII"))
    #expect(lines[8] == "content-type;host;x-amz-date;x-amz-x509")

    let sts = req.stringToSign.split(separator: "\n").map(String.init)
    #expect(sts[0] == "AWS4-X509-ECDSA-SHA256")
    #expect(sts[1] == "20270115T080000Z")
    #expect(sts[2] == "20270115/us-west-2/rolesanywhere/aws4_request")

    let auth = try #require(req.headers["authorization"])
    #expect(auth.hasPrefix("AWS4-X509-ECDSA-SHA256 Credential=\(decimalSerial(leaf.serialNumber))/20270115/us-west-2/rolesanywhere/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-x509, Signature="))

    // The signature verifies over the string to sign with the leaf's public key.
    let sigHex = String(auth.split(separator: "=").last!)
    var sig: [UInt8] = []
    var i = sigHex.startIndex
    while i < sigHex.endIndex {
        let j = sigHex.index(i, offsetBy: 2)
        sig.append(UInt8(sigHex[i..<j], radix: 16)!)
        i = j
    }
    let ecdsa = try P256.Signing.ECDSASignature(derRepresentation: sig)
    #expect(leafKey.publicKey.isValidSignature(ecdsa, for: Data(req.stringToSign.utf8)))
}

@Test func processCredentialsFormat() throws {
    let response = #"{"credentialSet":[{"assumedRoleUser":{"arn":"a","assumedRoleId":"b"},"credentials":{"accessKeyId":"AK","expiration":"2027-01-15T09:00:00Z","secretAccessKey":"SK","sessionToken":"ST"},"packedPolicySize":0,"roleArn":"r","sourceIdentity":"s"}],"subjectArn":"x"}"#
    let out = try RolesAnywhere.processCredentials(fromResponse: Data(response.utf8))
    #expect(String(decoding: out, as: UTF8.self) == #"{"AccessKeyId":"AK","Expiration":"2027-01-15T09:00:00Z","SecretAccessKey":"SK","SessionToken":"ST","Version":1}"#)
    #expect(throws: RolesAnywhere.Failure.self) { try RolesAnywhere.processCredentials(fromResponse: Data("{}".utf8)) }
}

@Test func processCredentialsErrorOmitsResponseBody() throws {
    let response = #"{"credentialSet":[{"credentials":{"accessKeyId":"AK","expiration":"2027-01-15T09:00:00Z","secretAccessKey":"SECRET"}}]}"#
    let error = try #require(throws: RolesAnywhere.Failure.self) {
        try RolesAnywhere.processCredentials(fromResponse: Data(response.utf8))
    }
    #expect(!error.description.contains("SECRET"))
    #expect(!error.description.contains("AK"))
}
