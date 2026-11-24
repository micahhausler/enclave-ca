import Crypto
import Foundation
import SwiftASN1
import X509

/// IAM Roles Anywhere CreateSession, signed with SigV4-X509 (AWS4-X509-ECDSA-SHA256).
///
/// Mirrors aws/rolesanywhere-credential-helper (aws_signing_helper/signer.go):
/// - signed headers: content-type, host, x-amz-date, x-amz-x509 (base64 DER of the leaf)
/// - scope: <yyyymmdd>/<region>/rolesanywhere/aws4_request
/// - credential: the leaf's serial number in decimal
/// - signature: hex of the DER ECDSA-SHA256 signature over the string to sign
public enum RolesAnywhere {
    public static let algorithm = "AWS4-X509-ECDSA-SHA256"
    public static let service = "rolesanywhere"

    public struct SessionParams: Sendable {
        public var trustAnchorArn: String
        public var profileArn: String
        public var roleArn: String
        public var durationSeconds: Int
        public var roleSessionName: String?

        public init(trustAnchorArn: String, profileArn: String, roleArn: String, durationSeconds: Int = 3600, roleSessionName: String? = nil) {
            self.trustAnchorArn = trustAnchorArn
            self.profileArn = profileArn
            self.roleArn = roleArn
            self.durationSeconds = durationSeconds
            self.roleSessionName = roleSessionName
        }
    }

    public enum Failure: Error, CustomStringConvertible {
        case badTrustAnchorArn(String)
        case http(status: Int, body: String)
        case noCredentials(String)

        public var description: String {
            switch self {
            case let .badTrustAnchorArn(arn):
                return "can't read a region from trust anchor ARN \"\(arn)\""
            case let .http(status, body):
                return "CreateSession returned HTTP \(status): \(body)"
            case let .noCredentials(body):
                return "CreateSession response had no credentials: \(body)"
            }
        }
    }

    /// arn:aws:rolesanywhere:<region>:<account>:trust-anchor/<id>
    public static func region(fromTrustAnchorArn arn: String) throws -> String {
        let parts = arn.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count >= 6, parts[0] == "arn", parts[2] == "rolesanywhere", !parts[3].isEmpty else {
            throw Failure.badTrustAnchorArn(arn)
        }
        return String(parts[3])
    }

    public struct SignedRequest {
        public var url: URL
        public var headers: [String: String]
        public var body: Data
        /// Exposed for tests and debugging.
        public var canonicalRequest: String
        public var stringToSign: String
    }

    /// Builds the signed CreateSession request. `sign` receives the string to sign and returns a DER ECDSA-SHA256 signature.
    public static func signedRequest(
        params: SessionParams,
        certificate: Certificate,
        region: String,
        now: Date = Date(),
        sign: (Data) throws -> Data
    ) throws -> SignedRequest {
        let host = "rolesanywhere.\(region).amazonaws.com"
        var bodyObject: [String: Any] = [
            "durationSeconds": params.durationSeconds,
            "profileArn": params.profileArn,
            "roleArn": params.roleArn,
            "trustAnchorArn": params.trustAnchorArn,
        ]
        if let name = params.roleSessionName { bodyObject["roleSessionName"] = name }
        let body = try JSONSerialization.data(withJSONObject: bodyObject, options: [.sortedKeys, .withoutEscapingSlashes])

        let amzDate = timestamp(now, "yyyyMMdd'T'HHmmss'Z'")
        let scope = "\(timestamp(now, "yyyyMMdd"))/\(region)/\(service)/aws4_request"
        let x509 = Data(try derBytes(certificate)).base64EncodedString()

        let signed: [(String, String)] = [
            ("content-type", "application/json"),
            ("host", host),
            ("x-amz-date", amzDate),
            ("x-amz-x509", x509),
        ]
        let signedHeaders = signed.map(\.0).joined(separator: ";")
        let canonicalHeaders = signed.map { "\($0.0):\($0.1)" }.joined(separator: "\n")
        let canonicalRequest = [
            "POST",
            "/sessions",
            "",
            canonicalHeaders,
            "",
            signedHeaders,
            hexSHA256(body),
        ].joined(separator: "\n")
        let stringToSign = [algorithm, amzDate, scope, hexSHA256(Data(canonicalRequest.utf8))].joined(separator: "\n")

        let signature = try sign(Data(stringToSign.utf8))
        let authorization = "\(algorithm) Credential=\(decimalSerial(certificate.serialNumber))/\(scope), "
            + "SignedHeaders=\(signedHeaders), Signature=\(hex(signature))"

        var headers = Dictionary(uniqueKeysWithValues: signed.map { ($0.0, $0.1) })
        headers["authorization"] = authorization
        return SignedRequest(
            url: URL(string: "https://\(host)/sessions")!,
            headers: headers,
            body: body,
            canonicalRequest: canonicalRequest,
            stringToSign: stringToSign
        )
    }

    /// The JSON a `credential_process` must print (AWS SDK "process credentials" format).
    public static func processCredentials(fromResponse data: Data) throws -> Data {
        struct Response: Decodable {
            struct Item: Decodable {
                struct Creds: Decodable {
                    var accessKeyId: String
                    var secretAccessKey: String
                    var sessionToken: String
                    var expiration: String
                }
                var credentials: Creds
            }
            var credentialSet: [Item]
        }
        let raw = String(decoding: data, as: UTF8.self)
        guard let first = try? JSONDecoder().decode(Response.self, from: data).credentialSet.first else {
            throw Failure.noCredentials(raw)
        }
        let c = first.credentials
        let out: [String: Any] = [
            "Version": 1,
            "AccessKeyId": c.accessKeyId,
            "SecretAccessKey": c.secretAccessKey,
            "SessionToken": c.sessionToken,
            "Expiration": c.expiration,
        ]
        return try JSONSerialization.data(withJSONObject: out, options: [.sortedKeys])
    }

    public static func createSession(_ req: SignedRequest) async throws -> Data {
        var r = URLRequest(url: req.url)
        r.httpMethod = "POST"
        r.httpBody = req.body
        for (k, v) in req.headers where k != "host" { r.setValue(v, forHTTPHeaderField: k) }
        let (data, resp) = try await URLSession.shared.data(for: r)
        let status = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else {
            throw Failure.http(status: status, body: String(decoding: data, as: UTF8.self))
        }
        return data
    }
}

func derBytes(_ cert: Certificate) throws -> [UInt8] {
    var s = DER.Serializer()
    try s.serialize(cert)
    return s.serializedBytes
}

public func hex<D: Sequence>(_ bytes: D) -> String where D.Element == UInt8 {
    bytes.map { String(format: "%02x", $0) }.joined()
}

public func hexSHA256(_ data: Data) -> String {
    hex(SHA256.hash(data: data))
}

func timestamp(_ date: Date, _ format: String) -> String {
    let f = DateFormatter()
    f.locale = Locale(identifier: "en_US_POSIX")
    f.timeZone = TimeZone(identifier: "UTC")
    f.dateFormat = format
    return f.string(from: date)
}

/// Big-endian unsigned bytes to a decimal string (the serial format Roles Anywhere expects).
func decimalSerial(_ serial: Certificate.SerialNumber) -> String {
    var digits = Array(serial.bytes)
    while digits.first == 0 { digits.removeFirst() }
    if digits.isEmpty { return "0" }
    var out: [Character] = []
    while !digits.isEmpty {
        var remainder = 0
        var next: [UInt8] = []
        for b in digits {
            let acc = remainder * 256 + Int(b)
            let q = acc / 10
            remainder = acc % 10
            if !(next.isEmpty && q == 0) { next.append(UInt8(q)) }
        }
        out.append(Character(String(remainder)))
        digits = next
    }
    return String(out.reversed())
}
