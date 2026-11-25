import Crypto
import Foundation
import SwiftASN1
import X509

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
