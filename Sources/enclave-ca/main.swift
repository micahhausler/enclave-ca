import EnclaveCA
import Foundation
import SwiftASN1
import X509

let usage = """
usage:
  enclave-ca init --key FILE --cert FILE --cn NAME [--days N]
      Create a Secure Enclave key and a self-signed root CA (default 3650 days).
      Refuses to overwrite either file. One Touch ID prompt.

  enclave-ca sign --key FILE --ca-cert FILE --csr FILE --cn NAME --out FILE [--days N]
      [--tpm-enrollment FILE --tpm-attestation FILE]
      Sign a client-auth leaf for CN=NAME (default 365 days). The CSR's subject
      must be exactly CN=NAME. One Touch ID prompt. With --tpm-enrollment and
      --tpm-attestation, first check that the CSR's key is a non-exportable key
      in the enrolled TPM, and add OU=\(tpmAttestedOU) to the leaf's subject.

  enclave-ca tpm-challenge --cn NAME --ek-cert FILE --ak-public FILE
      --enrollment FILE --out FILE
      Start TPM enrollment for CN=NAME: pin the host's EK certificate and AK
      (TPM2B_PUBLIC), and write a credential for tpm2_activatecredential.

  enclave-ca tpm-enroll --enrollment FILE --activated FILE
      Finish TPM enrollment with the secret tpm2_activatecredential recovered.

  enclave-ca client-key --key FILE --csr FILE --cn NAME [--access MODE]
      Create a Secure Enclave client key and a CSR for CN=NAME. Refuses to
      overwrite. MODE is what every use of the key needs:
        none           nothing; unattended, like a password-less TPM key (default)
        user-presence  Touch ID, or the login password
        passcode       the login password
      user-presence and passcode prompt once now, to sign the CSR.

  enclave-ca credential-process --key FILE --certificate FILE
      --trust-anchor-arn ARN --profile-arn ARN --role-arn ARN
      [--duration-seconds N] [--role-session-name NAME] [--cache]
      Get IAM Roles Anywhere credentials with a client key and print them in
      the AWS credential_process format. Prompts unless the key's access is
      none. With --cache, reuse the credentials from the login keychain until
      10 minutes before they expire, so a prompting key prompts about once
      per session instead of on every aws command.

  enclave-ca --version
      Print the version.

"""

func pem(_ cert: Certificate) throws -> String {
    try cert.serializeAsPEM().pemString + "\n"
}

/// Creates the file, failing if it already exists.
func writeNew(_ path: String, _ data: Data, mode: mode_t) throws {
    let fd = open(path, O_WRONLY | O_CREAT | O_EXCL, mode)
    guard fd >= 0 else { throw Failure("\(path): \(String(cString: strerror(errno)))") }
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    do {
        try handle.write(contentsOf: data)
    } catch {
        unlink(path)
        throw Failure("\(path): \(error.localizedDescription)")
    }
}

/// All or none.
func writeNewAll(_ files: [(path: String, data: Data, mode: mode_t)]) throws {
    var written: [String] = []
    do {
        for f in files {
            try writeNew(f.path, f.data, mode: f.mode)
            written.append(f.path)
        }
    } catch {
        for p in written { unlink(p) }
        throw error
    }
}

func readData(_ path: String) throws -> Data {
    do {
        return try Data(contentsOf: URL(fileURLWithPath: path))
    } catch {
        throw Failure("\(path): \((error as NSError).localizedFailureReason ?? error.localizedDescription)")
    }
}

func readText(_ path: String) throws -> String {
    do {
        return try String(contentsOfFile: path, encoding: .utf8)
    } catch {
        throw Failure("\(path): \((error as NSError).localizedFailureReason ?? error.localizedDescription)")
    }
}

func loadKey<K>(_ path: String, _ load: () throws -> K) throws -> K {
    do {
        return try load()
    } catch {
        throw Failure("\(path) is not a Secure Enclave key this Mac can use: \(error.localizedDescription)")
    }
}

func summary(_ cert: Certificate) throws -> String {
    """
    subject:    \(cert.subject)
    issuer:     \(cert.issuer)
    serial:     \(cert.serialNumber.bytes.map { String(format: "%02x", $0) }.joined(separator: ":"))
    not after:  \(cert.notValidAfter)
    sha256:     \(try fingerprint(cert))
    """
}

func runInit(_ flags: inout [String: String]) throws {
    let keyPath = try take(&flags, "key")
    let certPath = try take(&flags, "cert")
    let cn = try take(&flags, "cn")
    let days = try takeInt(&flags, "days", default: 3650)
    try rejectUnknown(flags)

    for p in [keyPath, certPath] where FileManager.default.fileExists(atPath: p) {
        throw Failure("\(p) already exists; refusing to overwrite")
    }

    let blob = try EnclaveKey.create(access: .userPresence).dataRepresentation
    let key = Certificate.PrivateKey(try EnclaveKey.load(blob, reason: "create root CA \"CN=\(cn)\""))
    let cert = try makeRoot(key: key, commonName: cn, days: days)

    try writeNewAll([(keyPath, blob, 0o600), (certPath, Data(try pem(cert).utf8), 0o644)])
    print(try summary(cert))
}

func readEnrollment(_ path: String) throws -> TPMEnrollment {
    try JSONDecoder().decode(TPMEnrollment.self, from: readData(path))
}

func encodeEnrollment(_ e: TPMEnrollment) throws -> Data {
    let enc = JSONEncoder()
    enc.outputFormatting = [.prettyPrinted, .sortedKeys]
    return try enc.encode(e) + Data("\n".utf8)
}

/// Writes beside the target and renames, so a failure never leaves a truncated file in place.
func writeAtomic(_ path: String, _ data: Data, mode: mode_t) throws {
    let tmp = path + ".tmp-\(getpid())"
    try writeNew(tmp, data, mode: mode)
    guard rename(tmp, path) == 0 else {
        let msg = String(cString: strerror(errno))
        unlink(tmp)
        throw Failure("\(path): \(msg)")
    }
}

func runSign(_ flags: inout [String: String]) throws {
    let keyPath = try take(&flags, "key")
    let caCertPath = try take(&flags, "ca-cert")
    let csrPath = try take(&flags, "csr")
    let cn = try take(&flags, "cn")
    let outPath = try take(&flags, "out")
    let days = try takeInt(&flags, "days", default: 365)
    let enrollmentPath = flags.removeValue(forKey: "tpm-enrollment")
    let attestationPath = flags.removeValue(forKey: "tpm-attestation")
    try rejectUnknown(flags)
    guard (enrollmentPath == nil) == (attestationPath == nil) else {
        throw UsageError(description: "--tpm-enrollment and --tpm-attestation go together")
    }

    let caCert = try Certificate(pemEncoded: readText(caCertPath))
    let csr = try parseCSR(pem: readText(csrPath))

    // Check the attestation before asking for Touch ID, so a bad one never prompts.
    var ou: String?
    if let enrollmentPath, let attestationPath {
        let bundle = try TPMAttestationBundle(pem: readText(attestationPath))
        try verifyTPMAttestation(bundle, enrollment: readEnrollment(enrollmentPath), csr: csr, commonName: cn)
        ou = tpmAttestedOU
        print("TPM attestation verified: CSR key is non-exportable in the TPM enrolled for CN=\(cn)")
    }

    let blob = try readData(keyPath)
    let what = ou.map { "\"OU=\($0), CN=\(cn)\"" } ?? "\"CN=\(cn)\""
    let key = try loadKey(keyPath) { Certificate.PrivateKey(try EnclaveKey.load(blob, reason: "sign \(what) for \(days) days")) }

    let leaf = try signLeaf(csr: csr, caCert: caCert, caKey: key, commonName: cn, days: days, organizationalUnit: ou)

    try writeAtomic(outPath, Data(try pem(leaf).utf8), mode: 0o644)
    print(try summary(leaf))
}

/// Reads a certificate as PEM or DER (tpm2_nvread writes DER).
func readCertificateDER(_ path: String) throws -> [UInt8] {
    let data = try readData(path)
    if let text = String(data: data, encoding: .utf8), text.contains("-----BEGIN") {
        return try PEMDocument(pemString: text).derBytes
    }
    return Array(data)
}

func runTPMChallenge(_ flags: inout [String: String]) throws {
    let cn = try take(&flags, "cn")
    let ekPath = try take(&flags, "ek-cert")
    let akPath = try take(&flags, "ak-public")
    let enrollmentPath = try take(&flags, "enrollment")
    let outPath = try take(&flags, "out")
    try rejectUnknown(flags)

    for p in [enrollmentPath, outPath] where FileManager.default.fileExists(atPath: p) {
        throw Failure("\(p) already exists; refusing to overwrite")
    }
    let (pending, blob) = try TPMEnrollment.challenge(
        commonName: cn,
        ekCertificateDER: readCertificateDER(ekPath),
        attestationKeyTPM2BPublic: Array(readData(akPath))
    )
    try writeNewAll([(outPath, Data(blob), 0o644), (enrollmentPath, try encodeEnrollment(pending), 0o644)])
    print("wrote \(outPath) (credential for tpm2_activatecredential) and pending \(enrollmentPath) for CN=\(cn)")
}

func runTPMEnroll(_ flags: inout [String: String]) throws {
    let enrollmentPath = try take(&flags, "enrollment")
    let activatedPath = try take(&flags, "activated")
    try rejectUnknown(flags)

    let done = try readEnrollment(enrollmentPath)
        .completing(withActivatedSecret: Array(readData(activatedPath)))
    try writeAtomic(enrollmentPath, try encodeEnrollment(done), mode: 0o644)
    print("""
    enrolled CN=\(done.commonName)
    EK cert sha256: \(hexSHA256(done.ekCertificate))
    AK name:        \(hex(try TPMECCPublic(tpm2bPublic: Array(done.attestationKey)).name))
    """)
}

func runClientKey(_ flags: inout [String: String]) throws {
    let keyPath = try take(&flags, "key")
    let csrPath = try take(&flags, "csr")
    let cn = try take(&flags, "cn")
    let access = try flags.removeValue(forKey: "access").map(ClientKeyAccess.init(flag:)) ?? .none
    try rejectUnknown(flags)

    for p in [keyPath, csrPath] where FileManager.default.fileExists(atPath: p) {
        throw Failure("\(p) already exists; refusing to overwrite")
    }
    let key = try EnclaveKey.create(access: access)
    let signer = try EnclaveKey.load(key.dataRepresentation, reason: "sign a CSR for \"CN=\(cn)\"")
    let csr = try makeCSR(key: Certificate.PrivateKey(signer), commonName: cn)
    try writeNewAll([
        (keyPath, key.dataRepresentation, 0o600),
        (csrPath, Data((try csr.serializeAsPEM().pemString + "\n").utf8), 0o644),
    ])
    print("wrote \(keyPath) and \(csrPath) for CN=\(cn)\(access == .none ? "" : " (access: \(access.rawValue))")")
}

func runCredentialProcess(_ flags: inout [String: String]) async throws {
    let keyPath = try take(&flags, "key")
    let certPath = try take(&flags, "certificate")
    let ta = try take(&flags, "trust-anchor-arn")
    let profile = try take(&flags, "profile-arn")
    let role = try take(&flags, "role-arn")
    let duration = try takeInt(&flags, "duration-seconds", default: 3600)
    let sessionName = flags.removeValue(forKey: "role-session-name")
    let useCache = takeSwitch(&flags, "cache")
    try rejectUnknown(flags)

    let cert = try Certificate(pemEncoded: readText(certPath))
    let blob = try readData(keyPath)
    let params = RolesAnywhere.SessionParams(
        trustAnchorArn: ta, profileArn: profile, roleArn: role,
        durationSeconds: duration, roleSessionName: sessionName
    )

    let cache = CredentialCache()
    let account = useCache ? try CredentialCache.account(keyBlob: blob, certificate: cert, params: params) : nil
    if let account {
        do {
            if let hit = try cache.lookup(account) {
                writeCredentials(hit)
                return
            }
        } catch {
            warn("credential cache: \(error)")
        }
    }

    let key = try loadKey(keyPath) { try EnclaveKey.load(blob, reason: "get AWS credentials for \(role)") }
    guard cert.publicKey == Certificate.PublicKey(key.publicKey) else {
        throw Failure("\(certPath) is not for the key in \(keyPath)")
    }
    let req = try RolesAnywhere.signedRequest(
        params: params,
        certificate: cert,
        region: RolesAnywhere.region(fromTrustAnchorArn: ta)
    ) { try key.signature(for: $0).derRepresentation }
    let out = try RolesAnywhere.processCredentials(fromResponse: await RolesAnywhere.createSession(req))
    if let account {
        do {
            try cache.save(account, out)
        } catch {
            warn("credential cache: \(error)")
        }
    }
    writeCredentials(out)
}

func writeCredentials(_ json: Data) {
    FileHandle.standardOutput.write(json)
    FileHandle.standardOutput.write(Data("\n".utf8))
}

func warn(_ msg: String) {
    FileHandle.standardError.write(Data("enclave-ca: \(msg)\n".utf8))
}

var args = CommandLine.arguments.dropFirst()
guard let cmd = args.popFirst() else {
    FileHandle.standardError.write(Data(usage.utf8))
    exit(2)
}
if ["-h", "--help", "help"].contains(cmd) {
    print(usage, terminator: "")
    exit(0)
}
if cmd == "--version" {
    print("enclave-ca \(enclaveCAVersion)")
    exit(0)
}

let commands: [String: (inout [String: String]) async throws -> Void] = [
    "init": runInit,
    "sign": runSign,
    "client-key": runClientKey,
    "tpm-challenge": runTPMChallenge,
    "tpm-enroll": runTPMEnroll,
    "credential-process": runCredentialProcess,
]

do {
    guard let run = commands[cmd] else { throw UsageError(description: "unknown command \"\(cmd)\"") }
    if args.contains("-h") || args.contains("--help") {
        print(usage, terminator: "")
        exit(0)
    }
    let switches: [String: Set<String>] = ["credential-process": ["cache"]]
    var flags = try parseFlags(args, switches: switches[cmd] ?? [])
    try await run(&flags)
} catch let e as UsageError {
    FileHandle.standardError.write(Data("enclave-ca: \(e)\n\n\(usage)".utf8))
    exit(2)
} catch {
    FileHandle.standardError.write(Data("enclave-ca: \(error)\n".utf8))
    exit(1)
}
