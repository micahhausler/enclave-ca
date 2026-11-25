import Crypto
import Foundation
import Security
import Testing
import X509

@testable import EnclaveCA

final class MemoryStore: CredentialStore {
    var items: [String: Data] = [:]
    var reads = 0

    func read(_ account: String) throws -> Data? {
        reads += 1
        return items[account]
    }

    func write(_ account: String, _ data: Data) throws {
        items[account] = data
    }
}

func credentials(expiring: String) -> Data {
    Data(#"{"AccessKeyId":"AK","Expiration":"\#(expiring)","SecretAccessKey":"SK","SessionToken":"ST","Version":1}"#.utf8)
}

func testLeaf() throws -> Certificate {
    let caKey = softwareKey()
    let root = try makeRoot(key: caKey, commonName: "Test Root", days: 3650, now: now)
    return try signLeaf(csr: makeCSR(cn: "mac"), caCert: root, caKey: caKey, commonName: "mac", days: 365, now: now)
}

@Test func switchesTakeNoValue() throws {
    var flags = try parseFlags(["--key", "k", "--cache", "--cn", "mac"], switches: ["cache"])
    #expect(takeSwitch(&flags, "cache"))
    #expect(!takeSwitch(&flags, "cache"))
    #expect(try take(&flags, "key") == "k")
    #expect(try take(&flags, "cn") == "mac")
    try rejectUnknown(flags)

    #expect(throws: UsageError.self) { try parseFlags(["--cache", "--cache"], switches: ["cache"]) }
    #expect(throws: UsageError.self) { try parseFlags(["--cache"]) }
    #expect(throws: UsageError.self) { try parseFlags(["--cache", "--key"]) }
    #expect(throws: UsageError.self) { try parseFlags(["--key", "--cn", "mac"]) }
    #expect(throws: UsageError.self) { try rejectUnknown(parseFlags(["--cache"], switches: ["cache"])) }
}

@Test func intFlags() throws {
    var flags = try parseFlags(["--days", "30", "--duration-seconds", "soon"])
    #expect(try takeInt(&flags, "days", default: 365) == 30)
    #expect(try takeInt(&flags, "days", default: 365) == 365)
    do {
        _ = try takeInt(&flags, "duration-seconds", default: 3600)
        Issue.record("expected UsageError")
    } catch let e as UsageError {
        #expect(e.description.contains("--duration-seconds"))
        #expect(e.description.contains("soon"))
    }
}

@Test func clientKeyAccessParsing() throws {
    #expect(try ClientKeyAccess(flag: "none") == .none)
    #expect(try ClientKeyAccess(flag: "user-presence") == .userPresence)
    #expect(try ClientKeyAccess(flag: "passcode") == .passcode)
    for bad in ["", "None", "biometry", "user-presence,passcode", "userPresence"] {
        #expect(throws: UsageError.self) { try ClientKeyAccess(flag: bad) }
    }
    do {
        _ = try ClientKeyAccess(flag: "x")
    } catch let e as UsageError {
        #expect(e.description.contains("none, user-presence, passcode"))
    }
}

@Test func clientKeyAccessFlags() {
    #expect(ClientKeyAccess.none.flags == [.privateKeyUsage])
    #expect(ClientKeyAccess.userPresence.flags == [.privateKeyUsage, .userPresence])
    #expect(ClientKeyAccess.passcode.flags == [.privateKeyUsage, .devicePasscode])
    #expect(ClientKeyAccess.none.protection as String == kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
    #expect(ClientKeyAccess.userPresence.protection as String == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
    #expect(ClientKeyAccess.passcode.protection as String == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
}

@Test func cacheAccountCoversEveryInput() throws {
    let leaf = try testLeaf()
    let blob = Data("key".utf8)
    let base = RolesAnywhere.SessionParams(trustAnchorArn: "ta", profileArn: "p", roleArn: "r")
    let a = try CredentialCache.account(keyBlob: blob, certificate: leaf, params: base)
    #expect(a == (try CredentialCache.account(keyBlob: blob, certificate: leaf, params: base)))
    #expect(a.count == 64)

    var variants: [String] = [
        try CredentialCache.account(keyBlob: Data("other".utf8), certificate: leaf, params: base),
        try CredentialCache.account(keyBlob: blob, certificate: testLeaf(), params: base),
    ]
    let changes: [(inout RolesAnywhere.SessionParams) -> Void] = [
        { $0.trustAnchorArn = "ta2" },
        { $0.profileArn = "p2" },
        { $0.roleArn = "r2" },
        { $0.durationSeconds = 900 },
        { $0.roleSessionName = "" },
        { $0.roleSessionName = "s" },
    ]
    for change in changes {
        var p = base
        change(&p)
        variants.append(try CredentialCache.account(keyBlob: blob, certificate: leaf, params: p))
    }
    #expect(Set(variants + [a]).count == variants.count + 1)
}

@Test func expirationParsing() {
    let d = Date(timeIntervalSince1970: 1_800_003_600)
    #expect(CredentialCache.expiration(credentials(expiring: "2027-01-15T09:00:00Z")) == d)
    #expect(CredentialCache.expiration(credentials(expiring: "2027-01-15T09:00:00.000Z")) == d)
    #expect(CredentialCache.expiration(credentials(expiring: "soon")) == nil)
    #expect(CredentialCache.expiration(Data("{}".utf8)) == nil)
    #expect(CredentialCache.expiration(Data("not json".utf8)) == nil)
}

@Test func cacheHitMissAndRefresh() throws {
    let store = MemoryStore()
    var clock = now
    let cache = CredentialCache(store: store, now: { clock })
    let creds = credentials(expiring: "2027-01-15T09:00:00Z")

    #expect(try cache.lookup("a") == nil)
    #expect(try cache.save("a", creds))
    #expect(try cache.lookup("a") == creds)
    #expect(try cache.lookup("b") == nil)

    clock = now.addingTimeInterval(3600 - CredentialCache.refreshMargin - 1)
    #expect(try cache.lookup("a") == creds)
    clock = now.addingTimeInterval(3600 - CredentialCache.refreshMargin)
    #expect(try cache.lookup("a") == nil)
    clock = now.addingTimeInterval(7200)
    #expect(try cache.lookup("a") == nil)
}

@Test func cacheSkipsStaleOrUnreadableCredentials() throws {
    let store = MemoryStore()
    let cache = CredentialCache(store: store, now: { now })
    #expect(!(try cache.save("a", credentials(expiring: "2027-01-15T08:05:00Z"))))
    #expect(!(try cache.save("a", credentials(expiring: "soon"))))
    #expect(store.items.isEmpty)

    store.items["a"] = Data("garbage".utf8)
    #expect(try cache.lookup("a") == nil)
}
